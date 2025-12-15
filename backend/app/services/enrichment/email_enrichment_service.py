from typing import Any, Dict, List
import asyncio
from ipaddress import ip_address
import logging, json

import httpx

from app.core.config import settings
from app.schemas.enrich.email_enrich import (
    AttachmentHashSet,
    EmailIOCBundle,
    EnrichedAttachment,
    EnrichedDomain,
    EnrichedIP,
    EmailEnrichmentBundle,
)

# Limit how many internal /enrich calls we make at once
# You can make this configurable via settings if you like
_INTERNAL_ENRICH_CONCURRENCY = getattr(settings, "INTERNAL_ENRICH_CONCURRENCY", 5)
_SEM = asyncio.Semaphore(_INTERNAL_ENRICH_CONCURRENCY)
logger = logging.getLogger("email_enrich_debug")


def is_valid_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ip_address(value.strip())
        return True
    except ValueError:
        return False


async def _post_json(
    client: httpx.AsyncClient,
    path: str,
    payload: dict,
) -> Dict[str, Any] | None:
    """
    POST JSON to internal /enrich endpoints.

    Returns:
      - Parsed JSON dict on success
      - {"failed": True, ...} dict on any error
    """
    async with _SEM:
        try:
            resp = await client.post(path, json=payload)
        except Exception as e:
            return {
                "failed": True,
                "stage": "request",
                "error_type": type(e).__name__,
                "error": str(e),
                "path": path,
                "payload": payload,
            }

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            # 4xx / 5xx from /enrich/*
            text = resp.text
            return {
                "failed": True,
                "stage": "status",
                "status_code": resp.status_code,
                "error_type": type(e).__name__,
                "error": str(e),
                "path": path,
                "payload": payload,
                "body_snippet": text[:300],
            }

        try:
            return resp.json()
        except Exception as e:
            text = resp.text
            return {
                "failed": True,
                "stage": "json",
                "status_code": resp.status_code,
                "error_type": type(e).__name__,
                "error": str(e),
                "path": path,
                "payload": payload,
                "body_snippet": text[:300],
            }


def _choose_hash(h: AttachmentHashSet) -> str | None:
    """
    Choose best hash to use for enrichment.
    Prefer sha256, then sha1, then md5.
    """
    if h.sha256:
        return h.sha256
    if h.sha1:
        return h.sha1
    if h.md5:
        return h.md5
    return None


async def enrich_email_iocs(iocs: EmailIOCBundle) -> EmailEnrichmentBundle:
    """
    Given the extracted IOCs from an email, call internal /enrich endpoints
    to get hash/domain/ip enrichment.
    """

    enriched_attachments: List[EnrichedAttachment] = []
    enriched_domains: List[EnrichedDomain] = []
    enriched_ips: List[EnrichedIP] = []

    # Prepare unique sets
    domain_set: set[str] = set()
    ip_set: set[str] = set()

    # --- Normalize domains ---
    if iocs.sender_domain:
        d = iocs.sender_domain.strip().lower()
        if d:
            domain_set.add(d)

    for d in iocs.received_domains:
        if not d:
            continue
        d_norm = d.strip().lower()
        if d_norm:
            domain_set.add(d_norm)

    # --- Normalize IPs ---
    for ip in iocs.received_ips:
        if not ip:
            continue
        ip_norm = ip.strip()
        if is_valid_ip(ip_norm):
            ip_set.add(ip_norm)

    # Base URL must match your curl base (inc. /api/v1 if you use that there)
    base = settings.INTERNAL_API_BASE_URL.rstrip("/")

    async with httpx.AsyncClient(
        base_url=base,
        timeout=httpx.Timeout(45.0, connect=10.0),
    ) as client:
        tasks: Dict[str, asyncio.Task] = {}

        # Attachment hash enrichment – one task per *unique* hash
        unique_hashes: set[str] = set()
        for h in iocs.attachment_hashes:
            chosen = _choose_hash(h)
            if not chosen:
                # attachments with no hash will be handled in the mapping step
                continue

            if chosen in unique_hashes:
                continue
            unique_hashes.add(chosen)

            key = f"hash:{chosen}"
            tasks[key] = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/hash",
                    {"hash_value": chosen},
                )
            )

        # Logging/Debug 
        # logger.warning("EMAIL_ENRICH DEBUG: extracted attachment_hashes=%s",
        #        [h.model_dump() for h in iocs.attachment_hashes])
        # logger.warning("EMAIL_ENRICH DEBUG: unique chosen hashes=%s", sorted(unique_hashes))
        # logger.warning("EMAIL_ENRICH DEBUG: INTERNAL_API_BASE_URL=%s", base)
        
        # Domain enrichment
        for d in sorted(domain_set):
            key = f"domain:{d}"
            tasks[key] = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/domain",
                    {"domain": d},
                )
            )

        # IP enrichment
        for ip in sorted(ip_set):
            key = f"ip:{ip}"
            tasks[key] = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/ip",
                    {"ip": ip},
                )
            )

        results: Dict[str, Dict[str, Any] | None] = {}
        if tasks:
            done_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for (key, _task), res in zip(tasks.items(), done_list):
                if isinstance(res, Exception):
                    results[key] = {
                        "failed": True,
                        "stage": "task",
                        "error_type": type(res).__name__,
                        "error": str(res),
                    }
                else:
                    results[key] = res

        # Logging/Debug purpose
        # for k, v in results.items():
        #     if k.startswith("hash:"):
        #         if v is None:
        #             logger.error("EMAIL_ENRICH DEBUG: %s -> None", k)
        #         else:
        #             logger.warning("EMAIL_ENRICH DEBUG: %s -> keys=%s", k, list(v.keys()))
        #             # show nested shape safely
        #             try:
        #                 logger.warning("EMAIL_ENRICH DEBUG: %s -> vt=%s risk=%s",
        #                             k, "present" if (isinstance(v, dict) and v.get("vt")) else "missing",
        #                             "present" if (isinstance(v, dict) and v.get("risk")) else "missing")
        #             except Exception as e:
        #                 logger.exception("EMAIL_ENRICH DEBUG: failed inspecting %s: %s", k, e)

        #             # print first 600 chars (so logs don't explode)
        #             try:
        #                 logger.warning("EMAIL_ENRICH DEBUG: %s -> body_snippet=%s",
        #                             k, json.dumps(v)[:600])
        #             except Exception:
        #                 logger.warning("EMAIL_ENRICH DEBUG: %s -> non-json-printable", k)


    # --- Map results back ---

    # Attachments
    for h in iocs.attachment_hashes:
        chosen = _choose_hash(h)
        if not chosen:
            # No hash available → no enrichment
            enriched_attachments.append(
                EnrichedAttachment(
                    hash_value="",
                    hashes=h,
                    enrichment=None,
                )
            )
            continue

        key = f"hash:{chosen}"
        enriched_attachments.append(
            EnrichedAttachment(
                hash_value=chosen,
                hashes=h,
                enrichment=results.get(key),
            )
        )

    # Domains
    for d in sorted(domain_set):
        key = f"domain:{d}"
        enriched_domains.append(
            EnrichedDomain(
                domain=d,
                enrichment=results.get(key),
            )
        )

    # IPs
    for ip in sorted(ip_set):
        key = f"ip:{ip}"
        enriched_ips.append(
            EnrichedIP(
                ip=ip,
                enrichment=results.get(key),
            )
        )

    return EmailEnrichmentBundle(
        attachments=enriched_attachments,
        domains=enriched_domains,
        ips=enriched_ips,
    )
