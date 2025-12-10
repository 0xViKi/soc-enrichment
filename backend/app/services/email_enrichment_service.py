from typing import Any, Dict, List, Tuple
import asyncio
from ipaddress import ip_address

import httpx

from app.config import settings
from app.schemas.email_analysis import (
    AttachmentHashSet,
    EmailIOCBundle,
    EnrichedAttachment,
    EnrichedDomain,
    EnrichedIP,
    EmailEnrichmentBundle,
)


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

    # NOTE: we rely on AsyncClient(base_url=...) so `path` is like "/enrich/hash"
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

    if iocs.sender_domain:
        domain_set.add(iocs.sender_domain.lower())

    for d in iocs.received_domains:
        if d:
            domain_set.add(d.lower())

    for ip in iocs.received_ips:
        if is_valid_ip(ip):
            ip_set.add(ip)

    # IMPORTANT: base_url must be the SAME as you use in curl, e.g.:
    #  INTERNAL_API_BASE_URL = "http://localhost:8000/api/v1"
    # or in docker network: "http://soc-backend:8000/api/v1"
    base = settings.INTERNAL_API_BASE_URL.rstrip("/")

    async with httpx.AsyncClient(
        base_url=base,
        timeout=httpx.Timeout(20.0, connect=10.0),
    ) as client:
        tasks: Dict[str, asyncio.Task] = {}

        # Attachment hash enrichment
        for h in iocs.attachment_hashes:
            chosen = _choose_hash(h)
            if not chosen:
                enriched_attachments.append(
                    EnrichedAttachment(hash_value="", hashes=h, enrichment=None)
                )
                continue

            key = f"hash:{chosen}"
            tasks[key] = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/hash",
                    {"hash_value": chosen},
                )
            )

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
                    # This should now be rare; still guard it
                    results[key] = {
                        "failed": True,
                        "stage": "task",
                        "error_type": type(res).__name__,
                        "error": str(res),
                    }
                else:
                    results[key] = res

    # Map results back

    # Attachments
    for h in iocs.attachment_hashes:
        chosen = _choose_hash(h)
        if not chosen:
            enriched_attachments.append(
                EnrichedAttachment(hash_value="", hashes=h, enrichment=None)
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
