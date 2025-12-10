from typing import Any, Dict, List, Tuple
import asyncio

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

from ipaddress import ip_address, AddressValueError


def is_valid_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ip_address(value.strip())
        return True
    except ValueError:
        return False

async def _post_json(client: httpx.AsyncClient, path: str, payload: dict) -> Dict[str, Any] | None:
    """
    Helper: POST JSON to internal API, swallow errors and return None on failure.
    """
    base = settings.INTERNAL_API_BASE_URL.rstrip("/")
    url = f"{base}{path}"
    try:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


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

    # Collect tasks
    async with httpx.AsyncClient(timeout=15.0) as client:
        tasks: List[Tuple[str, asyncio.Task]] = []

        # Attachment hash enrichment
        for h in iocs.attachment_hashes:
            chosen = _choose_hash(h)
            if not chosen:
                enriched_attachments.append(
                    EnrichedAttachment(hash_value="", hashes=h, enrichment=None)
                )
                continue

            t = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/hash",
                    {"hash_value": chosen},
                )
            )
            tasks.append((f"hash:{chosen}", t))

        # Domain enrichment
        for d in sorted(domain_set):
            t = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/domain",
                    {"domain": d},
                )
            )
            tasks.append((f"domain:{d}", t))

        # IP enrichment
        for ip in sorted(ip_set):
            t = asyncio.create_task(
                _post_json(
                    client,
                    "/enrich/ip",
                    {"ip": ip},
                )
            )
            tasks.append((f"ip:{ip}", t))

        # Await all
        results: Dict[str, Dict[str, Any] | None] = {}
        if tasks:
            done = await asyncio.gather(*(t for _, t in tasks), return_exceptions=True)
            for (key, _), res in zip(tasks, done):
                if isinstance(res, Exception):
                    results[key] = None
                else:
                    results[key] = res

    # Now map results back

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
