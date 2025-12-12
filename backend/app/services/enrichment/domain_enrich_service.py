# backend/app/services/enrichment/domain_enrich_service.py
from typing import Any, List, Optional
import logging

from app.schemas.enrich.domain_enrich import (
    WHOISData,
    DNSRecordData,
    URLScanData,
    URLScanFinding,
    VirusTotalDomainData,
    DomainEnrichResponse,
)
from app.services.enrichment.core_service.dns_service import resolve_dns_records
from app.services.enrichment.core_service.whois_service import normalize_whois
from app.services.enrichment.core_service.urlscan_service import search_urlscan_domain
from app.services.enrichment.core_service.vt_service import fetch_vt_domain
from app.services.risk_scoring.domain_risk import compute_domain_risk

logger = logging.getLogger(__name__)


def _safe_normalize_whois(domain: str) -> dict:
    try:
        return normalize_whois(domain)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return {}


async def _safe_resolve_dns(domain: str) -> dict:
    try:
        return await resolve_dns_records(domain)
    except Exception as e:
        logger.warning("DNS record resolution failed for %s: %s", domain, e)
        return {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "errors": {"exception": str(e)},
        }


async def _safe_urlscan(domain: str) -> Optional[dict]:
    try:
        return await search_urlscan_domain(domain)
    except Exception as e:
        logger.warning("URLScan lookup failed for %s: %s", domain, e)
        return None


async def _safe_vt_domain(domain: str) -> Optional[dict]:
    try:
        return await fetch_vt_domain(domain)
    except Exception as e:
        logger.warning("VirusTotal domain lookup failed for %s: %s", domain, e)
        return None


async def enrich_domain_value(domain: str) -> DomainEnrichResponse:
    """
    Enrich a single domain and return full enrichment + risk.
    This is the core logic reused by both:
      - /enrich/domain API route
      - internal event pipeline
    """
    domain = domain.strip().lower()

    # ---- WHOIS ----
    whois_norm = _safe_normalize_whois(domain)
    whois = WHOISData(**whois_norm)

    # ---- DNS ----
    dns_raw = await _safe_resolve_dns(domain)
    dns = DNSRecordData(
        enabled=True,
        a_records=dns_raw.get("a_records", []),
        mx_records=dns_raw.get("mx_records", []),
        txt_records=dns_raw.get("txt_records", []),
        errors=dns_raw.get("errors", {}),
    )

    # ---- URLScan ----
    urlscan_raw = await _safe_urlscan(domain)
    findings: List[URLScanFinding] = []
    malicious_count = 0

    if urlscan_raw and "results" in urlscan_raw:
        for item in urlscan_raw["results"]:
            task = item.get("task", {}) or {}
            page = item.get("page", {}) or {}
            verdicts = item.get("verdicts", {}) or {}
            malicious = False

            overall = verdicts.get("overall", {}) or {}
            if overall.get("malicious") or (overall.get("score", 0) > 0):
                malicious = True
                malicious_count += 1

            findings.append(
                URLScanFinding(
                    task_url=task.get("url"),
                    page_url=page.get("url"),
                    status=task.get("status"),
                    tags=item.get("tags", []),
                    malicious=malicious,
                    raw=item,
                )
            )

    urlscan = URLScanData(
        enabled=True if urlscan_raw else False,
        results=findings,
        malicious_count=malicious_count,
    )

    # ---- VirusTotal (Domain) ----
    vt_raw = await _safe_vt_domain(domain)
    if vt_raw:
        attr = vt_raw.get("attributes", {}) if isinstance(vt_raw, dict) else {}
        cats = attr.get("categories")
        if isinstance(cats, dict):
            categories = list(cats.keys())
        elif isinstance(cats, list):
            categories = cats
        else:
            categories = []

        tld = None
        parts = domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]

        vt = VirusTotalDomainData(
            enabled=True,
            reputation=attr.get("reputation"),
            last_analysis_stats=attr.get("last_analysis_stats"),
            last_analysis_date=attr.get("last_analysis_date"),
            categories=categories,
            registrar=attr.get("registrar"),
            tld=tld,
            whois=attr.get("whois"),
            raw=vt_raw,
        )
    else:
        vt = VirusTotalDomainData(enabled=False)

    # ---- Risk ----
    risk = compute_domain_risk(whois=whois, dns=dns, urlscan=urlscan, vt=vt)

    meta: dict[str, Any] = {
        # internal use; pipeline can override or ignore
    }

    return DomainEnrichResponse(
        ioc_type="domain",
        value=domain,
        whois=whois,
        dns=dns,
        urlscan=urlscan,
        vt=vt,
        risk=risk,
        meta=meta,
    )


async def enrich_domains(domains: list[str]) -> list[DomainEnrichResponse]:
    """
    Simple batch wrapper for internal event pipeline.
    (Can be optimized with asyncio.gather later if needed.)
    """
    results: list[DomainEnrichResponse] = []
    seen = set()
    for d in domains:
        d_norm = d.strip().lower()
        if not d_norm or d_norm in seen:
            continue
        seen.add(d_norm)
        res = await enrich_domain_value(d_norm)
        results.append(res)
    return results
