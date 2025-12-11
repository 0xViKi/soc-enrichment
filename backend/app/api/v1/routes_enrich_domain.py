from typing import Any, List, Optional
from fastapi import APIRouter
import logging

from app.schemas.enrich.domain_enrich import (
    DomainEnrichRequest,
    DomainEnrichResponse,
    WHOISData,
    DNSRecordData,
    URLScanData,
    URLScanFinding,
    VirusTotalDomainData,
)
from app.services.enrichment.dns_service import resolve_dns_records
from app.services.enrichment.whois_service import normalize_whois
from app.services.enrichment.urlscan_service import search_urlscan_domain
from app.services.enrichment.vt_service import fetch_vt_domain
from app.services.risk_scoring.domain_risk import compute_domain_risk

router = APIRouter()
logger = logging.getLogger(__name__)


def _safe_normalize_whois(domain: str) -> dict:
    try:
        return normalize_whois(domain)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        # Return minimal empty structure; WHOISData will fill defaults
        return {}


async def _safe_resolve_dns(domain: str) -> dict:
    try:
        return await resolve_dns_records(domain)
    except Exception as e:
        logger.warning("DNS record resolution failed for %s: %s", domain, e)
        return {"a_records": [], "mx_records": [], "txt_records": [], "errors": {"exception": str(e)}}


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


@router.post("/enrich/domain", response_model=DomainEnrichResponse, tags=["enrichment"])
async def enrich_domain(payload: DomainEnrichRequest) -> DomainEnrichResponse:
    domain = payload.domain.strip().lower()

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
            task = item.get("task", {})
            page = item.get("page", {})
            verdicts = item.get("verdicts", {})
            malicious = False

            overall = verdicts.get("overall", {})
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

        # simple TLD extraction for convenience
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
        "case_id": payload.case_id,
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
