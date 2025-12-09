from typing import Any, List

from fastapi import APIRouter

from app.schemas.domain_enrich import (
    DomainEnrichRequest,
    DomainEnrichResponse,
    WHOISData,
    DNSRecordData,
    URLScanData,
    URLScanFinding,
)
from app.services.dns_service import resolve_dns_records
from app.services.whois_service import normalize_whois
from app.services.urlscan_service import search_urlscan_domain
from app.services.risk_scoring.domain_risk import compute_domain_risk

router = APIRouter()


@router.post("/enrich/domain", response_model=DomainEnrichResponse, tags=["enrichment"])
async def enrich_domain(payload: DomainEnrichRequest) -> DomainEnrichResponse:
    domain = payload.domain.strip().lower()

    # ---- WHOIS ----
    whois_norm = normalize_whois(domain)
    whois = WHOISData(**whois_norm)

    # ---- DNS ----
    dns_raw = await resolve_dns_records(domain)
    dns = DNSRecordData(
        enabled=True,
        a_records=dns_raw.get("a_records", []),
        mx_records=dns_raw.get("mx_records", []),
        txt_records=dns_raw.get("txt_records", []),
        errors=dns_raw.get("errors", {}),
    )

    # ---- URLScan ----
    urlscan_raw = await search_urlscan_domain(domain)
    findings: List[URLScanFinding] = []
    malicious_count = 0

    if urlscan_raw and "results" in urlscan_raw:
        for item in urlscan_raw["results"]:
            task = item.get("task", {})
            page = item.get("page", {})
            verdicts = item.get("verdicts", {})
            malicious = False

            # Very basic: treat as malicious if verdicts.malicious or score > 0
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

    # ---- Risk ----
    risk = compute_domain_risk(whois=whois, dns=dns, urlscan=urlscan)

    meta: dict[str, Any] = {
        "case_id": payload.case_id,
    }

    return DomainEnrichResponse(
        ioc_type="domain",
        value=domain,
        whois=whois,
        dns=dns,
        urlscan=urlscan,
        risk=risk,
        meta=meta,
    )
