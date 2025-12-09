from fastapi import APIRouter
from typing import Any

from app.schemas.ip_enrich import (
    IPEnrichRequest,
    IPEnrichResponse,
    AbuseIPDBData,
    IPInfoData,
    DNSData,
)
from app.services.abuseipdb_service import fetch_abuseipdb
from app.services.ipinfo_service import fetch_ipinfo
from app.services.dns_service import resolve_a_records
from app.services.risk_scoring.ip_risk import compute_ip_risk

router = APIRouter()


@router.post("/enrich/ip", response_model=IPEnrichResponse, tags=["enrichment"])
async def enrich_ip(payload: IPEnrichRequest) -> IPEnrichResponse:
    ip_str = str(payload.ip)

    # ---- AbuseIPDB ----
    abuse_raw = await fetch_abuseipdb(ip_str)
    if abuse_raw:
        abuse = AbuseIPDBData(
            enabled=True,
            score=abuse_raw.get("abuseConfidenceScore"),
            total_reports=abuse_raw.get("totalReports"),
            last_reported_at=abuse_raw.get("lastReportedAt"),
            raw=abuse_raw,
        )
    else:
        abuse = AbuseIPDBData(enabled=False)

    # ---- IPInfo ----
    ipinfo_raw = await fetch_ipinfo(ip_str)
    if ipinfo_raw:
        ipinfo = IPInfoData(
            enabled=True,
            ip=ipinfo_raw.get("ip"),
            city=ipinfo_raw.get("city"),
            region=ipinfo_raw.get("region"),
            country=ipinfo_raw.get("country"),
            org=ipinfo_raw.get("org"),
            asn=str(ipinfo_raw.get("asn")) if ipinfo_raw.get("asn") else None,
            raw=ipinfo_raw,
        )
    else:
        ipinfo = IPInfoData(enabled=False)

    # ---- DNS ----
    a_records, dns_error = await resolve_a_records(ip_str)
    dns = DNSData(
        enabled=True,
        a_records=a_records,
        error=dns_error,
    )

    # ---- Risk ----
    risk = compute_ip_risk(abuse=abuse, ipinfo=ipinfo, dns=dns)

    # ---- Meta ----
    meta: dict[str, Any] = {
        "case_id": payload.case_id,
    }

    return IPEnrichResponse(
        ioc_type="ip",
        value=ip_str,
        abuseipdb=abuse,
        ipinfo=ipinfo,
        dns=dns,
        risk=risk,
        meta=meta,
    )
