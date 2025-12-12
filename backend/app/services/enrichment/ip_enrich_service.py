# backend/app/services/enrichment/ip_enrich_service.py
from typing import Optional, Any

from app.schemas.enrich.ip_enrich import (
    AbuseIPDBData, IPInfoData, DNSData, VirusTotalIPData,
    IPEnrichResponse
)
from app.services.enrichment.core_service.abuseipdb_service import fetch_abuseipdb
from app.services.enrichment.core_service.ipinfo_service import fetch_ipinfo
from app.services.enrichment.core_service.dns_service import resolve_a_records
from app.services.enrichment.core_service.vt_service import fetch_vt_ip
from app.services.risk_scoring.ip_risk import compute_ip_risk
import logging

logger = logging.getLogger(__name__)


async def enrich_ip_value(ip_str: str) -> IPEnrichResponse:
    """Enrich a single IP string and return the full enrichment+ risk model."""

    # ---- AbuseIPDB ----
    try:
        abuse_raw = await fetch_abuseipdb(ip_str)
    except Exception as e:
        logger.warning("Abuse fetch failed: %s", e)
        abuse_raw = None

    abuse = (
        AbuseIPDBData(
            enabled=True,
            score=abuse_raw.get("abuseConfidenceScore"),
            total_reports=abuse_raw.get("totalReports"),
            last_reported_at=abuse_raw.get("lastReportedAt"),
            raw=abuse_raw,
        )
        if abuse_raw else AbuseIPDBData(enabled=False)
    )

    # ---- IPInfo ----
    try:
        ipinfo_raw = await fetch_ipinfo(ip_str)
    except Exception as e:
        logger.warning("IPInfo fetch failed: %s", e)
        ipinfo_raw = None

    ipinfo = (
        IPInfoData(
            enabled=True,
            ip=ipinfo_raw.get("ip"),
            city=ipinfo_raw.get("city"),
            region=ipinfo_raw.get("region"),
            country=ipinfo_raw.get("country"),
            org=ipinfo_raw.get("org"),
            asn=str(ipinfo_raw.get("asn")) if ipinfo_raw.get("asn") else None,
            raw=ipinfo_raw,
        )
        if ipinfo_raw else IPInfoData(enabled=False)
    )

    # ---- DNS ----
    try:
        a_records, dns_error = await resolve_a_records(ip_str)
    except Exception as e:
        logger.warning("DNS resolve failed: %s", e)
        a_records, dns_error = [], str(e)

    dns = DNSData(
        enabled=True,
        a_records=a_records,
        error=dns_error,
    )

    # ---- VirusTotal ----
    try:
        vt_raw = await fetch_vt_ip(ip_str)
    except Exception:
        vt_raw = None

    if vt_raw:
        attr = vt_raw.get("attributes", {}) or {}
        categories = attr.get("categories")
        if isinstance(categories, dict):
            categories_list = list(categories.keys())
        elif isinstance(categories, list):
            categories_list = categories
        else:
            categories_list = []

        vt = VirusTotalIPData(
            enabled=True,
            reputation=attr.get("reputation"),
            last_analysis_stats=attr.get("last_analysis_stats"),
            last_analysis_date=attr.get("last_analysis_date"),
            categories=categories_list,
            country=attr.get("country"),
            as_owner=attr.get("as_owner"),
            raw=vt_raw,
        )
    else:
        vt = VirusTotalIPData(enabled=False)

    # ---- Risk Score ----
    risk = compute_ip_risk(
        abuse=abuse,
        ipinfo=ipinfo,
        dns=dns,
        vt=vt
    )

    return IPEnrichResponse(
        ioc_type="ip",
        value=ip_str,
        abuseipdb=abuse,
        ipinfo=ipinfo,
        dns=dns,
        vt=vt,
        risk=risk,
        meta={},
    )


async def enrich_ips(ip_list: list[str]):
    """Batch enrichment for pipeline use."""
    out = []
    for ip in ip_list:
        result = await enrich_ip_value(ip)
        out.append(result)
    return out
