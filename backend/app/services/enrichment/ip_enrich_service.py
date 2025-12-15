# backend/app/services/enrichment/ip_enrich_service.py
from ipaddress import IPv4Address, IPv6Address, ip_address
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
from app.services.enrichment.core_service.retry import async_retry
import logging

logger = logging.getLogger(__name__)


async def enrich_ip_value(ip_str:  str | IPv4Address | IPv6Address) -> IPEnrichResponse:
    """Enrich a single IP string and return the full enrichment + risk model."""
    
    ip_str: str = str(ip_str)
    ip_obj = ip_address(ip_str)
    meta: dict[str, Any] = {"errors": {}}

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    ):
        return IPEnrichResponse(
            ioc_type="ip",
            value=str(ip_obj),
            abuseipdb=AbuseIPDBData(enabled=False),
            ipinfo=IPInfoData(enabled=False),
            dns=DNSData(enabled=False),
            vt=VirusTotalIPData(enabled=False),
            risk=compute_ip_risk(
                abuse=AbuseIPDBData(enabled=False),
                ipinfo=IPInfoData(enabled=False),
                dns=DNSData(enabled=False),
                vt=None,
            ),
            meta={
                "scope": "internal",
                "reason": "private_or_reserved_ip",
            },
        )

    # ---- public IP enrichment continues below ----

    # ---- AbuseIPDB ----
    try:
        abuse_raw = await async_retry(lambda: fetch_abuseipdb(ip_str), attempts=3, base_delay=0.5)
    except Exception as e:
        meta["errors"]["abuseipdb"] = f"{type(e).__name__}: {e}"
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
        ipinfo_raw = await async_retry(lambda: fetch_ipinfo(ip_str), attempts=3, base_delay=0.5)
    except Exception as e:
        meta["errors"]["ipinfo"] = f"{type(e).__name__}: {e}"
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
        a_records, dns_error = await async_retry(lambda: resolve_a_records(ip_str), attempts=2, base_delay=0.5)
    except Exception as e:
        meta["errors"]["dns"] = f"{type(e).__name__}: {e}"
        a_records, dns_error = [], str(e)

    dns = DNSData(
        enabled=True,
        a_records=a_records,
        error=dns_error,
    )

    # ---- VirusTotal ----
    try:
        vt_raw = await async_retry(lambda: fetch_vt_ip(ip_str), attempts=3, base_delay=0.8)
    except Exception as e:
        meta["errors"]["virustotal"] = f"{type(e).__name__}: {e}"
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
        meta=meta,
    )


async def enrich_ips(ip_list: list[str]):
    """Batch enrichment for pipeline use."""
    out = []
    for ip in ip_list:
        result = await enrich_ip_value(ip)
        out.append(result)
    return out
