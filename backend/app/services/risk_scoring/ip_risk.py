from datetime import datetime, timedelta
from typing import Optional, List

from backend.app.schemas.enrich.ip_enrich import (
    AbuseIPDBData,
    IPInfoData,
    DNSData,
    IPRiskScore,
    IPRiskFactor,
    VirusTotalIPData,
)
from app.services.risk_scoring.risk_utils import severity_from_score


# --------------------------------------------------------
# Helper functions
# --------------------------------------------------------

HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "VN", "NG", "BR", "IN", "RO", "UA"
}

LOW_RISK_COUNTRIES = {
    "US", "CA", "AU", "GB", "NZ", "DE", "FR", "NL", "SE"
}

HIGH_RISK_ASNS = {
    "ovh", "digitalocean", "contabo", "m247", "hetzner",
    "choopa", "sharktech", "colo", "hostwinds", "linode"
}

BOTNET_BEHAVIOR = [
    "ssh brute force",
    "botnet",
    "ddos",
    "c&c",
    "c2",
    "malware",
    "scanner",
    "ransomware",
]


def _normalize(v, max_v):
    """Simple normalization 0–100 scaled by max_v."""
    if not v:
        return 0.0
    return min(100.0, (float(v) / max_v) * 100.0)


def _abuse_behavior_score(abuse: AbuseIPDBData) -> float:
    """
    Check AbuseIPDB categories for high-risk behaviors.
    If categories are missing, fallback to generic severity.
    """
    cats = getattr(abuse, "categories", []) or []
    if not cats:
        return 0.0

    cats_l = [c.lower() for c in cats]
    score = 0.0

    for b in BOTNET_BEHAVIOR:
        if b in cats_l:
            score += 30.0

    # Too many categories = high malicious diversity
    if len(cats_l) >= 4:
        score += 40.0
    elif len(cats_l) >= 2:
        score += 20.0

    return min(score, 100.0)


def _asn_risk_score(ipinfo: IPInfoData) -> float:
    """
    High-risk ASN heuristic.
    """
    asn_name = (getattr(ipinfo, "asn_name", "") or "").lower()
    if not asn_name:
        return 40.0

    for high in HIGH_RISK_ASNS:
        if high in asn_name:
            return 90.0

    # If it's a major ISP: lower risk baseline
    if any(x in asn_name for x in ("comcast", "telstra", "verizon", "rogers")):
        return 20.0

    # Unknown ASN → moderate risk
    return 40.0


def _geo_risk_score(ipinfo: IPInfoData) -> float:
    country = getattr(ipinfo, "country", None)
    if not country:
        return 40.0

    if country in HIGH_RISK_COUNTRIES:
        return 80.0
    if country in LOW_RISK_COUNTRIES:
        return 20.0

    return 50.0  # moderate risk for unknowns


def _reverse_dns_score(dns: DNSData) -> float:
    """
    PTR anomalies—malicious infrastructure often uses:
    - completely random PTRs
    - hosting provider PTR with no alignment to sender domain
    """
    ptr = getattr(dns, "reverse_dns", None)
    if not ptr:
        return 20.0  # unknown PTR → slight risk

    ptr_l = ptr.lower()

    if any(x in ptr_l for x in ("amazonaws", "googleusercontent", "digitalocean", "contaboserver", "ovh")):
        return 70.0  # cloud PTR used suspiciously

    # Random-looking PTR (long and meaningless)
    if len(ptr_l) > 25 and any(c.isdigit() for c in ptr_l):
        return 60.0

    return 20.0


def _recent_report_risk(abuse: AbuseIPDBData) -> float:
    """
    Weight recent malicious activity more heavily.
    If AbuseIPDB API provides timestamps per report, even better.
    """
    total = abuse.total_reports or 0
    if total <= 0:
        return 0.0

    # Normalize up to 100 for 50+ reports
    base = min(100.0, (total / 50.0) * 100.0)

    # If marked "last reported" recently, escalate:
    last_report = getattr(abuse, "last_reported_at", None)
    if last_report:
        try:
            dt = datetime.fromisoformat(last_report.replace("Z", "+00:00"))
            days = (datetime.utcnow() - dt).days
            if days <= 1:
                base += 40
            elif days <= 7:
                base += 20
        except:
            pass

    return min(base, 100.0)


def _ip_freshness_score(ipinfo: IPInfoData) -> float:
    """
    Newly assigned IP ranges (recent allocation) tend to be used for fast abuse.
    Only works if IPInfo provides allocation_date.
    """
    alloc = getattr(ipinfo, "allocation_date", None)
    if not alloc:
        return 20.0

    try:
        dt = datetime.fromisoformat(alloc.replace("Z", "+00:00"))
        days = (datetime.utcnow() - dt).days

        if days <= 7:
            return 80.0
        if days <= 30:
            return 50.0
        if days <= 180:
            return 30.0
        return 10.0
    except:
        return 20.0


def _vt_detection_score(vt: VirusTotalIPData) -> float:
    """
    Use VT last_analysis_stats to derive a 0–100 score based on
    proportion of malicious engines.
    """
    if not vt or not vt.enabled or not vt.last_analysis_stats:
        return 0.0

    stats = vt.last_analysis_stats or {}
    malicious = float(stats.get("malicious", 0) or 0)
    total = float(sum(stats.values()) or 1.0)

    ratio = (malicious / total) * 100.0
    # Cap at 100
    return min(100.0, ratio)


# --------------------------------------------------------
# Main Advanced IP Risk Engine
# --------------------------------------------------------

def compute_ip_risk(
    abuse: AbuseIPDBData,
    ipinfo: IPInfoData,
    dns: DNSData,
    vt: VirusTotalIPData | None = None,
) -> IPRiskScore:

    factors = []

    # 1) Abuse Confidence Score
    abuse_score = float(abuse.score or 0)
    factors.append(IPRiskFactor(
        name="abuseipdb_confidence",
        weight=0.22,
        value=abuse_score,
        contribution=abuse_score * 0.22,
    ))

    # 2) Malicious Behavior Category Score
    behavior_score = _abuse_behavior_score(abuse)
    factors.append(IPRiskFactor(
        name="malicious_behavior_categories",
        weight=0.15,
        value=behavior_score,
        contribution=behavior_score * 0.15,
    ))

    # 3) Recent Activity / Report Freshness
    recent_score = _recent_report_risk(abuse)
    factors.append(IPRiskFactor(
        name="recent_malicious_reports",
        weight=0.15,
        value=recent_score,
        contribution=recent_score * 0.15,
    ))

    # 4) ASN / ISP Risk Profile
    asn_score = _asn_risk_score(ipinfo)
    factors.append(IPRiskFactor(
        name="asn_risk_profile",
        weight=0.12,
        value=asn_score,
        contribution=asn_score * 0.12,
    ))

    # 5) Geolocation Risk
    geo_score = _geo_risk_score(ipinfo)
    factors.append(IPRiskFactor(
        name="geolocation_risk",
        weight=0.10,
        value=geo_score,
        contribution=geo_score * 0.10,
    ))

    # 6) Reverse DNS / PTR anomalies
    ptr_score = _reverse_dns_score(dns)
    factors.append(IPRiskFactor(
        name="reverse_dns_anomalies",
        weight=0.10,
        value=ptr_score,
        contribution=ptr_score * 0.10,
    ))

    # 7) IP Freshness (new allocations)
    fresh_score = _ip_freshness_score(ipinfo)
    factors.append(IPRiskFactor(
        name="ip_allocation_freshness",
        weight=0.08,
        value=fresh_score,
        contribution=fresh_score * 0.08,
    ))

    # 8) VirusTotal detection ratio
    vt_score = _vt_detection_score(vt) if vt else 0.0
    factors.append(IPRiskFactor(
        name="virustotal_detection_ratio",
        weight=0.08,
        value=vt_score,
        contribution=vt_score * 0.08,
    ))

    # Total score
    total = int(round(sum(f.contribution for f in factors)))
    severity = severity_from_score(total)

    return IPRiskScore(score=total, severity=severity, factors=factors)
