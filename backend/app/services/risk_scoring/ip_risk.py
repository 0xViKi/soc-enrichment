from app.schemas.ip_enrich import AbuseIPDBData, IPInfoData, DNSData, IPRiskScore, IPRiskFactor
from app.services.risk_scoring.risk_utils import severity_from_score


def compute_ip_risk(
    abuse: AbuseIPDBData,
    ipinfo: IPInfoData,
    dns: DNSData,
) -> IPRiskScore:

    factors = []

    # AbuseIPDB
    abuse_score = float(abuse.score or 0)
    factors.append(
        IPRiskFactor(
            name="abuseipdb_score",
            weight=0.35,
            value=abuse_score,
            contribution=abuse_score * 0.35,
        )
    )

    # Blacklisted
    blacklisted_value = 100.0 if (abuse.total_reports or 0) > 0 else 0.0
    factors.append(
        IPRiskFactor(
            name="blacklisted",
            weight=0.25,
            value=blacklisted_value,
            contribution=blacklisted_value * 0.25,
        )
    )

    # Geo-risk placeholder
    factors.append(
        IPRiskFactor(
            name="geo_risky_country",
            weight=0.10,
            value=0.0,
            contribution=0.0,
        )
    )

    # Recent malicious reports normalized
    total_reports = float(abuse.total_reports or 0)
    recent_value = min(total_reports, 50) / 50 * 100 if total_reports > 0 else 0.0
    factors.append(
        IPRiskFactor(
            name="recent_malicious_reports",
            weight=0.20,
            value=recent_value,
            contribution=recent_value * 0.20,
        )
    )

    # Correlated malware hashes placeholder
    factors.append(
        IPRiskFactor(
            name="correlated_malware_hashes",
            weight=0.10,
            value=0.0,
            contribution=0.0,
        )
    )

    total_score = int(round(sum(f.contribution for f in factors)))
    severity = severity_from_score(total_score)

    return IPRiskScore(score=total_score, severity=severity, factors=factors)
