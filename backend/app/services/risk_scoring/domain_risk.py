from app.schemas.domain_enrich import WHOISData, DNSRecordData, URLScanData, DomainRiskScore, DomainRiskFactor
from app.services.risk_scoring.risk_utils import severity_from_score


def _age_to_score(age_days):
    if age_days is None:
        return 50
    if age_days <= 7:
        return 100
    if age_days <= 30:
        return 80
    if age_days <= 180:
        return 40
    return 20


def compute_domain_risk(whois: WHOISData, dns: DNSRecordData, urlscan: URLScanData) -> DomainRiskScore:
    factors = []

    # Age
    age_score = _age_to_score(whois.domain_age_days)
    factors.append(DomainRiskFactor(
        name="domain_age_score",
        weight=0.25,
        value=age_score,
        contribution=age_score * 0.25,
    ))

    # URLScan maliciousness
    mal_count = urlscan.malicious_count or 0
    mal_score = min(mal_count, 10) / 10 * 100
    factors.append(DomainRiskFactor(
        name="urlscan_malicious",
        weight=0.35,
        value=mal_score,
        contribution=mal_score * 0.35,
    ))

    # Privacy protection
    privacy_score = 100 if whois.privacy_protected else 0
    factors.append(DomainRiskFactor(
        name="whois_privacy_enabled",
        weight=0.10,
        value=privacy_score,
        contribution=privacy_score * 0.10,
    ))

    # TXT suspicious placeholder
    factors.append(DomainRiskFactor(
        name="dns_txt_suspicious",
        weight=0.10,
        value=0.0,
        contribution=0.0,
    ))

    # Seen in URLScan
    seen_score = 100 if urlscan.results else 0
    factors.append(DomainRiskFactor(
        name="seen_in_urlscan",
        weight=0.20,
        value=seen_score,
        contribution=seen_score * 0.20,
    ))

    total = int(sum(f.contribution for f in factors))
    severity = severity_from_score(total)
    return DomainRiskScore(score=total, severity=severity, factors=factors)
