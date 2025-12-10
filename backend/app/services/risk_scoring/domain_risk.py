from typing import Optional, List

from app.schemas.domain_enrich import (
    WHOISData,
    DNSRecordData,
    URLScanData,
    DomainRiskScore,
    DomainRiskFactor,
)
from app.services.risk_scoring.risk_utils import severity_from_score


# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------


def _safe_get(obj, attr, default=None):
    return getattr(obj, attr, default) if obj is not None else default


def _age_to_score(age_days: Optional[int]) -> float:
    """
    Map domain age in days to a 0–100 risk score.
    Newer domains → higher risk.
    """
    if age_days is None:
        # Unknown age is moderately risky
        return 60.0
    if age_days <= 3:
        return 100.0
    if age_days <= 14:
        return 90.0
    if age_days <= 30:
        return 75.0
    if age_days <= 90:
        return 55.0
    if age_days <= 365:
        return 35.0
    return 10.0


def _urlscan_malicious_score(urlscan: URLScanData) -> float:
    """
    Use URLScan malicious_count as a strong signal.
    0 → 0, 1 → 40, 2 → 60, >=5 → 100 (capped).
    """
    if not urlscan:
        return 0.0
    mal_count = _safe_get(urlscan, "malicious_count", 0) or 0
    if mal_count <= 0:
        return 0.0
    if mal_count == 1:
        return 40.0
    if mal_count == 2:
        return 60.0
    if mal_count <= 4:
        return 80.0
    return 100.0


def _urlscan_seen_score(urlscan: URLScanData) -> float:
    """
    Being seen in URLScan at all is a moderate risk indicator, especially
    if tagged as phishing/malware/scam.
    """
    if not urlscan:
        return 0.0

    results = _safe_get(urlscan, "results", None)
    if not results:
        return 0.0

    base = 45.0
    tags: List[str] = _safe_get(urlscan, "tags", []) or []
    tags_l = [t.lower() for t in tags]

    if any(t in tags_l for t in ("phishing", "malware", "scam", "crypto-scam")):
        return 80.0

    page_title = (_safe_get(urlscan, "page_title", "") or "").lower()
    if any(x in page_title for x in ("parked", "suspended", "for sale")):
        return 65.0

    return base


HIGH_RISK_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "club",
    "online",
    "work",
    "loan",
    "men",
    "date",
    "download",
    "bid",
    "review",
    "win",
    "shop",
    "icu",
}

MEDIUM_RISK_TLDS = {
    "info",
    "biz",
    "space",
    "site",
    "live",
    "today",
    "support",
    "center",
}


def _extract_domain_string(
    whois: WHOISData, dns: DNSRecordData, urlscan: URLScanData
) -> Optional[str]:
    """
    Try to get the bare domain from any enrichment source.
    """
    candidates = [
        _safe_get(whois, "domain_name", None),
        _safe_get(dns, "domain", None),
        _safe_get(urlscan, "domain", None),
    ]

    for cand in candidates:
        if not cand:
            continue
        # WHOIS domain_name may be list or string
        if isinstance(cand, list) and cand:
            cand = cand[0]
        if isinstance(cand, str) and cand.strip():
            return cand.strip().lower()
    return None


def _tld_from_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return None
    return parts[-1]


def _tld_risk_score(domain: Optional[str]) -> float:
    """
    Some TLDs are statistically abused more often. We treat them as higher risk.
    """
    tld = _tld_from_domain(domain)
    if not tld:
        return 40.0  # unknown → mildly risky

    if tld in HIGH_RISK_TLDS:
        return 80.0
    if tld in MEDIUM_RISK_TLDS:
        return 55.0
    return 20.0


def _privacy_score(whois: WHOISData) -> float:
    """
    WHOIS privacy isn't inherently bad, but very common in abusive domains.
    """
    if _safe_get(whois, "privacy_protected", False):
        return 70.0
    # No privacy → low risk for this factor
    return 10.0


HIGH_RISK_REGISTRARS = {
    # Obviously not exhaustive; just an example list of commonly abused ones
    "namecheap",
    "godaddy",
    "hostinger",
    "gname.com",
    "nicenic",
    "publicdomainregistry",
    "pdr ltd.",
}


def _registrar_risk_score(whois: WHOISData) -> float:
    """
    Basic registrar reputation scoring.
    """
    reg = (_safe_get(whois, "registrar", "") or "").lower()
    if not reg:
        # No registrar in WHOIS → weird
        return 60.0

    for bad in HIGH_RISK_REGISTRARS:
        if bad in reg:
            return 75.0

    # Known registrar but not in high-risk list → low risk
    return 20.0


def _dns_suspicious_score(dns: DNSRecordData) -> float:
    """
    DNS heuristics:
    - Web-only (A/AAAA) but no MX while being used in mail context.
    - Overly-permissive SPF patterns.
    - Completely empty DNS.
    """
    if not dns:
        return 30.0  # unknown DNS → modest risk

    a_recs = _safe_get(dns, "a_records", []) or []
    aaaa_recs = _safe_get(dns, "aaaa_records", []) or []
    mx_recs = _safe_get(dns, "mx_records", []) or []
    txt_recs = _safe_get(dns, "txt_records", []) or []

    score = 0.0

    # Web-only but no MX: slightly suspicious when seen in email context
    if (a_recs or aaaa_recs) and not mx_recs:
        score += 45.0

    # SPF misconfig patterns in TXT
    joined_txt = " ".join(txt_recs).lower()
    if "v=spf1" in joined_txt:
        if "+all" in joined_txt or "?all" in joined_txt:
            # Overly-permissive SPF
            score += 40.0

    # Absolutely nothing configured
    if not any([a_recs, aaaa_recs, mx_recs, txt_recs]):
        score += 30.0

    return max(0.0, min(100.0, score))


BRAND_KEYWORDS = [
    "paypal",
    "microsoft",
    "office365",
    "outlook",
    "google",
    "gmail",
    "amazon",
    "apple",
    "netflix",
    "github",
    "cloudflare",
    "facebook",
]


def _normalize_label(label: str) -> str:
    """
    Normalise a label by mapping common lookalike characters and stripping
    non-alphanumerics.
    """
    label = label.lower()
    mapping = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
    }
    out = []
    for ch in label:
        if ch.isalnum():
            out.append(mapping.get(ch, ch))
    return "".join(out)


def _homograph_brand_impersonation_score(domain: Optional[str]) -> float:
    """
    Detect basic homograph / brand-impersonation:
    - Compare the 2nd-level label against known brands with a simple
      normalised similarity metric.
    """
    if not domain:
        return 0.0

    parts = domain.split(".")
    if len(parts) < 2:
        return 0.0

    sld = _normalize_label(parts[-2])

    if not sld or len(sld) < 4:
        return 0.0

    max_score = 0.0

    for brand in BRAND_KEYWORDS:
        b_norm = _normalize_label(brand)
        # rough similarity: ratio of matching chars in same positions
        m = sum(1 for a, b in zip(sld, b_norm) if a == b)
        sim = m / max(len(sld), len(b_norm))
        if sim >= 0.7:
            # High similarity to brand name → suspicious
            max_score = max(max_score, 90.0)
        elif sim >= 0.5:
            max_score = max(max_score, 60.0)

    return max_score


def _dga_like_score(domain: Optional[str]) -> float:
    """
    Extremely simple DGA-ish / random-looking domain heuristic:
    - Long SLD
    - Low vowel ratio
    - Few meaningful substrings.
    """
    if not domain:
        return 0.0

    parts = domain.split(".")
    if len(parts) < 2:
        return 0.0

    sld = parts[-2].lower()
    if len(sld) < 8:
        return 0.0

    vowels = sum(1 for c in sld if c in "aeiou")
    ratio = vowels / max(1, len(sld))

    if len(sld) >= 15 and ratio < 0.3:
        return 80.0
    if len(sld) >= 12 and ratio < 0.25:
        return 60.0
    return 0.0


def _domain_string_risk_score(domain: Optional[str]) -> float:
    """
    Combine homograph / brand impersonation and DGA-like look.
    """
    homograph = _homograph_brand_impersonation_score(domain)
    dga_like = _dga_like_score(domain)
    return max(homograph, dga_like)


def _whois_completeness_score(whois: WHOISData) -> float:
    """
    Check how complete WHOIS is:
    missing org / country / email → higher risk (privacy or cheap registrar).
    """
    org = _safe_get(whois, "org", None) or _safe_get(whois, "organization", None)
    country = _safe_get(whois, "country", None)
    email = _safe_get(whois, "emails", None)

    missing = 0
    if not org:
        missing += 1
    if not country:
        missing += 1
    if not email:
        missing += 1

    if missing == 0:
        return 10.0
    if missing == 1:
        return 35.0
    if missing == 2:
        return 60.0
    return 80.0


# --------------------------------------------------------------------
# Main API
# --------------------------------------------------------------------


def compute_domain_risk(
    whois: WHOISData,
    dns: DNSRecordData,
    urlscan: URLScanData,
) -> DomainRiskScore:
    """
    Advanced domain risk model combining:
    - Age
    - URLScan malicious usage
    - URLScan exposure/footprint
    - WHOIS privacy & completeness
    - TLD abuse profile
    - DNS misconfig / suspicious patterns
    - Registrar reputation
    - Homograph / DGA-like domain appearance
    into a 0–100 score.
    """

    domain = _extract_domain_string(whois, dns, urlscan)

    factors: List[DomainRiskFactor] = []

    # 1) Domain age
    age_val = _age_to_score(_safe_get(whois, "domain_age_days", None))
    factors.append(
        DomainRiskFactor(
            name="domain_age",
            weight=0.18,
            value=age_val,
            contribution=age_val * 0.18,
        )
    )

    # 2) URLScan maliciousness
    mal_val = _urlscan_malicious_score(urlscan)
    factors.append(
        DomainRiskFactor(
            name="urlscan_malicious",
            weight=0.25,
            value=mal_val,
            contribution=mal_val * 0.25,
        )
    )

    # 3) URLScan exposure / tags / parked pages
    seen_val = _urlscan_seen_score(urlscan)
    factors.append(
        DomainRiskFactor(
            name="urlscan_seen",
            weight=0.07,
            value=seen_val,
            contribution=seen_val * 0.07,
        )
    )

    # 4) WHOIS privacy
    privacy_val = _privacy_score(whois)
    factors.append(
        DomainRiskFactor(
            name="whois_privacy_enabled",
            weight=0.08,
            value=privacy_val,
            contribution=privacy_val * 0.08,
        )
    )

    # 5) TLD abuse profile
    tld_val = _tld_risk_score(domain)
    factors.append(
        DomainRiskFactor(
            name="tld_risk_profile",
            weight=0.08,
            value=tld_val,
            contribution=tld_val * 0.08,
        )
    )

    # 6) DNS suspiciousness
    dns_val = _dns_suspicious_score(dns)
    factors.append(
        DomainRiskFactor(
            name="dns_suspicious_configuration",
            weight=0.12,
            value=dns_val,
            contribution=dns_val * 0.12,
        )
    )

    # 7) Registrar risk
    reg_val = _registrar_risk_score(whois)
    factors.append(
        DomainRiskFactor(
            name="registrar_reputation",
            weight=0.07,
            value=reg_val,
            contribution=reg_val * 0.07,
        )
    )

    # 8) Domain string analysis (homograph / DGA-like)
    dom_str_val = _domain_string_risk_score(domain)
    factors.append(
        DomainRiskFactor(
            name="domain_string_appearance",
            weight=0.10,
            value=dom_str_val,
            contribution=dom_str_val * 0.10,
        )
    )

    # 9) WHOIS completeness
    whois_comp_val = _whois_completeness_score(whois)
    factors.append(
        DomainRiskFactor(
            name="whois_completeness",
            weight=0.05,
            value=whois_comp_val,
            contribution=whois_comp_val * 0.05,
        )
    )

    # Weights: 0.18 + 0.25 + 0.07 + 0.08 + 0.08 + 0.12 + 0.07 + 0.10 + 0.05 = 1.0

    total = int(round(sum(f.contribution for f in factors)))
    severity = severity_from_score(total)

    return DomainRiskScore(score=total, severity=severity, factors=factors)
