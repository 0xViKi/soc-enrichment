# backend/app/services/risk_scoring/email_risk.py

from typing import List, Any, Dict, Optional
import re

from app.schemas.email_analysis import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    EmailRiskScore,
)

# -------------------------------------------------------------------
# Heuristic wordlists / patterns
# -------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS: Dict[str, int] = {
    # Critical executables / scripts
    "exe": 40,
    "scr": 40,
    "bat": 35,
    "cmd": 35,
    "com": 40,
    "pif": 35,
    "msi": 30,
    "application": 35,
    "js": 35,
    "jse": 35,
    "vbs": 35,
    "vbe": 35,
    "ws": 30,
    "wsf": 30,
    "wsh": 30,
    "ps1": 35,
    "psm1": 30,
    # Shortcuts / libraries
    "lnk": 25,
    "inf": 25,
    "reg": 30,
    "dll": 25,
    "cpl": 30,
    # Archives
    "zip": 5,
    "rar": 5,
    "7z": 5,
    "tar": 5,
    "gz": 5,
    # Macro-enabled docs
    "docm": 20,
    "dotm": 20,
    "xlsm": 20,
    "xltm": 20,
    "pptm": 20,
    "potm": 20,
    "xlam": 20,
    # Other containers
    "iso": 25,
    "img": 25,
    "vhd": 25,
    "hta": 35,
}

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "goo.gl", "cutt.ly", "tiny.cc", "rb.gy", "shorturl.at",
}

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\bwithin\s+\d+\s+hours?\b",
    r"\bfinal\s+notice\b",
    r"\blast\s+chance\b",
    r"\bact\s+now\b",
    r"\bexpir(e|ing)\s+(today|soon|now)\b",
    r"\btime\s+sensitive\b",
    r"\bdeadline\b",
    r"\baction\s+required\b",
]

CREDENTIAL_PATTERNS = [
    r"\bverify\s+(your\s+)?(account|identity|email)\b",
    r"\bpassword\s+(reset|expired|expir)\b",
    r"\bconfirm\s+(your\s+)?(account|identity|email)\b",
    r"\baccount\s+(suspended|locked|disabled)\b",
    r"\bre-?validate\s+(your\s+)?account\b",
    r"\bsign\s+in\s+to\s+confirm\b",
    r"\bauthenticate\s+your\b",
    r"\bunusual\s+activity\b",
    r"\bsecurity\s+alert\b",
]

FINANCIAL_PATTERNS = [
    r"\binvoice\b",
    r"\bwire\s+transfer\b",
    r"\bpayment\s+(required|failed|overdue)\b",
    r"\bremittance\b",
    r"\bpayroll\b",
    r"\brefund\s+(pending|processing)\b",
    r"\btax\s+(refund|return)\b",
]

IMPERSONATED_BRANDS = [
    "microsoft", "office365", "o365", "google", "gmail",
    "apple", "icloud", "amazon", "paypal", "facebook", "meta",
    "netflix", "dropbox", "docusign", "adobe",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "club", "work", "live",
    "online", "site", "tech", "click", "link",
    "loan", "download",
}

ACTION_WORDS = ["click here", "access the link", "login here", "open attachment"]


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def text_from_bodies(bodies: List[EmailBody]) -> str:
    return " ".join((b.content or "").lower() for b in bodies)


def _safe_get(obj: Any, key: str, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def extract_urls(text: str) -> List[str]:
    urls: List[str] = []
    urls.extend(re.findall(r"https?://[^\s<>'\")]+", text))
    defanged = re.findall(r"h[xX]{2}ps?://[^\s<>'\")]+", text)
    urls.extend([u.replace("hxxp", "http").replace("hXXp", "http") for u in defanged])
    bracketed = re.findall(r"[\w.-]+\[\.\][\w.-]+", text)
    urls.extend([u.replace("[.]", ".") for u in bracketed])
    return list(set(urls))


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        u = re.sub(r"^https?://", "", url)
        d = u.split("/")[0].lower()
        d = d.split(":")[0]
        return d
    except Exception:
        return None


def check_homograph(domain: str) -> bool:
    if domain.startswith("xn--"):
        return True
    has_ascii = any(ord(c) < 128 for c in domain)
    has_non_ascii = any(ord(c) >= 128 for c in domain)
    return has_ascii and has_non_ascii


def _get_enrichment_domains(enrichment: Any) -> List[Any]:
    if not enrichment:
        return []
    if isinstance(enrichment, dict):
        return enrichment.get("domains") or []
    return getattr(enrichment, "domains", []) or []


def _get_enrichment_ips(enrichment: Any) -> List[Any]:
    if not enrichment:
        return []
    if isinstance(enrichment, dict):
        return enrichment.get("ips") or []
    return getattr(enrichment, "ips", []) or []


def _get_enrichment_attachments_list(enrichment: Any) -> List[Any]:
    if not enrichment:
        return []
    if isinstance(enrichment, dict):
        att = enrichment.get("attachments")
    else:
        att = getattr(enrichment, "attachments", None)
    if att is None:
        return []
    if isinstance(att, list):
        return att
    if isinstance(att, dict):
        return list(att.values())
    return []


# -------------------------------------------------------------------
# Main scoring function
# -------------------------------------------------------------------

def compute_email_risk(
    header: EmailHeader,
    bodies: List[EmailBody],
    attachments: List[EmailAttachment],
    verdicts: List[EngineVerdict],
    enrichment=None,
) -> EmailRiskScore:
    """
    Sublime-style email phishing risk engine.

    - Uses rule-based indicators grouped into Critical / Major / Minor.
    - Combines them into a 0–100 score.
    - Adds a Sublime-like classification in the first reason line.
    """

    reasons: List[str] = []

    body_text = text_from_bodies(bodies)
    subject = (header.subject or "").lower()
    combined_text = subject + " " + body_text

    # ------------------------------------------------------------------
    # 1) Extract IOC risk from enrichment (max scores)
    # ------------------------------------------------------------------
    domains_enr = _get_enrichment_domains(enrichment)
    ips_enr = _get_enrichment_ips(enrichment)
    att_enr_list = _get_enrichment_attachments_list(enrichment)

    max_domain_risk = 0
    max_ip_risk = 0
    max_hash_risk = 0

    for dom in domains_enr:
        risk = _safe_get(_safe_get(dom, "enrichment"), "risk")
        s = _safe_get(risk, "score")
        if s is not None:
            max_domain_risk = max(max_domain_risk, int(s))

    for ip in ips_enr:
        risk = _safe_get(_safe_get(ip, "enrichment"), "risk")
        s = _safe_get(risk, "score")
        if s is not None:
            max_ip_risk = max(max_ip_risk, int(s))

    for a in att_enr_list:
        enr = _safe_get(a, "enrichment")
        risk = _safe_get(enr, "risk")
        s = _safe_get(risk, "score")
        if s is not None:
            max_hash_risk = max(max_hash_risk, int(s))

    # ------------------------------------------------------------------
    # 2) Structural attachment checks (double-ext, exe-like)
    # ------------------------------------------------------------------
    has_exe_like = False
    double_ext = False

    for att in attachments:
        filename = (att.filename or "").lower()
        ext = (att.extension or "").lower()

        if ext in SUSPICIOUS_EXTENSIONS and SUSPICIOUS_EXTENSIONS[ext] >= 30:
            has_exe_like = True

        if re.search(r"\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\.(exe|scr|js|vbs|bat|cmd)$", filename):
            double_ext = True
            has_exe_like = True

    # ------------------------------------------------------------------
    # 3) Authentication & header anomalies
    # ------------------------------------------------------------------
    critical_indicators: List[str] = []
    major_indicators: List[str] = []
    minor_indicators: List[str] = []

    from_domain = None
    if header.from_addr and "@" in header.from_addr:
        from_domain = header.from_addr.split("@")[1].lower()

    spf = (header.spf_result or "").lower()
    dkim = (header.dkim_result or "").lower()
    dmarc = (header.dmarc_result or "").lower()

    if spf == "fail":
        major_indicators.append("SPF check failed")
        reasons.append("SPF check failed (sender not authorised)")
    elif spf in ("softfail", "neutral", "none", ""):
        minor_indicators.append("Weak/no SPF")
        reasons.append("Weak or missing SPF policy")

    if dkim == "fail":
        major_indicators.append("DKIM validation failed")
        reasons.append("DKIM signature validation failed")
    elif dkim in ("none", ""):
        minor_indicators.append("No DKIM")
        reasons.append("No DKIM signature present")

    if dmarc == "fail":
        critical_indicators.append("DMARC failed")
        reasons.append("DMARC policy failed (likely spoofed domain)")
    elif dmarc in ("none", ""):
        minor_indicators.append("No DMARC")
        reasons.append("No DMARC policy found")

    reply_domain = None
    if header.reply_to and "@" in header.reply_to:
        reply_domain = header.reply_to.split("@")[1].lower()
    if reply_domain and from_domain and reply_domain != from_domain:
        major_indicators.append("Reply-To mismatch")
        reasons.append(f"Reply-To domain mismatch ({reply_domain} ≠ {from_domain})")

    return_path_domain = None
    if header.return_path and "@" in header.return_path:
        return_path_domain = header.return_path.split("@")[1].lower()
    if return_path_domain and from_domain and return_path_domain != from_domain:
        major_indicators.append("Return-Path mismatch")
        reasons.append(f"Return-Path domain mismatch ({return_path_domain} ≠ {from_domain})")

    if from_domain and header.received_domains:
        if from_domain.lower() not in [d.lower() for d in header.received_domains]:
            minor_indicators.append("Sender not in Received chain")
            reasons.append("Sender domain not found in Received chain")

    # ------------------------------------------------------------------
    # 4) Content / social engineering
    # ------------------------------------------------------------------
    if any(re.search(p, combined_text, re.IGNORECASE) for p in URGENCY_PATTERNS):
        minor_indicators.append("Urgency language")
        reasons.append("Urgent / time-pressure wording detected")

    if any(re.search(p, combined_text, re.IGNORECASE) for p in CREDENTIAL_PATTERNS):
        major_indicators.append("Credential phishing language")
        reasons.append("Credential-harvesting language detected")

    if any(re.search(p, combined_text, re.IGNORECASE) for p in FINANCIAL_PATTERNS):
        major_indicators.append("Financial language")
        reasons.append("Financial/payment language detected")

    if any(b in combined_text for b in IMPERSONATED_BRANDS):
        major_indicators.append("Brand impersonation")
        reasons.append("Possible brand impersonation detected")

    if any(a in combined_text for a in ACTION_WORDS):
        minor_indicators.append("Call-to-action")
        reasons.append("Call-to-action language encouraging clicks / downloads")

    if re.search(r"\bdear (customer|user|member|client|sir|madam)\b",
                 combined_text, re.IGNORECASE):
        minor_indicators.append("Generic greeting")
        reasons.append("Generic greeting (not personalised)")

    # SpamAssassin
    sa_score = 0.0
    for v in verdicts:
        if (v.name or "").lower() == "spamassassin":
            sa_score = v.score or 0.0
            break
    if sa_score >= 7:
        major_indicators.append("SpamAssassin high")
        reasons.append(f"SpamAssassin high score ({sa_score})")
    elif sa_score >= 3:
        minor_indicators.append("SpamAssassin elevated")
        reasons.append(f"SpamAssassin elevated score ({sa_score})")

    # ------------------------------------------------------------------
    # 5) URL analysis
    # ------------------------------------------------------------------
    body_text_lower = body_text.lower()
    urls = extract_urls(body_text_lower)
    for url in urls:
        domain = extract_domain_from_url(url)
        if not domain:
            continue

        if domain in SHORTENERS:
            minor_indicators.append("URL shortener")
            reasons.append(f"URL shortener detected: {domain}")

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            major_indicators.append("IP URL")
            reasons.append(f"URL uses bare IP address: {domain}")

        tld = domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            minor_indicators.append("Suspicious TLD")
            reasons.append(f"Suspicious TLD: .{tld}")

        if check_homograph(domain):
            major_indicators.append("Homograph domain")
            reasons.append(f"Homograph/IDN-looking domain: {domain}")

        if len(domain) > 40:
            minor_indicators.append("Long domain")
            reasons.append(f"Unusually long domain: {domain[:50]}...")

        if domain.count(".") - 1 > 3:
            minor_indicators.append("Many subdomains")
            reasons.append(f"Domain with many subdomains: {domain}")

    # ------------------------------------------------------------------
    # 6) Attachment structural risk
    # ------------------------------------------------------------------
    if has_exe_like:
        major_indicators.append("Executable attachment")
        reasons.append("Executable / script-like attachment present")

    if double_ext:
        critical_indicators.append("Double extension")
        reasons.append("Double-extension attachment (e.g., .pdf.exe) detected")

    # ------------------------------------------------------------------
    # 7) IOC-based indicator tiers
    # ------------------------------------------------------------------
    # Hash risk
    if max_hash_risk >= 80:
        critical_indicators.append("Malicious hash")
        reasons.append(f"Attachment hash risk {max_hash_risk}/100 (malware)")
    elif max_hash_risk >= 60:
        major_indicators.append("High hash risk")
        reasons.append(f"Attachment hash risk {max_hash_risk}/100")
    elif max_hash_risk >= 40:
        minor_indicators.append("Medium hash risk")
        reasons.append(f"Attachment hash moderately risky ({max_hash_risk}/100)")

    # Domain risk
    if max_domain_risk >= 80:
        critical_indicators.append("Very high domain risk")
        reasons.append(f"Domain risk {max_domain_risk}/100 (infrastructure)")
    elif max_domain_risk >= 60:
        major_indicators.append("High domain risk")
        reasons.append(f"Domain risk {max_domain_risk}/100")
    elif max_domain_risk >= 40:
        minor_indicators.append("Medium domain risk")
        reasons.append(f"Domain moderately risky ({max_domain_risk}/100)")

    # IP risk
    if max_ip_risk >= 80:
        critical_indicators.append("Very high IP risk")
        reasons.append(f"IP risk {max_ip_risk}/100 (abuse)")
    elif max_ip_risk >= 60:
        major_indicators.append("High IP risk")
        reasons.append(f"IP risk {max_ip_risk}/100")
    elif max_ip_risk >= 40:
        minor_indicators.append("Medium IP risk")
        reasons.append(f"IP moderately risky ({max_ip_risk}/100)")

    # ------------------------------------------------------------------
    # 8) Translate indicators -> numeric risk
    # ------------------------------------------------------------------
    critical_count = len(critical_indicators)
    major_count = len(major_indicators)
    minor_count = len(minor_indicators)

    base_score = critical_count * 30 + major_count * 15 + minor_count * 5

    # IOC numeric contribution (up to +40 points)
    # Weighted more towards hash, then domain, then IP.
    ioc_component = (
        max_hash_risk * 0.4
        + max_domain_risk * 0.35
        + max_ip_risk * 0.25
    ) / 100.0 * 40.0

    overall = base_score + ioc_component
    final_score = int(round(max(0.0, min(100.0, overall))))

    # Critical override: known malicious hash + executable-like attachment
    if max_hash_risk >= 80 and has_exe_like and final_score < 80:
        final_score = 80
        reasons.append("Critical override: known malicious executable attachment")

    # ------------------------------------------------------------------
    # 9) Severity buckets (Sublime-like)
    # ------------------------------------------------------------------
    if final_score >= 80:
        level = "critical"   # treat as Malicious
        classification = "Classification: Malicious email (critical)"
    elif final_score >= 60:
        level = "high"       # Malicious / high-risk
        classification = "Classification: Malicious / high-risk email"
    elif final_score >= 40:
        level = "medium"     # Suspicious
        classification = "Classification: Suspicious email (requires analyst review)"
    else:
        level = "low"        # Likely benign
        classification = "Classification: Likely benign email (low risk)"

    if not reasons:
        reasons.append("No strong phishing indicators detected")

    # Deduplicate reasons
    seen = set()
    unique_reasons: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    # Prepend classification line to feel like Sublime
    unique_reasons.insert(0, classification)

    # Limit to top N for readability
    unique_reasons = unique_reasons[:20]

    return EmailRiskScore(
        score=final_score,
        level=level,
        reasons=unique_reasons,
    )
