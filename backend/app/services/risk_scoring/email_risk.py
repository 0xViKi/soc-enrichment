# backend/app/services/risk_scoring/email_risk.py

from typing import List, Any, Dict
import re

from app.schemas.email_analysis import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    EmailRiskScore,
)

# -----------------------------------------
# Heuristic keyword sets
# -----------------------------------------

SUSPICIOUS_EXTENSIONS = {"exe", "scr", "js", "vbs", "lnk", "ps1", "msi"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly"}

URGENCY_WORDS = ["urgent", "immediately", "asap", "24 hours", "final notice"]
CREDENTIAL_WORDS = [
    "verify your account",
    "password reset",
    "sign in",
    "login",
    "confirm your identity",
    "account locked",
]
FINANCIAL_WORDS = ["invoice", "payment", "wire transfer", "remittance", "payroll"]
AUTHORITY_WORDS = ["hr", "compliance", "security team", "ceo", "director"]

ACTION_WORDS = ["click here", "access the link", "download", "open attachment"]


# -----------------------------------------
# Helper utilities
# -----------------------------------------


def text_from_bodies(bodies: List[EmailBody]) -> str:
    return " ".join((b.content or "").lower() for b in bodies)


def contains(text: str, keywords: List[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def detect_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>\"']+", text)


def _get_enrichment_domains(enrichment: Any) -> List[Any]:
    """Support enrichment as dict or Pydantic model."""
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


def _get_enrichment_attachments_map(enrichment: Any) -> Dict[str, Any]:
    """
    Expect a mapping: { filename: EnrichedAttachment }.
    If enrichment is a dict, read enrichment["attachments"].
    """
    if not enrichment:
        return {}
    if isinstance(enrichment, dict):
        return enrichment.get("attachments") or {}
    return getattr(enrichment, "attachments", {}) or {}


# -----------------------------------------
# Main risk engine
# -----------------------------------------


def compute_email_risk(
    header: EmailHeader,
    bodies: List[EmailBody],
    attachments: List[EmailAttachment],
    verdicts: List[EngineVerdict],
    enrichment=None,
) -> EmailRiskScore:
    """
    Compute holistic email phishing risk (0–100) by combining:

      - Content / header / behavioral score (0–100)
      - Attachment hash risk (0–100)
      - Domain risk (0–100)
      - IP risk (0–100)

    Final score ~= 0.45*content + 0.25*hash + 0.20*domain + 0.10*ip.
    """

    # ============================================================
    # PART 1 – CONTENT / HEADER SCORE (raw points → 0–100)
    # ============================================================
    content_raw = 0
    reasons: List[str] = []

    body_text = text_from_bodies(bodies)
    subject = (header.subject or "").lower()

    # -----------------------------
    # 1. HEADER AUTHENTICITY
    # -----------------------------
    from_domain = None
    if header.from_addr and "@" in header.from_addr:
        from_domain = header.from_addr.split("@")[1].lower()

    reply_domain = None
    if header.reply_to and "@" in header.reply_to:
        reply_domain = header.reply_to.split("@")[1].lower()

    return_path_domain = None
    if header.return_path and "@" in header.return_path:
        return_path_domain = header.return_path.split("@")[1].lower()

    # Reply-To mismatch
    if reply_domain and from_domain and reply_domain != from_domain:
        content_raw += 10
        reasons.append(f"Reply-To domain mismatch ({reply_domain} vs {from_domain})")

    # Return-Path mismatch
    if return_path_domain and from_domain and return_path_domain != from_domain:
        content_raw += 8
        reasons.append(
            f"Return-Path mismatch ({return_path_domain} vs {from_domain})"
        )

    # Sender not in Received chain
    if from_domain and header.received_domains:
        received_chain = [d.lower() for d in header.received_domains]
        if from_domain not in received_chain:
            content_raw += 8
            reasons.append("Sender domain not found in Received chain")

    # Sender domain age from enrichment (header-specific)
    domains_enr = _get_enrichment_domains(enrichment)
    if from_domain and domains_enr:
        for dom in domains_enr:
            d_domain = getattr(dom, "domain", None)
            dom_enr = getattr(dom, "enrichment", None)
            whois = getattr(dom_enr, "whois", None) if dom_enr else None
            if d_domain == from_domain and whois:
                age = getattr(whois, "domain_age_days", None) or 9999
                if age < 30:
                    content_raw += 10
                    reasons.append("Sender domain newly registered (<30 days)")
                elif age < 90:
                    content_raw += 5
                    reasons.append("Sender domain fairly new (<90 days)")

    # -----------------------------
    # 2. BODY NLP
    # -----------------------------
    if contains(subject, URGENCY_WORDS) or contains(body_text, URGENCY_WORDS):
        content_raw += 7
        reasons.append("Urgent / pressure phrasing detected")

    if contains(subject, CREDENTIAL_WORDS) or contains(body_text, CREDENTIAL_WORDS):
        content_raw += 8
        reasons.append("Credential harvesting language detected")

    if contains(subject, FINANCIAL_WORDS) or contains(body_text, FINANCIAL_WORDS):
        content_raw += 8
        reasons.append("Financial / payment language detected")

    if contains(body_text, AUTHORITY_WORDS):
        content_raw += 5
        reasons.append("Authority impersonation wording detected")

    # -----------------------------
    # 3. URL ANALYSIS (structural)
    # -----------------------------
    urls = detect_urls(body_text)
    for url in urls:
        try:
            domain = url.split("/")[2].lower()
        except Exception:
            continue

        if domain in SHORTENERS:
            content_raw += 5
            reasons.append(f"URL shortener detected ({domain})")

        if domain.startswith("xn--"):
            content_raw += 10
            reasons.append("Punycode domain detected")

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            content_raw += 8
            reasons.append("URL uses direct IP address")

    # -----------------------------
    # 4. ATTACHMENTS (structure only)
    # -----------------------------
    for att in attachments:
        ext = (att.extension or "").lower()
        fn = (att.filename or "").lower()

        if ext in SUSPICIOUS_EXTENSIONS:
            content_raw += 20
            reasons.append(f"Executable attachment detected ({ext})")

        # double extension like "contract.pdf.exe"
        if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js)$", fn):
            content_raw += 15
            reasons.append(f"Double extension detected ({fn})")

    # -----------------------------
    # 5. BEHAVIORAL
    # -----------------------------
    if contains(body_text, ACTION_WORDS):
        content_raw += 7
        reasons.append("Call-to-action / manipulation language detected")

    if "internal" in body_text and from_domain and not from_domain.endswith(
        "company.com"
    ):
        content_raw += 3
        reasons.append("Email claims internal action but originates externally")

    # -----------------------------
    # 6. SPAMASSASSIN
    # -----------------------------
    sa_score = 0.0
    for v in verdicts:
        if (v.name or "").lower() == "spamassassin":
            sa_score = v.score or 0.0
            break

    if sa_score >= 8:
        content_raw += 15
        reasons.append(f"SpamAssassin very high score ({sa_score})")
    elif sa_score >= 5:
        content_raw += 10
        reasons.append(f"SpamAssassin high score ({sa_score})")
    elif sa_score >= 3:
        content_raw += 5
        reasons.append(f"SpamAssassin elevated ({sa_score})")

    # Convert content_raw to 0–100 range.
    # This 150 is your "max expected raw points" for pure content.
    CONTENT_MAX = 150.0
    content_score = min(100, round((content_raw / CONTENT_MAX) * 100)) if CONTENT_MAX else 0

    # ============================================================
    # PART 2 – IOC SCORES (hash / domain / IP), each 0–100
    # ============================================================

    attachments_enr = _get_enrichment_attachments_map(enrichment)
    ips_enr = _get_enrichment_ips(enrichment)

    # -----------------------------
    # Hash / attachment risk
    # -----------------------------
    hash_scores: List[int] = []
    if attachments_enr:
        for fn, att_enr in attachments_enr.items():
            enr = getattr(att_enr, "enrichment", None)
            if not enr:
                continue
            hash_risk = getattr(enr, "risk", None)
            if hash_risk:
                s = int(hash_risk.score or 0)
                hash_scores.append(s)
                reasons.append(
                    f"Attachment '{fn}' hash risk {hash_risk.score}/100 "
                    f"({hash_risk.severity})"
                )

    hash_score = max(hash_scores) if hash_scores else 0

    # -----------------------------
    # Domain risk
    # -----------------------------
    domain_scores: List[int] = []
    if domains_enr:
        for dom in domains_enr:
            dom_enr = getattr(dom, "enrichment", None)
            risk = getattr(dom_enr, "risk", None) if dom_enr else None
            if risk:
                s = int(risk.score or 0)
                domain_scores.append(s)
                reasons.append(
                    f"Domain '{getattr(dom, 'domain', '')}' risk "
                    f"{risk.score}/100 ({risk.severity})"
                )

    domain_score = max(domain_scores) if domain_scores else 0

    # -----------------------------
    # IP risk
    # -----------------------------
    ip_scores: List[int] = []
    if ips_enr:
        for ip in ips_enr:
            ip_enr = getattr(ip, "enrichment", None)
            risk = getattr(ip_enr, "risk", None) if ip_enr else None
            if risk:
                s = int(risk.score or 0)
                ip_scores.append(s)
                reasons.append(
                    f"IP '{getattr(ip, 'ip', '')}' risk "
                    f"{risk.score}/100 ({risk.severity})"
                )

    ip_score = max(ip_scores) if ip_scores else 0

    # ============================================================
    # PART 3 – COMBINE COMPONENTS INTO OVERALL SCORE
    # ============================================================

    # Weights for blending content + IOCs. They sum to 1.0.
    W_CONTENT = 0.40
    W_HASH = 0.27
    W_DOMAIN = 0.23
    W_IP = 0.10

    overall_float = (
        content_score * W_CONTENT
        + hash_score * W_HASH
        + domain_score * W_DOMAIN
        + ip_score * W_IP
    )
    final_score = int(round(min(100.0, max(0.0, overall_float))))

    # Severity mapping for email
    if final_score >= 75:
        level = "high"
    elif final_score >= 45:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("No strong phishing indicators detected")

    return EmailRiskScore(score=final_score, level=level, reasons=reasons)
