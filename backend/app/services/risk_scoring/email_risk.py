# backend/app/services/risk_scoring/email_risk.py

from typing import List, Optional
from datetime import datetime
from app.schemas.email_analysis import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    EmailRiskScore,
)

import re

SUSPICIOUS_EXTENSIONS = {"exe", "scr", "js", "vbs", "lnk", "ps1", "msi"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly"}

URGENCY_WORDS = ["urgent", "immediately", "asap", "24 hours", "final notice"]
CREDENTIAL_WORDS = [
    "verify your account", "password reset", "sign in", "login",
    "confirm your identity", "account locked"
]
FINANCIAL_WORDS = ["invoice", "payment", "wire transfer", "remittance", "payroll"]
AUTHORITY_WORDS = ["hr", "compliance", "security team", "ceo", "director"]

ACTION_WORDS = ["click here", "access the link", "download", "open attachment"]


def text_from_bodies(bodies: List[EmailBody]) -> str:
    return " ".join((b.content or "").lower() for b in bodies)


def contains(text: str, keywords: List[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def detect_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>\"']+", text)


def compute_email_risk(
    header: EmailHeader,
    bodies: List[EmailBody],
    attachments: List[EmailAttachment],
    verdicts: List[EngineVerdict],
    enrichment=None,
) -> EmailRiskScore:

    raw_score = 0
    reasons = []

    body_text = text_from_bodies(bodies)
    subject = (header.subject or "").lower()

    # --------------------------------------------------------
    # 1. HEADER AUTHENTICITY (0–30 pts)
    # --------------------------------------------------------
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
        raw_score += 10
        reasons.append(f"Reply-To domain mismatch ({reply_domain} vs {from_domain})")

    # Return-Path mismatch
    if return_path_domain and from_domain and return_path_domain != from_domain:
        raw_score += 8
        reasons.append(f"Return-Path mismatch ({return_path_domain} vs {from_domain})")

    # Sender not in Received chain
    if from_domain and header.received_domains:
        received_chain = [d.lower() for d in header.received_domains]
        if from_domain not in received_chain:
            raw_score += 8
            reasons.append("Sender domain not found in Received chain")

    # Domain age (requires enrichment)
    if enrichment and "domains" in enrichment:
        for dom in enrichment["domains"]:
            if dom.domain == from_domain and dom.enrichment and dom.enrichment.whois:
                age = dom.enrichment.whois.domain_age_days or 9999
                if age < 30:
                    raw_score += 10
                    reasons.append("Sender domain newly registered (<30 days)")
                elif age < 90:
                    raw_score += 5
                    reasons.append("Sender domain fairly new (<90 days)")

    # --------------------------------------------------------
    # 2. BODY NLP (0–25 pts)
    # --------------------------------------------------------
    if contains(subject, URGENCY_WORDS) or contains(body_text, URGENCY_WORDS):
        raw_score += 7
        reasons.append("Urgent / pressure phrasing detected")

    if contains(subject, CREDENTIAL_WORDS) or contains(body_text, CREDENTIAL_WORDS):
        raw_score += 8
        reasons.append("Credential harvesting language detected")

    if contains(subject, FINANCIAL_WORDS) or contains(body_text, FINANCIAL_WORDS):
        raw_score += 8
        reasons.append("Financial / payment language detected")

    if contains(body_text, AUTHORITY_WORDS):
        raw_score += 5
        reasons.append("Authority impersonation wording detected")

    # --------------------------------------------------------
    # 3. URL ANALYSIS (0–20 pts)
    # --------------------------------------------------------
    urls = detect_urls(body_text)
    for url in urls:
        domain = url.split("/")[2].lower()

        # shortened
        if domain in SHORTENERS:
            raw_score += 5
            reasons.append(f"URL shortener detected ({domain})")

        # punycode
        if domain.startswith("xn--"):
            raw_score += 10
            reasons.append("Punycode domain detected")

        # IP-based URL
        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            raw_score += 8
            reasons.append("URL uses direct IP address")

        # URLScan enrichment support
        if enrichment and "domains" in enrichment:
            for d in enrichment["domains"]:
                if d.domain == domain and d.enrichment:
                    if getattr(d.enrichment, "urlscan", None):
                        m = d.enrichment.urlscan.malicious_count or 0
                        if m > 0:
                            raw_score += 10
                            reasons.append(f"URL flagged malicious by URLScan ({m} hits)")

    # --------------------------------------------------------
    # 4. ATTACHMENTS (0–25 pts)
    # --------------------------------------------------------
    for att in attachments:
        ext = (att.extension or "").lower()

        if ext in SUSPICIOUS_EXTENSIONS:
            raw_score += 20
            reasons.append(f"Executable attachment detected ({ext})")

        # double extension
        fn = (att.filename or "").lower()
        if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js)$", fn):
            raw_score += 15
            reasons.append(f"Double extension detected ({fn})")

        # VirusTotal enrichment
        if att.hashes and enrichment and "attachments" in enrichment:
            if att.filename in enrichment["attachments"]:
                vt = enrichment["attachments"][att.filename].enrichment.vt
                if vt:
                    malicious = vt.last_analysis_stats.malicious or 0
                    raw_score += min(15, malicious)
                    if malicious > 0:
                        reasons.append(f"VirusTotal detections: {malicious}")

    # --------------------------------------------------------
    # 5. INFRASTRUCTURE (0–20 pts)
    # --------------------------------------------------------
    if enrichment:
        for dom in enrichment.get("domains", []):
            if dom.enrichment and dom.enrichment.risk:
                score = dom.enrichment.risk.score or 0
                if score >= 60:
                    raw_score += 10
                    reasons.append(f"Domain reputation high-risk ({dom.domain})")

        for ip in enrichment.get("ips", []):
            rep = getattr(ip.enrichment, "abuseipdb", None)
            if rep:
                if rep.abuseConfidenceScore >= 80:
                    raw_score += 10
                    reasons.append(f"IP high abuse score ({ip.ip})")

    # --------------------------------------------------------
    # 6. BEHAVIORAL (0–15 pts)
    # --------------------------------------------------------
    if contains(body_text, ACTION_WORDS):
        raw_score += 7
        reasons.append("Call-to-action / manipulation language detected")

    if "internal" in body_text and from_domain and not from_domain.endswith("company.com"):
        raw_score += 3
        reasons.append("Email claims internal action but originates externally")

    # --------------------------------------------------------
    # 7. SPAMASSASSIN (0–15 pts)
    # --------------------------------------------------------
    sa_score = 0
    for v in verdicts:
        if (v.name or "").lower() == "spamassassin":
            sa_score = v.score or 0.0
            break

    if sa_score >= 8:
        raw_score += 15
        reasons.append(f"SpamAssassin very high score ({sa_score})")
    elif sa_score >= 5:
        raw_score += 10
        reasons.append(f"SpamAssassin high score ({sa_score})")
    elif sa_score >= 3:
        raw_score += 5
        reasons.append(f"SpamAssassin elevated ({sa_score})")

    # --------------------------------------------------------
    # NORMALIZE TO 0–100
    # --------------------------------------------------------
    final_score = min(100, round((raw_score / 150) * 100))

    if final_score >= 75:
        level = "high"
    elif final_score >= 45:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("No strong phishing indicators detected")

    return EmailRiskScore(score=final_score, level=level, reasons=reasons)
