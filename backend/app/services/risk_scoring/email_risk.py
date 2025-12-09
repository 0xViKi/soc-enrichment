# backend/app/services/risk_scoring/email_risk.py
from typing import List, Optional
from app.schemas.email_analysis import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    EmailRiskScore,
)


SUSPICIOUS_EXTENSIONS = {"exe", "scr", "js", "vbs", "lnk", "ps1"}
URGENCY_KEYWORDS = [
    "urgent",
    "immediate action required",
    "verify your account",
    "contract",
    "payment",
    "invoice",
    "by the end of the day",
]


def _body_contains_urgency(bodies: List[EmailBody]) -> bool:
    text = " ".join((b.content or "").lower() for b in bodies)
    return any(kw in text for kw in URGENCY_KEYWORDS)


def _has_dangerous_attachment(attachments: List[EmailAttachment]) -> bool:
    for att in attachments:
        ext = (att.extension or "").lower()
        fn = (att.filename or "").lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            return True
        # crude double-extension detection e.g. "pdf.exe"
        if any(fn.endswith(f".{safe}.{bad}") for safe in ["pdf", "docx", "xlsx"]
               for bad in SUSPICIOUS_EXTENSIONS):
            return True
    return False


def _get_spamassassin_score(verdicts: List[EngineVerdict]) -> float:
    for v in verdicts:
        if v.name.lower() == "spamassassin":
            return v.score or 0.0
    return 0.0


def compute_email_risk(
    header: EmailHeader,
    bodies: List[EmailBody],
    attachments: List[EmailAttachment],
    verdicts: List[EngineVerdict],
) -> EmailRiskScore:
    score = 0
    reasons: List[str] = []

    # 1) Attachments
    if _has_dangerous_attachment(attachments):
        score += 40
        reasons.append("Suspicious executable or double-extension attachment")

    # 2) Urgency / pressure in content
    if _body_contains_urgency(bodies):
        score += 20
        reasons.append("Urgent / pressure language in email body")

    # 3) SpamAssassin
    sa_score = _get_spamassassin_score(verdicts)
    if sa_score >= 5:
        score += 25
        reasons.append(f"SpamAssassin high score ({sa_score})")
    elif sa_score >= 3:
        score += 15
        reasons.append(f"SpamAssassin moderately elevated ({sa_score})")

    # 4) From vs received domain mismatch (very rough heuristic)
    sender = (header.from_addr or "").lower()
    sender_domain: Optional[str] = None
    if "@" in sender:
        sender_domain = sender.split("@", 1)[1]
    received_domains = [d.lower() for d in header.received_domains]

    if sender_domain and received_domains and sender_domain not in received_domains:
        score += 15
        reasons.append(
            f"Sender domain ({sender_domain}) not present in Received chain"
        )

    # Clamp
    if score > 100:
        score = 100

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("No strong phishing indicators detected")

    return EmailRiskScore(score=score, level=level, reasons=reasons)
