from datetime import datetime
from typing import List, Tuple

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from app.schemas.email_analysis import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    VerdictDetail,
    AttachmentHashSet,
    EmailIOCBundle,
)
from app.services.eml_analyzer_service import analyze_eml_file
from app.services.risk_scoring.email_risk import compute_email_risk
from app.services.email_enrichment_service import enrich_email_iocs

router = APIRouter(prefix="/email", tags=["email-report"])

templates = Jinja2Templates(directory="app/reports/templates")


@router.post("/report", response_class=HTMLResponse)
async def email_report(request: Request, file: UploadFile = File(...)) -> HTMLResponse:
    """
    Generate an HTML phishing investigation report for a given .eml file.
    """
    try:
        raw = await analyze_eml_file(file)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"EML analyzer error: {e}")

    eml = raw.get("eml", {})
    verdicts_raw = raw.get("verdicts", [])

    # --- Header ---
    header_raw = eml.get("header", {})
    header = EmailHeader.model_validate(header_raw)

    # --- Bodies ---
    bodies_raw = eml.get("bodies", [])
    bodies: List[EmailBody] = [EmailBody.model_validate(b) for b in bodies_raw]

    # --- Attachments ---
    attachments_raw = eml.get("attachments", [])
    attachments: List[EmailAttachment] = [
        EmailAttachment.model_validate(a) for a in attachments_raw
    ]

    # --- Verdicts ---
    engine_verdicts: List[EngineVerdict] = []
    for v in verdicts_raw:
        details_raw = v.get("details", [])
        details = [
            VerdictDetail(
                key=d.get("key"),
                score=d.get("score"),
                description=d.get("description"),
                referenceLink=d.get("referenceLink"),
            )
            for d in details_raw
        ]
        engine_verdicts.append(
            EngineVerdict(
                name=v.get("name"),
                malicious=bool(v.get("malicious")),
                score=v.get("score"),
                details=details,
            )
        )

    # --- Risk scoring ---
    risk = compute_email_risk(
        header=header, bodies=bodies, attachments=attachments, verdicts=engine_verdicts
    )

    # --- IOC bundle ---
    attachment_hashes: List[AttachmentHashSet] = []
    for a in attachments:
        if a.hashes:
            attachment_hashes.append(a.hashes)

    sender_email = header.from_addr
    sender_domain = None
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1]

    iocs = EmailIOCBundle(
        attachment_hashes=attachment_hashes,
        sender_email=sender_email,
        sender_domain=sender_domain,
        received_ips=header.received_ips,
        received_domains=header.received_domains,
    )

    # --- Enrichment bundle ---
    enrichment_bundle = await enrich_email_iocs(iocs)

    # Pair attachments with their corresponding enrichment object (if any)
    attachment_pairs: List[Tuple[EmailAttachment, object | None]] = []
    hash_to_enriched = {
        e.hash_value: e for e in enrichment_bundle.attachments if e.hash_value
    }
    for att in attachments:
        chosen_hash = None
        if att.hashes:
            if att.hashes.sha256:
                chosen_hash = att.hashes.sha256
            elif att.hashes.sha1:
                chosen_hash = att.hashes.sha1
            elif att.hashes.md5:
                chosen_hash = att.hashes.md5
        attachment_pairs.append(
            (att, hash_to_enriched.get(chosen_hash) if chosen_hash else None)
        )

    # Simple timeline (reuse logic from /email/analyze)
    timeline = []
    if header.date:
        timeline.append(
            {
                "type": "email_received",
                "ts": header.date,
                "details": {"subject": header.subject},
            }
        )
    if attachments:
        timeline.append(
            {
                "type": "attachments_extracted",
                "ts": None,
                "details": {"count": len(attachments)},
            }
        )
    if enrichment_bundle.domains or enrichment_bundle.ips:
        timeline.append(
            {
                "type": "ioc_enrichment_completed",
                "ts": None,
                "details": {
                    "domains": len(enrichment_bundle.domains),
                    "ips": len(enrichment_bundle.ips),
                },
            }
        )

    meta = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    context = {
        "request": request,
        "header": header,
        "bodies": bodies,
        "attachments": attachments,
        "verdicts": engine_verdicts,
        "risk": risk,
        "enrichment": enrichment_bundle,
        "timeline": timeline,
        "attachment_pairs": attachment_pairs,
        "meta": meta,
    }

    return templates.TemplateResponse("email_report.html", context)
