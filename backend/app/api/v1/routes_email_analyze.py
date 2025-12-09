# backend/app/api/v1/routes_email_analyze.py
from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List

from app.schemas.email_analysis import (
    EmailAnalysisResponse,
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

router = APIRouter(prefix="/email", tags=["email"])


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(file: UploadFile = File(...)) -> EmailAnalysisResponse:
    """
    Accept an .eml file, send to Heroku analyzer, normalize + risk-score.
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
    bodies: List[EmailBody] = [
        EmailBody.model_validate(b) for b in bodies_raw
    ]

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
        header=header,
        bodies=bodies,
        attachments=attachments,
        verdicts=engine_verdicts,
    )

    # --- IOC bundle for downstream enrichment ---
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

    # --- NEW: Enrich IOCs using internal APIs ---
    enrichment_bundle = await enrich_email_iocs(iocs)

    return EmailAnalysisResponse(
        header=header,
        bodies=bodies,
        attachments=attachments,
        verdicts=engine_verdicts,
        risk=risk,
        iocs=iocs,
        enrichment=enrichment_bundle,
        raw=raw,
    )
