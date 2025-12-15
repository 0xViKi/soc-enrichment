from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import UploadFile

from app.schemas.enrich.email_enrich import (
    EmailHeader,
    EmailBody,
    EmailAttachment,
    EngineVerdict,
    VerdictDetail,
    AttachmentHashSet,
    EmailIOCBundle,
)
from app.services.email_analyzer.eml_analyzer_service import analyze_eml_file
from app.services.risk_scoring.email_risk import compute_email_risk
from app.services.enrichment.email_enrichment_service import enrich_email_iocs


@dataclass(frozen=True)
class EmailAnalysisData:
    raw: Dict[str, Any]
    header: EmailHeader
    bodies: List[EmailBody]
    attachments: List[EmailAttachment]
    verdicts: List[EngineVerdict]
    risk: Any
    iocs: EmailIOCBundle
    enrichment: Any


def _parse_header(eml: dict) -> EmailHeader:
    return EmailHeader.model_validate((eml or {}).get("header", {}) or {})


def _parse_bodies(eml: dict) -> List[EmailBody]:
    return [EmailBody.model_validate(b) for b in ((eml or {}).get("bodies", []) or [])]


def _parse_attachments(eml: dict) -> List[EmailAttachment]:
    return [EmailAttachment.model_validate(a) for a in ((eml or {}).get("attachments", []) or [])]


def _parse_verdicts(raw: dict) -> List[EngineVerdict]:
    verdicts_raw = raw.get("verdicts", []) or []
    out: List[EngineVerdict] = []

    for v in verdicts_raw:
        details_raw = v.get("details", []) or []
        details = [
            VerdictDetail(
                key=d.get("key"),
                score=d.get("score"),
                description=d.get("description"),
                referenceLink=d.get("referenceLink"),
            )
            for d in details_raw
        ]

        out.append(
            EngineVerdict(
                name=v.get("name"),
                malicious=bool(v.get("malicious")),
                score=v.get("score"),
                details=details,
            )
        )

    return out


def _build_iocs(header: EmailHeader, attachments: List[EmailAttachment]) -> EmailIOCBundle:
    attachment_hashes: List[AttachmentHashSet] = []
    for a in attachments:
        if a.hashes:
            attachment_hashes.append(a.hashes)

    sender_email = header.from_addr
    sender_domain: Optional[str] = None
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1]

    return EmailIOCBundle(
        attachment_hashes=attachment_hashes,
        sender_email=sender_email,
        sender_domain=sender_domain,
        received_ips=header.received_ips,
        received_domains=header.received_domains,
    )


async def analyze_email_pipeline(file: UploadFile) -> EmailAnalysisData:
    """
    Single source of truth for:
    external analyzer -> normalize -> risk score -> ioc bundle -> enrich
    """
    raw = await analyze_eml_file(file)
    eml = raw.get("eml", {}) or {}

    header = _parse_header(eml)
    bodies = _parse_bodies(eml)
    attachments = _parse_attachments(eml)
    verdicts = _parse_verdicts(raw)

    risk = compute_email_risk(
        header=header,
        bodies=bodies,
        attachments=attachments,
        verdicts=verdicts,
    )

    iocs = _build_iocs(header, attachments)
    enrichment = await enrich_email_iocs(iocs)

    return EmailAnalysisData(
        raw=raw,
        header=header,
        bodies=bodies,
        attachments=attachments,
        verdicts=verdicts,
        risk=risk,
        iocs=iocs,
        enrichment=enrichment,
    )
