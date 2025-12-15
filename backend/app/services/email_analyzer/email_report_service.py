from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional
import uuid
import logging,json

from fastapi import UploadFile

from app.schemas.enrich.email_enrich import EmailAttachment
from app.services.email_analyzer.email_analysis_service import analyze_email_pipeline

logger = logging.getLogger("email_report_debug")


@dataclass(frozen=True)
class EmailReportData:
    template_name: str
    context: Dict[str, Any]


def _pick_best_attachment_hash(att: EmailAttachment) -> Optional[str]:
    if not att.hashes:
        return None
    if att.hashes.sha256:
        return att.hashes.sha256
    if att.hashes.sha1:
        return att.hashes.sha1
    if att.hashes.md5:
        return att.hashes.md5
    return None


def _pair_attachments_with_enrichment(
    attachments: List[EmailAttachment],
    enrichment_bundle: Any,
) -> List[Tuple[EmailAttachment, object | None]]:
    hash_to_enriched = {
        e.hash_value: e
        for e in (getattr(enrichment_bundle, "attachments", []) or [])
        if getattr(e, "hash_value", None)
    }

    pairs: List[Tuple[EmailAttachment, object | None]] = []
    for att in attachments:
        chosen_hash = _pick_best_attachment_hash(att)
        pairs.append((att, hash_to_enriched.get(chosen_hash) if chosen_hash else None))
    return pairs


def _build_timeline(header: Any, attachments: List[EmailAttachment], enrichment_bundle: Any):
    timeline: List[Dict[str, Any]] = []

    if getattr(header, "date", None):
        timeline.append(
            {
                "type": "email_received",
                "ts": header.date,
                "details": {"subject": getattr(header, "subject", None)},
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

    domains = getattr(enrichment_bundle, "domains", []) or []
    ips = getattr(enrichment_bundle, "ips", []) or []
    if domains or ips:
        timeline.append(
            {
                "type": "ioc_enrichment_completed",
                "ts": None,
                "details": {"domains": len(domains), "ips": len(ips)},
            }
        )

    return timeline


async def build_email_report(file: UploadFile) -> EmailReportData:
    """
    Builds template + context for HTML report using the SAME pipeline as /email/analyze.
    Route should only inject `request` and call TemplateResponse.
    """
    data = await analyze_email_pipeline(file)

    # DEBUG PURPOSE
    # try:
    #     att_list = [(a.filename, (a.hashes.model_dump() if a.hashes else None)) for a in data.attachments]
    #     logger.warning("EMAIL_REPORT DEBUG: attachments=%s", att_list)
    # except Exception:
    #     logger.warning("EMAIL_REPORT DEBUG: attachments dump failed")

    # try:
    #     # dump enrichment attachments from bundle
    #     e_atts = getattr(data.enrichment, "attachments", []) or []
    #     simplified = []
    #     for e in e_atts:
    #         # e.enrichment may be dict
    #         enr = getattr(e, "enrichment", None)
    #         keys = list(enr.keys()) if isinstance(enr, dict) else type(enr).__name__
    #         simplified.append({"hash_value": getattr(e, "hash_value", None), "enrichment_keys": keys})
    #     logger.warning("EMAIL_REPORT DEBUG: enrichment.attachments=%s", simplified)
    # except Exception as ex:
    #     logger.exception("EMAIL_REPORT DEBUG: enrichment attachments inspect failed: %s", ex)


    attachment_pairs = _pair_attachments_with_enrichment(data.attachments, data.enrichment)
    timeline = _build_timeline(data.header, data.attachments, data.enrichment)

    meta = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "case_id" : str(uuid.uuid4())
    }

    context: Dict[str, Any] = {
        "header": data.header,
        "bodies": data.bodies,
        "attachments": data.attachments,
        "verdicts": data.verdicts,
        "risk": data.risk,
        "enrichment": data.enrichment,
        "timeline": timeline,
        "attachment_pairs": attachment_pairs,
        "meta": meta,
        "raw": data.raw,
        "iocs": data.iocs,
    }

    return EmailReportData(template_name="email_report.html", context=context)
