from typing import Any, Optional
from fastapi import APIRouter
import logging

from app.schemas.enrich.hash_enrich import (
    HashEnrichRequest,
    HashEnrichResponse,
    VTData,
    VTRawStats,
)
from app.services.enrichment.vt_service import fetch_vt_file
from app.services.risk_scoring.hash_risk import compute_hash_risk

router = APIRouter()
logger = logging.getLogger(__name__)


async def _safe_fetch_vt(hash_value: str) -> Optional[dict]:
    try:
        return await fetch_vt_file(hash_value)
    except Exception as e:
        logger.warning("VT file lookup failed for %s: %s", hash_value, e)
        return None


@router.post("/enrich/hash", response_model=HashEnrichResponse, tags=["enrichment"])
async def enrich_hash(payload: HashEnrichRequest) -> HashEnrichResponse:
    hash_value = payload.hash_value.strip().lower()

    vt_raw = await _safe_fetch_vt(hash_value)
    if vt_raw:
        attr = vt_raw.get("attributes", {}) or {}

        stats = attr.get("last_analysis_stats", {}) or {}
        vt_stats = VTRawStats(
            harmless=stats.get("harmless", 0),
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            undetected=stats.get("undetected", 0),
            timeout=stats.get("timeout", 0),
        )

        total = (
            vt_stats.harmless
            + vt_stats.malicious
            + vt_stats.suspicious
            + vt_stats.undetected
            + vt_stats.timeout
        )
        det_ratio = 0.0
        if total > 0:
            det_ratio = (vt_stats.malicious + vt_stats.suspicious) / total

        vt_data = VTData(
            enabled=True,
            sha256=attr.get("sha256"),
            md5=attr.get("md5"),
            sha1=attr.get("sha1"),
            type_description=attr.get("type_description"),
            size=attr.get("size"),
            names=attr.get("names", []) or [],
            last_analysis_stats=vt_stats,
            last_analysis_date=(
                attr.get("last_analysis_date") and
                str(attr.get("last_analysis_date"))
            ),
            first_submission_date=(
                attr.get("first_submission_date") and
                str(attr.get("first_submission_date"))
            ),
            reputation=attr.get("reputation"),
            raw=vt_raw,
            detection_ratio=det_ratio,
            detection_percentage=det_ratio * 100.0 if det_ratio else 0.0,
        )
    else:
        vt_data = VTData(enabled=False)

    risk = compute_hash_risk(vt=vt_data)

    meta: dict[str, Any] = {
        "case_id": payload.case_id,
    }

    return HashEnrichResponse(
        ioc_type="hash",
        value=hash_value,
        vt=vt_data,
        risk=risk,
        meta=meta,
    )
