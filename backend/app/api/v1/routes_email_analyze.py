from fastapi import APIRouter, UploadFile, File, HTTPException

from app.schemas.enrich.email_enrich import EmailAnalysisResponse
from app.services.email_analyzer.email_analysis_service import analyze_email_pipeline

router = APIRouter(prefix="/email", tags=["email"])


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(file: UploadFile = File(...)) -> EmailAnalysisResponse:
    """
    Accept an .eml file, send to analyzer, normalize + risk-score + enrich.
    (Thin wrapper; logic lives in analyze_email_pipeline)
    """
    try:
        data = await analyze_email_pipeline(file)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"EML analyzer error: {e}")

    return EmailAnalysisResponse(
        header=data.header,
        bodies=data.bodies,
        attachments=data.attachments,
        verdicts=data.verdicts,
        risk=data.risk,
        iocs=data.iocs,
        enrichment=data.enrichment,
        raw=data.raw,
    )

@router.post("/report/debug")
async def email_report_debug(file: UploadFile = File(...)):
    data = await analyze_email_pipeline(file)
    return {
        "attachments": [a.model_dump() for a in data.attachments],
        "enriched_attachments": [ea.model_dump() for ea in data.enrichment.attachments],
    }