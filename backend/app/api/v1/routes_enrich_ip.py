# backend/app/routes/routes_ip_enrich.py

from fastapi import APIRouter
from app.schemas.enrich.ip_enrich import IPEnrichRequest, IPEnrichResponse
from app.services.enrichment.ip_enrich_service import enrich_ip_value

router = APIRouter()


@router.post("/enrich/ip", response_model=IPEnrichResponse, tags=["enrichment"])
async def enrich_ip(payload: IPEnrichRequest) -> IPEnrichResponse:
    """
    Public API endpoint for enriching a single IP address.
    Thin wrapper over internal enrichment service.
    """
    # Call internal enrichment logic
    resp = await enrich_ip_value(payload.ip)

    # Add case_id to meta (consistent with domain/hash routes)
    resp.meta["case_id"] = payload.case_id

    return resp
