# backend/app/routes/routes_domain_enrich.py
from fastapi import APIRouter
from app.schemas.enrich.domain_enrich import DomainEnrichRequest, DomainEnrichResponse
from app.services.enrichment.domain_enrich_service import enrich_domain_value

router = APIRouter()


@router.post("/enrich/domain", response_model=DomainEnrichResponse, tags=["enrichment"])
async def enrich_domain(payload: DomainEnrichRequest) -> DomainEnrichResponse:
    # case_id still comes from the request, you can add it into meta if you want
    resp = await enrich_domain_value(payload.domain)
    resp.meta["case_id"] = payload.case_id
    return resp
