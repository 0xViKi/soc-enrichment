# backend/app/routes/routes_hash_enrich.py
from fastapi import APIRouter
from app.schemas.enrich.hash_enrich import HashEnrichRequest, HashEnrichResponse
from app.services.enrichment.hash_enrich_service import enrich_hash_value

router = APIRouter()


@router.post("/enrich/hash", response_model=HashEnrichResponse, tags=["enrichment"])
async def enrich_hash(payload: HashEnrichRequest) -> HashEnrichResponse:
    resp = await enrich_hash_value(payload.hash_value)
    resp.meta["case_id"] = payload.case_id
    return resp
