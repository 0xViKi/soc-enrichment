# backend/app/api/v1/routes_events.py

from typing import List

from fastapi import APIRouter, HTTPException, status

from app.schemas.events import (
    EventIngestRequest,
    EventIngestResponse,
)
from app.services.events.event_store_service import event_store_service
from app.services.events.event_pipeline_service import event_pipeline_service  # NEW

router = APIRouter(
    prefix="/events",
    tags=["events", "siem"],
)


@router.post(
    "/ingest",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest SIEM/log event",
)
async def ingest_event(payload: EventIngestRequest) -> EventIngestResponse:
    """
    Ingest a normalized event, run IOC enrichment, correlation,
    and (for high-risk events) dispatch alerts to Slack / webhooks.

    This now uses the EventPipelineService, which:
      - stores the event
      - enriches IPs/domains/hashes
      - attaches TI context into raw_event
      - runs correlation_engine
      - calls alert_dispatcher
    """
    return await event_pipeline_service.process_ingested_event(payload)


@router.get("/latest", summary="List latest ingested events (dev/debug)")
def list_latest_events(limit: int = 50) -> List[dict]:
    """
    Dev/debug endpoint to quickly see what has been ingested.
    In production, you might protect/remove this.
    """
    return event_store_service.list_events(limit=limit)


@router.get("/{event_id}", summary="Get a single ingested event")
def get_event(event_id: str) -> dict:
    try:
        return event_store_service.get_event(event_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found",
        )
