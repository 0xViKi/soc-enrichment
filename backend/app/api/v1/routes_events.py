# backend/app/api/v1/routes_events.py
from typing import List

from fastapi import APIRouter, HTTPException, status

from app.schemas.events import (
    EventIngestRequest,
    EventIngestResponse,
)
from app.services.events.events_store_service import event_store_service

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
def ingest_event(payload: EventIngestRequest) -> EventIngestResponse:
    """
    Ingest a normalized event from Wazuh / Sentinel / Splunk / n8n / etc.

    This is the main entry point for Phase 4:
    SIEM → (webhook/HTTP) → /api/v1/events/ingest → event store.
    """
    event_id = event_store_service.store_event(payload)
    return EventIngestResponse(event_id=event_id)


@router.get(
    "/latest",
    summary="List latest ingested events (dev/debug)",
)
def list_latest_events(limit: int = 50) -> List[dict]:
    """
    Dev/debug endpoint to quickly see what has been ingested.
    In production, you might protect/remove this.
    """
    return event_store_service.list_events(limit=limit)


@router.get(
    "/{event_id}",
    summary="Get a single ingested event",
)
def get_event(event_id: str) -> dict:
    try:
        return event_store_service.get_event(event_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found",
        )
