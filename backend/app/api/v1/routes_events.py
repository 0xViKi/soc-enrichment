# backend/app/api/v1/routes_events.py
from typing import List

from fastapi import APIRouter, HTTPException, status

from app.schemas.events import (
    EventIngestRequest,
    EventIngestResponse,
)
from app.schemas.correlation import CorrelationInput
from app.services.events.events_store_service import event_store_service
from app.services.correlation.correlation_engine import correlation_engine
from app.services.alerting.alert_dispatcher import dispatch_alerts

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
    Ingest a normalized event, run correlation, and (for high-risk events)
    dispatch alerts to Slack / webhooks.
    """
    # 1) Store event
    event_id = event_store_service.store_event(payload)

    # 2) Build correlation input
    ci = CorrelationInput(
        event_id=event_id,
        extracted_iocs=payload.iocs.dict(),
        raw_event=payload.raw_event,
    )

    # 3) Run correlation engine
    verdict = correlation_engine.correlate_event(ci)

    # 4) Fetch stored event doc for alert context
    event_doc = event_store_service.get_event(event_id)

    # 5) Dispatch alerts (non-blocking in sense of errors)
    try:
        dispatch_alerts(verdict, event_doc)
    except Exception:
        # Already logged inside, but we don't want to break ingestion.
        pass

    # 6) Return enriched response
    return EventIngestResponse(
        event_id=event_id,
        status="accepted",
        message="Event ingested, correlated, and alerting evaluated.",
        correlation=verdict,
    )


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
