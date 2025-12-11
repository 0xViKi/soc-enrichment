# backend/app/services/events/event_store_service.py
from typing import Dict, List
from datetime import datetime
import uuid

from app.schemas.events import EventIngestRequest


class EventStoreService:
    """
    Very simple in-memory event store for Phase 4 dev.
    Later we can replace this with a DB-backed repository.
    """

    def __init__(self) -> None:
        # event_id -> stored event object
        self._events: Dict[str, Dict] = {}

    def store_event(self, payload: EventIngestRequest) -> str:
        event_id = str(uuid.uuid4())

        occurred_at = payload.occurred_at or datetime.utcnow()

        self._events[event_id] = {
            "id": event_id,
            "source": payload.source,
            "severity": payload.severity,
            "vendor": payload.vendor,
            "product": payload.product,
            "event_type": payload.event_type,
            "occurred_at": occurred_at,
            "description": payload.description,
            "iocs": payload.iocs.dict(),
            "raw_event": payload.raw_event,
            "created_at": datetime.utcnow(),
        }

        return event_id

    def get_event(self, event_id: str) -> Dict:
        return self._events[event_id]

    def list_events(self, limit: int = 50) -> List[Dict]:
        # naive: return most recent N by created_at
        events = list(self._events.values())
        events.sort(key=lambda e: e["created_at"], reverse=True)
        return events[:limit]


# simple singleton-style instance for now
event_store_service = EventStoreService()
