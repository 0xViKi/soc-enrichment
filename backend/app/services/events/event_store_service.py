# backend/app/services/events/event_store_service.py

from typing import Dict, List
from datetime import datetime
import uuid

from sqlalchemy.orm import Session

from app.schemas.events import EventIngestRequest
from app.models.event_record import EventRecord
from app.db.session import SessionLocal   # your DB session factory


class EventStoreService:
    """
    DB-backed event store (Postgres via SQLAlchemy).

    Interface is the same as before so correlation_engine doesn't break.
    """

    def __init__(self) -> None:
        pass

    def _get_db(self) -> Session:
        return SessionLocal()

    def store_event(self, payload: EventIngestRequest) -> str:
        db = self._get_db()
        try:
            event_id = str(uuid.uuid4())
            occurred_at = payload.occurred_at or datetime.utcnow()

            record = EventRecord(
                id=event_id,
                source=payload.source.value,        # Enum -> str
                severity=payload.severity.value,    # Enum -> str
                vendor=payload.vendor,
                product=payload.product,
                event_type=payload.event_type,
                occurred_at=occurred_at,
                description=payload.description,
                iocs=payload.iocs.dict(),
                raw_event=payload.raw_event,
                created_at=datetime.utcnow(),
            )
            db.add(record)
            db.commit()
            return event_id
        finally:
            db.close()

    def get_event(self, event_id: str) -> Dict:
        db = self._get_db()
        try:
            record = db.query(EventRecord).filter(EventRecord.id == event_id).one()
            # Return a dict shaped like the old in-memory version
            return {
                "id": record.id,
                "source": record.source,
                "severity": record.severity,
                "vendor": record.vendor,
                "product": record.product,
                "event_type": record.event_type,
                "occurred_at": record.occurred_at,
                "description": record.description,
                "iocs": record.iocs,
                "raw_event": record.raw_event,
                "created_at": record.created_at,
            }
        finally:
            db.close()

    def list_events(self, limit: int = 50) -> List[Dict]:
        db = self._get_db()
        try:
            q = (
                db.query(EventRecord)
                .order_by(EventRecord.created_at.desc())
                .limit(limit)
            )
            out: List[Dict] = []
            for r in q:
                out.append(
                    {
                        "id": r.id,
                        "source": r.source,
                        "severity": r.severity,
                        "vendor": r.vendor,
                        "product": r.product,
                        "event_type": r.event_type,
                        "occurred_at": r.occurred_at,
                        "description": r.description,
                        "iocs": r.iocs,
                        "raw_event": r.raw_event,
                        "created_at": r.created_at,
                    }
                )
            return out
        finally:
            db.close()


event_store_service = EventStoreService()
