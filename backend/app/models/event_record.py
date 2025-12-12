# backend/app/models/event_record.py
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from app.db.base_class import Base  # or wherever your Base is

class EventRecord(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, index=True)   # store UUID as string
    source = Column(String, index=True)
    severity = Column(String, index=True)
    vendor = Column(String, nullable=True)
    product = Column(String, nullable=True)
    event_type = Column(String, nullable=True)

    occurred_at = Column(DateTime, index=True)
    description = Column(String, nullable=True)

    iocs = Column(JSONB)        # {"src_ips": [...], "domains": [...], ...}
    raw_event = Column(JSONB)   # original SIEM / enrichment context

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
