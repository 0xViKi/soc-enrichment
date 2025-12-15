# backend/app/schemas/events.py
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.schemas.correlation import CorrelationVerdict  


class EventSource(str, Enum):
    WAZUH = "wazuh"
    AZURE_SENTINEL = "azure_sentinel"
    SPLUNK = "splunk"
    EMAIL_GATEWAY = "email_gateway" 
    MANUAL = "manual"
    CUSTOM = "custom"


class EventSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCBundle(BaseModel):
    """Normalized IOC container extracted from the event."""
    src_ips: List[str] = Field(default_factory=list)
    dst_ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    message_ids: List[str] = Field(default_factory=list)


class EventIngestRequest(BaseModel):
    """
    Generic SIEM / log event ingestion payload.
    This is what Wazuh/Sentinel/Splunk/n8n will POST to your API.
    """
    source: EventSource = Field(
        ..., description="Origin of this event (wazuh/splunk/etc.)"
    )
    severity: EventSeverity = EventSeverity.LOW
    vendor: Optional[str] = Field(
        None, description="Original vendor name, e.g., elastic, microsoft"
    )
    product: Optional[str] = Field(
        None, description="Original product name, e.g., wazuh, defender, etc."
    )

    event_type: Optional[str] = Field(
        None, description="Free-form event type: auth_failure, dns_query, email, etc."
    )

    occurred_at: Optional[datetime] = Field(
        None,
        description="When the event occurred. If omitted, backend will set to now().",
    )

    description: Optional[str] = Field(
        None,
        description="Human-readable description or short summary of the event.",
    )

    # Normalized IOCs extracted upstream (or leave empty and let backend extract later)
    iocs: IOCBundle = Field(default_factory=IOCBundle)

    # Raw SIEM / log document (original source payload)
    raw_event: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original SIEM/log payload for reference.",
    )


class EventIngestResponse(BaseModel):
    event_id: str
    status: str = "accepted"
    message: str = "Event ingested successfully."
    correlation: Optional[CorrelationVerdict] = None  
