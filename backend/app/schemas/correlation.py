# backend/app/schemas/correlation.py
from typing import List, Optional, Dict
from pydantic import BaseModel
from datetime import datetime


class CorrelationFinding(BaseModel):
    """
    A single correlation signal, e.g.
    - "IP appeared 3 times in 24h"
    - "Domain age < 30 days"
    """
    type: str  # e.g. "repeated_ip", "new_domain", "vt_flag", etc.
    description: str
    severity: str = "info"  # info | low | medium | high | critical
    metadata: Dict = {}


class CorrelationVerdict(BaseModel):
    """
    Final output after correlation.
    """
    event_id: str
    risk_score: int  # 0-100
    risk_level: str  # low/medium/high/critical
    findings: List[CorrelationFinding]
    timestamp: datetime


class CorrelationInput(BaseModel):
    """
    Input to correlation engine.
    """
    event_id: str
    extracted_iocs: Dict
    raw_event: Dict
