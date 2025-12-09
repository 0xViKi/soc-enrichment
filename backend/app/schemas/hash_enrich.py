from typing import Any, Optional, Dict

from pydantic import BaseModel


class VTRawStats(BaseModel):
    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0


class VTData(BaseModel):
    enabled: bool = False
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    type_description: Optional[str] = None
    size: Optional[int] = None
    names: list[str] = []
    last_analysis_stats: Optional[VTRawStats] = None
    last_analysis_date: Optional[str] = None
    first_submission_date: Optional[str] = None
    reputation: Optional[int] = None
    raw: Optional[dict[str, Any]] = None
    detection_ratio: Optional[float] = None  # 0–1
    detection_percentage: Optional[float] = None  # 0–100


class HashRiskFactor(BaseModel):
    name: str
    weight: float
    value: float      # 0–100
    contribution: float


class HashRiskScore(BaseModel):
    score: int
    severity: str
    factors: list[HashRiskFactor]


class HashEnrichRequest(BaseModel):
    hash_value: str
    case_id: str | None = None


class HashEnrichResponse(BaseModel):
    ioc_type: str = "hash"
    value: str
    vt: VTData
    risk: HashRiskScore
    meta: Dict[str, Any]
