from pydantic import BaseModel, IPvAnyAddress
from typing import Any, Optional


class AbuseIPDBData(BaseModel):
    enabled: bool = False
    score: Optional[int] = None  # AbuseConfidenceScore 0–100
    total_reports: Optional[int] = None
    last_reported_at: Optional[str] = None
    raw: Optional[dict[str, Any]] = None


class IPInfoData(BaseModel):
    enabled: bool = False
    ip: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    raw: Optional[dict[str, Any]] = None


class DNSData(BaseModel):
    enabled: bool = False
    a_records: list[str] = []
    error: Optional[str] = None


class VirusTotalIPData(BaseModel):
    """
    Normalized VirusTotal metadata for an IP address.
    Mirrors the style you used for VT hash.
    """
    enabled: bool = False
    reputation: Optional[int] = None
    last_analysis_stats: Optional[dict[str, Any]] = None
    last_analysis_date: Optional[int] = None
    categories: list[str] = []
    country: Optional[str] = None
    as_owner: Optional[str] = None
    raw: Optional[dict[str, Any]] = None


class IPRiskFactor(BaseModel):
    name: str
    weight: float
    value: float      # 0–100
    contribution: float


class IPRiskScore(BaseModel):
    score: int
    severity: str
    factors: list[IPRiskFactor]


class IPEnrichRequest(BaseModel):
    ip: IPvAnyAddress
    case_id: str | None = None


class IPEnrichResponse(BaseModel):
    ioc_type: str = "ip"
    value: str
    abuseipdb: AbuseIPDBData
    ipinfo: IPInfoData
    dns: DNSData
    vt: VirusTotalIPData
    risk: IPRiskScore
    meta: dict[str, Any]
