from typing import Any, Optional, List

from pydantic import BaseModel


class WHOISData(BaseModel):
    enabled: bool = False
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    domain_name: Optional[str] = None
    raw: Optional[dict[str, Any]] = None
    domain_age_days: Optional[int] = None
    privacy_protected: Optional[bool] = None


class DNSRecordData(BaseModel):
    enabled: bool = False
    a_records: list[str] = []
    mx_records: list[str] = []
    txt_records: list[str] = []
    errors: dict[str, str] = {}


class URLScanFinding(BaseModel):
    task_url: Optional[str] = None
    page_url: Optional[str] = None
    status: Optional[str] = None
    tags: list[str] = []
    malicious: bool = False
    raw: Optional[dict[str, Any]] = None


class URLScanData(BaseModel):
    enabled: bool = False
    results: list[URLScanFinding] = []
    malicious_count: int = 0


class VirusTotalDomainData(BaseModel):
    """
    Normalized VirusTotal metadata for a domain.
    """
    enabled: bool = False
    reputation: Optional[int] = None
    last_analysis_stats: Optional[dict[str, Any]] = None
    last_analysis_date: Optional[int] = None
    categories: list[str] = []
    registrar: Optional[str] = None
    tld: Optional[str] = None
    whois: Optional[str] = None
    raw: Optional[dict[str, Any]] = None


class DomainRiskFactor(BaseModel):
    name: str
    weight: float
    value: float    # 0–100
    contribution: float


class DomainRiskScore(BaseModel):
    score: int
    severity: str
    factors: list[DomainRiskFactor]


class DomainEnrichRequest(BaseModel):
    domain: str
    case_id: str | None = None


class DomainEnrichResponse(BaseModel):
    ioc_type: str = "domain"
    value: str
    whois: WHOISData
    dns: DNSRecordData
    urlscan: URLScanData
    vt: VirusTotalDomainData
    risk: DomainRiskScore
    meta: dict[str, Any]
