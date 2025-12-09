# backend/app/schemas/email_analysis.py
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EmailHeader(BaseModel):
    message_id: Optional[str] = Field(None, alias="messageId")
    subject: Optional[str]
    from_addr: Optional[str] = Field(None, alias="from")
    to: List[str] = []
    cc: Optional[List[str]] = None
    date: Optional[str]
    received_domains: List[str] = Field(default_factory=list, alias="receivedDomain")
    received_ips: List[str] = Field(default_factory=list, alias="receivedIp")


class EmailBody(BaseModel):
    content_type: str = Field(..., alias="contentType")
    hash: Optional[str] = None
    content: Optional[str] = None


class AttachmentHashSet(BaseModel):
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None


class EmailAttachment(BaseModel):
    filename: Optional[str] = None
    size: Optional[int] = None
    extension: Optional[str] = None
    mime_type: Optional[str] = Field(None, alias="mimeType")
    mime_type_short: Optional[str] = Field(None, alias="mimeTypeShort")
    hashes: Optional[AttachmentHashSet] = Field(None, alias="hash")


class VerdictDetail(BaseModel):
    key: str
    score: Optional[float] = None
    description: Optional[str] = None
    reference_link: Optional[str] = Field(None, alias="referenceLink")


class EngineVerdict(BaseModel):
    name: str
    malicious: bool
    score: Optional[float] = None
    details: List[VerdictDetail] = []


class EmailRiskScore(BaseModel):
    score: int        # 0–100
    level: str        # "low" | "medium" | "high"
    reasons: List[str]


class EmailIOCBundle(BaseModel):
    attachment_hashes: List[AttachmentHashSet]
    sender_domain: Optional[str]
    sender_email: Optional[str]
    received_ips: List[str]
    received_domains: List[str]


class EmailAnalysisResponse(BaseModel):
    header: EmailHeader
    bodies: List[EmailBody]
    attachments: List[EmailAttachment]
    verdicts: List[EngineVerdict]
    risk: EmailRiskScore
    iocs: EmailIOCBundle
    raw: Dict[str, Any]  # full raw response from Heroku, for debugging

class EnrichedAttachment(BaseModel):
    hash_value: str
    hashes: AttachmentHashSet
    enrichment: Dict[str, Any] | None = None  # JSON from /enrich/hash


class EnrichedDomain(BaseModel):
    domain: str
    enrichment: Dict[str, Any] | None = None  # JSON from /enrich/domain


class EnrichedIP(BaseModel):
    ip: str
    enrichment: Dict[str, Any] | None = None  # JSON from /enrich/ip


class EmailEnrichmentBundle(BaseModel):
    attachments: List[EnrichedAttachment] = []
    domains: List[EnrichedDomain] = []
    ips: List[EnrichedIP] = []


# Update EmailAnalysisResponse to include enrichment
class EmailAnalysisResponse(BaseModel):
    header: EmailHeader
    bodies: List[EmailBody]
    attachments: List[EmailAttachment]
    verdicts: List[EngineVerdict]
    risk: EmailRiskScore
    iocs: EmailIOCBundle
    enrichment: EmailEnrichmentBundle  # <--- add this line
    raw: Dict[str, Any]