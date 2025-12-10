# backend/app/schemas/email_analysis.py
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EmailHeader(BaseModel):
    message_id: Optional[str] = Field(None, alias="messageId")
    subject: Optional[str]

    # Sender fields
    from_addr: Optional[str] = Field(None, alias="from")
    sender_name: Optional[str] = None   # Display name
    reply_to: Optional[str] = None
    return_path: Optional[str] = Field(None, alias="returnPath")

    # Recipient fields
    to: List[str] = []
    cc: Optional[List[str]] = None

    # Date
    date: Optional[str]

    # Authentication results
    spf_result: Optional[str] = Field(None, alias="spfResult")
    dkim_result: Optional[str] = Field(None, alias="dkimResult")
    dmarc_result: Optional[str] = Field(None, alias="dmarcResult")
    authentication_results: Optional[str] = Field(None, alias="authResults")

    # IP & routing metadata
    received_domains: List[str] = Field(default_factory=list, alias="receivedDomain")
    received_ips: List[str] = Field(default_factory=list, alias="receivedIp")
    originating_ip: Optional[str] = Field(None, alias="originatingIp")

    # Mail client metadata
    x_mailer: Optional[str] = Field(None, alias="xMailer")
    user_agent: Optional[str] = Field(None, alias="userAgent")


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