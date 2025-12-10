# backend/app/schemas/email_analysis.py
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


# ================================================================
# EMAIL HEADER SCHEMA
# ================================================================

class EmailHeader(BaseModel):
    message_id: Optional[str] = Field(None, alias="messageId")
    subject: Optional[str] = None

    # Sender fields
    from_addr: Optional[str] = Field(None, alias="from")
    sender_name: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = Field(None, alias="returnPath")

    # Recipients
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)

    # Date
    date: Optional[str] = None

    # Authentication results
    spf_result: Optional[str] = Field(None, alias="spfResult")
    dkim_result: Optional[str] = Field(None, alias="dkimResult")
    dmarc_result: Optional[str] = Field(None, alias="dmarcResult")
    authentication_results: Optional[str] = Field(None, alias="authResults")

    # Routing / IP metadata
    received_domains: List[str] = Field(default_factory=list, alias="receivedDomain")
    received_ips: List[str] = Field(default_factory=list, alias="receivedIp")
    originating_ip: Optional[str] = Field(None, alias="originatingIp")

    # Mail software
    x_mailer: Optional[str] = Field(None, alias="xMailer")
    user_agent: Optional[str] = Field(None, alias="userAgent")

    # FIX: Convert null → []
    @field_validator("cc", "received_domains", "received_ips", mode="before")
    def convert_null_to_list(cls, v):
        if v is None:
            return []
        return v


# ================================================================
# EMAIL BODY SCHEMA
# ================================================================

class EmailBody(BaseModel):
    content_type: str = Field(..., alias="contentType")
    hash: Optional[str] = None
    content: Optional[str] = None


# ================================================================
# ATTACHMENTS
# ================================================================

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


# ================================================================
# VERDICTS
# ================================================================

class VerdictDetail(BaseModel):
    key: str
    score: Optional[float] = None
    description: Optional[str] = None
    reference_link: Optional[str] = Field(None, alias="referenceLink")


class EngineVerdict(BaseModel):
    name: str
    malicious: bool
    score: Optional[float] = None
    details: List[VerdictDetail] = Field(default_factory=list)


# ================================================================
# RISK SCORE
# ================================================================

class EmailRiskScore(BaseModel):
    score: int          # 0–100
    level: str          # "low" | "medium" | "high" | "critical"
    reasons: List[str]


# ================================================================
# IOC BUNDLE
# ================================================================

class EmailIOCBundle(BaseModel):
    attachment_hashes: List[AttachmentHashSet] = Field(default_factory=list)
    sender_domain: Optional[str] = None
    sender_email: Optional[str] = None
    received_ips: List[str] = Field(default_factory=list)
    received_domains: List[str] = Field(default_factory=list)


# ================================================================
# ENRICHMENT STRUCTURES
# ================================================================

class EnrichedAttachment(BaseModel):
    hash_value: str
    hashes: AttachmentHashSet
    enrichment: Optional[Dict[str, Any]] = None


class EnrichedDomain(BaseModel):
    domain: str
    enrichment: Optional[Dict[str, Any]] = None


class EnrichedIP(BaseModel):
    ip: str
    enrichment: Optional[Dict[str, Any]] = None


class EmailEnrichmentBundle(BaseModel):
    attachments: List[EnrichedAttachment] = Field(default_factory=list)
    domains: List[EnrichedDomain] = Field(default_factory=list)
    ips: List[EnrichedIP] = Field(default_factory=list)


# ================================================================
# FINAL RESPONSE MODEL (ONLY ONE VERSION)
# ================================================================

class EmailAnalysisResponse(BaseModel):
    header: EmailHeader
    bodies: List[EmailBody]
    attachments: List[EmailAttachment]
    verdicts: List[EngineVerdict]
    risk: EmailRiskScore
    iocs: EmailIOCBundle
    enrichment: EmailEnrichmentBundle
    raw: Dict[str, Any]
