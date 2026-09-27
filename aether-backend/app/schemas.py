from __future__ import annotations

import re
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


# ---------- Regex Patterns for Input Validation ---------- #

EVIDENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")
PGP_HEX_PATTERN = re.compile(r"^[0-9a-fA-F\s]{16,64}$")
BTC_ADDR_PATTERN = re.compile(r"^[13bc1q][0-9a-zA-HJ-NP-Z]{25,90}$")


class CaseCreate(BaseModel):
    evidence_id: str = Field(min_length=3, max_length=32)
    actor_name: str = Field(min_length=1, max_length=128)
    aliases: list[str] = Field(default_factory=list)
    origin_ip: str = Field("", max_length=45)
    geo: str = Field("", max_length=128)
    asn: str = Field("", max_length=128)
    pgp_fingerprint: str = Field("", max_length=64)
    btc_root: str = Field("", max_length=90)
    confidence: float = Field(0.0, ge=0.0, le=100.0)
    onion_url: str = Field("", max_length=256)
    target_url: str = Field("", max_length=512)
    target_type: str = Field("domain", max_length=32)

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id(cls, v: str) -> str:
        v_clean = v.strip()
        if not EVIDENCE_ID_PATTERN.match(v_clean):
            raise ValueError("evidence_id must be 3-32 alphanumeric characters, dashes, or underscores.")
        return v_clean


class CustodyEntryCreate(BaseModel):
    actor: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=3, max_length=1000)

    @field_validator("actor", "action")
    @classmethod
    def sanitize_text(cls, v: str) -> str:
        clean = v.strip()
        # Defuse formula injection prefixes
        if clean and clean[0] in ("=", "+", "-", "@"):
            clean = "'" + clean
        return clean


class CustodyEntryOut(BaseModel):
    seq: int
    timestamp: str
    actor: str
    action: str
    prev_hash: str
    entry_hash: str
    signature: str | None = None
    key_id: str | None = None

    @computed_field
    @property
    def signed(self) -> bool:
        return bool(self.signature)

    model_config = ConfigDict(from_attributes=True)


class EvidenceCreate(BaseModel):
    evidence_type: str = Field(..., max_length=64, description="ORIGIN_IP, PGP_KEY, BTC_WALLET, FAVICON_HASH, TLS_JARM, STYLOMETRY, etc.")
    title: str = Field(..., max_length=256)
    raw_value: str = Field(..., max_length=10000)
    normalized_hash: str = Field("", max_length=64)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    provenance: str = Field("DEMO_DATA", description="LIVE_SOURCE, DEMO_DATA, STATIC_OSINT, SOURCE_UNAVAILABLE")
    source_reference: str = Field("", max_length=256)
    metadata_json: dict = Field(default_factory=dict)


class EvidenceOut(BaseModel):
    id: int
    case_id: int
    evidence_type: str
    title: str
    raw_value: str
    normalized_hash: str
    confidence: float
    provenance: str
    source_reference: str
    metadata_json: dict
    created_at: datetime | str | None = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceCorrelationOut(BaseModel):
    id: int
    case_id: int
    source_node: str
    target_node: str
    relationship_type: str
    weight: float
    deterministic: int
    notes: str

    model_config = ConfigDict(from_attributes=True)


class AuditLogOut(BaseModel):
    id: int
    timestamp: str
    operator: str
    action: str
    details: dict

    model_config = ConfigDict(from_attributes=True)


class CaseOut(BaseModel):
    evidence_id: str
    actor_name: str
    aliases: list[str]
    origin_ip: str
    geo: str
    asn: str
    pgp_fingerprint: str
    btc_root: str
    confidence: float
    onion_url: str
    target_url: str = ""
    target_type: str = "domain"
    status: str = "ACTIVE"
    custody: list[CustodyEntryOut] = Field(default_factory=list)
    evidence_records: list[EvidenceOut] = Field(default_factory=list)
    correlations: list[EvidenceCorrelationOut] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class CaseListItem(BaseModel):
    id: int
    evidence_id: str
    actor_name: str
    target_url: str = ""
    target_type: str = "domain"
    confidence: float = 0.0
    status: str = "ACTIVE"
    created_at: str | None = None
    evidence_count: int = 0
    custody_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class InvestigationStartRequest(BaseModel):
    case_name: str = Field(..., min_length=2, max_length=64, description="Human reference, e.g. Operation Chimera")
    evidence_id: str | None = Field(None, max_length=32, description="Case ID, e.g. AT-2026-0048")
    actor_name: str = Field("UNC-3844", max_length=128)
    target: str = Field(..., min_length=3, max_length=512, description="Domain, IP, URL, or onion descriptor")
    target_type: str = Field("domain", description="domain, ip, onion, btc, pgp")
    known_pgp: str | None = Field(None, max_length=64)
    known_btc: str | None = Field(None, max_length=90)
    text_sample: str | None = Field(None, max_length=50000)
    mode: str = Field("auto", description="'live' (authorized public only), 'demo' (synthetic benchmark), 'auto'")

    @field_validator("evidence_id")
    @classmethod
    def validate_opt_evidence_id(cls, v: str | None) -> str | None:
        if v is not None:
            v_clean = v.strip()
            if not EVIDENCE_ID_PATTERN.match(v_clean):
                raise ValueError("evidence_id must be 3-32 alphanumeric characters, dashes, or underscores.")
            return v_clean
        return None

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        allowed = ("domain", "ip", "onion", "btc", "pgp")
        if v.lower() not in allowed:
            raise ValueError(f"target_type must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = ("auto", "live", "demo")
        if v.lower() not in allowed:
            raise ValueError(f"mode must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator("known_pgp")
    @classmethod
    def validate_pgp(cls, v: str | None) -> str | None:
        if v is not None and v.strip():
            clean = v.strip()
            if not PGP_HEX_PATTERN.match(clean):
                raise ValueError("known_pgp must contain only valid hexadecimal characters and spaces.")
            return clean
        return None


class InvestigationResultOut(BaseModel):
    case: CaseOut
    attribution: dict
    graph: dict
    diurnal: dict
    stylometry: dict
    custody_verification: dict
    provenance_summary: dict
    timeline: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class VerifyResult(BaseModel):
    valid: bool
    broken_at_seq: int | None = None
    entry_count: int = 0
    seal: str = ""
    hash_ok: bool = True
    signature_ok: bool = True
    last_checkpoint: dict | None = None
    anchor_type: str = "internal"
    failure_layer: str | None = None
    signed_count: int = 0


# ---------- Investigation Job & Streaming Schemas (Phase 4) ---------- #

class InvestigationJobAccepted(BaseModel):
    job_id: str
    status_url: str
    events_url: str
    evidence_id: str


class JobModuleStatus(BaseModel):
    module: str
    name: str
    status: str  # pending | running | done | failed | skipped
    started_at: str | None = None
    finished_at: str | None = None
    summary: str | None = None
    error: str | None = None


class InvestigationJobOut(BaseModel):
    id: str
    case_id: int | None = None
    evidence_id: str | None = None
    status: str  # queued | running | partial | complete | failed
    error: str | None = None
    modules: list[dict] = Field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None
    result: dict | None = None

    model_config = ConfigDict(from_attributes=True)
