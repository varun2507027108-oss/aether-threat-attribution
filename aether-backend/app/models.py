from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(128))
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    origin_ip: Mapped[str] = mapped_column(String(45), default="")
    geo: Mapped[str] = mapped_column(String(128), default="")
    asn: Mapped[str] = mapped_column(String(128), default="")
    pgp_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    btc_root: Mapped[str] = mapped_column(String(64), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    onion_url: Mapped[str] = mapped_column(String(256), default="")
    target_url: Mapped[str] = mapped_column(String(512), default="")
    target_type: Mapped[str] = mapped_column(String(64), default="domain")
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    custody: Mapped[list["CustodyRow"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CustodyRow.seq"
    )
    checkpoints: Mapped[list["CustodyCheckpoint"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CustodyCheckpoint.id"
    )
    evidence_records: Mapped[list["Evidence"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Evidence.id"
    )
    correlations: Mapped[list["EvidenceCorrelation"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="EvidenceCorrelation.id"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="AuditLog.id"
    )


class CustodyRow(Base):
    __tablename__ = "custody_entries"
    __table_args__ = (UniqueConstraint("case_id", "seq", name="uq_case_seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    key_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)

    case: Mapped[Case] = relationship(back_populates="custody")


class CustodyCheckpoint(Base):
    """Periodic or external cryptographic anchor checkpoint for custody verification."""
    __tablename__ = "custody_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    tip_hash: Mapped[str] = mapped_column(String(64))
    anchor_type: Mapped[str] = mapped_column(String(32), default="internal")  # 'internal' | 'rfc3161'
    anchor_token: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    case: Mapped[Case] = relationship(back_populates="checkpoints")


class Evidence(Base):
    """Structured forensic evidence item with provenance and confidence."""
    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    raw_value: Mapped[str] = mapped_column(Text)
    normalized_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    provenance: Mapped[str] = mapped_column(String(32), default="DEMO_DATA")  # LIVE_SOURCE, DEMO_DATA, STATIC_OSINT, SOURCE_UNAVAILABLE
    source_reference: Mapped[str] = mapped_column(String(256), default="")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    case: Mapped[Case] = relationship(back_populates="evidence_records")


class EvidenceCorrelation(Base):
    """Evidence-backed relationship link between entities or indicators."""
    __tablename__ = "evidence_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    source_node: Mapped[str] = mapped_column(String(128))
    target_node: Mapped[str] = mapped_column(String(128))
    relationship_type: Mapped[str] = mapped_column(String(64))
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    deterministic: Mapped[int] = mapped_column(Integer, default=1)  # 1 for deterministic, 0 for heuristic
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    case: Mapped[Case] = relationship(back_populates="correlations")


class AuditLog(Base):
    """Immutable record of investigator actions and analytical operations."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=True)
    timestamp: Mapped[str] = mapped_column(String(40))
    operator: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    case: Mapped[Case] = relationship(back_populates="audit_logs")

