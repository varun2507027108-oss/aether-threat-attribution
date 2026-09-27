"""FastAPI router for analytical engines in Project AETHER.

Exposes endpoints for stylometry NLP, diurnal timezone inference,
Bitcoin peel clustering, entity knowledge graph generation, and calibrated
confidence scoring. Protected by investigator access control.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db import get_db
from app.security import InvestigatorPrincipal, record_audit_log, verify_investigator_auth
from app.services.diurnal import analyze_diurnal_activity
from app.services.graph import (
    build_default_case_graph,
    cluster_bitcoin_transactions,
)
from app.services.scoring import (
    calculate_calibrated_confidence,
    make_evidence,
    score_evidence,
)
from app.services.stylometry import analyze_stylometry

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


# ---------- Request & Response Schemas with Strict Limits ---------- #

class StylometryRequest(BaseModel):
    text_a: str = Field(..., min_length=10, max_length=50000, description="First text sample (max 50KB)")
    text_b: str = Field(..., min_length=10, max_length=50000, description="Second text sample (max 50KB)")


class DiurnalRequest(BaseModel):
    timestamps: List[str] = Field(..., min_length=1, max_length=10000, description="List of ISO 8601 UTC timestamps (max 10,000)")
    window_size: int = Field(6, ge=4, le=10, description="Sliding sleep trough window in hours")


class GraphRequest(BaseModel):
    evidence_id: Optional[str] = Field("AT-2026-0047", max_length=32, description="Evidence case identifier")
    case_data: Optional[Dict[str, Any]] = Field(None, description="Optional custom case parameters")


class BtcClusterRequest(BaseModel):
    transactions: List[Dict[str, Any]] = Field(..., min_length=1, max_length=1000, description="List of transaction dictionaries (max 1,000)")


class EvidenceInput(BaseModel):
    """A single graded attribution indicator for probabilistic fusion."""

    name: str = Field(..., min_length=1, max_length=64, description="Indicator name from the LR table")
    strength: float = Field(..., ge=0.0, le=1.0, description="Graded indicator strength in [0, 1]")
    stance: str = Field("supports", description="supports | contradicts | neutral")
    raw_value: Optional[Any] = Field(None, description="Original observed value for the record")
    detail: str = Field("", max_length=2000, description="Examiner note explaining this indicator")

    @field_validator("stance")
    @classmethod
    def validate_stance(cls, stance: str) -> str:
        normalized = stance.strip().lower()
        if normalized not in {"supports", "contradicts", "neutral"}:
            raise ValueError("stance must be one of: supports, contradicts, neutral")
        return normalized


class ScoreRequest(BaseModel):
    deterministic_signals: Dict[str, float] = Field(
        default_factory=lambda: {"pgp_match": 1.0, "origin_ip_match": 0.95, "btc_cluster_match": 0.88}
    )
    probabilistic_signals: Dict[str, float] = Field(
        default_factory=lambda: {"stylometry_similarity": 0.87, "diurnal_consistency": 0.82}
    )
    contradictions: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    evidence: Optional[List[EvidenceInput]] = Field(
        default=None,
        description="Explicit indicator list. When provided, the signal dicts above are ignored.",
    )
    prior_probability: Optional[float] = Field(
        default=None, ge=1e-6, le=1 - 1e-6,
        description="Override AETHER_PRIOR_ODDS for this evaluation only.",
    )
    conflict_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="Override AETHER_CONFLICT_THRESHOLD for this evaluation only.",
    )

    @field_validator("deterministic_signals", "probabilistic_signals")
    @classmethod
    def validate_weights(cls, signals: Dict[str, float]) -> Dict[str, float]:
        for k, v in signals.items():
            if not isinstance(v, (int, float)) or v < 0.0 or v > 1.0:
                raise ValueError(f"Signal weight for '{k}' must be between 0.0 and 1.0 inclusive (got {v}).")
        return signals


# ---------- Endpoints (Protected) ---------- #

@router.post("/stylometry")
def compare_stylometry(
    payload: StylometryRequest,
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Dict[str, Any]:
    """Compare two text samples using token/char n-gram cosine similarity and lexical metrics."""
    return analyze_stylometry(payload.text_a, payload.text_b)


@router.post("/diurnal")
def evaluate_diurnal(
    payload: DiurnalRequest,
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Dict[str, Any]:
    """Analyze activity timestamps to identify sleep trough and estimate operational UTC timezone."""
    return analyze_diurnal_activity(payload.timestamps, window_size=payload.window_size)


@router.post("/graph")
def get_entity_graph(
    payload: GraphRequest,
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Dict[str, Any]:
    """Generate entity relationship graph and Neo4j Cypher statements."""
    data = payload.case_data or {}
    if "evidence_id" not in data and payload.evidence_id:
        data["evidence_id"] = payload.evidence_id
    graph = build_default_case_graph(data if data else None)
    result = graph.to_dict()
    result["cypher_statements"] = graph.to_cypher()
    return result


@router.post("/btc-cluster")
def cluster_bitcoin(
    payload: BtcClusterRequest,
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Dict[str, Any]:
    """Execute multi-input peel-chain heuristic clustering on transaction inputs."""
    return cluster_bitcoin_transactions(payload.transactions)


@router.post("/score")
def compute_attribution_score(
    payload: ScoreRequest,
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Dict[str, Any]:
    """Calculate calibrated confidence score (C_attr) via likelihood-ratio fusion.

    Accepts either explicit ``evidence`` indicators (preferred, supports
    contradicting evidence) or the legacy deterministic/probabilistic signal
    dicts, and returns the full explainability payload: per-indicator
    likelihood ratios and contribution shares, the prior used, and the
    Dempster-Shafer conflict analysis.
    """
    if payload.evidence is not None:
        items = [
            make_evidence(
                item.name,
                item.strength,
                stance=item.stance,
                raw_value=item.raw_value,
                detail=item.detail,
            )
            for item in payload.evidence
        ]
        result = score_evidence(
            items,
            prior=payload.prior_probability,
            conflict_threshold=payload.conflict_threshold,
        )
        if payload.contradictions:
            result.setdefault("legacy_contradictions", payload.contradictions)
        return result

    return calculate_calibrated_confidence(
        deterministic_signals=payload.deterministic_signals,
        probabilistic_signals=payload.probabilistic_signals,
        contradictions=payload.contradictions,
    )
