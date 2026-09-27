from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Case, CustodyRow
from app.schemas import (
    EVIDENCE_ID_PATTERN,
    CaseCreate,
    CaseListItem,
    CaseOut,
    CustodyEntryCreate,
    CustodyEntryOut,
    InvestigationResultOut,
    InvestigationStartRequest,
    VerifyResult,
)
from app.security import (
    InvestigatorPrincipal,
    is_safe_target_url,
    record_audit_log,
    verify_investigator_auth,
)
from app.services.anchor import checkpoint_if_needed, get_last_checkpoint
from app.services.custody import GENESIS_HASH, CustodyChain, CustodyEntry
from app.services.investigation import run_full_investigation

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _validate_evidence_id_param(evidence_id: str) -> str:
    cleaned = evidence_id.strip()
    if not EVIDENCE_ID_PATTERN.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid evidence_id format. Must be 3-32 alphanumeric characters, hyphens, or underscores.",
        )
    return cleaned


def _get_case_or_404(db: Session, evidence_id: str) -> Case:
    valid_id = _validate_evidence_id_param(evidence_id)
    case = db.execute(select(Case).where(Case.evidence_id == valid_id)).scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No case with evidence_id '{evidence_id}'")
    return case


@router.get("", response_model=list[CaseListItem])
def list_cases(
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> list[CaseListItem]:
    cases = db.execute(select(Case).order_by(Case.id.desc())).scalars().all()
    items = []
    for c in cases:
        items.append(
            CaseListItem(
                id=c.id,
                evidence_id=c.evidence_id,
                actor_name=c.actor_name,
                target_url=c.target_url or c.onion_url or "",
                target_type=c.target_type or "domain",
                confidence=c.confidence,
                status=c.status,
                created_at=c.created_at.isoformat() if c.created_at else None,
                evidence_count=len(c.evidence_records),
                custody_count=len(c.custody),
            )
        )
    return items


@router.post("/investigate", response_model=InvestigationResultOut, status_code=200)
def start_investigation(
    payload: InvestigationStartRequest,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> InvestigationResultOut:
    # SSRF Protection: In live and auto modes, strictly reject private, loopback, or metadata addresses
    if payload.mode != "demo":
        is_safe, reason = is_safe_target_url(payload.target)
        if not is_safe:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Policy: Target rejected by SSRF guard ({reason})",
            )

    result = run_full_investigation(payload, db)

    record_audit_log(
        db=db,
        operator=principal.operator,
        action="START_INVESTIGATION",
        case_id=result.case.evidence_id,  # references case
        details={
            "case_name": payload.case_name,
            "target": payload.target,
            "mode": payload.mode,
            "confidence": result.attribution.get("confidence_score"),
        },
    )

    return result


@router.get("/{evidence_id}/investigation", response_model=InvestigationResultOut)
def get_case_investigation(
    evidence_id: str,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> InvestigationResultOut:
    case = _get_case_or_404(db, evidence_id)
    req = InvestigationStartRequest(
        case_name=f"Case {case.evidence_id}",
        evidence_id=case.evidence_id,
        actor_name=case.actor_name,
        target=case.target_url or case.onion_url or "185.220.101.42",
        target_type=case.target_type or "onion",
        known_pgp=case.pgp_fingerprint,
        known_btc=case.btc_root,
    )
    return run_full_investigation(req, db)


@router.post("", response_model=CaseOut, status_code=201)
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Case:
    existing = db.execute(select(Case).where(Case.evidence_id == payload.evidence_id)).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Case '{payload.evidence_id}' already exists")

    case = Case(**payload.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)

    record_audit_log(
        db=db,
        operator=principal.operator,
        action="CREATE_CASE",
        case_id=case.id,
        details={"evidence_id": case.evidence_id, "actor_name": case.actor_name},
    )

    return case


@router.get("/{evidence_id}", response_model=CaseOut)
def get_case(
    evidence_id: str,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> Case:
    return _get_case_or_404(db, evidence_id)


@router.post("/{evidence_id}/custody", response_model=CustodyEntryOut, status_code=201)
def add_custody_entry(
    evidence_id: str,
    payload: CustodyEntryCreate,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> CustodyRow:
    case = _get_case_or_404(db, evidence_id)

    prev_hash = case.custody[-1].entry_hash if case.custody else GENESIS_HASH
    next_seq = (case.custody[-1].seq + 1) if case.custody else 1
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    entry = CustodyEntry(seq=next_seq, timestamp=timestamp, actor=payload.actor, action=payload.action, prev_hash=prev_hash)

    row = CustodyRow(
        case_id=case.id,
        seq=entry.seq,
        timestamp=entry.timestamp,
        actor=entry.actor,
        action=entry.action,
        prev_hash=entry.prev_hash,
        entry_hash=entry.entry_hash,
        signature=entry.signature,
        key_id=entry.key_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # Checkpoint to external anchor (or periodic internal anchor) if interval reached
    checkpoint_if_needed(db, case.id, row.seq, row.entry_hash)

    record_audit_log(
        db=db,
        operator=principal.operator,
        action="APPEND_CUSTODY_BLOCK",
        case_id=case.id,
        details={
            "seq": row.seq,
            "entry_hash": row.entry_hash,
            "actor": payload.actor,
            "signed": bool(row.signature),
            "key_id": row.key_id,
        },
    )

    return row


@router.get("/{evidence_id}/verify", response_model=VerifyResult)
def verify_custody_chain(
    evidence_id: str,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> VerifyResult:
    case = _get_case_or_404(db, evidence_id)
    rows = [
        {
            "seq": r.seq,
            "timestamp": r.timestamp,
            "actor": r.actor,
            "action": r.action,
            "prev_hash": r.prev_hash,
            "entry_hash": r.entry_hash,
            "signature": r.signature,
            "key_id": r.key_id,
        }
        for r in case.custody
    ]
    chain = CustodyChain.from_rows(rows)
    verify_res = chain.verify()
    seal = chain.seal()

    # Retrieve last checkpoint if present
    last_cp = get_last_checkpoint(db, case.id)
    cp_dict = None
    anchor_type = "internal"
    if last_cp is not None:
        anchor_type = last_cp.anchor_type
        cp_dict = {
            "id": last_cp.id,
            "seq": last_cp.seq,
            "tip_hash": last_cp.tip_hash,
            "anchor_type": last_cp.anchor_type,
            "anchor_token": last_cp.anchor_token,
            "created_at": last_cp.created_at.isoformat() if last_cp.created_at else None,
        }

    record_audit_log(
        db=db,
        operator=principal.operator,
        action="VERIFY_CUSTODY_CHAIN",
        case_id=case.id,
        details={
            "valid": verify_res.valid,
            "hash_ok": verify_res.hash_ok,
            "signature_ok": verify_res.signature_ok,
            "entry_count": len(chain.entries),
            "seal": seal,
            "anchor_type": anchor_type,
        },
    )

    return VerifyResult(
        valid=verify_res.valid,
        broken_at_seq=verify_res.broken_at_seq,
        entry_count=len(chain.entries),
        seal=seal,
        hash_ok=verify_res.hash_ok,
        signature_ok=verify_res.signature_ok,
        last_checkpoint=cp_dict,
        anchor_type=anchor_type,
        failure_layer=verify_res.failure_layer,
        signed_count=verify_res.signed_count,
    )
