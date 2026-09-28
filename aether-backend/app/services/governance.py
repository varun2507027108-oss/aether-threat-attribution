"""Human-in-the-loop export gate and DPDP retention governance.

Two related controls that both exist to answer the same question: *what is
allowed to leave this system, and for how long does it stay here?*

The export gate implements a deliberate separation of duties. A machine may
**propose** an export; only a named human investigator may **affirm** it, and
the affirmation is itself written into the append-only custody chain with the
dossier hash. The chain therefore records who released the dossier and exactly
what they released, which is the fact a defence counsel or a court will ask for.
Auditors can read and export for verification but can never satisfy the gate: a
reviewer who can authorize their own release has not reviewed anything.

Retention implements purpose limitation under the Digital Personal Data
Protection Act, 2023. A purge is itself an append-only event: expired cases are
removed, and a checkpoint row records precisely what was removed and when, so
the record of destruction is itself evidence rather than a gap.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Case, CustodyRow, Evidence

logger = logging.getLogger("aether.governance")

EXPORT_ACTION = "EXPORT_CONFIRMED"
PURGE_ACTION = "RETENTION_PURGE"


def get_retention_days() -> int:
    """Retention window in days for case data (default 365)."""
    raw = os.getenv("AETHER_RETENTION_DAYS", "365").strip() or "365"
    try:
        value = int(raw)
    except ValueError:
        logger.warning("AETHER_RETENTION_DAYS=%r is not an integer; using 365.", raw)
        return 365
    # A zero or negative retention window would delete a case the instant it is
    # created, so it is treated as "keep everything" rather than as a request.
    return value if value > 0 else 365


def dossier_hash(case: Case) -> str:
    """Compute a stable hash of the exported dossier content.

    This is the value the export gate binds its confirmation to, so it must
    change whenever anything in the exported dossier changes. Only fields that
    actually appear in an export are included; the hash would be misleading if it
    covered internal state the exporter never emits.
    """
    parts = [
        str(case.evidence_id or ""),
        str(case.actor_name or ""),
        ",".join(case.aliases or []),
        str(case.origin_ip or ""),
        str(case.geo or ""),
        str(case.asn or ""),
        str(case.pgp_fingerprint or ""),
        str(case.btc_root or ""),
        f"{float(case.confidence or 0.0):.4f}",
        str(case.onion_url or ""),
        str(case.target_url or ""),
        str(case.target_type or ""),
        str(case.scoring or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def find_export_confirmation(case: Case) -> Optional[CustodyRow]:
    """Return the most recent EXPORT_CONFIRMED entry that matches the current dossier.

    A confirmation is bound to a specific dossier hash. If the case changes after
    an analyst confirms an export, the previous confirmation does not carry over:
    otherwise a confirmation given for a partial dossier would silently authorize
    release of a fuller one.
    """
    current = dossier_hash(case)
    for row in reversed(list(case.custody)):
        # startswith, not equality: the stored action carries the dossier hash and
        # key id as a suffix, so an equality test would silently never match and
        # the gate would reject every export forever.
        if row.action and row.action.startswith(EXPORT_ACTION) and current in row.action:
            return row
    return None


def export_gate_status(case: Case) -> Dict[str, Any]:
    """Report whether the dossier is currently cleared for export."""
    confirmation = find_export_confirmation(case)
    return {
        "cleared": confirmation is not None,
        "dossier_hash": dossier_hash(case),
        "confirmed_at": confirmation.timestamp if confirmation else None,
        "confirmed_by": confirmation.actor if confirmation else None,
        "confirmed_at_seq": confirmation.seq if confirmation else None,
    }


def require_export_confirmation(case: Case) -> None:
    """Raise 409 when the current dossier has not been human-confirmed."""
    from fastapi import HTTPException, status

    status_block = export_gate_status(case)
    if status_block["cleared"]:
        return

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "export_not_confirmed",
            "message": (
                "This dossier has not been released by a human investigator. Call "
                f"POST /api/cases/{case.evidence_id}/confirm-export to affirm release of the "
                "current dossier state."
            ),
            "dossier_hash": status_block["dossier_hash"],
            "action_required": "confirm-export",
        },
    )


def confirm_export(
    case: Case,
    db: Session,
    *,
    operator: str,
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a signed EXPORT_CONFIRMED custody entry for the current dossier.

    Idempotent in effect but not in record: confirming an already-confirmed
    dossier still appends an entry, because the audit trail should show each
    time a release was authorized, not merely that it happened once.
    """
    from app.services.anchor import checkpoint_if_needed
    from app.services.custody import GENESIS_HASH, CustodyEntry

    current = dossier_hash(case)
    prev_hash = case.custody[-1].entry_hash if case.custody else GENESIS_HASH
    next_seq = (case.custody[-1].seq + 1) if case.custody else 1
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    action = f"{EXPORT_ACTION} dossier_sha256={current}"
    if key_id:
        action += f" key={key_id}"

    entry = CustodyEntry(
        seq=next_seq,
        timestamp=timestamp,
        actor=operator,
        action=action,
        prev_hash=prev_hash,
    )
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
    # Append through the relationship as well as the session. The Case row was
    # loaded (and its custody collection populated) before this entry existed, so
    # adding to the session alone leaves `case.custody` stale under
    # expire_on_commit=False, which the test harness uses. A stale collection
    # makes find_export_confirmation() miss the very entry we just wrote, and the
    # gate would then reject the export it just approved.
    case.custody.append(row)
    db.flush()
    checkpoint_if_needed(db, case.id, row.seq, row.entry_hash)

    db.add(AuditLog(
        case_id=case.id,
        timestamp=timestamp,
        operator=operator,
        action=EXPORT_ACTION,
        details={
            "dossier_hash": current,
            "seq": entry.seq,
            "entry_hash": entry.entry_hash,
            "key_id": key_id,
        },
    ))
    db.commit()

    return {
        "confirmed": True,
        "dossier_hash": current,
        "seq": entry.seq,
        "entry_hash": entry.entry_hash,
        "timestamp": entry.timestamp,
        "operator": operator,
        "message": "Export released by human affirmation. The confirmation is sealed in the custody chain.",
    }


# --------------------------------------------------------------------------- #
# DPDP Act 2023 retention
# --------------------------------------------------------------------------- #

def find_expired_cases(db: Session, retention_days: Optional[int] = None) -> List[Case]:
    """Cases whose age exceeds the retention window.

    Age is measured from ``created_at`` rather than last activity: purpose
    limitation means a case cannot be kept open indefinitely by continuing to
    touch it.
    """
    days = get_retention_days() if retention_days is None else retention_days
    if days <= 0:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    expired: List[Case] = []
    for case in db.execute(select(Case)).scalars().all():
        created = case.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created <= cutoff:
            expired.append(case)
    return expired


def summarize_case_contents(case: Case) -> Dict[str, int]:
    """Counts of everything a purge would destroy, for the dry-run report."""
    return {
        "custody_entries": len(case.custody),
        "evidence_records": len(case.evidence_records),
        "correlations": len(case.correlations),
        "checkpoints": len(case.checkpoints),
        "audit_logs": len(case.audit_logs),
    }


def purge_expired_cases(
    db: Session,
    *,
    commit: bool = False,
    retention_days: Optional[int] = None,
    operator: str = "AETHER Retention Governor",
) -> Dict[str, Any]:
    """Purge cases past the retention window, recording the purge itself.

    Dry-run by default. A purge is irreversible, so the operator must pass an
    explicit ``commit=True``; the default is a report, not an action.

    The purge record is written to a case-independent custody chain anchored to
    a zero ``case_id``, so the fact of destruction survives the destruction. The
    alternative — logging it inside the case — would delete the only evidence
    that the deletion was authorized and lawful.
    """
    days = get_retention_days() if retention_days is None else retention_days
    expired = find_expired_cases(db, days)

    report: List[Dict[str, Any]] = []
    for case in expired:
        report.append({
            "case_id": case.id,
            "evidence_id": case.evidence_id,
            "actor_name": case.actor_name,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "dossier_hash": dossier_hash(case),
            "contents": summarize_case_contents(case),
        })

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest = hashlib.sha256(
        "|".join(sorted(item["evidence_id"] for item in report)).encode("utf-8")
    ).hexdigest() if report else hashlib.sha256(b"empty").hexdigest()

    result: Dict[str, Any] = {
        "mode": "commit" if commit else "dry-run",
        "retention_days": days,
        "operator": operator,
        "timestamp": timestamp,
        "purged_count": 0,
        "purged_case_ids": [],
        "manifest_hash": manifest,
        "cases": report,
    }

    if not commit:
        result["note"] = (
            "Dry run. Nothing was deleted. Re-run with --commit to purge. "
            "Under the Digital Personal Data Protection Act, 2023, purpose limitation "
            "requires erasure once the stated investigative purpose is exhausted."
        )
        return result

    purged_ids: List[int] = []
    for case in expired:
        db.delete(case)
        purged_ids.append(case.id)

    db.add(AuditLog(
        case_id=None,
        timestamp=timestamp,
        operator=operator,
        action=PURGE_ACTION,
        details={
            "retention_days": days,
            "purged_count": len(purged_ids),
            "purged_case_ids": purged_ids,
            "purged_evidence_ids": [item["evidence_id"] for item in report],
            "manifest_hash": manifest,
        },
    ))

    # A no-op purge does not get a custody entry. The chain records the
    # destruction of evidence; writing entries for scheduled runs that found
    # nothing would bury the ones that mattered.
    purge_entry = None
    if purged_ids:
        purge_entry = _append_purge_custody_entry(
            db,
            action=(
                f"{PURGE_ACTION} cases={len(purged_ids)} retention_days={days} manifest={manifest}"
            ),
            operator=operator,
            timestamp=timestamp,
        )
    db.commit()

    result.update({
        "purged_count": len(purged_ids),
        "purged_case_ids": purged_ids,
        "purge_custody_entry": purge_entry,
        "note": (
            "Purge committed. The manifest hash is anchored in a case-independent custody "
            "entry, so proof of what was destroyed and when survives the destruction itself."
            if purged_ids
            else "Purge committed. No cases were past the retention window, so nothing was deleted."
        ),
    })
    return result


def _append_purge_custody_entry(
    db: Session,
    *,
    action: str,
    operator: str,
    timestamp: str,
) -> Dict[str, Any]:
    """Append a custody entry for the retention governor, outside any case."""
    from app.services.custody import GENESIS_HASH, CustodyEntry

    prior = db.execute(
        select(CustodyRow).where(CustodyRow.case_id == 0).order_by(CustodyRow.seq.desc())
    ).scalars().first()

    prev_hash = prior.entry_hash if prior else GENESIS_HASH
    next_seq = (prior.seq + 1) if prior else 1

    entry = CustodyEntry(
        seq=next_seq,
        timestamp=timestamp,
        actor=operator,
        action=action,
        prev_hash=prev_hash,
    )
    row = CustodyRow(
        case_id=0,
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
    db.flush()
    return {
        "seq": entry.seq,
        "entry_hash": entry.entry_hash,
        "prev_hash": entry.prev_hash,
        "timestamp": entry.timestamp,
    }


def verify_purge_chain(db: Session) -> Dict[str, Any]:
    """Verify the append-only purge chain anchored outside any case."""
    from app.services.custody import CustodyChain

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
        for r in db.execute(
            select(CustodyRow).where(CustodyRow.case_id == 0).order_by(CustodyRow.seq)
        ).scalars().all()
    ]
    chain = CustodyChain.from_rows(rows)
    return {
        "valid": chain.verify().valid,
        "entry_count": len(chain.entries),
        "seal": chain.seal(),
    }
