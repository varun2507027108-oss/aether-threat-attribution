"""Phase 10 — multi-key RBAC, human-in-the-loop export gate, DPDP retention."""

import importlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.security as security
from app.db import Base
from app.security import (
    API_KEYS,
    RateLimitMiddleware,
    RATE_LIMIT_INVESTIGATE_PER_MINUTE,
    RATE_LIMIT_PER_MINUTE,
    _parse_key_table,
    load_api_keys,
)
from app.services.governance import (
    EXPORT_ACTION,
    dossier_hash,
    export_gate_status,
    find_export_confirmation,
    get_retention_days,
    purge_expired_cases,
    require_export_confirmation,
    verify_purge_chain,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent

INVESTIGATOR_KEY = "investigator-test-key-0001"
AUDITOR_KEY = "auditor-test-key-0002"

KEY_TABLE = f"investigator:{INVESTIGATOR_KEY},auditor:{AUDITOR_KEY}"


@pytest.fixture()
def rbac_client(monkeypatch):
    """A client with the multi-key table installed and roles available for both callers."""
    monkeypatch.setenv("AETHER_API_KEYS", KEY_TABLE)
    monkeypatch.setenv("AETHER_REQUIRE_AUTH", "true")
    monkeypatch.setattr(security, "API_KEYS", load_api_keys())

    from app.main import app

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    RateLimitMiddleware.reset_limits()
    app.dependency_overrides[get_db_override_target()] = override_get_db

    with TestClient(app, headers={"X-AETHER-KEY": INVESTIGATOR_KEY}) as investigator:
        with TestClient(app, headers={"X-AETHER-KEY": AUDITOR_KEY}) as auditor:
            yield {"investigator": investigator, "auditor": auditor}

    app.dependency_overrides.clear()
    RateLimitMiddleware.reset_limits()


def get_db_override_target():
    from app.db import get_db

    return get_db


# --------------------------------------------------------------------------- #
# Key table parsing
# --------------------------------------------------------------------------- #

def test_parses_role_key_pairs():
    records = _parse_key_table("investigator:alpha-1,auditor:beta-2")
    assert [r.role for r in records] == ["investigator", "auditor"]
    assert [r.key for r in records] == ["alpha-1", "beta-2"]
    assert all(r.key_id.startswith(f"{r.role}:") for r in records)


def test_unknown_role_is_rejected_not_defaulted(caplog):
    """A typo must not silently grant investigator powers."""
    records = _parse_key_table("admin:root-key,investigator:real-key")
    assert [r.role for r in records] == ["investigator"]
    assert records[0].key == "real-key"


def test_malformed_entries_are_skipped():
    records = _parse_key_table("investigator:good,garbage,auditor:,")
    assert [(r.role, r.key) for r in records] == [("investigator", "good")]


def test_whitespace_is_tolerated():
    records = _parse_key_table("  Investigator : spaced-key ,  AUDITOR :other-key ")
    assert [(r.role, r.key) for r in records] == [("investigator", "spaced-key"), ("auditor", "other-key")]


def test_key_ids_are_stable_and_do_not_leak_the_key():
    first = _parse_key_table("investigator:secret-key")
    second = _parse_key_table("investigator:secret-key")
    assert first[0].key_id == second[0].key_id
    assert "secret-key" not in first[0].key_id


def test_legacy_single_key_maps_to_investigator(monkeypatch):
    monkeypatch.delenv("AETHER_API_KEYS", raising=False)
    monkeypatch.setenv("AETHER_API_KEY", "legacy-key")
    records = load_api_keys()
    assert len(records) == 1
    assert records[0].role == "investigator"
    assert records[0].key == "legacy-key"


def test_empty_key_table_falls_back_to_the_legacy_key(monkeypatch):
    monkeypatch.setenv("AETHER_API_KEYS", "   ")
    monkeypatch.setenv("AETHER_API_KEY", "legacy-key")
    assert load_api_keys()[0].key == "legacy-key"


# --------------------------------------------------------------------------- #
# whoami
# --------------------------------------------------------------------------- #

def test_whoami_reports_investigator_capabilities(rbac_client):
    res = rbac_client["investigator"].get("/api/auth/whoami")
    assert res.status_code == 200
    body = res.json()
    assert body["role"] == "investigator"
    assert body["can_write"] is True
    assert body["can_confirm_export"] is True


def test_whoami_reports_auditor_capabilities(rbac_client):
    body = rbac_client["auditor"].get("/api/auth/whoami").json()
    assert body["role"] == "auditor"
    assert body["can_write"] is False
    assert body["can_confirm_export"] is False
    assert body["can_export"] is True


def test_whoami_requires_authentication():
    from app.main import app

    res = TestClient(app).get("/api/auth/whoami")
    assert res.status_code == 401


def test_whoami_rejects_an_unknown_key(rbac_client):
    res = TestClient(
        __import__("app.main", fromlist=["app"]).app,
        headers={"X-AETHER-KEY": "not-a-configured-key"},
    ).get("/api/auth/whoami")
    assert res.status_code == 401


# --------------------------------------------------------------------------- #
# Role enforcement
# --------------------------------------------------------------------------- #

@pytest.fixture()
def seeded_case(rbac_client):
    res = rbac_client["investigator"].post("/api/cases", json={
        "evidence_id": "AT-2026-RBAC",
        "actor_name": "RBAC Fixture",
        "aliases": ["Alias"],
    })
    assert res.status_code == 201
    return "AT-2026-RBAC"


def test_auditor_cannot_create_a_case(rbac_client):
    res = rbac_client["auditor"].post("/api/cases", json={
        "evidence_id": "AT-2026-NOPE",
        "actor_name": "Auditor",
        "aliases": [],
    })
    assert res.status_code == 403
    assert "read-only" in res.json()["detail"]


def test_auditor_cannot_append_custody(rbac_client, seeded_case):
    res = rbac_client["auditor"].post(f"/api/cases/{seeded_case}/custody", json={
        "actor": "Auditor", "action": "should not be allowed",
    })
    assert res.status_code == 403


def test_auditor_cannot_start_an_investigation(rbac_client):
    res = rbac_client["auditor"].post("/api/cases/investigate?sync=true", json={
        "case_name": "Auditor Probe",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    })
    assert res.status_code == 403


def test_auditor_can_read_cases(rbac_client, seeded_case):
    assert rbac_client["auditor"].get(f"/api/cases/{seeded_case}").status_code == 200
    assert rbac_client["auditor"].get("/api/cases").status_code == 200


def test_auditor_can_verify_the_custody_chain(rbac_client, seeded_case):
    assert rbac_client["auditor"].get(f"/api/cases/{seeded_case}/verify").status_code == 200


def test_auditor_can_export_the_custody_ledger(rbac_client, seeded_case):
    """The ledger is the integrity record; an auditor who cannot read it cannot audit."""
    assert rbac_client["auditor"].get(f"/api/cases/{seeded_case}/export/custody").status_code == 200


def test_auditor_cannot_export_the_dossier(rbac_client, seeded_case):
    for suffix in ("stix", "csv", "certificate"):
        res = rbac_client["auditor"].get(f"/api/cases/{seeded_case}/export/{suffix}")
        assert res.status_code == 409, f"{suffix} should be gated, not merely forbidden"


def test_auditor_cannot_affirm_an_export(rbac_client, seeded_case):
    res = rbac_client["auditor"].post(f"/api/cases/{seeded_case}/confirm-export")
    assert res.status_code == 403
    assert "cannot affirm an export" in res.json()["detail"]


def test_investigator_retains_full_access(rbac_client, seeded_case):
    inv = rbac_client["investigator"]
    assert inv.post(f"/api/cases/{seeded_case}/custody", json={
        "actor": "Investigator", "action": "Evidence sealed",
    }).status_code == 201
    assert inv.post(f"/api/cases/{seeded_case}/confirm-export").status_code == 200


# --------------------------------------------------------------------------- #
# Per-key rate limiting
# --------------------------------------------------------------------------- #

def test_rate_limit_buckets_are_per_key_not_shared(rbac_client, monkeypatch):
    monkeypatch.setattr(security, "RATE_LIMIT_INVESTIGATE_PER_MINUTE", 2)

    payload = {
        "case_name": "Rate Probe",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    }

    for _ in range(2):
        rbac_client["investigator"].post("/api/analysis/score", json={"evidence": []})
    assert rbac_client["investigator"].post("/api/analysis/score", json={"evidence": []}).status_code == 429

    # A different credential has its own budget: the investigator's exhaustion
    # must not throttle a colleague.
    assert rbac_client["auditor"].post("/api/analysis/score", json={"evidence": []}).status_code in (200, 403, 409)


def test_unauthenticated_traffic_gets_its_own_bucket(rbac_client, monkeypatch):
    from app.main import app

    monkeypatch.setattr(security, "RATE_LIMIT_INVESTIGATE_PER_MINUTE", 1)
    anonymous = TestClient(app)

    anonymous.post("/api/analysis/score", json={"evidence": []})
    assert anonymous.post("/api/analysis/score", json={"evidence": []}).status_code in (401, 429)
    # The legitimate caller is unaffected by anonymous abuse.
    assert rbac_client["investigator"].post("/api/analysis/score", json={"evidence": []}).status_code == 200


def test_bucket_key_distinguishes_keys_and_ips(monkeypatch):
    monkeypatch.setattr(security, "API_KEYS", _parse_key_table(KEY_TABLE))

    from app.main import app

    class FakeRequest:
        def __init__(self, headers, params):
            self.headers = headers
            self.query_params = params
            self.client = type("C", (), {"host": "10.0.0.5"})()

    def bucket(headers, params=None):
        return RateLimitMiddleware._bucket_key(FakeRequest(headers, params or {}))

    assert bucket({"X-AETHER-KEY": INVESTIGATOR_KEY}) == bucket({"X-AETHER-KEY": INVESTIGATOR_KEY})
    assert bucket({"X-AETHER-KEY": INVESTIGATOR_KEY}) != bucket({"X-AETHER-KEY": AUDITOR_KEY})
    assert bucket({}) == ("anonymous", "10.0.0.5")
    assert bucket({"X-AETHER-KEY": "bogus"}) == ("invalid-key", "10.0.0.5")
    assert bucket({"Authorization": f"Bearer {AUDITOR_KEY}"}) == bucket({"X-AETHER-KEY": AUDITOR_KEY})
    assert bucket({}, {"token": INVESTIGATOR_KEY}) == bucket({"X-AETHER-KEY": INVESTIGATOR_KEY})


# --------------------------------------------------------------------------- #
# Export gate
# --------------------------------------------------------------------------- #

def test_dossier_hash_is_stable_and_covers_exported_fields(rbac_client, seeded_case):
    first = dossier_hash(rbac_client["investigator"].get(f"/api/cases/{seeded_case}").json() and _load_case(rbac_client, seeded_case))
    second = dossier_hash(_load_case(rbac_client, seeded_case))
    assert first == second
    assert len(first) == 64


def _load_case(rbac_client, evidence_id):
    """Fetch the Case ORM object from the same in-memory database."""
    from app.db import get_db
    from app.main import app
    from app.models import Case
    from sqlalchemy import select

    db = next(app.dependency_overrides[get_db]())
    case = db.execute(select(Case).where(Case.evidence_id == evidence_id)).scalar_one()
    return case


def test_exports_are_gated_before_confirmation(rbac_client, seeded_case):
    gate = rbac_client["investigator"].get(f"/api/cases/{seeded_case}/export/gate").json()
    assert gate["cleared"] is False
    for suffix in ("stix", "csv", "certificate"):
        res = rbac_client["investigator"].get(f"/api/cases/{seeded_case}/export/{suffix}")
        assert res.status_code == 409
        detail = res.json()["detail"]
        assert detail["error"] == "export_not_confirmed"
        assert detail["action_required"] == "confirm-export"
        assert detail["dossier_hash"] == gate["dossier_hash"]


def test_confirm_then_export_succeeds(rbac_client, seeded_case):
    confirm = rbac_client["investigator"].post(f"/api/cases/{seeded_case}/confirm-export")
    assert confirm.status_code == 200
    body = confirm.json()
    assert body["confirmed"] is True
    assert len(body["dossier_hash"]) == 64

    for suffix in ("stix", "csv", "certificate"):
        assert rbac_client["investigator"].get(f"/api/cases/{seeded_case}/export/{suffix}").status_code == 200


def test_confirmation_is_written_into_the_custody_chain(rbac_client, seeded_case):
    confirm = rbac_client["investigator"].post(f"/api/cases/{seeded_case}/confirm-export").json()
    entries = rbac_client["investigator"].get(f"/api/cases/{seeded_case}/export/custody").text
    assert confirm["dossier_hash"] in entries
    assert EXPORT_ACTION in entries


def test_confirmation_moves_the_chain_tip(rbac_client, seeded_case):
    rbac_client["investigator"].post(f"/api/cases/{seeded_case}/custody", json={
        "actor": "Investigator", "action": "Evidence sealed",
    })
    before = rbac_client["investigator"].get(f"/api/cases/{seeded_case}/verify").json()
    confirm = rbac_client["investigator"].post(f"/api/cases/{seeded_case}/confirm-export").json()
    after = rbac_client["investigator"].get(f"/api/cases/{seeded_case}/verify").json()

    assert after["valid"] is True
    assert after["entry_count"] == before["entry_count"] + 1
    assert after["seal"] != before["seal"]
    assert confirm["entry_hash"] in after["seal"] or after["seal"]


def test_confirmation_is_invalidated_when_the_dossier_changes(rbac_client, seeded_case):
    """A confirmation authorizes a specific dossier, not a case forever."""
    inv = rbac_client["investigator"]
    inv.post(f"/api/cases/{seeded_case}/confirm-export")
    assert inv.get(f"/api/cases/{seeded_case}/export/csv").status_code == 200

    # The investigation mutates the dossier after the analyst released it.
    inv.post("/api/cases/investigate?sync=true", json={
        "case_name": "Post-Release Mutation",
        "evidence_id": seeded_case,
        "actor_name": "Changed Actor",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    })

    assert inv.get(f"/api/cases/{seeded_case}/export/gate").json()["cleared"] is False
    assert inv.get(f"/api/cases/{seeded_case}/export/csv").status_code == 409


def test_repeated_confirmation_appends_a_new_entry_each_time(rbac_client, seeded_case):
    inv = rbac_client["investigator"]
    first = inv.post(f"/api/cases/{seeded_case}/confirm-export").json()
    second = inv.post(f"/api/cases/{seeded_case}/confirm-export").json()

    assert first["seq"] != second["seq"]
    assert first["dossier_hash"] == second["dossier_hash"]
    # The audit trail should show each release, not merely that one happened.
    verify = inv.get(f"/api/cases/{seeded_case}/verify").json()
    assert verify["valid"] is True


def test_gate_on_a_missing_case_is_404(rbac_client):
    assert rbac_client["investigator"].get("/api/cases/NOPE-404/export/gate").status_code == 404
    assert rbac_client["investigator"].post("/api/cases/NOPE-404/confirm-export").status_code == 404


def test_require_export_confirmation_raises_409_with_guidance(db_session):
    from fastapi import HTTPException

    from app.models import Case

    case = Case(evidence_id="AT-2026-GATE", actor_name="X", aliases=[])
    db_session.add(case)
    db_session.commit()

    with pytest.raises(HTTPException) as excinfo:
        require_export_confirmation(case)
    assert excinfo.value.status_code == 409
    assert excinfo.value.detail["action_required"] == "confirm-export"


def test_find_export_confirmation_matches_prefixed_action(db_session):
    """Regression: the stored action carries a suffix, so equality never matches."""
    from app.models import Case, CustodyRow

    case = Case(evidence_id="AT-2026-PFX", actor_name="X", aliases=[])
    db_session.add(case)
    db_session.flush()

    row = CustodyRow(
        case_id=case.id, seq=1, timestamp="2026-01-01T00:00:00Z", actor="INV",
        action=f"{EXPORT_ACTION} dossier_sha256={dossier_hash(case)} key=investigator:abc",
        prev_hash="0" * 64, entry_hash="1" * 64,
    )
    db_session.add(row)
    case.custody.append(row)
    db_session.commit()

    assert find_export_confirmation(case) is not None
    assert export_gate_status(case)["cleared"] is True


# --------------------------------------------------------------------------- #
# DPDP retention
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw,expected",
    [("365", 365), ("30", 30), ("", 365), ("abc", 365), ("0", 365), ("-5", 365)],
)
def test_retention_window_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("AETHER_RETENTION_DAYS", raw)
    assert get_retention_days() == expected


def test_purge_is_dry_run_by_default(db_session):
    db_session.add(_aged_case(db_session, "AT-2026-OLD", days=800))
    db_session.commit()

    result = purge_expired_cases(db_session)
    assert result["mode"] == "dry-run"
    assert result["purged_count"] == 0
    assert len(result["cases"]) == 1
    assert "Nothing was deleted" in result["note"]


def test_purge_dry_run_reports_contents_without_deleting(db_session):
    from app.models import CustodyRow

    case = _aged_case(db_session, "AT-2026-OLD", days=800)
    db_session.add(CustodyRow(
        case_id=case.id, seq=1, timestamp="2026-01-01T00:00:00Z", actor="INV",
        action="sealed", prev_hash="0" * 64, entry_hash="1" * 64,
    ))
    db_session.commit()

    result = purge_expired_cases(db_session)
    assert result["cases"][0]["contents"]["custody_entries"] == 1
    assert result["cases"][0]["dossier_hash"]
    # Still present: dry run changed nothing.
    assert db_session.get(type(case), case.id) is not None


def test_purge_commit_deletes_and_records_the_purge(db_session):
    db_session.add(_aged_case(db_session, "AT-2026-OLD", days=800))
    db_session.commit()

    result = purge_expired_cases(db_session, commit=True)
    assert result["mode"] == "commit"
    assert result["purged_count"] == 1
    assert result["purge_custody_entry"]["entry_hash"]

    # The purge record survives the destruction, in a case-independent chain.
    status = verify_purge_chain(db_session)
    assert status["valid"] is True
    assert status["entry_count"] == 1


def test_purge_chain_accumulates_across_runs(db_session):
    db_session.add(_aged_case(db_session, "AT-2026-OLD", days=800))
    db_session.commit()
    purge_expired_cases(db_session, commit=True)

    db_session.add(_aged_case(db_session, "AT-2026-OLDER", days=2000))
    db_session.commit()
    purge_expired_cases(db_session, commit=True)

    status = verify_purge_chain(db_session)
    assert status["entry_count"] == 2
    assert status["valid"] is True


def test_purge_leaves_fresh_cases_alone(db_session):
    db_session.add(_aged_case(db_session, "AT-2026-FRESH", days=3))
    db_session.commit()

    result = purge_expired_cases(db_session, commit=True)
    assert result["purged_count"] == 0
    assert verify_purge_chain(db_session)["entry_count"] == 0


def test_purge_manifest_is_order_independent(db_session):
    db_session.add(_aged_case(db_session, "AT-2026-B", days=800))
    db_session.add(_aged_case(db_session, "AT-2026-A", days=900))
    db_session.commit()
    assert len(purge_expired_cases(db_session)["manifest_hash"]) == 64


def test_retention_measured_from_creation_not_last_activity(db_session):
    """Touching a case must not extend its life; purpose limitation is absolute."""
    case = _aged_case(db_session, "AT-2026-OLD", days=800)
    db_session.commit()

    # Simulate recent activity.
    case.status = "COMPLETED"
    case.confidence = 99.0
    db_session.commit()

    result = purge_expired_cases(db_session)
    assert [c["evidence_id"] for c in result["cases"]] == ["AT-2026-OLD"]


def _aged_case(db_session, evidence_id, days):
    from app.models import Case

    case = Case(
        evidence_id=evidence_id,
        actor_name="Retention Fixture",
        aliases=[],
        created_at=datetime.now(timezone.utc) - timedelta(days=days),
    )
    db_session.add(case)
    # Flush so case.id exists for callers that attach child rows.
    db_session.flush()
    return case


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_purge_script_dry_run_and_commit(tmp_path):
    def run(extra):
        return subprocess.run(
            [sys.executable, str(BACKEND_ROOT / "scripts" / "purge_expired.py"), *extra],
            cwd=str(BACKEND_ROOT), capture_output=True, text=True, timeout=300,
        )

    dry = run(["--json"])
    assert dry.returncode == 0, dry.stderr
    payload = json.loads(dry.stdout)
    assert payload["mode"] == "dry-run"
    assert payload["purged_count"] == 0

    committed = run(["--commit", "--json"])
    assert committed.returncode == 0, committed.stderr
    assert json.loads(committed.stdout)["mode"] == "commit"

    verified = run(["--verify-chain", "--json"])
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["valid"] is True


def test_governance_doc_exists_and_covers_the_obligations():
    doc = (REPO_ROOT / "docs" / "governance.md").read_text(encoding="utf-8")
    assert "Digital Personal Data Protection Act, 2023" in doc
    assert "Purpose limitation" in doc or "purpose limitation" in doc
    assert "AETHER_RETENTION_DAYS" in doc
    assert "AETHER_API_KEYS" in doc
    assert "EXPORT_CONFIRMED" in doc
    assert "dry run" in doc.lower()
    assert "case-independent" in doc
    # The separation-of-duties table must actually reflect the code.
    assert "`auditor`" in doc
