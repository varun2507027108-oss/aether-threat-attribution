import asyncio
import json
import pytest
from unittest.mock import patch

from app.services.investigation import run_full_investigation_async, run_investigation_job_background
from app.services.job_events import job_event_broadcaster


def test_start_investigation_async_202(client):
    """POST /api/cases/investigate returns 202 Accepted with job metadata."""
    payload = {
        "case_name": "Async Operation Test",
        "evidence_id": "AT-2026-JOB01",
        "actor_name": "AsyncSpecter",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    }

    res = client.post("/api/cases/investigate", json=payload)
    assert res.status_code == 202, res.text
    data = res.json()

    assert "job_id" in data
    assert data["job_id"].startswith("job-")
    assert data["status_url"] == f"/api/jobs/{data['job_id']}"
    assert data["events_url"] == f"/api/jobs/{data['job_id']}/events"
    assert data["evidence_id"] == "AT-2026-JOB01"


def test_get_job_snapshot(client):
    """GET /api/jobs/{id} returns job snapshot with per-module progress."""
    payload = {
        "case_name": "Snapshot Test",
        "evidence_id": "AT-2026-JOB02",
        "actor_name": "SnapshotActor",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    }

    res = client.post("/api/cases/investigate", json=payload)
    assert res.status_code == 202
    job_id = res.json()["job_id"]

    # Immediate snapshot
    job_res = client.get(f"/api/jobs/{job_id}")
    assert job_res.status_code == 200
    job = job_res.json()
    assert job["id"] == job_id
    assert job["status"] in ("queued", "running", "complete")
    assert len(job["modules"]) == 9


def test_job_execution_lifecycle_and_background_runner(db_session):
    """Verify background job execution updates job status to complete and stores result."""
    from app.schemas import InvestigationStartRequest
    from app.models import InvestigationJob

    job_id = "job-lifecycle-01"
    evidence_id = "AT-2026-LIFECYCLE"
    payload = InvestigationStartRequest(
        case_name="Lifecycle Case",
        evidence_id=evidence_id,
        actor_name="LifecycleActor",
        target="185.220.101.42",
        target_type="ip",
        mode="demo",
    )

    initial_job = InvestigationJob(
        id=job_id,
        status="queued",
        modules=[],
    )
    db_session.add(initial_job)
    db_session.commit()

    # Run background runner
    asyncio.run(run_investigation_job_background(job_id, payload, evidence_id, db=db_session))

    db_session.expire_all()
    updated_job = db_session.get(InvestigationJob, job_id)
    assert updated_job is not None
    assert updated_job.status == "complete"
    assert updated_job.case_id is not None
    assert len(updated_job.modules) == 9
    for m in updated_job.modules:
        assert m["status"] == "done"

    # Check cached result in broadcaster
    cached = job_event_broadcaster.get_cached_result(job_id)
    assert cached is not None
    assert cached["case"]["evidence_id"] == evidence_id


def test_partial_module_failure_tolerance(db_session):
    """When a single module raises an exception, job status becomes partial and others succeed."""
    from app.schemas import InvestigationStartRequest
    from app.models import InvestigationJob

    job_id = "job-partial-01"
    evidence_id = "AT-2026-PARTIAL"
    payload = InvestigationStartRequest(
        case_name="Partial Failure Case",
        evidence_id=evidence_id,
        actor_name="PartialActor",
        target="185.220.101.42",
        target_type="ip",
        mode="demo",
    )

    initial_job = InvestigationJob(
        id=job_id,
        status="queued",
        modules=[],
    )
    db_session.add(initial_job)
    db_session.commit()

    # Monkeypatch _run_module_jarm to raise an error
    def failing_jarm(*args, **kwargs):
        raise RuntimeError("Simulated JARM probe timeout")

    with patch("app.services.investigation._run_module_jarm", side_effect=failing_jarm):
        asyncio.run(run_investigation_job_background(job_id, payload, evidence_id, db=db_session))

    db_session.expire_all()
    updated_job = db_session.get(InvestigationJob, job_id)
    assert updated_job is not None
    assert updated_job.status == "partial"
    jarm_mod = next((m for m in updated_job.modules if m["module"] == "jarm"), None)
    assert jarm_mod is not None
    assert jarm_mod["status"] == "failed"
    assert "Simulated JARM probe timeout" in str(jarm_mod["error"])

    # Other modules succeeded
    favicon_mod = next((m for m in updated_job.modules if m["module"] == "favicon"), None)
    assert favicon_mod is not None
    assert favicon_mod["status"] == "done"


def test_sse_endpoint_replays_and_terminates(client):
    """GET /api/jobs/{id}/events returns text/event-stream with initial state and updates."""
    from app.db import get_db
    from app.models import InvestigationJob
    from app.security import AETHER_API_KEY

    job_id = "job-sse-test-01"
    evidence_id = "AT-2026-JOB-SSE"

    # Insert job directly into client's in-memory database
    db_gen = client.app.dependency_overrides[get_db]()
    db = next(db_gen)
    try:
        job = InvestigationJob(
            id=job_id,
            status="complete",
            modules=[
                {"module": "favicon", "name": "Favicon MurmurHash3", "status": "done", "summary": "Match found"},
                {"module": "jarm", "name": "JARM TLS", "status": "done", "summary": "Fingerprint verified"},
            ],
        )
        db.add(job)
        db.commit()
    finally:
        db.close()

    job_event_broadcaster.cache_result(job_id, {"case": {"evidence_id": evidence_id}})

    # Header authentication
    sse_res = client.get(f"/api/jobs/{job_id}/events")
    assert sse_res.status_code == 200
    assert "text/event-stream" in sse_res.headers.get("content-type", "")
    body = sse_res.text
    assert "event: snapshot" in body
    assert "event: terminal" in body
    assert f'"job_id": "{job_id}"' in body
    assert '"status": "complete"' in body

    # Token query parameter authentication (for browser EventSource)
    from fastapi.testclient import TestClient
    from app.main import app
    unauth_client = TestClient(app)
    token_res = unauth_client.get(f"/api/jobs/{job_id}/events?token={AETHER_API_KEY}")
    assert token_res.status_code == 200
    assert "text/event-stream" in token_res.headers.get("content-type", "")
    assert "event: snapshot" in token_res.text


def test_sync_true_compatibility(client):
    """POST /api/cases/investigate?sync=true returns legacy 200 with full InvestigationResultOut."""
    payload = {
        "case_name": "Sync Mode Compat",
        "evidence_id": "AT-2026-SYNCTEST",
        "actor_name": "SyncActor",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    }

    res = client.post("/api/cases/investigate?sync=true", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()

    assert "case" in data
    assert data["case"]["evidence_id"] == "AT-2026-SYNCTEST"
    assert "evidence_records" in data["case"]
    assert "custody_verification" in data
    assert data["custody_verification"]["valid"] is True
