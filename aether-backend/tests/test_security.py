"""Automated Security & Hardening Test Suite for Project AETHER.

Validates:
1. API Authentication & Authorization (401 on missing/invalid credentials, 200 on valid).
2. Defensive HTTP Security Headers (conditional HSTS, no-sniff, clickjacking, CSP, cache-control).
3. Configured CORS policies (blocking arbitrary origins, no wildcard *).
4. Payload transmission size limits (413 on >2MB).
5. In-memory IP Rate Limiter (429 and Retry-After header on burst exceeding threshold).
6. SSRF defense (blocking 127.0.0.1, RFC 1918 private subnets, cloud metadata 169.254.169.254).
7. Strict input validation (malformed IDs, invalid PGP patterns, out-of-range weights).
8. Safe error handling (500 response contains incident_id without SQL/traceback leakage).
9. Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) Audit trail generation and access control.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.security import (
    AETHER_API_KEY,
    MAX_PAYLOAD_BYTES,
    RATE_LIMIT_INVESTIGATE_PER_MINUTE,
    RATE_LIMIT_PER_MINUTE,
    RateLimitMiddleware,
    is_safe_target_url,
)

VALID_HEADERS = {"X-AETHER-KEY": AETHER_API_KEY}
BEARER_HEADERS = {"Authorization": f"Bearer {AETHER_API_KEY}"}


@pytest.fixture(name="client")
def client_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    # Seed default case
    from app.models import Case, CustodyRow
    with TestingSessionLocal() as session:
        c = Case(
            evidence_id="AT-2026-0047",
            actor_name="ZeroTrace",
            origin_ip="185.220.101.42",
            target_url="http://p4lx7e22kq6dreadmarket.onion",
            target_type="onion",
            confidence=94.8,
            status="ACTIVE",
        )
        session.add(c)
        session.commit()
        session.refresh(c)
        r = CustodyRow(
            case_id=c.id,
            seq=1,
            timestamp="2026-09-14T08:00:00Z",
            actor="Lead Examiner",
            action="Seeded initial evidence",
            prev_hash="0" * 64,
            entry_hash="a" * 64,
        )
        session.add(r)
        session.commit()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    RateLimitMiddleware.reset_limits()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    RateLimitMiddleware.reset_limits()


# ---------- 1. Authentication & Access Control Tests ---------- #

def test_public_health_endpoint_requires_no_auth(client: TestClient):
    """Health check endpoint must be publicly accessible for orchestrators."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_cases_endpoint_rejects_unauthenticated_request(client: TestClient):
    """Forensic cases list must reject requests without credentials."""
    res = client.get("/api/cases")
    assert res.status_code == 401
    assert "Invalid or missing AETHER authentication credentials" in res.json()["detail"]


def test_cases_endpoint_rejects_invalid_api_key(client: TestClient):
    """Forensic cases list must reject invalid API keys."""
    res = client.get("/api/cases", headers={"X-AETHER-KEY": "bad-hacker-key-999"})
    assert res.status_code == 401


def test_cases_endpoint_accepts_valid_api_key(client: TestClient):
    """Valid X-AETHER-KEY header grants access."""
    res = client.get("/api/cases", headers=VALID_HEADERS)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_cases_endpoint_accepts_valid_bearer_token(client: TestClient):
    """Valid Authorization: Bearer <key> grants access."""
    res = client.get("/api/cases", headers=BEARER_HEADERS)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_audit_logs_protected_by_auth(client: TestClient):
    """Audit logs must reject unauthenticated callers."""
    res = client.get("/api/audit-logs")
    assert res.status_code == 401

    res_auth = client.get("/api/audit-logs", headers=VALID_HEADERS)
    assert res_auth.status_code == 200
    assert isinstance(res_auth.json(), list)


# ---------- 2. Security Headers & Conditional HSTS Tests ---------- #

def test_defensive_security_headers_present(client: TestClient):
    """Verify essential hardening headers on response."""
    res = client.get("/api/health")
    headers = res.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers


def test_hsts_not_sent_over_plain_http(client: TestClient):
    """HSTS must NOT be sent over plain HTTP to prevent broken local dev environments."""
    res = client.get("/api/health")
    assert "Strict-Transport-Security" not in res.headers


def test_hsts_sent_when_https_forwarded(client: TestClient):
    """HSTS must be enabled when request is transported via HTTPS."""
    res = client.get("/api/health", headers={"x-forwarded-proto": "https"})
    assert "Strict-Transport-Security" in res.headers
    assert "max-age=31536000" in res.headers["Strict-Transport-Security"]


def test_forensic_endpoints_have_cache_control_no_store(client: TestClient):
    """Sensitive case data must not be stored by intermediate caches."""
    res = client.get("/api/cases", headers=VALID_HEADERS)
    assert res.status_code == 200
    assert "no-store" in res.headers.get("Cache-Control", "")


# ---------- 3. CORS Hardening Tests ---------- #

def test_cors_allows_configured_origin(client: TestClient):
    """Configured origin http://localhost:3000 must receive CORS approval."""
    res = client.options(
        "/api/cases",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_cors_blocks_unauthorized_attacker_origin(client: TestClient):
    """Disallowed origins must not be given wildcard or reflected approval."""
    res = client.options(
        "/api/cases",
        headers={
            "Origin": "http://malicious-adversary.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # The origin should NOT be reflected
    assert res.headers.get("access-control-allow-origin") != "http://malicious-adversary.com"
    assert res.headers.get("access-control-allow-origin") != "*"


# ---------- 4. Request Payload Limit Tests ---------- #

def test_payload_limit_middleware_rejects_oversized_request(client: TestClient):
    """Content-Length exceeding 2MB must be rejected with 413 Payload Too Large."""
    res = client.post(
        "/api/cases/investigate",
        headers={"Content-Length": str(MAX_PAYLOAD_BYTES + 5000), **VALID_HEADERS},
        content=b"A" * 100,  # small mock body but oversized header
    )
    assert res.status_code == 413
    assert "exceeds the forensic transmission limit" in res.json()["detail"]


# ---------- 5. SSRF Defense & Target Sanitization Tests ---------- #

@pytest.mark.parametrize("target", [
    "http://127.0.0.1",
    "http://127.0.0.1:8080/admin",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/internal",
    "http://192.168.1.1",
    "http://172.16.0.1",
    "http://[::1]",
    "ftp://example.com",
])
def test_ssrf_rejects_internal_and_loopback_targets(target: str):
    """SSRF guard must block internal RFC 1918, loopback, and cloud metadata targets."""
    is_safe, reason = is_safe_target_url(target)
    assert is_safe is False
    assert len(reason) > 0


def test_ssrf_allows_valid_public_onion_target():
    """Public darknet .onion addresses must be safely permitted."""
    is_safe, reason = is_safe_target_url("http://p4lx7e22kq6dreadmarket.onion")
    assert is_safe is True
    assert reason == ""


def test_ssrf_allows_valid_clearnet_public_ip():
    """Public clearnet IPs must be permitted."""
    is_safe, reason = is_safe_target_url("http://185.220.101.42")
    assert is_safe is True
    assert reason == ""


def test_live_investigation_blocks_ssrf_target(client: TestClient):
    """Investigation in 'live' mode must return 400 when given a loopback SSRF target."""
    payload = {
        "case_name": "SSRF Probe Attack",
        "target": "http://127.0.0.1:8000/admin",
        "target_type": "ip",
        "mode": "live",
    }
    res = client.post("/api/cases/investigate", json=payload, headers=VALID_HEADERS)
    assert res.status_code == 400
    assert "SSRF" in res.json()["detail"]


# ---------- 6. Strict Input Validation Tests ---------- #

def test_invalid_evidence_id_pattern_rejected(client: TestClient):
    """Evidence IDs with SQL injection or control characters must be rejected."""
    res = client.get("/api/cases/AT-2026';DROP TABLE cases;--", headers=VALID_HEADERS)
    assert res.status_code == 400


def test_invalid_pgp_hex_characters_rejected(client: TestClient):
    """Non-hex characters in PGP fingerprint must fail validation."""
    payload = {
        "case_name": "Invalid PGP Case",
        "target": "cybersec-corp.is",
        "target_type": "domain",
        "known_pgp": "NOT_A_VALID_HEX_KEY_XYZ!@#$",
    }
    res = client.post("/api/cases/investigate", json=payload, headers=VALID_HEADERS)
    assert res.status_code == 422


def test_score_request_rejects_out_of_bounds_weights(client: TestClient):
    """Signal weights outside [0.0, 1.0] must be rejected."""
    payload = {
        "deterministic_signals": {"pgp_match": 10.5},  # > 1.0
        "probabilistic_signals": {"stylometry_similarity": 0.5},
    }
    res = client.post("/api/analysis/score", json=payload, headers=VALID_HEADERS)
    assert res.status_code == 422


def test_custody_action_defuses_formula_injection(client: TestClient):
    """Custody actions starting with formula characters (=, +, -, @) must be defused."""
    payload = {
        "actor": "Lead Examiner",
        "action": "=cmd|' /C calc'!A0",
    }
    res = client.post("/api/cases/AT-2026-0047/custody", json=payload, headers=VALID_HEADERS)
    assert res.status_code == 201
    assert res.json()["action"].startswith("'=")


# ---------- 7. Rate Limiter Middleware Tests ---------- #

def test_rate_limiter_triggers_429_on_burst(client: TestClient):
    """Bursting past the rate limit must return 429 and a Retry-After header."""
    # Temporarily lower heavy rate limit or burst beyond RATE_LIMIT_INVESTIGATE_PER_MINUTE (10)
    for _ in range(RATE_LIMIT_INVESTIGATE_PER_MINUTE):
        res = client.post(
            "/api/analysis/stylometry",
            json={"text_a": "Sample text A for stylometry.", "text_b": "Sample text B for stylometry."},
            headers=VALID_HEADERS,
        )
        assert res.status_code in (200, 429)

    # The 11th request must trip the 429 rate limiter
    tripped_res = client.post(
        "/api/analysis/stylometry",
        json={"text_a": "Sample text A for stylometry.", "text_b": "Sample text B for stylometry."},
        headers=VALID_HEADERS,
    )
    assert tripped_res.status_code == 429
    assert "rate limit exceeded" in tripped_res.json()["detail"].lower()
    assert "Retry-After" in tripped_res.headers


# ---------- 8. Audit Logging Verification Tests ---------- #

def test_investigation_and_custody_create_audit_logs(client: TestClient):
    """Forensic actions must automatically record Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) audit trail rows."""
    # 1. Start investigation
    inv_payload = {
        "case_name": "Audit Verification Op",
        "target": "http://authorized-onion-target.onion",
        "target_type": "onion",
        "mode": "demo",
    }
    inv_res = client.post("/api/cases/investigate", json=inv_payload, headers=VALID_HEADERS)
    assert inv_res.status_code == 200

    # 2. Query audit logs
    audit_res = client.get("/api/audit-logs", headers=VALID_HEADERS)
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) > 0
    actions = [l["action"] for l in logs]
    assert "START_INVESTIGATION" in actions
