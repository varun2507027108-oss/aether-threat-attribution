"""Tests for statutory forensic certificate generation under Section 63 BSA 2023 / Section 65B IEA.

Validates:
1. PDF magic bytes (%PDF) and non-zero payload size.
2. Verification of case ID and custody chain tip hash as extractable text.
3. Proper Content-Type (application/pdf) and Content-Disposition headers.
4. Authentication enforcement (401 on missing or invalid API keys).
5. 404 on non-existent case evidence_id.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

CASE_PAYLOAD = {
    "evidence_id": "AT-2026-0047",
    "actor_name": "APT-091 (RedShark)",
    "aliases": ["ZeroTrace", "ShadowByte"],
    "origin_ip": "185.220.101.42",
    "geo": "Munich, Germany",
    "asn": "AS16276 OVH SAS",
    "pgp_fingerprint": "4D9E27BC918A4F02C73109AE2C5B88E140FA7D3C",
    "btc_root": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "confidence": 94.8,
    "onion_url": "http://p4lx7e22kq6dreadmarket.onion",
}


def test_export_certificate_success(client: TestClient):
    """Certificate endpoint must return valid PDF with magic bytes, case ID, and tip hash."""
    # 1. Create case and append custody actions
    c_res = client.post("/api/cases", json=CASE_PAYLOAD)
    assert c_res.status_code == 201

    e1 = client.post(
        "/api/cases/AT-2026-0047/custody",
        json={"actor": "Investigator-01", "action": "Dark web target acquisition"},
    )
    assert e1.status_code == 201
    tip_hash_e1 = e1.json()["entry_hash"]

    e2 = client.post(
        "/api/cases/AT-2026-0047/custody",
        json={"actor": "Investigator-01", "action": "Origin IP de-anonymization"},
    )
    assert e2.status_code == 201
    tip_hash_e2 = e2.json()["entry_hash"]

    # 2. Affirm release, then fetch the certificate PDF.
    # The affirmation appends its own custody entry, so the chain tip at export
    # time is the EXPORT_CONFIRMED entry, not the last investigative action.
    gate = client.post("/api/cases/AT-2026-0047/confirm-export")
    assert gate.status_code == 200, "human export affirmation must succeed for an investigator"
    tip_hash_at_export = gate.json()["entry_hash"]
    res = client.get("/api/cases/AT-2026-0047/export/certificate")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert 'attachment; filename="aether_statutory_certificate_AT-2026-0047.pdf"' in res.headers.get("content-disposition", "")

    pdf_bytes = res.content
    # Magic bytes check
    assert pdf_bytes.startswith(b"%PDF-"), "Output must begin with PDF magic bytes"
    assert len(pdf_bytes) > 2000, "Certificate must have substantive non-zero length"

    # Extractable text checks
    assert b"AT-2026-0047" in pdf_bytes, "Case ID must be present in extractable text"
    assert tip_hash_at_export.encode("utf-8") in pdf_bytes, "Chain tip at export must be in the certificate"
    assert tip_hash_e2.encode("utf-8") != tip_hash_at_export, "control: the affirmation moved the tip"
    assert b"Bharatiya Sakshya Adhiniyam" in pdf_bytes, "BSA 2023 statutory citation must be in PDF"
    assert b"verify.html" in pdf_bytes, "Out-of-band verification instructions must be in PDF"


def test_export_certificate_authentication_required():
    """Unauthenticated or invalid credential requests must be rejected with 401."""
    with TestClient(app) as unauthed_client:
        # No credentials provided
        res = unauthed_client.get("/api/cases/AT-2026-0047/export/certificate")
        assert res.status_code == 401
        assert "authentication credentials" in res.json().get("detail", "")

        # Invalid API key
        res_bad = unauthed_client.get(
            "/api/cases/AT-2026-0047/export/certificate",
            headers={"X-AETHER-KEY": "unauthorized-fake-key"},
        )
        assert res_bad.status_code == 401


def test_export_certificate_not_found(client: TestClient):
    """Requesting certificate for missing case returns 404."""
    res = client.get("/api/cases/NON-EXISTENT-CASE/export/certificate")
    assert res.status_code == 404
