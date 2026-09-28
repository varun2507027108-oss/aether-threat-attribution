import csv
import io

import stix2

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


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_create_and_get_case(client):
    r = client.post("/api/cases", json=CASE_PAYLOAD)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["evidence_id"] == "AT-2026-0047"
    assert body["custody"] == []

    r2 = client.get("/api/cases/AT-2026-0047")
    assert r2.status_code == 200
    assert r2.json()["actor_name"] == "APT-091 (RedShark)"


def test_duplicate_case_rejected(client):
    client.post("/api/cases", json=CASE_PAYLOAD)
    r = client.post("/api/cases", json=CASE_PAYLOAD)
    assert r.status_code == 409


def test_missing_case_404(client):
    r = client.get("/api/cases/NOPE-0000")
    assert r.status_code == 404


def test_custody_entries_append_and_chain(client):
    client.post("/api/cases", json=CASE_PAYLOAD)

    e1 = client.post("/api/cases/AT-2026-0047/custody", json={"actor": "Analyst-01", "action": "Target acquired"})
    assert e1.status_code == 201
    e1_body = e1.json()
    assert e1_body["seq"] == 1
    assert e1_body["prev_hash"] == "0" * 64

    e2 = client.post("/api/cases/AT-2026-0047/custody", json={"actor": "Analyst-01", "action": "Recon completed"})
    e2_body = e2.json()
    assert e2_body["seq"] == 2
    assert e2_body["prev_hash"] == e1_body["entry_hash"]

    case = client.get("/api/cases/AT-2026-0047").json()
    assert len(case["custody"]) == 2


def test_verify_returns_valid_for_untouched_chain(client):
    client.post("/api/cases", json=CASE_PAYLOAD)
    for i in range(5):
        client.post("/api/cases/AT-2026-0047/custody", json={"actor": f"Actor-{i}", "action": f"Step {i}"})

    r = client.get("/api/cases/AT-2026-0047/verify")
    body = r.json()
    assert body["valid"] is True
    assert body["broken_at_seq"] is None
    assert body["entry_count"] == 5
    assert len(body["seal"]) == 64


def test_verify_detects_tampering_via_raw_sql(client):
    """Simulate an attacker editing a row directly at rest (bypassing the API),
    then confirm /verify catches it. This exercises the DB, not just the pure
    custody.py unit logic already covered elsewhere."""
    client.post("/api/cases", json=CASE_PAYLOAD)
    for i in range(4):
        client.post("/api/cases/AT-2026-0047/custody", json={"actor": f"Actor-{i}", "action": f"Step {i}"})

    from app.db import get_db
    from app.main import app as fastapi_app
    from app.models import Case, CustodyRow
    from sqlalchemy import select

    override = fastapi_app.dependency_overrides[get_db]
    db_gen = override()
    db = next(db_gen)
    case = db.execute(select(Case).where(Case.evidence_id == "AT-2026-0047")).scalar_one()
    row = db.execute(select(CustodyRow).where(CustodyRow.case_id == case.id, CustodyRow.seq == 2)).scalar_one()
    row.action = "TAMPERED"
    db.commit()

    r = client.get("/api/cases/AT-2026-0047/verify")
    body = r.json()
    assert body["valid"] is False
    assert body["broken_at_seq"] == 2


def test_export_stix_is_valid_and_downloadable(client):
    client.post("/api/cases", json=CASE_PAYLOAD)
    client.post("/api/cases/AT-2026-0047/custody", json={"actor": "Analyst-01", "action": "Sealed"})

    client.post("/api/cases/AT-2026-0047/confirm-export")
    r = client.get("/api/cases/AT-2026-0047/export/stix")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert "aether_stix_bundle_AT-2026-0047.json" in r.headers["content-disposition"]

    parsed = stix2.parse(r.text, allow_custom=False)
    assert parsed.type == "bundle"
    actor = next(o for o in parsed.objects if o.type == "threat-actor")
    assert actor.name == "APT-091 (RedShark)"


def test_export_csv_is_downloadable_and_well_formed(client):
    client.post("/api/cases", json=CASE_PAYLOAD)

    client.post("/api/cases/AT-2026-0047/confirm-export")
    r = client.get("/api/cases/AT-2026-0047/export/csv")
    assert r.status_code == 200
    assert "aether_attribution_matrix_AT-2026-0047.csv" in r.headers["content-disposition"]

    text = r.text
    assert text.startswith("\ufeff")
    rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
    assert rows[0][0] == "entity_type"
    assert any("185.220.101.42" in row for row in rows)


def test_export_404_for_unknown_case(client):
    assert client.get("/api/cases/NOPE/export/stix").status_code == 404
    assert client.get("/api/cases/NOPE/export/csv").status_code == 404


def test_seal_changes_after_new_custody_entry(client):
    client.post("/api/cases", json=CASE_PAYLOAD)
    client.post("/api/cases/AT-2026-0047/confirm-export")
    seal_before = client.get("/api/cases/AT-2026-0047/export/csv").text
    client.post("/api/cases/AT-2026-0047/custody", json={"actor": "Analyst-01", "action": "New evidence added"})
    client.post("/api/cases/AT-2026-0047/confirm-export")
    seal_after = client.get("/api/cases/AT-2026-0047/export/csv").text
    assert seal_before != seal_after  # seal_hash row differs because the chain changed
