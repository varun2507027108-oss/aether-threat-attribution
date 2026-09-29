"""Regression tests: honest provenance, integer audit-log case IDs, stored-result retrieval."""
HARDCODED = {"FAVICON_HASH", "STYLOMETRY", "PGP_KEY", "ORIGIN_IP", "BTC_WALLET"}
BODY = {
    "case_name": "Honesty Case",
    "evidence_id": "AT-2026-0202",
    "actor_name": "TestActor",
    "target": "http://p4lx7e22kq6dreadmarket.onion",
    "target_type": "onion",
    "mode": "demo",
    "text_sample": "some supplied text " * 20,
    "known_pgp": "4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C",
    "known_btc": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
}


def test_hardcoded_modules_never_labelled_live(client):
    r = client.post("/api/cases/investigate?sync=true", json=BODY)
    assert r.status_code == 200
    for e in r.json()["case"]["evidence_records"]:
        if e["evidence_type"] in HARDCODED:
            assert e["provenance"] == "DEMO_DATA", e["evidence_type"]


def test_pgp_forum_reuse_not_fabricated(client):
    r = client.post("/api/cases/investigate?sync=true", json=BODY)
    pgp = next(e for e in r.json()["case"]["evidence_records"] if e["evidence_type"] == "PGP_KEY")
    assert pgp["metadata_json"]["cross_forum_reuse"] == []


def test_audit_log_case_id_is_integer_pk(client):
    client.post("/api/cases/investigate?sync=true", json=BODY)
    logs = client.get("/api/audit-logs").json()
    starts = [l for l in logs if l["action"] == "START_INVESTIGATION"]
    assert starts and all(isinstance(l["case_id"], int) for l in starts)


def test_case_view_reads_stored_result_without_rerun(client):
    first = client.post("/api/cases/investigate?sync=true", json=BODY).json()
    before = len(client.get("/api/cases/AT-2026-0202").json()["custody"])
    second = client.get("/api/cases/AT-2026-0202/investigation")
    assert second.status_code == 200
    assert second.json()["attribution"]["confidence_score"] == first["attribution"]["confidence_score"]
    assert len(client.get("/api/cases/AT-2026-0202").json()["custody"]) == before


def test_case_view_404_without_snapshot(client):
    client.post("/api/cases", json={
        "evidence_id": "AT-2026-0303", "actor_name": "X", "aliases": [], "origin_ip": "", "geo": "",
        "asn": "", "pgp_fingerprint": "", "btc_root": "", "confidence": 0.0, "onion_url": "", "status": "ACTIVE",
    })
    assert client.get("/api/cases/AT-2026-0303/investigation").status_code == 404
