"""Test suite for Project AETHER New Investigation Workflow.

Verifies end-to-end:
1. POST /api/cases/investigate executes all 9 forensic modules.
2. Structured Evidence persistence with explicit provenance tags (LIVE_SOURCE, DEMO_DATA, SOURCE_UNAVAILABLE).
3. Evidentiary caveats disclaiming single-indicator identity proof.
4. Calibrated 0-100 attribution confidence calculation.
5. Dynamic 3D Entity Knowledge Graph generation.
6. Tamper-evident SHA-256 chain of custody logging and verification.
7. Case listing and investigation retrieval.
8. STIX 2.1 JSON and CSV matrix export for investigated cases.
"""

import json
import pytest
from app.services.custody import CustodyChain


def test_start_investigation_onion_target(client):
    """Test full investigation lifecycle on a darknet onion target."""
    payload = {
        "case_name": "Operation Chimera",
        "evidence_id": "AT-2026-0088",
        "actor_name": "UNC-3844",
        "target": "http://p4lx7e22kq6dreadmarket.onion",
        "target_type": "onion",
        "known_pgp": "4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C",
        "known_btc": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "mode": "demo",
    }

    r = client.post("/api/cases/investigate", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    # 1. Case record
    case = data["case"]
    assert case["evidence_id"] == "AT-2026-0088"
    assert case["actor_name"] == "UNC-3844"
    assert case["target_url"] == "http://p4lx7e22kq6dreadmarket.onion"
    assert case["origin_ip"] == "185.220.101.42"
    assert case["confidence"] > 75.0

    # 2. Structured Evidence records
    records = case["evidence_records"]
    assert len(records) >= 8
    types = {e["evidence_type"] for e in records}
    assert "FAVICON_HASH" in types
    assert "STYLOMETRY" in types
    assert "PGP_KEY" in types
    assert "ORIGIN_IP" in types
    assert "TLS_JARM" in types
    assert "BTC_WALLET" in types
    assert "DIURNAL_TIMEZONE" in types
    assert "VISUAL_SIMILARITY" in types

    # 3. Verify Provenance Labeling (Never silently simulate)
    for e in records:
        assert e["provenance"] in ["LIVE_SOURCE", "DEMO_DATA", "SOURCE_UNAVAILABLE", "STATIC_OSINT"]
        # Ensure evidentiary caveats exist on probabilistic/investigative indicators
        if e["evidence_type"] in ["FAVICON_HASH", "STYLOMETRY", "TLS_JARM", "DIURNAL_TIMEZONE", "VISUAL_SIMILARITY"]:
            assert "evidentiary_caveat" in e["metadata_json"]
            assert len(e["metadata_json"]["evidentiary_caveat"]) > 10

    # 4. Attribution Score
    attribution = data["attribution"]
    assert 0.0 <= attribution["confidence_score"] <= 100.0
    assert "confidence_tier" in attribution
    assert "breakdown" in attribution
    assert "judicial_admissibility" in attribution

    # 5. Dynamic Knowledge Graph
    graph = data["graph"]
    assert graph["node_count"] >= 6
    assert graph["edge_count"] >= 5
    assert len(graph["cypher_statements"]) > 0

    # 6. Custody Chain Verification
    custody_verif = data["custody_verification"]
    assert custody_verif["valid"] is True
    assert custody_verif["entry_count"] >= 6
    assert len(custody_verif["seal"]) == 64

    # 7. Timeline
    timeline = data["timeline"]
    assert len(timeline) >= 6
    assert timeline[0]["title"] == "Investigation Initiated"


def test_start_investigation_clearnet_ip(client):
    """Test investigation on a direct clearnet IP."""
    payload = {
        "case_name": "Operation Ironclad",
        "evidence_id": "AT-2026-0099",
        "actor_name": "ShadowByte",
        "target": "185.220.101.42",
        "target_type": "ip",
        "text_sample": "We operate automated payment processing for ransomware operations.",
        "mode": "auto",
    }

    r = client.post("/api/cases/investigate", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["case"]["evidence_id"] == "AT-2026-0099"
    assert data["case"]["origin_ip"] == "185.220.101.42"
    assert data["provenance_summary"]["demo_count"] > 0 or data["provenance_summary"]["live_count"] > 0


def test_list_cases_and_get_investigation(client):
    """Test listing all cases and retrieving investigation details for a specific case."""
    # First create via investigate
    client.post("/api/cases/investigate", json={
        "case_name": "Test Listing Case",
        "evidence_id": "AT-2026-0101",
        "actor_name": "TestActor",
        "target": "http://p4lx7e22kq6dreadmarket.onion",
        "target_type": "onion",
    })

    # Query list
    r_list = client.get("/api/cases")
    assert r_list.status_code == 200
    items = r_list.json()
    assert len(items) >= 1
    found = next((c for c in items if c["evidence_id"] == "AT-2026-0101"), None)
    assert found is not None
    assert found["evidence_count"] >= 8
    assert found["custody_count"] >= 6

    # Query investigation details
    r_detail = client.get("/api/cases/AT-2026-0101/investigation")
    assert r_detail.status_code == 200
    detail = r_detail.json()
    assert detail["case"]["evidence_id"] == "AT-2026-0101"
    assert detail["custody_verification"]["valid"] is True


def test_export_stix_and_csv_from_investigated_case(client):
    """Verify STIX 2.1 and CSV export generate valid bundles for investigated cases."""
    client.post("/api/cases/investigate", json={
        "case_name": "Export Validation Case",
        "evidence_id": "AT-2026-0102",
        "actor_name": "ExportActor",
        "target": "http://p4lx7e22kq6dreadmarket.onion",
        "target_type": "onion",
    })

    # STIX 2.1 Export
    r_stix = client.get("/api/cases/AT-2026-0102/export/stix")
    assert r_stix.status_code == 200
    stix_json = json.loads(r_stix.text)
    assert stix_json["type"] == "bundle"
    assert len(stix_json["objects"]) >= 5

    # CSV Export
    r_csv = client.get("/api/cases/AT-2026-0102/export/csv")
    assert r_csv.status_code == 200
    assert "evidence_id" in r_csv.text
    assert "AT-2026-0102" in r_csv.text
