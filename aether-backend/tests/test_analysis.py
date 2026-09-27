"""Tests for the analytical services and endpoints in Project AETHER.

Covers stylometry cosine calculation, diurnal circadian sleep trough detection,
Bitcoin multi-input peel clustering, entity knowledge graph generation,
calibrated confidence scoring, and API integration.
"""

from fastapi.testclient import TestClient

from app.main import app
from app.services.diurnal import analyze_diurnal_activity, estimate_utc_offset, find_sleep_trough
from app.services.graph import build_default_case_graph, cluster_bitcoin_transactions
from app.services.scoring import calculate_calibrated_confidence
from app.services.stylometry import analyze_stylometry, compute_lexical_metrics, cosine_similarity, extract_char_ngrams


# =====================================================================
# 1. Stylometry Unit Tests
# =====================================================================

def test_stylometry_identical_text():
    text = "We provide high-grade cobalt strike beacons; delivery via PGP encrypted key exchange."
    result = analyze_stylometry(text, text)
    assert result["similarity_score"] == 1.0
    assert result["breakdown"]["char_3gram_cosine"] == 1.0
    assert result["breakdown"]["word_unigram_cosine"] == 1.0
    assert result["breakdown"]["word_bigram_cosine"] == 1.0


def test_stylometry_disjoint_text():
    text_a = "ransomware payload bitcoin ransom negotiation decryptor"
    text_b = "gardening organic tomatoes compost soil vegetables irrigation"
    result = analyze_stylometry(text_a, text_b)
    # Cosine similarity between completely disjoint vocabularies should be low
    assert result["similarity_score"] < 0.20
    assert result["shared_tokens_count"] == 0


def test_stylometry_lexical_metrics():
    sample = "Hello world! This is a test; let's verify sentence length and punctuation... Ok?"
    metrics = compute_lexical_metrics(sample)
    assert metrics["sentence_count"] == 3
    assert metrics["word_count"] > 10
    assert metrics["type_token_ratio"] > 0.0
    assert metrics["punctuation_counts"]["semicolons"] == 1
    assert metrics["punctuation_counts"]["exclamations"] == 1
    assert metrics["punctuation_counts"]["questions"] == 1
    assert metrics["punctuation_counts"]["ellipses"] == 1


# =====================================================================
# 2. Diurnal Timezone Unit Tests
# =====================================================================

def test_diurnal_sleep_trough_detection():
    # Active hours: 05:00 UTC to 21:00 UTC (16 hours active)
    # Inactive hours (sleep trough): 22:00 UTC to 04:00 UTC (6 hours inactive)
    timestamps = []
    for day in range(1, 10):
        for hour in range(5, 22):
            timestamps.append(f"2026-09-0{day}T{hour:02d}:15:00Z")

    result = analyze_diurnal_activity(timestamps, window_size=6)
    assert result["total_events"] == 9 * 17
    assert result["sleep_trough"]["events_in_trough"] == 0
    # Sleep trough starts around 22:00 or 23:00 UTC
    assert result["sleep_trough"]["start_utc"] in [22, 23]
    # Inferred timezone should be around UTC+3 / UTC+2.5 (Moscow/EET)
    assert result["estimated_timezone"]["offset_hours"] in [2.5, 3.0, 3.5]
    assert any("Moscow" in r or "CET" in r or "EET" in r for r in result["estimated_timezone"]["candidate_regions"])


def test_diurnal_empty_timestamps():
    result = analyze_diurnal_activity([])
    assert result["total_events"] == 0
    assert result["sleep_trough"] is None
    assert result["estimated_offset"] is None


# =====================================================================
# 3. Graph & Bitcoin Clustering Unit Tests
# =====================================================================

def test_bitcoin_multi_input_clustering():
    # tx1 inputs: addr_A, addr_B -> grouped
    # tx2 inputs: addr_B, addr_C -> merges addr_C into the same cluster
    # tx3 inputs: addr_X, addr_Y -> separate cluster
    txs = [
        {"txid": "tx1", "inputs": ["addr_A", "addr_B"], "outputs": [{"address": "out1", "amount": 0.5}]},
        {"txid": "tx2", "inputs": ["addr_B", "addr_C"], "outputs": [{"address": "out2", "amount": 0.4}]},
        {"txid": "tx3", "inputs": ["addr_X", "addr_Y"], "outputs": [{"address": "out3", "amount": 1.2}]},
    ]
    result = cluster_bitcoin_transactions(txs)
    assert result["cluster_count"] == 2
    clusters = result["clusters"]
    # One cluster has 3 addresses: A, B, C
    assert any(len(c) == 3 and "addr_A" in c and "addr_C" in c for c in clusters)
    # Another cluster has 2 addresses: X, Y
    assert any(len(c) == 2 and "addr_X" in c and "addr_Y" in c for c in clusters)


def test_entity_graph_and_cypher_export():
    graph = build_default_case_graph()
    graph_dict = graph.to_dict()
    assert graph_dict["case_id"] == "AT-2026-0047"
    assert graph_dict["node_count"] >= 5
    assert graph_dict["edge_count"] >= 5

    cypher = graph.to_cypher()
    assert len(cypher) >= 10
    assert any("MERGE (n:ThreatActor" in stmt for stmt in cypher)
    assert any("ROUTED_THROUGH" in stmt for stmt in cypher)


# =====================================================================
# 4. Calibrated Confidence Scoring Unit Tests
# =====================================================================

def test_calibrated_scoring_definitive():
    # Strong deterministic and AI signals with no contradictions
    det = {"pgp_match": 1.0, "origin_ip_match": 1.0, "btc_cluster_match": 0.90}
    ai = {"stylometry_similarity": 0.88, "diurnal_consistency": 0.85}
    res = calculate_calibrated_confidence(det, ai)
    assert res["confidence_score"] >= 0.90
    assert res["confidence_tier"] == "DEFINITIVE JUDICIAL ATTRIBUTION"


def test_calibrated_scoring_contradiction_deduction():
    # Strong signals but severe contradiction (conflicting PGP key)
    det = {"pgp_match": 1.0, "origin_ip_match": 0.90, "btc_cluster_match": 0.80}
    ai = {"stylometry_similarity": 0.85, "diurnal_consistency": 0.80}
    penalties = [{"name": "Conflicting PGP key published on Dread mirror", "penalty": 0.40}]

    baseline = calculate_calibrated_confidence(det, ai)
    res = calculate_calibrated_confidence(det, ai, contradictions=penalties)

    # A documented contradiction must (a) remove at least its stated penalty
    # from the posterior and (b) never be presented as a clean attribution.
    assert res["confidence_score"] <= baseline["confidence_score"] - 0.40
    assert res["breakdown"]["total_penalty"] == 0.40
    assert res["conflict"]["legacy_penalty_applied"] == 0.40
    assert res["confidence_tier"] == "CONTRADICTION DETECTED - EVIDENCE CONFLICT"
    # Below the definitive threshold even after a single 0.40 deduction.
    assert res["confidence_score"] < baseline["confidence_score"]


# =====================================================================
# 5. FastAPI Integration Endpoint Tests
# =====================================================================

def test_api_stylometry_endpoint(client):
    res = client.post("/api/analysis/stylometry", json={
        "text_a": "We operate high volume ransom payment gateways. Quick escrow.",
        "text_b": "We run high volume payment portals with fast escrow guarantees."
    })
    assert res.status_code == 200
    data = res.json()
    assert "similarity_score" in data
    assert "breakdown" in data
    assert data["similarity_score"] > 0.0


def test_api_diurnal_endpoint(client):
    res = client.post("/api/analysis/diurnal", json={
        "timestamps": [
            "2026-09-01T12:00:00Z",
            "2026-09-01T14:00:00Z",
            "2026-09-01T18:00:00Z",
            "2026-09-02T13:00:00Z",
        ],
        "window_size": 6
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] == 4
    assert len(data["histogram"]) == 24
    assert "sleep_trough" in data
    assert "estimated_timezone" in data


def test_api_graph_endpoint(client):
    res = client.post("/api/analysis/graph", json={"evidence_id": "AT-2026-0047"})
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == "AT-2026-0047"
    assert "nodes" in data
    assert "edges" in data
    assert "cypher_statements" in data


def test_api_score_endpoint(client):
    res = client.post("/api/analysis/score", json={
        "deterministic_signals": {"pgp_match": 1.0, "origin_ip_match": 0.95, "btc_cluster_match": 0.85},
        "probabilistic_signals": {"stylometry_similarity": 0.87, "diurnal_consistency": 0.80},
        "contradictions": []
    })
    assert res.status_code == 200
    data = res.json()
    assert "confidence_score" in data
    assert "confidence_tier" in data
    assert data["confidence_score"] > 0.85
