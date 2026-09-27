import csv
import io
import json

import stix2

from app.services.export import build_csv, build_stix_bundle

CASE = {
    "evidence_id": "AT-2026-0047",
    "actor_name": "APT-091 (RedShark)",
    "aliases": ["ZeroTrace", "ShadowByte", "RedShark"],
    "origin_ip": "185.220.101.42",
    "geo": "Munich, Germany",
    "asn": "AS16276 OVH SAS",
    "pgp_fingerprint": "4D9E27BC918A4F02C73109AE2C5B88E140FA7D3C",
    "btc_root": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "confidence": 94.8,
    "seal_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

SCORING = {
    "engine": "naive_bayes_log_odds+dempster_shafer",
    "prior_probability": 0.1,
    "log_likelihood_ratio_total": 2.0,
    "conflict": {
        "conflict_mass": 0.0, "threshold": 0.6, "conflict_detected": False,
        "severity": "none", "applied_discount": 0.0,
    },
    "contributions": [
        {
            "indicator": "pgp_match", "category": "deterministic", "raw_value": "4D9E27BC",
            "stance": "supports", "likelihood_ratio": 20.0, "log_likelihood_ratio": 2.9957,
            "detail": "PGP key reuse", "share_pct": 75.0, "direction": "up",
        },
        {
            "indicator": "stylometry_similarity", "category": "probabilistic", "raw_value": 0.4,
            "stance": "supports", "likelihood_ratio": 1.57, "log_likelihood_ratio": 0.4511,
            "detail": "Prose stylometry", "share_pct": 25.0, "direction": "up",
        },
    ],
    "contradicting_evidence": [],
}


def test_bundle_round_trips_through_official_parser():
    """stix2.parse re-validates the entire bundle against the spec."""
    bundle = build_stix_bundle(CASE)
    parsed = stix2.parse(bundle.serialize(), allow_custom=False)
    assert parsed.type == "bundle"
    assert len(parsed.objects) == 10


def test_bundle_object_types():
    bundle = json.loads(build_stix_bundle(CASE).serialize())
    types = sorted({o["type"] for o in bundle["objects"]})
    assert types == ["identity", "indicator", "ipv4-addr", "relationship", "report", "threat-actor"]


def test_relationship_refs_resolve_inside_bundle():
    bundle = json.loads(build_stix_bundle(CASE).serialize())
    ids = {o["id"] for o in bundle["objects"]}
    for o in bundle["objects"]:
        if o["type"] == "relationship":
            assert o["source_ref"] in ids and o["target_ref"] in ids
        if o["type"] == "report":
            assert all(r in ids for r in o["object_refs"])


def test_actor_carries_evidence_id_and_seal():
    bundle = json.loads(build_stix_bundle(CASE).serialize())
    actor = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
    refs = {r["source_name"]: r for r in actor["external_references"]}
    assert refs["aether-evidence-id"]["external_id"] == "AT-2026-0047"
    assert refs["sha256-seal"]["description"] == CASE["seal_hash"]


CSV_HEADER = [
    "entity_type", "entity_value", "description", "source_stage", "confidence",
    "signature", "key_id", "likelihood_ratio", "log_likelihood_ratio",
    "contribution_pct", "stance",
]


def test_csv_has_bom_header_and_rows():
    out = build_csv(CASE)
    assert out.startswith("\ufeff")
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    assert rows[0] == CSV_HEADER
    assert all(len(r) == len(CSV_HEADER) for r in rows)
    flat = {c for r in rows for c in r}
    assert "185.220.101.42" in flat and CASE["seal_hash"] in flat


def test_csv_emits_one_row_per_scoring_indicator():
    scored = dict(CASE, scoring=SCORING)
    out = build_csv(scored)
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    indicators = [r for r in rows if r[0] == "scoring_indicator"]
    assert [r[1] for r in indicators] == ["pgp_match", "stylometry_similarity"]
    assert indicators[0][7] == "20.0"      # likelihood_ratio
    assert indicators[0][8] == "2.9957"    # log_likelihood_ratio
    assert indicators[0][9] == "75.0"      # contribution_pct
    assert indicators[0][10] == "supports"


def test_csv_flags_a_detected_conflict():
    scored = dict(CASE, scoring=dict(SCORING, conflict={
        "conflict_mass": 0.81, "threshold": 0.6, "conflict_detected": True,
        "severity": "high", "applied_discount": 0.75,
    }))
    out = build_csv(scored)
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    conflict_rows = [r for r in rows if r[0] == "scoring_conflict"]
    assert len(conflict_rows) == 1
    assert "CONFLICT DETECTED" in conflict_rows[0][2]
    assert conflict_rows[0][10] == "conflict"


def test_csv_defuses_formula_injection():
    evil = dict(CASE, aliases=["=HYPERLINK(\"http://evil\")", "+cmd|calc", "@SUM(A1)", "-2+3"])
    out = build_csv(evil)
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    alias_values = [r[1] for r in rows if r[0] == "alias"]
    assert all(v.startswith("'") for v in alias_values)
    assert not any(v[0] in "=+-@" for v in alias_values)


def test_stix_confidence_comes_from_the_calibrated_posterior():
    bundle = json.loads(build_stix_bundle(dict(CASE, confidence=72.4, scoring=SCORING)).serialize())
    actor = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
    assert actor["confidence"] == 72
    assert "Calibrated posterior 72%" in actor["description"]
    assert "log-LR total" in actor["description"]


def test_stix_actor_description_warns_when_conflict_was_detected():
    conflicted = dict(SCORING, conflict={
        "conflict_mass": 0.81, "threshold": 0.6, "conflict_detected": True, "severity": "high",
    })
    bundle = json.loads(build_stix_bundle(dict(CASE, scoring=conflicted)).serialize())
    actor = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
    assert "EVIDENCE CONFLICT" in actor["description"]
    assert "must not be presented as a clean attribution" in actor["description"]
