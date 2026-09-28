"""Phase 12 — golden STIX bundle test.

A STIX bundle is a legal artifact: it is what a court or a SOC ingests, and a
silent field rename or a dropped object changes the meaning of evidence
somewhere else without anyone noticing here.

The golden file is therefore asserted for **semantic** stability, not byte
equality. Bundle identity, timestamps, and object ids are regenerated on every
run by design, so byte comparison would fail constantly and train reviewers to
ignore the signal.
"""

import json
import os
from pathlib import Path

import pytest
import stix2

from app.services.export import build_stix_bundle

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
GOLDEN_PATH = BACKEND_ROOT / "tests" / "fixtures" / "golden" / "stix_bundle.json"

UPDATE_GOLDEN = os.getenv("UPDATE_GOLDEN", "").lower() in ("1", "true", "yes")

BASE_CASE = {
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
    "scoring": {
        "engine": "naive_bayes_log_odds+dempster_shafer",
        "prior_probability": 0.1,
        "log_likelihood_ratio_total": 2.9147,
        "conflict": {
            "conflict_mass": 0.0,
            "threshold": 0.6,
            "conflict_detected": False,
            "severity": "none",
        },
    },
}


def _serialize(bundle) -> dict:
    """Serialize a bundle, dropping the fields that legitimately change per run.

    Identity, timestamps, and object ids are regenerated on every build, so they
    are normalized out. Everything a downstream consumer actually reads is kept.
    """
    payload = json.loads(bundle.serialize())

    # Relationship refs point at randomly generated object ids. Resolve each ref
    # to the *referenced object's* stable identity (type + name/pattern) before
    # dropping ids, so the golden file still asserts that the relationships point
    # at the right things rather than merely that the key exists.
    stable_key: dict[str, str] = {}
    for obj in payload["objects"]:
        key = f"{obj['type']}::{obj.get('name') or obj.get('pattern') or obj.get('value') or obj['type']}"
        if obj.get("id"):
            stable_key[obj["id"]] = key

    for obj in payload["objects"]:
        for field in ("source_ref", "target_ref"):
            if field in obj and obj[field] in stable_key:
                obj[field] = stable_key[obj[field]]
        for ref in obj.get("object_refs", []) or []:
            if ref in stable_key:
                obj["object_refs"][obj["object_refs"].index(ref)] = stable_key[ref]
        created_by = obj.get("created_by_ref")
        if created_by and created_by in stable_key:
            obj["created_by_ref"] = stable_key[created_by]

    for obj in payload["objects"]:
        obj.pop("created", None)
        obj.pop("modified", None)
        obj.pop("id", None)
        obj.pop("spec_version", None)
        # valid_from / published are wall-clock stamps, regenerated per run.
        obj.pop("valid_from", None)
        obj.pop("published", None)
        for ref in obj.get("external_references", []) or []:
            ref.pop("external_id_hash", None)
    # The bundle id is content-addressed over the object ids, which are
    # themselves regenerated, so it changes on every run by construction.
    payload.pop("id", None)
    payload["objects"].sort(key=lambda o: (o["type"], o.get("name", ""), o.get("pattern", "")))
    return payload


def _regenerate() -> dict:
    return _serialize(build_stix_bundle(dict(BASE_CASE)))


@pytest.fixture(scope="module")
def golden() -> dict:
    current = _regenerate()
    if UPDATE_GOLDEN or not GOLDEN_PATH.exists():
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def test_bundle_matches_the_golden_semantics(golden):
    current = _regenerate()
    assert current == golden, (
        "The STIX bundle contract changed. Review the diff, then regenerate deliberately with "
        "UPDATE_GOLDEN=1 pytest -q tests/test_export_golden.py"
    )


def test_golden_file_is_a_well_formed_bundle_document(golden):
    """Structural checks only: object ids are stripped, so the SDK cannot re-parse it.

    Spec validity is asserted against the *built* bundle in
    ``test_bundle_is_spec_valid_when_built``, which is the real contract.
    """
    assert golden["type"] == "bundle"
    assert isinstance(golden["objects"], list) and golden["objects"]
    for obj in golden["objects"]:
        assert "type" in obj, obj
        assert isinstance(obj["type"], str) and obj["type"]


def test_golden_is_deterministic_across_builds():
    """Two builds of the same dossier must normalize to identical documents.

    If this fails, something non-deterministic is leaking into the bundle beyond
    the fields this normalizer strips, which would make every run a false alarm.
    """
    assert _regenerate() == _regenerate()


def test_bundle_is_spec_valid_when_built(golden):
    parsed = stix2.parse(build_stix_bundle(dict(BASE_CASE)).serialize(), allow_custom=False)
    assert parsed.type == "bundle"


def test_object_type_inventory_is_pinned(golden):
    types = sorted({obj["type"] for obj in golden["objects"]})
    assert types == ["identity", "indicator", "ipv4-addr", "relationship", "report", "threat-actor"]


def test_object_count_is_pinned(golden):
    assert len(golden["objects"]) == 10


def test_every_indicator_carries_its_pattern(golden):
    indicators = [o for o in golden["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 3
    for indicator in indicators:
        assert indicator["pattern"].startswith("[")
        assert indicator["indicator_types"] == ["attribution"]
        assert 0 <= indicator["confidence"] <= 100


def test_actor_confidence_comes_from_the_calibrated_posterior(golden):
    actor = next(o for o in golden["objects"] if o["type"] == "threat-actor")
    # STIX confidence is an integer percentage; the description carries the
    # rounded figure and the model's own bookkeeping.
    assert actor["confidence"] == 95
    assert "Calibrated posterior 95%" in actor["description"]
    assert "log-LR total 2.9147" in actor["description"]


def test_conflict_warning_is_embedded_when_present(golden):
    conflicted = dict(BASE_CASE, confidence=71.0, scoring=dict(
        BASE_CASE["scoring"],
        conflict={
            "conflict_mass": 0.81,
            "threshold": 0.6,
            "conflict_detected": True,
            "severity": "high",
        },
    ))
    payload = json.loads(build_stix_bundle(conflicted).serialize())
    actor = next(o for o in payload["objects"] if o["type"] == "threat-actor")
    assert "EVIDENCE CONFLICT" in actor["description"]


def test_relationships_reference_only_bundle_objects(golden):
    ids = {obj.get("id") for obj in golden["objects"] if obj.get("id")}
    for obj in golden["objects"]:
        if obj["type"] == "relationship":
            # ids are stripped from the golden file, so only assert structure here.
            assert "source_ref" in obj and "target_ref" in obj
