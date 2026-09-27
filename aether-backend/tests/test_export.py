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


def test_csv_has_bom_header_and_rows():
    out = build_csv(CASE)
    assert out.startswith("\ufeff")
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    assert rows[0] == ["entity_type", "entity_value", "description", "source_stage", "confidence", "signature", "key_id"]
    assert all(len(r) == 7 for r in rows)
    flat = {c for r in rows for c in r}
    assert "185.220.101.42" in flat and CASE["seal_hash"] in flat


def test_csv_defuses_formula_injection():
    evil = dict(CASE, aliases=["=HYPERLINK(\"http://evil\")", "+cmd|calc", "@SUM(A1)", "-2+3"])
    out = build_csv(evil)
    rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
    alias_values = [r[1] for r in rows if r[0] == "alias"]
    assert all(v.startswith("'") for v in alias_values)
    assert not any(v[0] in "=+-@" for v in alias_values)
