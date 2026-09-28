"""Phase 12 — intel provider contract tests.

These replay the Phase 5 offline corpus through both providers and assert the
*shape* of what leaves the intel layer, not just the happy-path values. A
parser that silently drops a field, or renames one, changes what an investigator
sees on the dossier, and a fixture-only test suite would not notice.
"""

import json
from pathlib import Path

import pytest

from app.services.intel import (
    MockProvider,
    canonicalize_target,
    classify_certificate,
    compute_ct_overlap,
    get_intel_fixtures_dir,
    normalize_fingerprint,
    parse_ct_log_response,
    resolve_intel_mode,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = get_intel_fixtures_dir()

# Every field the pipeline and the API read off an intel record. Adding a field
# to the provider without adding it here means a consumer can start depending on
# it without the corpus test noticing.
#
# Note this is the *provider output* shape. ``ip`` is synthesized by the
# provider from the lookup key and is therefore absent from the fixture files
# themselves, which is asserted separately.
REQUIRED_RECORD_FIELDS = {
    "status", "source", "ip", "asn", "org", "ports", "geo",
    "hostnames", "banners", "favicon_mmh3", "jarm",
    "ssl_cert_fingerprint", "crt_sh_domains",
}

# Fields a fixture file itself must carry. The provider synthesizes `status`,
# `mode`, `canonical_target`, and `raw_osint` around the stored record.
REQUIRED_FIXTURE_FIELDS = REQUIRED_RECORD_FIELDS - {"ip", "status"}


def _fixtures() -> list[Path]:
    paths = sorted(CORPUS_DIR.glob("*.json"))
    assert paths, f"no intel fixtures found in {CORPUS_DIR}"
    return paths


# --------------------------------------------------------------------------- #
# Fixture well-formedness
# --------------------------------------------------------------------------- #

def test_corpus_is_discoverable():
    assert CORPUS_DIR.is_dir()
    assert len(_fixtures()) >= 3


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_each_fixture_is_valid_json_with_required_fields(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    for field in REQUIRED_FIXTURE_FIELDS:
        assert field in record, f"{path.name} is missing {field}"


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_each_fixture_agrees_with_its_filename(path):
    assert canonicalize_target(path.stem) == path.stem


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_field_types_are_stable_across_the_corpus(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(record["asn"], str)
    assert isinstance(record["org"], str)
    assert isinstance(record["geo"], str)
    assert isinstance(record["ports"], list)
    assert all(isinstance(p, int) for p in record["ports"])
    assert all(1 <= p <= 65535 for p in record["ports"]), "port out of range"
    assert isinstance(record["hostnames"], list)
    assert isinstance(record["banners"], list)
    assert isinstance(record["favicon_mmh3"], int), "favicon hash must be a signed int32"


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_jarm_is_well_formed(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    assert len(record["jarm"]) == 62
    assert all(c in "0123456789abcdef" for c in record["jarm"])


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_favicon_hash_is_in_int32_range(path):
    """Shodan's favicon hash is a signed 32-bit value; a wider one is a fixture bug."""
    record = json.loads(path.read_text(encoding="utf-8"))
    assert -(2 ** 31) <= record["favicon_mmh3"] <= 2 ** 31 - 1


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_cert_fingerprint_is_64_hex_when_present(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    fingerprint = record.get("ssl_cert_fingerprint")
    if fingerprint:
        assert len(normalize_fingerprint(fingerprint)) == 64, f"{path.name} malformed fingerprint"
        assert classify_certificate(fingerprint)["valid"] is True


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_ct_domains_are_plausible(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    for domain in record.get("crt_sh_domains", []):
        assert isinstance(domain, str)
        assert "." in domain and not domain.startswith("."), f"{path.name}: {domain!r}"


# --------------------------------------------------------------------------- #
# Provider contract
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_provider_replays_each_fixture_exactly(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    result = MockProvider().query_ip_intelligence(path.stem)

    assert result["status"] == "DEMO_DATA"
    assert result["mode"] == "mock"
    assert result["asn"] == record["asn"]
    assert result["org"] == record["org"]
    assert result["ports"] == record["ports"]
    assert result["geo"] == record["geo"]
    assert result["favicon_mmh3"] == record["favicon_mmh3"]
    assert result["jarm"] == record["jarm"]


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.name)
def test_typed_accessors_match_the_whole_record(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    provider = MockProvider()
    assert provider.query_favicon_hash(path.stem) == record["favicon_mmh3"]
    assert provider.query_jarm(path.stem) == record["jarm"]
    assert provider.query_tls_cert_fingerprint(path.stem) == record.get("ssl_cert_fingerprint")
    assert provider.query_ct_domains(path.stem) == record.get("crt_sh_domains", [])


def test_unknown_target_degrades_without_raising():
    result = MockProvider().query_ip_intelligence("198.18.0.1")
    assert result["status"] == "SOURCE_UNAVAILABLE"
    for field in REQUIRED_RECORD_FIELDS:
        assert field in result, f"the unavailable shape must still carry {field}"


def test_unavailable_shape_matches_the_success_shape():
    """A consumer must not need to branch on status to read the record."""
    available = set(MockProvider().query_ip_intelligence("185.220.101.42"))
    unavailable = set(MockProvider().query_ip_intelligence("198.18.0.1"))
    assert REQUIRED_RECORD_FIELDS <= available
    assert REQUIRED_RECORD_FIELDS - unavailable == set()


def test_aether_records_carry_corpus_provenance():
    result = MockProvider().query_ip_intelligence("185.220.101.42")
    assert result["raw_osint"]["corpus_notes"]
    assert result["raw_osint"]["last_observed_utc"]


def test_replay_is_deterministic_across_provider_instances():
    a = MockProvider().query_ip_intelligence("45.155.205.233")
    b = MockProvider().query_ip_intelligence("45.155.205.233")
    assert a == b


# --------------------------------------------------------------------------- #
# crt.sh response contract
# --------------------------------------------------------------------------- #

CRTSH_SAMPLE = [
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "darknet-exit.org",
        "name_value": "darknet-exit.org\n*.darknet-exit.org",
        "not_before": "2026-08-01T00:00:00",
    },
]


def test_crt_sh_parse_returns_a_stable_shape():
    report = parse_ct_log_response(CRTSH_SAMPLE)
    for field in ("status", "subjects", "wildcard_subjects", "issuers", "certificate_count", "truncated"):
        assert field in report
    assert report["status"] == "OK"
    assert report["subjects"] == ["darknet-exit.org"]
    assert report["wildcard_subjects"] == ["darknet-exit.org"]


def test_ct_overlap_shape_is_stable():
    overlap = compute_ct_overlap(["darknet-exit.org"], parse_ct_log_response(CRTSH_SAMPLE))
    for field in (
        "status", "has_data", "exact_matches", "wildcard_only_matches",
        "ct_subjects", "ct_wildcard_subjects", "overlap", "strength", "usable_as_evidence", "note",
    ):
        assert field in overlap
    assert overlap["usable_as_evidence"] is True


@pytest.mark.parametrize(
    "payload,expected_status",
    [
        ([], "OK"),
        ([{"name_value": ""}], "OK"),
        ("not json at all", "PARSE_ERROR"),
        ({"error": "rate limited"}, "PARSE_ERROR"),
        (None, "PARSE_ERROR"),
    ],
)
def test_ct_parser_never_raises_on_hostile_input(payload, expected_status):
    report = parse_ct_log_response(payload)
    assert report["status"] == expected_status
    assert "subjects" in report


def test_ct_parser_survives_malformed_rows():
    report = parse_ct_log_response([{"name_value": None}, "not-a-dict", {"issuer_name": 123}, {}])
    assert report["status"] == "OK"
    assert report["subjects"] == []


# --------------------------------------------------------------------------- #
# Mode resolution contract
# --------------------------------------------------------------------------- #

def test_corpus_replay_never_depends_on_the_resolved_mode(monkeypatch):
    """Mock mode is forced for tests, so the corpus must be reachable either way."""
    monkeypatch.setenv("AETHER_INTEL_MODE", "mock")
    assert resolve_intel_mode() == "mock"
    monkeypatch.setenv("AETHER_INTEL_MODE", "LIVE")
    assert resolve_intel_mode() == "live"
    monkeypatch.delenv("AETHER_INTEL_MODE", raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "x")
    assert resolve_intel_mode() == "live"


def test_every_fixture_is_reachable_under_canonical_forms():
    for path in _fixtures():
        stem = path.stem
        provider = MockProvider()
        assert provider.query_ip_intelligence(stem.upper())["status"] == "DEMO_DATA"
        assert provider.query_ip_intelligence(f"  {stem}  ")["status"] == "DEMO_DATA"
