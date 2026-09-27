"""Phase 5 — intel mode resolution and offline fixture determinism."""

import json
import os
from pathlib import Path

import pytest

from app.services.intel import (
    LiveProvider,
    MockProvider,
    canonicalize_target,
    get_intel_fixtures_dir,
    get_intel_provider,
    resolve_intel_mode,
)

FIXTURE_TARGET = "185.220.101.42"


@pytest.fixture(autouse=True)
def _clear_mode_env(monkeypatch):
    monkeypatch.delenv("AETHER_INTEL_MODE", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    yield


# --------------------------------------------------------------------------- #
# Mode resolution precedence
# --------------------------------------------------------------------------- #

def test_mode_defaults_to_mock_without_shodan_key(monkeypatch):
    monkeypatch.delenv("AETHER_INTEL_MODE", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert resolve_intel_mode() == "mock"


def test_mode_defaults_to_live_when_shodan_key_present(monkeypatch):
    monkeypatch.delenv("AETHER_INTEL_MODE", raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "live-key")
    assert resolve_intel_mode() == "live"


def test_env_var_overrides_presence_of_api_key(monkeypatch):
    monkeypatch.setenv("AETHER_INTEL_MODE", "mock")
    monkeypatch.setenv("SHODAN_API_KEY", "live-key")
    assert resolve_intel_mode() == "mock"


def test_explicit_argument_beats_env_var(monkeypatch):
    monkeypatch.setenv("AETHER_INTEL_MODE", "mock")
    assert resolve_intel_mode("live") == "live"


def test_explicit_argument_is_case_and_space_insensitive(monkeypatch):
    assert resolve_intel_mode("  LiVe ") == "live"
    assert resolve_intel_mode("MOCK") == "mock"


def test_invalid_mode_values_are_ignored_not_fatal(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "live-key")
    monkeypatch.setenv("AETHER_INTEL_MODE", "proxied-tor-only")
    assert resolve_intel_mode() == "live"

    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert resolve_intel_mode() == "mock"


def test_blank_env_var_does_not_force_a_mode(monkeypatch):
    monkeypatch.setenv("AETHER_INTEL_MODE", "   ")
    assert resolve_intel_mode() == "mock"


# --------------------------------------------------------------------------- #
# Provider selection
# --------------------------------------------------------------------------- #

def test_get_intel_provider_returns_mock_in_mock_mode(monkeypatch):
    monkeypatch.setenv("AETHER_INTEL_MODE", "mock")
    assert isinstance(get_intel_provider(), MockProvider)


def test_get_intel_provider_returns_live_in_live_mode(monkeypatch):
    monkeypatch.setenv("AETHER_INTEL_MODE", "live")
    monkeypatch.setenv("SHODAN_API_KEY", "live-key")
    assert isinstance(get_intel_provider(), LiveProvider)


def test_live_provider_never_falls_back_to_demo_data(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    result = LiveProvider().query_ip_intelligence(FIXTURE_TARGET)
    assert result["status"] == "SOURCE_UNAVAILABLE"
    assert "banners" not in result


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("  185.220.101.42  ", "185.220.101.42"),
        ("185.220.101.042", "185.220.101.42"),
        ("2001:0DB8:0000::1", "2001:db8::1"),
        ("EXAMPLE.Onion.", "example.onion"),
        ("Static-Assets-CDN-Metrics.xyz", "static-assets-cdn-metrics.xyz"),
    ],
)
def test_canonicalize_target(raw, expected):
    assert canonicalize_target(raw) == expected


def test_canonicalize_target_handles_empty_input():
    assert canonicalize_target("") == ""
    assert canonicalize_target(None) == ""


# --------------------------------------------------------------------------- #
# Fixture loading + determinism
# --------------------------------------------------------------------------- #

def test_fixtures_dir_exists_and_is_configurable(monkeypatch, tmp_path):
    assert get_intel_fixtures_dir().is_dir()

    monkeypatch.setenv("AETHER_INTEL_FIXTURES_DIR", str(tmp_path))
    assert get_intel_fixtures_dir() == tmp_path


def test_mock_provider_returns_expected_fields():
    provider = MockProvider()
    result = provider.query_ip_intelligence(FIXTURE_TARGET)

    assert result["status"] == "DEMO_DATA"
    assert result["mode"] == "mock"
    assert result["asn"] == "AS9009 M247 Europe"
    assert result["ports"] == [80, 443, 8080, 9050]
    assert result["favicon_mmh3"] == -129482710
    assert len(result["jarm"]) == 62
    assert result["geo"] == "Munich, Bavaria, Germany"
    assert result["hostnames"] == ["node-de-42.darknet-exit.org"]


def test_mock_provider_is_deterministic_across_instances():
    first = MockProvider().query_ip_intelligence(FIXTURE_TARGET)
    second = MockProvider().query_ip_intelligence(FIXTURE_TARGET)
    assert first == second


def test_mock_provider_canonicalizes_before_lookup():
    provider = MockProvider()
    assert (
        provider.query_ip_intelligence("185.220.101.042")
        == provider.query_ip_intelligence("185.220.101.42")
    )


def test_mock_provider_handles_onion_fixture():
    provider = MockProvider()
    result = provider.query_ip_intelligence("QZS5X3KQJ2HFP6LM7ONR4TUVCXA.EMAIL.ONION")
    assert result["status"] == "DEMO_DATA"
    assert result["org"] == "Hidden Service (Tor)"


def test_mock_provider_unknown_target_degrades_softly():
    result = MockProvider().query_ip_intelligence("203.0.113.99")

    assert result["status"] == "SOURCE_UNAVAILABLE"
    assert result["ports"] == []
    assert result["asn"] == "Unknown"
    assert "203.0.113.99" in result["message"]
    assert "AETHER_INTEL_MODE=mock" in result["message"]


def test_mock_provider_typed_accessors():
    provider = MockProvider()
    assert provider.query_favicon_hash(FIXTURE_TARGET) == -129482710
    assert provider.query_jarm(FIXTURE_TARGET).startswith("29d29d")
    assert provider.query_ct_domains(FIXTURE_TARGET) == [
        "darknet-exit.org",
        "node-de-42.darknet-exit.org",
    ]

    assert provider.query_favicon_hash("203.0.113.99") is None
    assert provider.query_jarm("203.0.113.99") is None
    assert provider.query_ct_domains("203.0.113.99") == []


def test_mock_provider_does_not_cache_across_mutated_files(tmp_path):
    fixture = tmp_path / "198.51.100.77.json"
    fixture.write_text(json.dumps({"asn": "AS-FIRST"}), encoding="utf-8")

    provider = MockProvider(fixtures_dir=tmp_path)
    assert provider.query_ip_intelligence("198.51.100.77")["asn"] == "AS-FIRST"

    fixture.write_text(json.dumps({"asn": "AS-SECOND"}), encoding="utf-8")
    assert MockProvider(fixtures_dir=tmp_path).query_ip_intelligence("198.51.100.77")["asn"] == "AS-SECOND"


def test_mock_provider_survives_corrupt_fixture(tmp_path, caplog):
    (tmp_path / "198.51.100.77.json").write_text("{not valid json", encoding="utf-8")
    result = MockProvider(fixtures_dir=tmp_path).query_ip_intelligence("198.51.100.77")
    assert result["status"] == "SOURCE_UNAVAILABLE"


def test_mock_provider_ignores_path_traversal_attempts(tmp_path):
    provider = MockProvider(fixtures_dir=tmp_path)
    result = provider.query_ip_intelligence("../../../../etc/passwd")
    assert result["status"] == "SOURCE_UNAVAILABLE"


def test_every_shipped_fixture_parses_and_has_required_fields():
    fixtures_dir = get_intel_fixtures_dir()
    fixtures = sorted(fixtures_dir.glob("*.json"))
    assert len(fixtures) >= 3, "expected a curated offline corpus of at least 3 targets"

    for path in fixtures:
        record = json.loads(path.read_text(encoding="utf-8"))
        for field in ("asn", "org", "ports", "geo", "jarm", "favicon_mmh3"):
            assert field in record, f"{path.name} missing required field '{field}'"
        assert len(record["jarm"]) == 62, f"{path.name} has a malformed JARM string"
        assert isinstance(record["ports"], list)
        assert isinstance(record["favicon_mmh3"], int)


def test_shipped_fixture_filenames_match_their_canonical_target():
    for path in get_intel_fixtures_dir().glob("*.json"):
        assert canonicalize_target(path.stem) == path.stem
