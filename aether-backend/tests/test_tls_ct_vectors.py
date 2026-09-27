"""Phase 8 — TLS certificate fingerprinting and Certificate Transparency vector."""

import json

import pytest

from app.security import (
    ALLOWED_EXTERNAL_INTEL_HOSTS,
    is_allowed_external_intel_url,
)
from app.services.intel import (
    CT_LOG_TTL_SECONDS,
    MockProvider,
    build_ct_log_url,
    classify_certificate,
    compute_ct_overlap,
    match_certificate_fingerprint,
    normalize_fingerprint,
    parse_ct_log_response,
    query_certificate_transparency,
    resolve_tls_fingerprint,
)

# A real, non-commodity self-signed certificate fingerprint from the corpus.
UNIQUE_FP = "b81d4e0c927fa3650e14b7c8d2936f05ca7149be230cd86f5a3710be984c7d2f"
COMMODITY_FP = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    for var in ("AETHER_ACTIVE_PROBE_ENABLED", "AETHER_TOR_SOCKS_URL", "AETHER_INTEL_MODE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AETHER_INTEL_MODE", "mock")


# --------------------------------------------------------------------------- #
# Fingerprint normalization
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw",
    [
        UNIQUE_FP,
        UNIQUE_FP.upper(),
        ":".join(UNIQUE_FP[i:i + 2] for i in range(0, len(UNIQUE_FP), 2)),          # OpenSSL per-byte
        ":".join(UNIQUE_FP[i:i + 16] for i in range(0, len(UNIQUE_FP), 16)),          # Shodan 16-byte groups
        f"SHA256:{UNIQUE_FP}",
        f"sha-256={':'.join(UNIQUE_FP[i:i + 2] for i in range(0, len(UNIQUE_FP), 2))}",
        f"  {UNIQUE_FP}  ",
    ],
)
def test_normalize_fingerprint_accepts_every_real_world_shape(raw):
    assert normalize_fingerprint(raw) == UNIQUE_FP


def test_normalize_fingerprint_handles_empty_and_garbage():
    assert normalize_fingerprint("") == ""
    assert normalize_fingerprint(None) == ""
    # Garbage is reduced to whatever hex characters it happens to contain; the
    # 64-character length check in classify_certificate is what rejects it.
    assert len(normalize_fingerprint("not-a-hash")) != 64
    assert classify_certificate("not-a-hash")["valid"] is False


# --------------------------------------------------------------------------- #
# Certificate classification
# --------------------------------------------------------------------------- #

def test_unique_self_signed_certificate_is_usable_evidence():
    result = classify_certificate(UNIQUE_FP, subject="CN=market-node, O=RedShark, OU=self-signed")
    assert result["valid"] is True
    assert result["commodity"] is False
    assert result["usable_as_evidence"] is True
    assert result["uniqueness"] == "high"


def test_commodity_certificate_is_excluded_from_evidence():
    result = classify_certificate(COMMODITY_FP, subject="CN=example.com, O=Let's Encrypt, C=US")
    assert result["commodity"] is True
    assert result["usable_as_evidence"] is False
    assert result["commodity_marker"] == "let's encrypt"
    assert "excluded from attribution" in result["note"]


@pytest.mark.parametrize("issuer", ["cPanel, Inc.", "Plesk", "Cloudflare Inc", "Amazon RSA 2048 M01", "DigiCert Inc"])
def test_known_commodity_issuers_are_all_recognised(issuer):
    assert classify_certificate(COMMODITY_FP, subject=f"CN=host, O={issuer}")["usable_as_evidence"] is False


def test_malformed_fingerprint_is_rejected():
    result = classify_certificate("abc123")
    assert result["valid"] is False
    assert "64 hex characters" in result["error"]


# --------------------------------------------------------------------------- #
# Fingerprint matching
# --------------------------------------------------------------------------- #

def test_unique_fingerprint_match_reports_the_candidate():
    result = match_certificate_fingerprint(
        UNIQUE_FP, {"suspect-A-mirror": UNIQUE_FP, "unrelated": "ff" * 32}
    )
    assert result["matched"] is True
    assert result["candidate"] == "suspect-A-mirror"
    assert result["strength"] == "moderate"
    assert result["classification"]["usable_as_evidence"] is True


def test_self_signed_match_is_reported_as_high_strength():
    result = match_certificate_fingerprint(
        UNIQUE_FP, {"mirror": UNIQUE_FP}, subject="CN=market-node, O=RedShark"
    )
    assert result["strength"] == "high"


def test_commodity_match_is_superseded_not_counted():
    """The whole point: a shared CA certificate must not attribute anybody."""
    result = match_certificate_fingerprint(
        UNIQUE_FP, {"innocent-host": UNIQUE_FP}, subject="CN=host, O=Let's Encrypt"
    )
    assert result["matched"] is False
    assert result["reason"] == "fingerprint_matches_but_certificate_is_commodity"
    assert result["superseded_by"] == ["innocent-host"]
    assert result["note"]


def test_no_match_is_reported_cleanly():
    result = match_certificate_fingerprint(UNIQUE_FP, {"other": "ff" * 32})
    assert result["matched"] is False
    assert result["reason"] == "no_candidate_match"


def test_malformed_target_fingerprint_short_circuits():
    result = match_certificate_fingerprint("nope", {"x": UNIQUE_FP})
    assert result["matched"] is False
    assert "64 hex characters" in result["reason"]


def test_candidate_fingerprints_are_normalized_before_comparison():
    result = match_certificate_fingerprint(
        UNIQUE_FP, {"shodan-style": UNIQUE_FP.upper().replace("", "")}
    )
    assert result["matched"] is True


def test_multiple_candidates_are_all_listed():
    other = "cc" * 32
    result = match_certificate_fingerprint(UNIQUE_FP, {"a": UNIQUE_FP, "b": other})
    assert result["matched"] is True
    assert result["candidate"] == "a"
    assert result["additional_matches"] == []


# --------------------------------------------------------------------------- #
# Resolution honours OPSEC policy
# --------------------------------------------------------------------------- #

def test_passive_by_default_uses_stored_telemetry():
    result = resolve_tls_fingerprint("45.155.205.233", candidates={})
    assert result["active_probe_conducted"] is False
    assert result["routed_via_tor"] is False
    assert result["status"] == "STORED_TELEMETRY"
    assert "OPSEC policy" in result["opsec_note"]


def test_active_probe_without_tor_is_refused(monkeypatch):
    monkeypatch.setenv("AETHER_ACTIVE_PROBE_ENABLED", "true")
    monkeypatch.delenv("AETHER_TOR_SOCKS_URL", raising=False)
    result = resolve_tls_fingerprint("45.155.205.233", candidates={})
    assert result["status"] == "probe_skipped_no_tor"
    assert result["active_probe_conducted"] is False
    assert "no active probe was attempted" in result["error"]


def test_active_probe_with_tor_is_routed_through_isolated_circuit(monkeypatch):
    monkeypatch.setenv("AETHER_ACTIVE_PROBE_ENABLED", "true")
    monkeypatch.setenv("AETHER_TOR_SOCKS_URL", "socks5://tor:9050")
    result = resolve_tls_fingerprint("45.155.205.233", candidates={})
    assert result["active_probe_conducted"] is True
    assert result["routed_via_tor"] is True
    assert "aether-tls-fingerprint" in result["tor_proxy_used"]


def test_resolution_reports_unavailable_when_no_fingerprint_is_known():
    result = resolve_tls_fingerprint("203.0.113.99", candidates={})
    assert result["status"] == "SOURCE_UNAVAILABLE"
    assert result["fingerprint"] is None


def test_resolution_matches_against_the_offline_corpus():
    corpus = MockProvider().query_ip_intelligence("45.155.205.233")
    result = resolve_tls_fingerprint(
        "45.155.205.233", candidates={"known-c2-cluster": corpus["ssl_cert_fingerprint"]}
    )
    assert result["status"] == "STORED_TELEMETRY"
    assert result["match"]["matched"] is True
    assert result["match"]["candidate"] == "known-c2-cluster"


# --------------------------------------------------------------------------- #
# crt.sh URL construction and the outbound allowlist
# --------------------------------------------------------------------------- #

def test_ct_url_targets_crt_sh_over_https():
    url = build_ct_log_url("example.com")
    assert url.startswith("https://crt.sh/?q=")
    assert "example.com" in url
    assert "&output=json" in url


def test_ct_url_encodes_the_query():
    url = build_ct_log_url("a b.com&evil=1")
    assert " " not in url
    assert "&evil" not in url.split("output=")[0].replace("&output", "")


def test_ct_url_rejects_empty_domain():
    with pytest.raises(ValueError):
        build_ct_log_url("  ")


@pytest.mark.parametrize("host", sorted(ALLOWED_EXTERNAL_INTEL_HOSTS))
def test_allowlist_permits_its_own_hosts(host):
    safe, reason = is_allowed_external_intel_url(f"https://{host}/path")
    assert safe is True, reason


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/?q=x",
        "https://crt.sh.evil.com/",
        "https://evil.com/crt.sh",
        "http://crt.sh/",            # plaintext is refused
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://localhost:8000/docs",
        "file:///etc/passwd",
        "",
    ],
)
def test_allowlist_refuses_everything_else(url):
    safe, reason = is_allowed_external_intel_url(url)
    assert safe is False
    assert reason


def test_allowlist_requires_https_even_for_an_allowed_host():
    safe, reason = is_allowed_external_intel_url("http://crt.sh")
    assert safe is False
    assert "https" in reason


# --------------------------------------------------------------------------- #
# crt.sh response parsing
# --------------------------------------------------------------------------- #

CRTSH_FIXTURE = [
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "darknet-exit.org",
        "name_value": "darknet-exit.org\n*.darknet-exit.org\nnode-de-42.darknet-exit.org",
        "not_before": "2026-08-01T00:00:00",
    },
    {
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "login-paypal-secure.xyz",
        "name_value": "login-paypal-secure.xyz",
        "not_before": "2026-08-14T12:00:00",
    },
]


def test_parses_subjects_and_separates_wildcards():
    report = parse_ct_log_response(CRTSH_FIXTURE)
    assert report["status"] == "OK"
    assert report["subjects"] == ["darknet-exit.org", "login-paypal-secure.xyz", "node-de-42.darknet-exit.org"]
    assert report["wildcard_subjects"] == ["darknet-exit.org"]
    assert report["certificate_count"] == 2
    assert report["earliest_not_before"] == "2026-08-01T00:00:00"
    assert report["latest_not_before"] == "2026-08-14T12:00:00"


def test_parses_a_json_string_payload():
    assert parse_ct_log_response(json.dumps(CRTSH_FIXTURE))["status"] == "OK"


def test_invalid_json_is_reported_not_raised():
    report = parse_ct_log_response("<html>502 Bad Gateway</html>")
    assert report["status"] == "PARSE_ERROR"
    assert report["subjects"] == []


def test_non_array_payload_is_reported():
    report = parse_ct_log_response({"error": "rate limited"})
    assert report["status"] == "PARSE_ERROR"
    assert "array" in report["error"]


def test_empty_log_is_a_valid_empty_report():
    report = parse_ct_log_response([])
    assert report["status"] == "OK"
    assert report["subjects"] == []


def test_oversized_log_is_truncated_flagged():
    report = parse_ct_log_response([{"name_value": f"h{i}.example.com"} for i in range(600)])
    assert report["truncated"] is True
    assert report["certificate_count"] == 600
    assert len(report["subjects"]) == 500


# --------------------------------------------------------------------------- #
# Overlap computation
# --------------------------------------------------------------------------- #

def test_exact_overlap_is_strong_evidence():
    overlap = compute_ct_overlap(["darknet-exit.org"], parse_ct_log_response(CRTSH_FIXTURE))
    assert overlap["usable_as_evidence"] is True
    assert overlap["strength"] == "strong"
    assert overlap["exact_matches"] == ["darknet-exit.org"]
    assert "1 exact subject match" in overlap["note"]


def test_wildcard_only_is_not_counted_as_disclosure():
    """A wildcard for *.example.com does not leak the name of a specific host."""
    report = parse_ct_log_response([{"name_value": "*.example.com"}])
    overlap = compute_ct_overlap(["example.com"], report)
    assert overlap["exact_matches"] == []
    assert overlap["wildcard_only_matches"] == ["example.com"]
    assert overlap["usable_as_evidence"] is False
    assert overlap["strength"] == "weak"
    assert "does not disclose a specific name" in overlap["note"]


def test_exact_match_wins_over_a_wildcard_for_the_same_base():
    report = parse_ct_log_response([{"name_value": "*.example.com\nexample.com"}])
    overlap = compute_ct_overlap(["example.com"], report)
    assert overlap["exact_matches"] == ["example.com"]
    assert overlap["usable_as_evidence"] is True


def test_no_overlap_is_clean():
    overlap = compute_ct_overlap(["unrelated.org"], parse_ct_log_response(CRTSH_FIXTURE))
    assert overlap["strength"] == "none"
    assert overlap["usable_as_evidence"] is False


def test_identifiers_are_normalized_and_empty_ones_ignored():
    overlap = compute_ct_overlap(
        ["  DARKNET-EXIT.ORG. ", "", None], parse_ct_log_response(CRTSH_FIXTURE)
    )
    assert overlap["exact_matches"] == ["darknet-exit.org"]


def test_onion_address_in_a_ct_log_is_a_disclosure():
    report = parse_ct_log_response([{
        "name_value": "abc.onion\nqzs5x3kqj2hfp6lm7onr4tuvcxa.email.onion",
    }])
    overlap = compute_ct_overlap(["qzs5x3kqj2hfp6lm7onr4tuvcxa.email.onion"], report)
    assert overlap["usable_as_evidence"] is True
    assert overlap["exact_matches"] == ["qzs5x3kqj2hfp6lm7onr4tuvcxa.email.onion"]


# --------------------------------------------------------------------------- #
# Query orchestration: caching, allowlist, and fail-soft
# --------------------------------------------------------------------------- #

def test_query_is_blocked_for_a_non_allowlisted_host(monkeypatch):
    monkeypatch.setattr(
        "app.services.intel.build_ct_log_url",
        lambda domain: (_ for _ in ()).throw(ValueError("host not allowlisted")),
    )
    report = query_certificate_transparency("evil.example", ["evil.example"])
    assert report["status"] == "BLOCKED"


def test_query_fails_soft_when_the_network_is_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("app.services.intel.httpx.get", boom)
    report = query_certificate_transparency("example.com", ["example.com"], use_cache=False)
    assert report["status"] == "SOURCE_UNAVAILABLE"
    assert "unreachable" in report["error"]
    assert report["subjects"] == []


def test_query_succeeds_and_computes_overlap(monkeypatch):
    class FakeResponse:
        text = json.dumps(CRTSH_FIXTURE)

        def raise_for_status(self):
            return None

    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("app.services.intel.httpx.get", fake_get)
    report = query_certificate_transparency("darknet-exit.org", ["node-de-42.darknet-exit.org"], use_cache=False)

    assert report["status"] == "OK"
    assert report["overlap_report"]["usable_as_evidence"] is True
    assert len(calls) == 1
    assert calls[0][0].startswith("https://crt.sh/")
    assert calls[0][1]["follow_redirects"] is False, "must not follow redirects off the allowlist"


def test_query_does_not_repeat_itself_within_the_ttl(monkeypatch):
    calls = []
    cache: dict = {}

    class FakeResponse:
        text = json.dumps(CRTSH_FIXTURE)

        def raise_for_status(self):
            return None

    monkeypatch.setattr(
        "app.services.intel.httpx.get",
        lambda url, **kwargs: (calls.append(url), FakeResponse())[1],
    )
    monkeypatch.setattr("app.services.intel._ct_cache", lambda: cache)

    query_certificate_transparency("cache-probe.example", [], use_cache=True)
    second = query_certificate_transparency("cache-probe.example", [], use_cache=True)
    assert len(calls) == 1
    assert second["cache_hit"] is True


def test_ttl_is_one_hour():
    assert CT_LOG_TTL_SECONDS == 3600


# --------------------------------------------------------------------------- #
# Indicator wiring
# --------------------------------------------------------------------------- #

def test_certificate_reuse_is_a_strong_deterministic_indicator():
    from app.services.scoring import make_evidence

    assert make_evidence("tls_cert_match", 1.0).category == "deterministic"
    assert make_evidence("tls_cert_match", 1.0).likelihood_ratio > make_evidence("ct_log_overlap", 1.0).likelihood_ratio


def test_ct_overlap_is_weaker_than_certificate_reuse():
    from app.services.scoring import LIKELIHOOD_RATIO_TABLE

    assert LIKELIHOOD_RATIO_TABLE["ct_log_overlap"].lr_full < LIKELIHOOD_RATIO_TABLE["tls_cert_match"].lr_full
    assert LIKELIHOOD_RATIO_TABLE["ct_log_overlap"].category == "probabilistic"


def test_ct_module_appears_in_the_pipeline_module_list():
    from app.services.investigation import MODULE_DEFS

    assert any(m["module"] == "ct_log" for m in MODULE_DEFS)
    assert len(MODULE_DEFS) == 10


def test_investigation_reports_the_certificate_fingerprint(client):
    res = client.post("/api/cases/investigate?sync=true", json={
        "case_name": "CT Vector Probe",
        "evidence_id": "AT-2026-CT01",
        "actor_name": "Tester",
        "target": "45.155.205.233",
        "target_type": "ip",
        "mode": "demo",
    })
    assert res.status_code == 200
    data = res.json()
    records = data["case"]["evidence_records"]

    jarm = next(m for m in records if m["evidence_type"] == "TLS_JARM")
    assert "tls_cert_fingerprint" in jarm["metadata_json"]
    assert jarm["metadata_json"]["tls_cert_fingerprint"]["status"] == "STORED_TELEMETRY"

    ct = next(m for m in records if m["evidence_type"] == "CT_LOG_DISCLOSURE")
    assert ct["metadata_json"]["status"] in ("OK", "SKIPPED", "NO_DATA")
    assert "evidentiary_caveat" in ct["metadata_json"]


def test_commodity_certificate_suppresses_attribution_rather_than_boosting_it(client, monkeypatch):
    """A shared CA certificate must never add support to the hypothesis."""
    import app.services.investigation as investigation

    monkeypatch.setattr(
        investigation, "resolve_tls_fingerprint",
        lambda target, candidates=None, subject="", provider=None: {
            "status": "STORED_TELEMETRY",
            "active_probe_conducted": False,
            "match": {
                "matched": False,
                "reason": "fingerprint_matches_but_certificate_is_commodity",
                "fingerprint": COMMODITY_FP,
                "superseded_by": ["innocent-host"],
                "classification": {"commodity": True, "commodity_marker": "letsencrypt", "uniqueness": "low"},
            },
        },
    )

    res = client.post("/api/cases/investigate?sync=true", json={
        "case_name": "Commodity Cert Probe",
        "evidence_id": "AT-2026-CC01",
        "actor_name": "Tester",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    })
    data = res.json()
    contributions = {c["indicator"]: c for c in data["attribution"]["contributions"]}
    tls = contributions.get("tls_cert_match")
    assert tls is not None
    assert tls["stance"] == "contradicts"
    assert tls["likelihood_ratio"] < 1.0
    assert any(e["indicator"] == "tls_cert_match" for e in data["attribution"]["contradicting_evidence"])
