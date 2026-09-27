"""Unit and integration tests for Tor transport, per-module circuit isolation,
and investigator OPSEC protections (Phase 3).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from app.security import (
    assert_safe_direct_fetch,
    is_safe_direct_fetch,
    is_safe_target_url,
)
from app.services.intel import (
    build_isolated_socks_url,
    fetch_onion_target,
    fetch_onion_target_sync,
    get_onion_client,
    get_onion_client_sync,
    is_active_probe_enabled,
    probe_tls_jarm,
)


# ============================================================================ #
# 1. SOCKS5 Proxy URL Construction & Circuit Isolation
# ============================================================================ #

def test_build_isolated_socks_url_standard():
    """Verify SOCKS5 URL includes distinct username for Tor circuit isolation."""
    base = "socks5://tor:9050"
    url = build_isolated_socks_url(base, "favicon")
    assert url == "socks5://aether-favicon:x@tor:9050"


def test_build_isolated_socks_url_ip_and_port():
    """Verify proxy URL with loopback IP and custom port formats correctly."""
    base = "socks5://127.0.0.1:9150"
    url = build_isolated_socks_url(base, "stylometry")
    assert url == "socks5://aether-stylometry:x@127.0.0.1:9050" or url == "socks5://aether-stylometry:x@127.0.0.1:9150"
    assert "aether-stylometry:x" in url


def test_build_isolated_socks_url_sanitizes_module_name():
    """Module name with spaces or uppercase should be normalized."""
    base = "socks5://tor:9050"
    url = build_isolated_socks_url(base, "JARM Probe v2")
    assert "aether-jarmprobev2:x@tor:9050" in url


def test_build_isolated_socks_url_empty_base():
    """Empty base proxy string returns empty string."""
    assert build_isolated_socks_url("", "crypto") == ""
    assert build_isolated_socks_url("   ", "crypto") == ""


def test_build_isolated_socks_url_socks5h_scheme():
    """Remote DNS socks5h scheme is preserved."""
    base = "socks5h://127.0.0.1:9050"
    url = build_isolated_socks_url(base, "osint")
    assert url.startswith("socks5h://aether-osint:x@127.0.0.1:9050")


# ============================================================================ #
# 2. Direct Clearnet Fetch of .onion Targets Must Be Blocked (OPSEC)
# ============================================================================ #

def test_is_safe_direct_fetch_blocks_onion_domains():
    """Direct clearnet fetch of any .onion address must be rejected."""
    onion_targets = [
        "http://p4lx7e22kq6dreadmarket.onion",
        "https://expyuz5wqqfdgah56trldjbdymsevlvhsfdggc3umnvxfsxrwh4626yd.onion/login",
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "darkmarketxyz.onion",
    ]
    for target in onion_targets:
        safe, reason = is_safe_direct_fetch(target)
        assert safe is False, f"Target {target} should be blocked for direct fetch"
        assert "direct" in reason.lower() or "blocked" in reason.lower() or "onion" in reason.lower()


def test_assert_safe_direct_fetch_raises_on_onion():
    """assert_safe_direct_fetch must raise ValueError for .onion destinations."""
    with pytest.raises(ValueError) as exc_info:
        assert_safe_direct_fetch("http://p4lx7e22kq6dreadmarket.onion")
    assert "Direct fetch blocked" in str(exc_info.value)


def test_is_safe_direct_fetch_allows_public_clearnet():
    """Valid clearnet IPs and domains are permitted for direct fetch."""
    assert is_safe_direct_fetch("http://185.220.101.42")[0] is True
    assert is_safe_direct_fetch("https://shodan.io")[0] is True


def test_is_safe_target_url_respects_direct_fetch_flag():
    """is_safe_target_url allows .onion for investigation target but blocks for direct fetch."""
    onion = "http://p4lx7e22kq6dreadmarket.onion"
    # Allowed as an investigation target descriptor
    assert is_safe_target_url(onion, allow_onion=True, direct_fetch=False)[0] is True
    # Blocked if directly fetching over clearnet
    assert is_safe_target_url(onion, allow_onion=True, direct_fetch=True)[0] is False


# ============================================================================ #
# 3. Graceful Degradation / transport_unavailable Path
# ============================================================================ #

import asyncio

def test_fetch_onion_target_unconfigured_proxy_soft_fail():
    """When AETHER_TOR_SOCKS_URL is unset, return transport_unavailable without raising."""
    async def _test():
        with patch.dict(os.environ, {"AETHER_TOR_SOCKS_URL": "", "TOR_SOCKS_PROXY": ""}, clear=True):
            res = await fetch_onion_target("http://target.onion/index.html", module_name="scraper")
            assert res["status"] == "transport_unavailable"
            assert res["available"] is False
            assert "not configured" in res["error"]

    asyncio.run(_test())


def test_fetch_onion_target_sync_unconfigured_proxy_soft_fail():
    """Sync fetch also returns transport_unavailable when proxy is unconfigured."""
    with patch.dict(os.environ, {"AETHER_TOR_SOCKS_URL": "", "TOR_SOCKS_PROXY": ""}, clear=True):
        res = fetch_onion_target_sync("http://target.onion/index.html", module_name="scraper")
        assert res["status"] == "transport_unavailable"
        assert res["available"] is False


def test_fetch_onion_target_connection_failure_soft_fail():
    """When Tor proxy connection fails, return transport_unavailable without crashing."""
    async def _test():
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("SOCKS5 connection refused to 127.0.0.1:9999")

        with patch.dict(os.environ, {"AETHER_TOR_SOCKS_URL": "socks5://127.0.0.1:9999"}):
            res = await fetch_onion_target(
                "http://testmarket56xyz.onion",
                module_name="favicon",
                client=mock_client,
            )
            assert res["status"] == "transport_unavailable"
            assert res["available"] is False
            assert "connection failed" in res["error"] or "SOCKS5" in res["error"]

    asyncio.run(_test())


def test_fetch_onion_target_success_with_mocked_client():
    """When Tor transport succeeds, return response payload."""
    async def _test():
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html>Darknet Market</html>"
        mock_response.text = "<html>Darknet Market</html>"
        mock_response.headers = {"Content-Type": "text/html"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.dict(os.environ, {"AETHER_TOR_SOCKS_URL": "socks5://tor:9050"}):
            res = await fetch_onion_target(
                "http://testmarket56xyz.onion",
                module_name="scraper",
                client=mock_client,
            )
            assert res["status"] == "success"
            assert res["available"] is True
            assert res["status_code"] == 200
            assert res["content"] == b"<html>Darknet Market</html>"

    asyncio.run(_test())


# ============================================================================ #
# 4. OPSEC Probing Flag (AETHER_ACTIVE_PROBE_ENABLED)
# ============================================================================ #

def test_active_probe_flag_default_is_false():
    """Active probing must be disabled by default to prevent investigator deanonymization."""
    with patch.dict(os.environ, {}, clear=True):
        assert is_active_probe_enabled() is False


def test_probe_tls_jarm_passive_when_opsec_flag_disabled():
    """When active probe is disabled, probe_tls_jarm uses passive stored telemetry."""
    with patch.dict(os.environ, {"AETHER_ACTIVE_PROBE_ENABLED": "false"}):
        res = probe_tls_jarm("target.onion")
        assert res["mode"] == "PASSIVE_STORED"
        assert res["active_probe_conducted"] is False
        assert "OPSEC" in res["opsec_note"]
        assert res["provenance"] in ("DEMO_DATA", "STORED_TELEMETRY")


def test_probe_tls_jarm_active_when_opsec_flag_enabled():
    """When active probe is enabled, probe_tls_jarm routes through Tor proxy if available."""
    with patch.dict(os.environ, {
        "AETHER_ACTIVE_PROBE_ENABLED": "true",
        "AETHER_TOR_SOCKS_URL": "socks5://tor:9050",
    }):
        res = probe_tls_jarm("target.onion")
        assert res["mode"] == "ACTIVE_PROBE"
        assert res["active_probe_conducted"] is True
        assert res["routed_via_tor"] is True
        assert res["tor_proxy_used"] == "socks5://aether-jarm-probe:x@tor:9050"
        assert res["provenance"] == "LIVE_SOURCE"


def test_get_onion_client_proxy_assignment():
    """Client constructor correctly assigns SOCKS proxy URL."""
    client = get_onion_client("testmod", base_proxy_url="socks5://proxy:9050")
    # Verify client was created without errors
    assert isinstance(client, httpx.AsyncClient)
    sync_client = get_onion_client_sync("testmod", base_proxy_url="socks5://proxy:9050")
    assert isinstance(sync_client, httpx.Client)
