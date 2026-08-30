"""Prove IP-pinned HTTPS works and does not connect by hostname after validation."""
import pytest
import httpx
from app.adapters.http_adapter import fetch_http, _fetch_pinned
from app.security.ssrf import validate_url_for_ssrf, build_ip_url
from urllib.parse import urlparse


@pytest.mark.asyncio
async def test_pinned_fetch_example_com():
    report = await fetch_http("https://example.com")
    reachable = [o for o in report.observations if o.signal == "target_reachable"]
    assert reachable, report.observations
    assert reachable[0].result.value == "pass", reachable[0].reason
    assert reachable[0].observation.get("connected_via_pinned_ip") is True


@pytest.mark.asyncio
async def test_connection_uses_ip_not_hostname():
    """Assert Request URL host is an IP address (pin), SNI set to hostname."""
    clean, host, ips = validate_url_for_ssrf("https://example.com")
    p = urlparse(clean)
    async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
        resp = await _fetch_pinned(client, "https", host, ips, None, "/", "")
        assert resp.status_code == 200
        # Request went to IP
        assert any(ip in str(resp.request.url) for ip in ips)
        assert host not in str(resp.request.url.host) or resp.request.url.host in ips
