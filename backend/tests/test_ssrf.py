import pytest
from app.security.ssrf import (
    validate_url_for_ssrf,
    validate_hostname,
    validate_redirect_location,
    public_ips_only,
    _is_private_ip,
    TargetBlockedError,
    InvalidTargetError,
)


def test_rejects_localhost():
    with pytest.raises(TargetBlockedError):
        validate_url_for_ssrf("http://localhost/")
    with pytest.raises(TargetBlockedError):
        validate_url_for_ssrf("http://127.0.0.1/")


def test_rejects_loopback_ipv6():
    with pytest.raises(TargetBlockedError):
        validate_hostname("::1")


def test_rejects_private_rfc1918():
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
        with pytest.raises(TargetBlockedError):
            validate_url_for_ssrf(f"http://{ip}/")


def test_rejects_link_local_and_metadata():
    with pytest.raises(TargetBlockedError):
        validate_url_for_ssrf("http://169.254.169.254/")
    with pytest.raises(TargetBlockedError):
        validate_hostname("metadata.google.internal")


def test_rejects_credentials():
    with pytest.raises(InvalidTargetError):
        validate_url_for_ssrf("https://user:pass@example.com/")


def test_public_ips_only_filters():
    assert public_ips_only(["8.8.8.8", "10.0.0.1"]) == ["8.8.8.8"]


def test_redirect_to_private_blocked():
    with pytest.raises(TargetBlockedError):
        validate_redirect_location("http://127.0.0.1/admin", "https://example.com/")


def test_validate_example_public():
    try:
        clean, host, ips = validate_url_for_ssrf("https://example.com/")
        assert host == "example.com"
        assert ips
        assert all(not _is_private_ip(ip) for ip in ips)
    except InvalidTargetError:
        pytest.skip("DNS unavailable")
