"""
SSRF protection with DNS-rebinding defense.

Resolve → validate all IPs public → connect ONLY to validated IP.
Preserve hostname for TLS SNI and Host header.
"""

from __future__ import annotations
import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import structlog

logger = structlog.get_logger()


class TargetBlockedError(ValueError):
    """Target resolves to non-public / blocked destination (SSRF)."""
    pass


class InvalidTargetError(ValueError):
    """Malformed or unsupported target syntax."""
    pass


BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
    "metadata",
}

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".corp",
    ".lan",
)


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
            or (hasattr(addr, "is_site_local") and addr.is_site_local)
        )
    except ValueError:
        return True


def resolve_host(hostname: str) -> List[str]:
    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    if not ips:
        try:
            import dns.resolver
            for r in dns.resolver.resolve(hostname, "A"):
                s = str(r)
                if s not in ips:
                    ips.append(s)
        except Exception:
            pass
        try:
            import dns.resolver
            for r in dns.resolver.resolve(hostname, "AAAA"):
                s = str(r)
                if s not in ips:
                    ips.append(s)
        except Exception:
            pass
    return ips


def public_ips_only(ips: List[str]) -> List[str]:
    return [ip for ip in ips if not _is_private_ip(ip)]


def validate_hostname(hostname: str) -> None:
    hostname = hostname.lower().strip(".")
    if not hostname:
        raise InvalidTargetError("Empty hostname")
    if hostname in BLOCKED_HOSTNAMES:
        raise TargetBlockedError(f"Blocked hostname: {hostname}")
    for suf in BLOCKED_SUFFIXES:
        if hostname.endswith(suf):
            raise TargetBlockedError(f"Blocked hostname suffix: {hostname}")
    try:
        ip = ipaddress.ip_address(hostname)
        if _is_private_ip(str(ip)):
            raise TargetBlockedError(f"Private/non-public IP not allowed: {hostname}")
    except ValueError as e:
        if isinstance(e, (TargetBlockedError, InvalidTargetError)):
            raise
        if "not allowed" in str(e) or "Private" in str(e) or "Blocked" in str(e):
            raise TargetBlockedError(str(e))


def validate_url_for_ssrf(url: str) -> Tuple[str, str, List[str]]:
    """
    Returns (clean_url, hostname, validated_public_ips).
    Raises InvalidTargetError or TargetBlockedError.
    """
    if not url or not isinstance(url, str):
        raise InvalidTargetError("Invalid target")

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError("Only http/https schemes allowed")
    if not parsed.hostname:
        raise InvalidTargetError("Missing hostname")
    if parsed.username or parsed.password:
        raise InvalidTargetError("Credentials in URL not allowed")

    hostname = parsed.hostname.lower()
    # Strip brackets for IPv6 literals in hostname from urlparse
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    validate_hostname(hostname)

    ips = resolve_host(hostname)
    if not ips:
        raise InvalidTargetError(f"Could not resolve hostname: {hostname}")

    public = public_ips_only(ips)
    if not public:
        raise TargetBlockedError(f"Hostname resolves only to non-public IPs: {ips}")

    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    clean = f"{parsed.scheme}://{hostname}{port}{path}{query}"
    return clean, hostname, public


def validate_redirect_location(location: str, base_url: str) -> Tuple[str, str, List[str]]:
    absolute = urljoin(base_url, location)
    return validate_url_for_ssrf(absolute)


def build_ip_url(scheme: str, ip: str, port: Optional[int], path: str, query: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        host = f"[{ip}]" if addr.version == 6 else ip
    except ValueError:
        host = ip
    port_s = f":{port}" if port else ""
    q = f"?{query}" if query else ""
    path = path or "/"
    return f"{scheme}://{host}{port_s}{path}{q}"
