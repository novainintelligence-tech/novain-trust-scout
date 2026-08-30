"""
HTTP adapter with SSRF-safe, DNS-rebinding-resistant fetches.

Connect only to a validated public IP.
Preserve Host header and TLS SNI (original hostname).
httpx 0.28+: set Request.extensions['sni_hostname'] — do NOT pass extensions= to send().
"""

from __future__ import annotations
import time
from typing import Optional, List
from urllib.parse import urlparse
import httpx
from app.adapters.base import Observation, SignalResult, SourceReport
from app.security.ssrf import (
    validate_url_for_ssrf,
    validate_redirect_location,
    build_ip_url,
)
from app.config import settings
import structlog

logger = structlog.get_logger()


async def _fetch_pinned(
    client: httpx.AsyncClient,
    scheme: str,
    hostname: str,
    public_ips: List[str],
    port: Optional[int],
    path: str,
    query: str,
) -> httpx.Response:
    """
    Connect to validated public IP only.
    Host header + TLS SNI use original hostname.
    Never falls back to connecting by hostname (rebinding defense).
    """
    last_err: Optional[Exception] = None
    host_header = hostname if not port else f"{hostname}:{port}"

    for ip in public_ips:
        ip_url = build_ip_url(scheme, ip, port, path, query)
        try:
            req = client.build_request(
                "GET",
                ip_url,
                headers={"Host": host_header},
            )
            # httpx 0.28: SNI override lives on the Request, not send()
            if scheme == "https":
                req.extensions["sni_hostname"] = hostname
            response = await client.send(req)
            return response
        except Exception as e:
            last_err = e
            logger.warning("pinned_connect_failed", ip=ip, host=hostname, error=str(e), err_type=type(e).__name__)
            continue

    raise last_err or RuntimeError("No public IP reachable")


async def fetch_http(target: str) -> SourceReport:
    report = SourceReport(source="http", status="ACTIVE")
    try:
        clean_url, hostname, public_ips = validate_url_for_ssrf(target)
    except ValueError as e:
        report.status = "UNAVAILABLE"
        report.error = str(e)
        report.observations.append(
            Observation(
                source="http",
                signal="target_reachable",
                result=SignalResult.UNAVAILABLE,
                reason=str(e),
                weight=0,
                confidence=0.0,
            )
        )
        return report

    parsed = urlparse(clean_url)
    scheme = parsed.scheme
    port = parsed.port
    path = parsed.path or "/"
    query = parsed.query or ""

    redirects_followed = 0
    current_url = clean_url
    current_host = hostname
    current_ips = public_ips
    final_url = clean_url
    status_code: Optional[int] = None
    elapsed_ms = 0.0
    headers: dict = {}
    body_preview = ""

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=settings.HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": "NOVAIN-Trust/1.0 (+https://api.novain.trust)"},
            verify=True,
        ) as client:
            for _ in range(settings.MAX_REDIRECTS + 1):
                p = urlparse(current_url)
                scheme = p.scheme
                port = p.port
                path = p.path or "/"
                query = p.query or ""
                start = time.perf_counter()
                resp = await _fetch_pinned(
                    client, scheme, current_host, current_ips, port, path, query
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                status_code = resp.status_code
                headers = dict(resp.headers)

                if status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location")
                    if not loc:
                        break
                    try:
                        next_url, next_host, next_ips = validate_redirect_location(loc, current_url)
                    except ValueError as e:
                        report.observations.append(
                            Observation(
                                source="http",
                                signal="redirect_safe",
                                result=SignalResult.FAIL,
                                reason=f"Unsafe redirect blocked: {e}",
                                weight=0,
                                confidence=1.0,
                                observation={"from": current_url, "location": loc},
                            )
                        )
                        report.status = "DEGRADED"
                        return report
                    redirects_followed += 1
                    current_url = next_url
                    current_host = next_host
                    current_ips = next_ips
                    final_url = next_url
                    continue
                else:
                    body_preview = resp.text[:4000] if resp.text else ""
                    break
    except Exception as e:
        logger.warning("http_adapter_error", error=str(e), err_type=type(e).__name__)
        is_timeout = "timeout" in type(e).__name__.lower()
        report.observations.append(
            Observation(
                source="http",
                signal="target_reachable",
                result=SignalResult.FAIL if is_timeout else SignalResult.UNAVAILABLE,
                reason=f"HTTP error: {type(e).__name__}: {e}",
                weight=5 if is_timeout else 0,
                confidence=0.5 if is_timeout else 0.0,
            )
        )
        if not is_timeout:
            report.status = "DEGRADED"
        return report

    if status_code and 200 <= status_code < 400:
        report.observations.append(
            Observation(
                source="http",
                signal="target_reachable",
                result=SignalResult.PASS,
                weight=5,
                confidence=0.9,
                observation={
                    "status_code": status_code,
                    "final_url": final_url,
                    "redirects": redirects_followed,
                    "connected_via_pinned_ip": True,
                },
                reason=f"HTTP {status_code}",
            )
        )
    elif status_code:
        report.observations.append(
            Observation(
                source="http",
                signal="target_reachable",
                result=SignalResult.FAIL,
                weight=5,
                confidence=0.8,
                observation={"status_code": status_code},
                reason=f"HTTP {status_code}",
            )
        )
    else:
        report.observations.append(
            Observation(
                source="http",
                signal="target_reachable",
                result=SignalResult.UNKNOWN,
                weight=5,
                confidence=0.0,
                reason="No status obtained",
            )
        )

    scheme_pass = final_url.startswith("https://")
    report.observations.append(
        Observation(
            source="http",
            signal="https_scheme",
            result=SignalResult.PASS if scheme_pass else SignalResult.FAIL,
            weight=3,
            confidence=1.0,
            observation={"final_url": final_url},
            reason="Uses HTTPS" if scheme_pass else "Does not use HTTPS",
        )
    )

    if elapsed_ms > 0:
        ok = elapsed_ms < 5000
        report.observations.append(
            Observation(
                source="http",
                signal="response_time",
                result=SignalResult.PASS if ok else SignalResult.FAIL,
                weight=2,
                confidence=0.7,
                observation={"ms": round(elapsed_ms, 1)},
                reason=f"{round(elapsed_ms)}ms",
            )
        )

    report.observations.append(
        Observation(
            source="http",
            signal="_body_preview",
            result=SignalResult.PASS,
            weight=0,
            confidence=0.0,
            observation={"text": body_preview, "headers": {k.lower(): v for k, v in headers.items()}},
            reason="internal",
        )
    )

    return report
