from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.adapters.base import Observation, SignalResult, SourceReport
import structlog

logger = structlog.get_logger()


async def check_tls(target: str) -> SourceReport:
    import asyncio
    report = SourceReport(source="tls", status="ACTIVE")

    def _sync():
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                return cert, protocol

    try:
        result = await asyncio.to_thread(_sync)
        if result is None:
            report.observations.append(
                Observation(source="tls", signal="tls_valid", result=SignalResult.UNAVAILABLE, reason="No hostname", weight=0)
            )
            return report
        cert, protocol = result
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName") or issuer.get("commonName") or "unknown"

        report.observations.append(
            Observation(
                source="tls",
                signal="tls_valid",
                result=SignalResult.PASS,
                weight=8,
                confidence=0.95,
                observation={"issuer": issuer_name, "protocol": protocol, "days_left": days_left},
                reason=f"Valid TLS ({protocol}), issuer={issuer_name}",
            )
        )
        if days_left < 14:
            report.observations.append(
                Observation(
                    source="tls",
                    signal="tls_expiry",
                    result=SignalResult.FAIL,
                    weight=3,
                    confidence=0.9,
                    observation={"days_left": days_left},
                    reason=f"Certificate expires in {days_left} days",
                )
            )
        else:
            report.observations.append(
                Observation(
                    source="tls",
                    signal="tls_expiry",
                    result=SignalResult.PASS,
                    weight=3,
                    confidence=0.9,
                    observation={"days_left": days_left},
                    reason=f"{days_left} days remaining",
                )
            )
    except Exception as e:
        logger.warning("tls_adapter_error", error=str(e))
        report.observations.append(
            Observation(
                source="tls",
                signal="tls_valid",
                result=SignalResult.FAIL if "certificate" in str(e).lower() or "ssl" in str(e).lower() else SignalResult.UNAVAILABLE,
                weight=8,
                reason=f"TLS check failed: {type(e).__name__}",
            )
        )
        if report.observations[-1].result == SignalResult.UNAVAILABLE:
            report.status = "DEGRADED"
    return report
