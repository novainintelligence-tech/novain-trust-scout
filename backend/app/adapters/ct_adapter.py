"""
Certificate Transparency signals via crt.sh (Phase A4).
Read-only public data. Failures → UNAVAILABLE (score 0).
"""
from __future__ import annotations
from urllib.parse import urlparse
import httpx
import tldextract
from app.adapters.base import Observation, SignalResult, SourceReport
from app.services.circuit_breaker import provider_breakers
import structlog

logger = structlog.get_logger()


def _domain(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or target).lower()
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


async def check_ct(target: str) -> SourceReport:
    report = SourceReport(source="ct", status="ACTIVE")
    domain = _domain(target)
    name = "crtsh"
    if not provider_breakers.allow(name):
        report.status = "UNAVAILABLE"
        report.observations.append(
            Observation(
                source="ct",
                signal="ct_presence",
                result=SignalResult.UNAVAILABLE,
                weight=4,
                confidence=0.0,
                reason="CT provider circuit open",
            )
        )
        return report

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.get(
                "https://crt.sh/",
                params={"q": domain, "output": "json"},
                headers={"User-Agent": "NOVAIN-Trust/2.0"},
            )
        if r.status_code != 200:
            provider_breakers.record_failure(name)
            report.status = "DEGRADED"
            report.observations.append(
                Observation(
                    source="ct",
                    signal="ct_presence",
                    result=SignalResult.UNAVAILABLE,
                    weight=4,
                    confidence=0.0,
                    reason=f"crt.sh HTTP {r.status_code}",
                )
            )
            return report

        provider_breakers.record_success(name)
        try:
            data = r.json()
        except Exception:
            data = []
        if not isinstance(data, list):
            data = []

        count = len(data)
        # Distinct issuers / names as weak signal of established presence
        names = set()
        for row in data[:200]:
            n = row.get("common_name") or row.get("name_value") or ""
            for part in str(n).split("\n"):
                if part.strip():
                    names.add(part.strip().lower())

        if count == 0:
            report.observations.append(
                Observation(
                    source="ct",
                    signal="ct_presence",
                    result=SignalResult.FAIL,
                    weight=4,
                    confidence=0.6,
                    observation={"cert_count": 0},
                    reason="No Certificate Transparency records found",
                )
            )
        else:
            report.observations.append(
                Observation(
                    source="ct",
                    signal="ct_presence",
                    result=SignalResult.PASS,
                    weight=4,
                    confidence=0.85,
                    observation={"cert_count": count, "name_samples": list(names)[:10]},
                    reason=f"CT records present ({count} entries)",
                )
            )
            # Multiple historical certs suggests longer operational history
            report.observations.append(
                Observation(
                    source="ct",
                    signal="ct_history_depth",
                    result=SignalResult.PASS if count >= 3 else SignalResult.UNKNOWN,
                    weight=2,
                    confidence=0.7 if count >= 3 else 0.0,
                    observation={"cert_count": count},
                    reason=f"CT history depth: {count}",
                )
            )
    except Exception as e:
        provider_breakers.record_failure(name)
        report.status = "DEGRADED"
        report.observations.append(
            Observation(
                source="ct",
                signal="ct_presence",
                result=SignalResult.UNAVAILABLE,
                weight=4,
                confidence=0.0,
                reason=f"CT error: {type(e).__name__}",
            )
        )
    return report
