"""
WHOIS adapter (not RDAP). Failures become UNKNOWN/UNAVAILABLE with zero contribution.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import whois
from dateutil import parser as date_parser
from app.adapters.base import Observation, SignalResult, SourceReport
from urllib.parse import urlparse
import tldextract
import structlog

logger = structlog.get_logger()
SOURCE = "whois"


def _domain(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}".lower()


def _to_aware(dt):
    if dt is None:
        return None
    if isinstance(dt, list):
        dt = dt[0]
    if isinstance(dt, str):
        try:
            dt = date_parser.parse(dt)
        except Exception:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def check_whois(target: str) -> SourceReport:
    report = SourceReport(source=SOURCE, status="ACTIVE")
    domain = _domain(target)

    def _whois_sync():
        try:
            return whois.whois(domain)
        except Exception as e:
            return e

    raw = await asyncio.to_thread(_whois_sync)
    if isinstance(raw, Exception) or raw is None:
        report.status = "UNAVAILABLE"
        report.error = str(raw) if raw else "WHOIS unavailable"
        for signal, weight in [
            ("domain_registered", 6),
            ("domain_age", 10),
            ("registrar_present", 3),
            ("registrar_abuse_contact", 2),
        ]:
            report.observations.append(
                Observation(
                    source=SOURCE,
                    signal=signal,
                    result=SignalResult.UNAVAILABLE,
                    weight=weight,
                    reason="WHOIS unavailable",
                    confidence=0.0,
                )
            )
        return report

    try:
        creation = _to_aware(raw.creation_date)
        expiration = _to_aware(raw.expiration_date)
        registrar = str(raw.registrar) if getattr(raw, "registrar", None) else None
        age_days = None
        if creation:
            age_days = (datetime.now(timezone.utc) - creation).days

        report.observations.append(
            Observation(
                source=SOURCE,
                signal="domain_registered",
                result=SignalResult.PASS if creation else SignalResult.UNKNOWN,
                weight=6,
                confidence=0.8 if creation else 0.0,
                observation={"creation": creation.isoformat() if creation else None},
                reason="Registration date found" if creation else "Registration date unknown",
            )
        )

        if age_days is not None:
            report.observations.append(
                Observation(
                    source=SOURCE,
                    signal="domain_age",
                    result=SignalResult.PASS,
                    weight=10,
                    confidence=0.8,
                    observation={"age_days": age_days, "age_years": round(age_days / 365.25, 2)},
                    reason=f"Domain age {age_days} days",
                )
            )
        else:
            report.observations.append(
                Observation(
                    source=SOURCE,
                    signal="domain_age",
                    result=SignalResult.UNKNOWN,
                    weight=10,
                    confidence=0.0,
                    reason="Domain age could not be determined",
                )
            )

        report.observations.append(
            Observation(
                source=SOURCE,
                signal="registrar_present",
                result=SignalResult.PASS if registrar else SignalResult.UNKNOWN,
                weight=3,
                confidence=0.7 if registrar else 0.0,
                observation={"registrar": registrar},
                reason=f"Registrar: {registrar}" if registrar else "Registrar unknown",
            )
        )

        report.observations.append(
            Observation(
                source=SOURCE,
                signal="registrar_abuse_contact",
                result=SignalResult.UNKNOWN,
                weight=2,
                confidence=0.0,
                reason="Abuse contact not reliably available via WHOIS",
            )
        )

        if expiration:
            days_left = (expiration - datetime.now(timezone.utc)).days
            report.observations.append(
                Observation(
                    source=SOURCE,
                    signal="domain_expiry",
                    result=SignalResult.PASS if days_left > 30 else SignalResult.FAIL,
                    weight=4,
                    confidence=0.8,
                    observation={"days_left": days_left, "expiration": expiration.isoformat()},
                    reason=f"Expires in {days_left} days",
                )
            )

    except Exception as e:
        logger.warning("whois_parse_error", error=str(e))
        report.status = "DEGRADED"
        report.observations.append(
            Observation(
                source=SOURCE,
                signal="domain_registered",
                result=SignalResult.UNAVAILABLE,
                weight=0,
                confidence=0.0,
                reason=f"Parse error: {type(e).__name__}",
            )
        )

    return report
