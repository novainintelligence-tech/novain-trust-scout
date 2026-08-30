from __future__ import annotations
import asyncio
import dns.resolver
from app.adapters.base import Observation, SignalResult, SourceReport
from urllib.parse import urlparse
import tldextract
import structlog

logger = structlog.get_logger()


def _domain_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}".lower()


async def check_dns(target: str) -> SourceReport:
    report = SourceReport(source="dns", status="ACTIVE")
    domain = _domain_from_target(target)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    async def resolve(qtype: str):
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, qtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    a, mx, ns, txt = await asyncio.gather(
        resolve("A"), resolve("MX"), resolve("NS"), resolve("TXT")
    )

    has_a = bool(a)
    report.observations.append(
        Observation(
            source="dns",
            signal="dns_a_record",
            result=SignalResult.PASS if has_a else SignalResult.FAIL,
            weight=4,
            confidence=0.9 if has_a else 0.7,
            observation={"records": a[:5]},
            reason="A record present" if has_a else "No A record",
        )
    )

    has_spf = any("v=spf1" in t.lower() for t in txt)
    report.observations.append(
        Observation(
            source="dns",
            signal="spf_present",
            result=SignalResult.PASS if has_spf else SignalResult.FAIL,
            weight=3,
            confidence=0.85,
            observation={"txt_count": len(txt)},
            reason="SPF found" if has_spf else "No SPF record",
        )
    )

    # DMARC on _dmarc.
    dmarc = False
    dmarc_val = None
    try:
        answers = await asyncio.to_thread(resolver.resolve, f"_dmarc.{domain}", "TXT")
        for r in answers:
            val = str(r)
            if "v=dmarc1" in val.lower():
                dmarc = True
                dmarc_val = val
    except Exception:
        pass

    report.observations.append(
        Observation(
            source="dns",
            signal="dmarc_present",
            result=SignalResult.PASS if dmarc else SignalResult.FAIL,
            weight=4,
            confidence=0.85,
            observation={"record": dmarc_val},
            reason="DMARC found" if dmarc else "No DMARC record",
        )
    )

    report.observations.append(
        Observation(
            source="dns",
            signal="nameservers_present",
            result=SignalResult.PASS if ns else SignalResult.FAIL,
            weight=2,
            confidence=0.8,
            observation={"ns": ns[:4]},
            reason="NS present" if ns else "No NS records",
        )
    )

    return report
