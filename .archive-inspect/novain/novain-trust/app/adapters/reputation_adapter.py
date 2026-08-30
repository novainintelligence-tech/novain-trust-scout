"""
Reputation intelligence (Phase A1).

Providers:
- Google Safe Browsing (API key required)
- URLhaus (abuse.ch public API, no key)
- OpenPhish community feed (public, cached)
- VirusTotal URL report (optional API key)

Rules:
- Unconfigured or failed providers → UNAVAILABLE (contribution 0)
- Never invent PASS when a provider could not be queried
- Circuit breaker opens after repeated failures
"""

from __future__ import annotations
import time
from typing import Optional, Set
from urllib.parse import urlparse, quote
import httpx
import tldextract
import structlog

from app.adapters.base import Observation, SignalResult, SourceReport
from app.config import settings
from app.services.circuit_breaker import provider_breakers

logger = structlog.get_logger()

# Process-local OpenPhish cache
_OPENPHISH_URLS: Set[str] = set()
_OPENPHISH_LOADED_AT: float = 0.0
_OPENPHISH_TTL = 3600.0  # 1 hour


def _domain(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or target).lower()
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def _full_url(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


async def _load_openphish(client: httpx.AsyncClient) -> None:
    global _OPENPHISH_URLS, _OPENPHISH_LOADED_AT
    if _OPENPHISH_URLS and (time.monotonic() - _OPENPHISH_LOADED_AT) < _OPENPHISH_TTL:
        return
    if not provider_breakers.allow("openphish"):
        return
    try:
        r = await client.get("https://openphish.com/feed.txt", timeout=15.0)
        if r.status_code != 200:
            provider_breakers.record_failure("openphish")
            return
        urls = set()
        for line in r.text.splitlines():
            line = line.strip().lower()
            if line.startswith("http"):
                urls.add(line)
                # also store domain form
                try:
                    host = urlparse(line).hostname
                    if host:
                        urls.add(host.lower())
                except Exception:
                    pass
        _OPENPHISH_URLS = urls
        _OPENPHISH_LOADED_AT = time.monotonic()
        provider_breakers.record_success("openphish")
        logger.info("openphish_feed_loaded", count=len(urls))
    except Exception as e:
        provider_breakers.record_failure("openphish")
        logger.warning("openphish_load_failed", error=str(e))


async def _check_safe_browsing(client: httpx.AsyncClient, url: str, domain: str) -> Observation:
    name = "safe_browsing"
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return Observation(
            source="reputation",
            signal="safe_browsing",
            result=SignalResult.UNAVAILABLE,
            weight=12,
            confidence=0.0,
            reason="Safe Browsing provider not configured",
        )
    if not provider_breakers.allow(name):
        return Observation(
            source="reputation",
            signal="safe_browsing",
            result=SignalResult.UNAVAILABLE,
            weight=12,
            confidence=0.0,
            reason="Safe Browsing circuit open",
        )
    try:
        payload = {
            "client": {"clientId": "novain-trust", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}, {"url": f"https://{domain}"}],
            },
        }
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=8.0,
        )
        if r.status_code != 200:
            provider_breakers.record_failure(name)
            return Observation(
                source="reputation",
                signal="safe_browsing",
                result=SignalResult.UNAVAILABLE,
                weight=12,
                confidence=0.0,
                reason=f"Safe Browsing HTTP {r.status_code}",
            )
        provider_breakers.record_success(name)
        matches = (r.json() or {}).get("matches") or []
        if matches:
            threat = matches[0].get("threatType", "UNKNOWN")
            return Observation(
                source="reputation",
                signal="safe_browsing",
                result=SignalResult.FAIL,
                weight=12,
                confidence=0.95,
                observation={"threat": threat, "matches": len(matches)},
                reason=f"Listed: {threat}",
                severity="critical",
            )
        return Observation(
            source="reputation",
            signal="safe_browsing",
            result=SignalResult.PASS,
            weight=12,
            confidence=0.9,
            reason="No Safe Browsing matches",
        )
    except Exception as e:
        provider_breakers.record_failure(name)
        return Observation(
            source="reputation",
            signal="safe_browsing",
            result=SignalResult.UNAVAILABLE,
            weight=12,
            confidence=0.0,
            reason=f"Safe Browsing error: {type(e).__name__}",
        )


async def _check_urlhaus(client: httpx.AsyncClient, url: str, domain: str) -> Observation:
    name = "urlhaus"
    if not provider_breakers.allow(name):
        return Observation(
            source="reputation",
            signal="urlhaus",
            result=SignalResult.UNAVAILABLE,
            weight=10,
            confidence=0.0,
            reason="URLhaus circuit open",
        )
    try:
        # Official auth-key optional; public host lookup
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=8.0,
            headers={"User-Agent": "NOVAIN-Trust/2.0"},
        )
        if r.status_code != 200:
            provider_breakers.record_failure(name)
            return Observation(
                source="reputation",
                signal="urlhaus",
                result=SignalResult.UNAVAILABLE,
                weight=10,
                confidence=0.0,
                reason=f"URLhaus HTTP {r.status_code}",
            )
        data = r.json() or {}
        provider_breakers.record_success(name)
        query_status = data.get("query_status")
        if query_status == "ok" and data.get("urls"):
            # active malware distribution host
            return Observation(
                source="reputation",
                signal="urlhaus",
                result=SignalResult.FAIL,
                weight=10,
                confidence=0.92,
                observation={"query_status": query_status, "url_count": len(data.get("urls") or [])},
                reason="Host listed on URLhaus (malware distribution)",
                severity="critical",
            )
        if query_status in ("no_results", "ok"):
            return Observation(
                source="reputation",
                signal="urlhaus",
                result=SignalResult.PASS,
                weight=10,
                confidence=0.85,
                reason="Host not listed on URLhaus",
            )
        return Observation(
            source="reputation",
            signal="urlhaus",
            result=SignalResult.UNKNOWN,
            weight=10,
            confidence=0.0,
            reason=f"URLhaus status: {query_status}",
        )
    except Exception as e:
        provider_breakers.record_failure(name)
        return Observation(
            source="reputation",
            signal="urlhaus",
            result=SignalResult.UNAVAILABLE,
            weight=10,
            confidence=0.0,
            reason=f"URLhaus error: {type(e).__name__}",
        )


async def _check_openphish(client: httpx.AsyncClient, url: str, domain: str) -> Observation:
    await _load_openphish(client)
    if not _OPENPHISH_URLS:
        return Observation(
            source="reputation",
            signal="openphish",
            result=SignalResult.UNAVAILABLE,
            weight=10,
            confidence=0.0,
            reason="OpenPhish feed unavailable",
        )
    u = url.lower().rstrip("/")
    d = domain.lower()
    if u in _OPENPHISH_URLS or d in _OPENPHISH_URLS or any(d in x for x in _OPENPHISH_URLS if d in x):
        # more precise: hostname match on feed URLs
        hit = False
        for feed_url in _OPENPHISH_URLS:
            if feed_url == d or feed_url == u:
                hit = True
                break
            if feed_url.startswith("http"):
                try:
                    fh = urlparse(feed_url).hostname
                    if fh and (fh == d or fh.endswith("." + d)):
                        hit = True
                        break
                except Exception:
                    pass
        if hit:
            return Observation(
                source="reputation",
                signal="openphish",
                result=SignalResult.FAIL,
                weight=10,
                confidence=0.9,
                reason="URL/host present on OpenPhish feed",
                severity="critical",
            )
    return Observation(
        source="reputation",
        signal="openphish",
        result=SignalResult.PASS,
        weight=10,
        confidence=0.8,
        reason="Not present on current OpenPhish feed",
    )


async def _check_virustotal(client: httpx.AsyncClient, url: str) -> Observation:
    name = "virustotal"
    if not settings.VIRUSTOTAL_API_KEY:
        return Observation(
            source="reputation",
            signal="virustotal",
            result=SignalResult.UNAVAILABLE,
            weight=8,
            confidence=0.0,
            reason="VirusTotal provider not configured",
        )
    if not provider_breakers.allow(name):
        return Observation(
            source="reputation",
            signal="virustotal",
            result=SignalResult.UNAVAILABLE,
            weight=8,
            confidence=0.0,
            reason="VirusTotal circuit open",
        )
    try:
        r = await client.get(
            "https://www.virustotal.com/api/v3/urls/" + quote(url, safe=""),
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=10.0,
        )
        # VT requires URL id = base64; simpler: use search
        if r.status_code == 404:
            # try submit lookup via URL id encoding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=10.0,
            )
        if r.status_code == 404:
            provider_breakers.record_success(name)
            return Observation(
                source="reputation",
                signal="virustotal",
                result=SignalResult.UNKNOWN,
                weight=8,
                confidence=0.0,
                reason="VirusTotal has no report for this URL",
            )
        if r.status_code != 200:
            provider_breakers.record_failure(name)
            return Observation(
                source="reputation",
                signal="virustotal",
                result=SignalResult.UNAVAILABLE,
                weight=8,
                confidence=0.0,
                reason=f"VirusTotal HTTP {r.status_code}",
            )
        provider_breakers.record_success(name)
        stats = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        last = stats.get("last_analysis_stats") or {}
        malicious = int(last.get("malicious") or 0)
        suspicious = int(last.get("suspicious") or 0)
        if malicious >= 3:
            return Observation(
                source="reputation",
                signal="virustotal",
                result=SignalResult.FAIL,
                weight=8,
                confidence=0.9,
                observation={"malicious": malicious, "suspicious": suspicious},
                reason=f"VirusTotal malicious engines: {malicious}",
                severity="critical",
            )
        if malicious >= 1 or suspicious >= 3:
            return Observation(
                source="reputation",
                signal="virustotal",
                result=SignalResult.FAIL,
                weight=8,
                confidence=0.7,
                observation={"malicious": malicious, "suspicious": suspicious},
                reason=f"VirusTotal flagged (malicious={malicious}, suspicious={suspicious})",
                severity="high",
            )
        return Observation(
            source="reputation",
            signal="virustotal",
            result=SignalResult.PASS,
            weight=8,
            confidence=0.75,
            observation={"malicious": malicious, "suspicious": suspicious},
            reason="VirusTotal: no significant malicious consensus",
        )
    except Exception as e:
        provider_breakers.record_failure(name)
        return Observation(
            source="reputation",
            signal="virustotal",
            result=SignalResult.UNAVAILABLE,
            weight=8,
            confidence=0.0,
            reason=f"VirusTotal error: {type(e).__name__}",
        )


async def check_reputation(target: str) -> SourceReport:
    report = SourceReport(source="reputation", status="ACTIVE")
    url = _full_url(target)
    domain = _domain(target)

    async with httpx.AsyncClient(
        timeout=12.0,
        headers={"User-Agent": "NOVAIN-Trust/2.0 (+https://api.novain.trust)"},
        follow_redirects=False,
    ) as client:
        sb, uh, op, vt = (
            await _check_safe_browsing(client, url, domain),
            await _check_urlhaus(client, url, domain),
            await _check_openphish(client, url, domain),
            await _check_virustotal(client, url),
        )

    for obs in (sb, uh, op, vt):
        report.observations.append(obs)

    statuses = [o.result for o in report.observations]
    if all(s == SignalResult.UNAVAILABLE for s in statuses):
        report.status = "UNAVAILABLE"
    elif any(s == SignalResult.UNAVAILABLE for s in statuses):
        report.status = "DEGRADED"
    return report
