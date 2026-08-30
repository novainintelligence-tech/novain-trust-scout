"""
Verification orchestrator.
API → validation → adapters → engine → persistence → response
"""

from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.adapters.http_adapter import fetch_http
from app.adapters.tls_adapter import check_tls
from app.adapters.dns_adapter import check_dns
from app.adapters.whois_adapter import check_whois
from app.adapters.content_adapter import analyze_content
from app.adapters.reputation_adapter import check_reputation
from app.adapters.ct_adapter import check_ct
from app.services import verify_cache
from app.services import metrics as metrics_svc
from app.engine.risk_engine import run_engine, EngineResult
from app.models.db import (
    Verification, VerificationEvidence, ScoreContribution,
    VerificationRiskGate,     utcnow, generate_uuid,
)
from app.models.schemas import (
    WebsiteVerifyResponse, Assessment, RiskGateItem, UnknownItem, EvidenceItem
)
from app.security.ssrf import validate_url_for_ssrf, TargetBlockedError, InvalidTargetError
from app.services.public_id import allocate_public_id
from app.config import settings
import structlog

logger = structlog.get_logger()


async def run_website_verification(
    db: AsyncSession,
    target: str,
    request_id: str,
    api_key_id: Optional[str] = None,
) -> WebsiteVerifyResponse:
    try:
        clean_target, _, _ = validate_url_for_ssrf(target)
    except TargetBlockedError:
        raise
    except InvalidTargetError:
        raise
    except ValueError as e:
        raise InvalidTargetError(str(e))

    # Phase B: short TTL cache (identical target + engine)
    cached = verify_cache.get(clean_target)
    if cached is not None:
        metrics_svc.incr("verify.cache_hit")
        return cached
    metrics_svc.incr("verify.cache_miss")

    http_report, tls_report, dns_report, whois_report, rep_report, ct_report = await asyncio.gather(
        fetch_http(clean_target),
        check_tls(clean_target),
        check_dns(clean_target),
        check_whois(clean_target),
        check_reputation(clean_target),
        check_ct(clean_target),
    )

    body = None
    headers = None
    for obs in http_report.observations:
        if obs.signal == "_body_preview":
            body = (obs.observation or {}).get("text")
            headers = (obs.observation or {}).get("headers")
            break
    content_report = analyze_content(body, headers)

    source_reports = [http_report, tls_report, dns_report, whois_report, content_report, rep_report, ct_report]
    engine: EngineResult = run_engine(source_reports)

    public_id = await allocate_public_id(db)
    ver_id = generate_uuid()

    verification = Verification(
        id=ver_id,
        public_id=public_id,
        target=clean_target,
        target_type="website",
        normalized_domain=_extract_domain(clean_target),
        score=engine.score,
        raw_score=engine.raw_score,
        risk_level=engine.risk_level,
        confidence=engine.confidence,
        coverage=engine.coverage,
        status=engine.status,
        capped=engine.capped,
        recommendation=engine.recommendation,
        engine=settings.ENGINE_VERSION,
        request_id=request_id,
        api_key_id=api_key_id,
    )
    db.add(verification)

    evidence_id_map = {}
    for idx, item in enumerate(engine.evidence_items):
        ev_public = f"EV-{uuid.uuid4().hex[:10].upper()}"
        ev = VerificationEvidence(
            id=generate_uuid(),
            evidence_id=ev_public,
            verification_id=ver_id,
            check_id=f"CHK_{item['signal'].upper()}",
            source_id=item["source"],
            signal=item["signal"],
            observation=item.get("observation"),
            result=item["result"],
            severity=None,
            confidence=item.get("confidence") or 0.0,
            weight=item.get("weight") or 0,
            observed_at=utcnow(),
        )
        db.add(ev)
        evidence_id_map[idx] = (ev.id, ev_public)

        sc = ScoreContribution(
            id=generate_uuid(),
            verification_id=ver_id,
            evidence_id=ev.id,
            check_id=f"CHK_{item['signal'].upper()}",
            rule_id=f"RULE_{item['signal'].upper()}",
            contribution=item.get("contribution", 0),
            reason=item.get("reason") or item["result"],
        )
        db.add(sc)

    for g in engine.risk_gates:
        db.add(
            VerificationRiskGate(
                id=generate_uuid(),
                verification_id=ver_id,
                gate=g.gate,
                cap=g.cap,
                reason=g.reason,
                triggered=True,
            )
        )

    await db.commit()

    evidence_out = []
    for idx, item in enumerate(engine.evidence_items):
        _, ev_public = evidence_id_map[idx]
        evidence_out.append(
            EvidenceItem(
                evidence_id=ev_public,
                signal=item["signal"],
                result=item["result"],
                weight=item.get("weight") or 0,
                source=item["source"],
                contribution=item.get("contribution"),
                reason=item.get("reason"),
            )
        )

    response = WebsiteVerifyResponse(
        verification_id=public_id,
        target=clean_target,
        target_type="website",
        assessment=Assessment(
            score=engine.score,
            raw_score=engine.raw_score,
            risk_level=engine.risk_level,
            confidence=engine.confidence,
            coverage=engine.coverage,
            status=engine.status,
            capped=engine.capped,
        ),
        recommendation=engine.recommendation,
        risk_gates=[RiskGateItem(gate=g.gate, cap=g.cap, reason=g.reason) for g in engine.risk_gates],
        unknowns=[UnknownItem(signal=u["signal"], reason=u["reason"]) for u in engine.unknowns],
        evidence=evidence_out,
        engine=settings.ENGINE_VERSION,
        created_at=datetime.now(timezone.utc),
        request_id=request_id,
    )
    from app.config import settings as _settings
    verify_cache.set(clean_target, response, ttl=getattr(_settings, "VERIFY_CACHE_TTL_SECONDS", 300))
    metrics_svc.incr("verify.completed")
    return response


async def get_verification(db: AsyncSession, id_or_public: str) -> Optional[WebsiteVerifyResponse]:
    q = select(Verification)
    if id_or_public.startswith("NV-"):
        q = q.where(Verification.public_id == id_or_public)
    else:
        q = q.where(Verification.id == id_or_public)
    result = await db.execute(q)
    ver = result.scalar_one_or_none()
    if not ver:
        return None

    ev_result = await db.execute(
        select(VerificationEvidence).where(VerificationEvidence.verification_id == ver.id)
    )
    evidence_rows = ev_result.scalars().all()

    sc_result = await db.execute(
        select(ScoreContribution).where(ScoreContribution.verification_id == ver.id)
    )
    contrib_map = {c.evidence_id: c for c in sc_result.scalars().all()}

    gate_result = await db.execute(
        select(VerificationRiskGate).where(VerificationRiskGate.verification_id == ver.id)
    )
    gates = gate_result.scalars().all()

    evidence_out = []
    unknowns = []
    for ev in evidence_rows:
        c = contrib_map.get(ev.id)
        evidence_out.append(
            EvidenceItem(
                evidence_id=ev.evidence_id,
                signal=ev.signal,
                result=ev.result,
                weight=ev.weight or 0,
                source=ev.source_id,
                contribution=c.contribution if c else 0,
                reason=c.reason if c else None,
            )
        )
        if ev.result in ("unknown", "unavailable"):
            unknowns.append(UnknownItem(signal=ev.signal, reason=c.reason if c else ev.result))

    return WebsiteVerifyResponse(
        verification_id=ver.public_id,
        target=ver.target,
        target_type=ver.target_type,
        assessment=Assessment(
            score=ver.score,
            raw_score=ver.raw_score,
            risk_level=ver.risk_level,
            confidence=ver.confidence,
            coverage=ver.coverage,
            status=ver.status,
            capped=ver.capped,
        ),
        recommendation=ver.recommendation,
        risk_gates=[RiskGateItem(gate=g.gate, cap=g.cap, reason=g.reason) for g in gates],
        unknowns=unknowns,
        evidence=evidence_out,
        engine=ver.engine,
        created_at=ver.created_at,
        request_id=ver.request_id,
    )


def _extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    import tldextract
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}".lower()
