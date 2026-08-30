"""
novain-risk-2.0

SOURCE → OBSERVATION → EVIDENCE → CHECK → RISK RULE → SCORE CONTRIBUTION
→ RAW SCORE → RISK GATES → FINAL SCORE

Unknown / Unavailable always contribute 0.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from app.adapters.base import Observation, SignalResult, SourceReport
import structlog

logger = structlog.get_logger()

# Explicit scoring rules: signal → (pass_points, fail_points)
# Unknown/Unavailable always 0 regardless of table.
RULES: Dict[str, Tuple[int, int]] = {
    # http
    "target_reachable": (5, -8),
    "https_scheme": (3, -2),
    "response_time": (2, -1),
    "redirect_safe": (0, -15),  # fail = blocked unsafe redirect
    # tls
    "tls_valid": (8, -10),
    "tls_expiry": (3, -4),
    # dns
    "dns_a_record": (4, -5),
    "spf_present": (3, -1),
    "dmarc_present": (4, -1),
    "nameservers_present": (2, -2),
    # rdap
    "domain_registered": (6, 0),
    "domain_age": (0, 0),  # age is observed; gates handle very new domains
    "registrar_present": (3, 0),
    "registrar_abuse_contact": (2, 0),
    "domain_expiry": (4, -3),
    # content
    "has_contact_info": (3, -1),
    "has_privacy_policy": (3, -1),
    "has_about_page": (2, 0),
    # reputation
    "safe_browsing": (12, -40),
    "urlhaus": (10, -35),
    "openphish": (10, -35),
    "virustotal": (8, -30),
    # certificate transparency
    "ct_presence": (4, -2),
    "ct_history_depth": (2, 0),
}

# Baseline so a fully observed clean site lands near 70–90
BASELINE = 40


@dataclass
class Contribution:
    signal: str
    source: str
    result: str
    contribution: int
    reason: str
    rule_id: str
    weight: int
    evidence_ref: Optional[str] = None


@dataclass
class RiskGateResult:
    gate: str
    cap: Optional[int]
    reason: str


@dataclass
class EngineResult:
    raw_score: int
    score: int
    capped: bool
    risk_level: str
    confidence: float
    coverage: float
    status: str
    recommendation: str
    contributions: List[Contribution]
    risk_gates: List[RiskGateResult]
    unknowns: List[Dict[str, str]]
    evidence_items: List[Dict[str, Any]]


def _contribution_for(obs: Observation) -> int:
    if obs.result in (SignalResult.UNKNOWN, SignalResult.UNAVAILABLE):
        return 0
    pass_pts, fail_pts = RULES.get(obs.signal, (0, 0))
    if obs.result == SignalResult.PASS:
        return pass_pts
    if obs.result == SignalResult.FAIL:
        return fail_pts
    return 0


def _apply_domain_age_gate(observations: List[Observation]) -> Optional[RiskGateResult]:
    for obs in observations:
        if obs.signal == "domain_age" and obs.result == SignalResult.PASS:
            days = (obs.observation or {}).get("age_days")
            if days is not None and days < 30:
                return RiskGateResult(
                    gate="domain_age",
                    cap=55,
                    reason=f"Domain younger than 30 days ({days} days). Score capped.",
                )
            if days is not None and days < 90:
                return RiskGateResult(
                    gate="domain_age",
                    cap=70,
                    reason=f"Domain younger than 90 days ({days} days). Score capped.",
                )
    return None


def _apply_reachability_gate(observations: List[Observation]) -> Optional[RiskGateResult]:
    for obs in observations:
        if obs.signal == "target_reachable" and obs.result == SignalResult.FAIL:
            return RiskGateResult(
                gate="target_unreachable",
                cap=25,
                reason="Target did not respond successfully.",
            )
        if obs.signal == "redirect_safe" and obs.result == SignalResult.FAIL:
            return RiskGateResult(
                gate="critical_security_indicator",
                cap=10,
                reason="Unsafe redirect destination blocked by SSRF controls.",
            )
    return None


def _apply_reputation_gate(observations: List[Observation]) -> Optional[RiskGateResult]:
    critical_signals = ("safe_browsing", "urlhaus", "openphish", "virustotal")
    for obs in observations:
        if obs.signal in critical_signals and obs.result == SignalResult.FAIL:
            return RiskGateResult(
                gate="critical_security_indicator",
                cap=15,
                reason=f"Reputation provider reported a threat match ({obs.signal}).",
            )
    return None


def run_engine(source_reports: List[SourceReport]) -> EngineResult:
    all_obs: List[Observation] = []
    for sr in source_reports:
        for obs in sr.observations:
            if obs.signal.startswith("_"):  # internal
                continue
            all_obs.append(obs)

    contributions: List[Contribution] = []
    unknowns: List[Dict[str, str]] = []
    evidence_items: List[Dict[str, Any]] = []

    raw = BASELINE
    observed_count = 0
    expected_signals = set(RULES.keys())
    seen_signals = set()

    for obs in all_obs:
        seen_signals.add(obs.signal)
        contrib = _contribution_for(obs)
        rule_id = f"RULE_{obs.signal.upper()}"
        contributions.append(
            Contribution(
                signal=obs.signal,
                source=obs.source,
                result=obs.result.value,
                contribution=contrib,
                reason=obs.reason or obs.result.value,
                rule_id=rule_id,
                weight=obs.weight,
            )
        )
        raw += contrib

        if obs.result in (SignalResult.UNKNOWN, SignalResult.UNAVAILABLE):
            unknowns.append({"signal": obs.signal, "reason": obs.reason or obs.result.value})
        else:
            observed_count += 1

        evidence_items.append(
            {
                "signal": obs.signal,
                "result": obs.result.value,
                "weight": obs.weight,
                "source": obs.source,
                "contribution": contrib,
                "reason": obs.reason,
                "observation": obs.observation,
                "confidence": obs.confidence,
            }
        )

    raw = max(0, min(100, raw))

    # Risk gates
    gates: List[RiskGateResult] = []
    for fn in (_apply_reachability_gate, _apply_reputation_gate, _apply_domain_age_gate):
        g = fn(all_obs)
        if g:
            gates.append(g)

    score = raw
    capped = False
    for g in gates:
        if g.cap is not None and score > g.cap:
            score = g.cap
            capped = True

    # Coverage: fraction of expected signals that were actually observed (not unknown/unavailable)
    available = sum(
        1
        for o in all_obs
        if o.signal in expected_signals and o.result not in (SignalResult.UNKNOWN, SignalResult.UNAVAILABLE)
    )
    total_expected = len(expected_signals)
    coverage = round(available / total_expected, 2) if total_expected else 0.0

    # Confidence: average confidence of observed (non-unknown) signals
    conf_vals = [
        o.confidence
        for o in all_obs
        if o.result not in (SignalResult.UNKNOWN, SignalResult.UNAVAILABLE) and o.confidence > 0
    ]
    confidence = round(sum(conf_vals) / len(conf_vals), 2) if conf_vals else 0.0

    # Risk level & status
    if score >= 85:
        risk_level, status, rec = "very_low", "PASS", "proceed"
    elif score >= 70:
        risk_level, status, rec = "low", "PASS", "proceed"
    elif score >= 50:
        risk_level, status, rec = "medium", "WARNING", "proceed_with_caution"
    elif score >= 30:
        risk_level, status, rec = "high", "FAIL", "review_required"
    else:
        risk_level, status, rec = "critical", "FAIL", "do_not_proceed"

    # Critical gates force status
    for g in gates:
        if g.gate in ("critical_security_indicator", "target_unreachable"):
            status = "FAIL"
            if rec == "proceed":
                rec = "do_not_proceed"

    return EngineResult(
        raw_score=raw,
        score=score,
        capped=capped,
        risk_level=risk_level,
        confidence=confidence,
        coverage=coverage,
        status=status,
        recommendation=rec,
        contributions=contributions,
        risk_gates=gates,
        unknowns=unknowns,
        evidence_items=evidence_items,
    )
