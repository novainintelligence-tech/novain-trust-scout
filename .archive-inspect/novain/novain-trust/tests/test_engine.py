from app.adapters.base import Observation, SignalResult, SourceReport
from app.engine.risk_engine import run_engine, BASELINE


def test_unknown_contributes_zero():
    reports = [
        SourceReport(
            source="whois",
            status="UNAVAILABLE",
            observations=[
                Observation(
                    source="whois",
                    signal="domain_age",
                    result=SignalResult.UNAVAILABLE,
                    weight=10,
                    reason="WHOIS unavailable",
                )
            ],
        )
    ]
    result = run_engine(reports)
    for c in result.contributions:
        if c.signal == "domain_age":
            assert c.contribution == 0
    assert any(u["signal"] == "domain_age" for u in result.unknowns)


def test_pass_contributes_positive():
    reports = [
        SourceReport(
            source="tls",
            status="ACTIVE",
            observations=[
                Observation(
                    source="tls",
                    signal="tls_valid",
                    result=SignalResult.PASS,
                    weight=8,
                    confidence=0.8,
                    reason="Valid",
                )
            ],
        )
    ]
    result = run_engine(reports)
    contrib = next(c for c in result.contributions if c.signal == "tls_valid")
    assert contrib.contribution == 8
    assert result.raw_score == BASELINE + 8


def test_risk_gate_caps_score():
    reports = [
        SourceReport(
            source="http",
            status="ACTIVE",
            observations=[
                Observation(
                    source="http",
                    signal="target_reachable",
                    result=SignalResult.FAIL,
                    weight=5,
                    reason="timeout",
                )
            ],
        )
    ]
    result = run_engine(reports)
    assert result.score <= 25
    assert any(g.gate == "target_unreachable" for g in result.risk_gates)
