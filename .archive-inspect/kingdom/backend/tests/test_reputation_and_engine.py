import pytest
from app.adapters.base import Observation, SignalResult, SourceReport
from app.engine.risk_engine import run_engine, _contribution_for


def test_unavailable_contributes_zero():
    obs = Observation(source="reputation", signal="safe_browsing", result=SignalResult.UNAVAILABLE, weight=12)
    assert _contribution_for(obs) == 0


def test_unknown_contributes_zero():
    obs = Observation(source="reputation", signal="openphish", result=SignalResult.UNKNOWN, weight=10)
    assert _contribution_for(obs) == 0


def test_reputation_fail_triggers_gate():
    reports = [
        SourceReport(
            source="reputation",
            status="ACTIVE",
            observations=[
                Observation(
                    source="reputation",
                    signal="urlhaus",
                    result=SignalResult.FAIL,
                    weight=10,
                    confidence=0.9,
                    reason="listed",
                )
            ],
        )
    ]
    result = run_engine(reports)
    assert any(g.gate == "critical_security_indicator" for g in result.risk_gates)
    assert result.score <= 15
