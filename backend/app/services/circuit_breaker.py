"""
Per-source circuit breaker.
Fail open to UNAVAILABLE observations — never invent PASS scores.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict
import structlog

logger = structlog.get_logger()


@dataclass
class BreakerState:
    failures: int = 0
    opened_at: float = 0.0
    half_open: bool = False


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 60.0):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._states: Dict[str, BreakerState] = {}

    def allow(self, name: str) -> bool:
        st = self._states.setdefault(name, BreakerState())
        if st.failures < self.failure_threshold:
            return True
        if time.monotonic() - st.opened_at >= self.cooldown_seconds:
            st.half_open = True
            return True
        return False

    def record_success(self, name: str) -> None:
        self._states[name] = BreakerState()

    def record_failure(self, name: str) -> None:
        st = self._states.setdefault(name, BreakerState())
        st.failures += 1
        if st.failures >= self.failure_threshold:
            st.opened_at = time.monotonic()
            st.half_open = False
            logger.warning("circuit_open", source=name, failures=st.failures)

    def status(self) -> Dict[str, str]:
        out = {}
        for name, st in self._states.items():
            if st.failures >= self.failure_threshold and not (
                time.monotonic() - st.opened_at >= self.cooldown_seconds
            ):
                out[name] = "OPEN"
            elif st.half_open:
                out[name] = "HALF_OPEN"
            else:
                out[name] = "CLOSED"
        return out


# Process-local breakers for outbound intelligence providers
provider_breakers = CircuitBreaker(failure_threshold=5, cooldown_seconds=120.0)
