from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from enum import Enum


class SignalResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


@dataclass
class Observation:
    source: str
    signal: str
    result: SignalResult
    observation: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    severity: Optional[str] = None
    weight: int = 0  # max points this signal can contribute if PASS
    reason: str = ""
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SourceReport:
    source: str
    status: str  # ACTIVE | DEGRADED | UNAVAILABLE
    observations: List[Observation] = field(default_factory=list)
    error: Optional[str] = None
