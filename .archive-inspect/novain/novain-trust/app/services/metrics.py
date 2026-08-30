"""Lightweight in-process metrics for ops visibility (Phase C)."""
from __future__ import annotations
import time
from collections import defaultdict
from typing import Dict, List
import threading

_lock = threading.Lock()
_counters: Dict[str, int] = defaultdict(int)
_latencies: Dict[str, List[float]] = defaultdict(list)


def incr(name: str, n: int = 1) -> None:
    with _lock:
        _counters[name] += n


def observe_ms(name: str, ms: float) -> None:
    with _lock:
        bucket = _latencies[name]
        bucket.append(ms)
        if len(bucket) > 500:
            del bucket[:250]


def snapshot() -> Dict:
    with _lock:
        lat = {}
        for k, vals in _latencies.items():
            if not vals:
                continue
            s = sorted(vals)
            def pct(p):
                return round(s[min(len(s) - 1, int(len(s) * p / 100))], 1)
            lat[k] = {"count": len(s), "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99)}
        return {"counters": dict(_counters), "latency": lat, "ts": time.time()}
