"""
Short TTL cache for identical target + engine version.
Security: only caches successful responses; never caches auth or keys.
"""
from __future__ import annotations
import time
import hashlib
from typing import Any, Dict, Optional, Tuple
from app.config import settings

_CACHE: Dict[str, Tuple[float, Any]] = {}
DEFAULT_TTL_SECONDS = 300  # 5 minutes


def _key(target: str) -> str:
    norm = target.strip().lower()
    raw = f"{settings.ENGINE_VERSION}|{norm}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get(target: str) -> Optional[Any]:
    k = _key(target)
    item = _CACHE.get(k)
    if not item:
        return None
    expires, value = item
    if time.monotonic() > expires:
        _CACHE.pop(k, None)
        return None
    return value


def set(target: str, value: Any, ttl: int = DEFAULT_TTL_SECONDS) -> None:
    # Cap memory: simple eviction of oldest when large
    if len(_CACHE) > 2000:
        oldest = sorted(_CACHE.items(), key=lambda x: x[1][0])[:500]
        for ok, _ in oldest:
            _CACHE.pop(ok, None)
    _CACHE[_key(target)] = (time.monotonic() + ttl, value)


def stats() -> Dict[str, int]:
    return {"entries": len(_CACHE)}
