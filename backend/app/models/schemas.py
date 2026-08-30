from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re


class RiskLevel(str, Enum):
    very_low = "very_low"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AssessmentStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Recommendation(str, Enum):
    proceed = "proceed"
    proceed_with_caution = "proceed_with_caution"
    review_required = "review_required"
    do_not_proceed = "do_not_proceed"


# ---------- Request ----------

class WebsiteVerifyRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048, description="URL or domain to verify, e.g. https://example.com")

    @field_validator("target")
    @classmethod
    def normalize_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target is required")
        return v


# ---------- Response building blocks ----------

class Assessment(BaseModel):
    score: int = Field(..., ge=0, le=100)
    raw_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    coverage: float = Field(..., ge=0.0, le=1.0)
    status: AssessmentStatus
    capped: bool


class RiskGateItem(BaseModel):
    gate: str
    cap: Optional[int] = None
    reason: str


class UnknownItem(BaseModel):
    signal: str
    reason: str


class EvidenceItem(BaseModel):
    evidence_id: str
    signal: str
    result: str  # pass | fail | unknown | unavailable
    weight: int
    source: str
    contribution: Optional[int] = None
    reason: Optional[str] = None


class WebsiteVerifyResponse(BaseModel):
    verification_id: str
    target: str
    target_type: str = "website"
    assessment: Assessment
    recommendation: str
    risk_gates: List[RiskGateItem]
    unknowns: List[UnknownItem]
    evidence: List[EvidenceItem]
    engine: str
    created_at: datetime
    request_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    api_version: str
    engine: str
    sources: Dict[str, str]
    database: str
    timestamp: datetime


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


# Documented agent error codes (see GET /api/public/v1/errors)
AGENT_ERROR_CODES = (
    "UNAUTHORIZED",
    "KEY_REVOKED",
    "KEY_EXPIRED",
    "FORBIDDEN",
    "RATE_LIMITED",
    "TARGET_BLOCKED",
    "INVALID_TARGET",
    "INVALID_REQUEST",
    "NOT_FOUND",
    "INTERNAL_ERROR",
    "SERVICE_UNAVAILABLE",
)


# ---------- Admin (protected) ----------

class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    owner_email: Optional[str] = None
    environment: str = Field(default="test", pattern="^(live|test)$")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)


class CreateKeyResponse(BaseModel):
    key_id: str
    api_key: str  # shown only once: nv_live_<key_id>_<secret>
    name: str
    environment: str
    rate_limit_per_minute: int
    created_at: datetime


class KeyListItem(BaseModel):
    key_id: str
    name: str
    prefix: str
    is_active: bool
    is_revoked: bool
    rate_limit_per_minute: int
    created_at: datetime
    last_used_at: Optional[datetime] = None
    request_count: int


class BatchVerifyRequest(BaseModel):
    targets: List[str] = Field(..., min_length=1, max_length=20, description="Up to 20 URLs/domains")

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        out = []
        for item in v:
            s = (item or "").strip()
            if not s:
                raise ValueError("empty target not allowed")
            out.append(s)
        if len(out) > 20:
            raise ValueError("maximum 20 targets per batch")
        return out


class BatchItemResult(BaseModel):
    target: str
    ok: bool
    result: Optional[WebsiteVerifyResponse] = None
    error: Optional[Dict[str, Any]] = None


class BatchVerifyResponse(BaseModel):
    results: List[BatchItemResult]
    engine: str
    request_id: Optional[str] = None
