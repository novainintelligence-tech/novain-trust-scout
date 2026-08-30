"""
NOVAIN TRUST — canonical API error catalog (enterprise contract).

Every public error response MUST use:

{
  "error": {
    "code": "<CODE>",
    "message": "<human-readable>",
    "request_id": "<uuid>"
  }
}

Agents should branch on error.code, never on message text.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from fastapi.responses import ORJSONResponse


@dataclass(frozen=True)
class ErrorDef:
    code: str
    http_status: int
    message: str
    retryable: bool
    agent_action: str


# ---------------------------------------------------------------------------
# Canonical catalog — single source of truth
# ---------------------------------------------------------------------------
ERROR_CATALOG: Dict[str, ErrorDef] = {
    "UNAUTHORIZED": ErrorDef(
        code="UNAUTHORIZED",
        http_status=401,
        message="Invalid or missing API key.",
        retryable=False,
        agent_action="Fix or rotate credentials. Do not retry with the same token.",
    ),
    "KEY_REVOKED": ErrorDef(
        code="KEY_REVOKED",
        http_status=403,
        message="API key has been revoked.",
        retryable=False,
        agent_action="Stop. Request a new key from the operator.",
    ),
    "KEY_EXPIRED": ErrorDef(
        code="KEY_EXPIRED",
        http_status=403,
        message="API key has expired.",
        retryable=False,
        agent_action="Stop. Request a renewed key from the operator.",
    ),
    "FORBIDDEN": ErrorDef(
        code="FORBIDDEN",
        http_status=403,
        message="Access denied.",
        retryable=False,
        agent_action="Do not retry. Check key environment and permissions.",
    ),
    "RATE_LIMITED": ErrorDef(
        code="RATE_LIMITED",
        http_status=429,
        message="API rate limit exceeded.",
        retryable=True,
        agent_action="Back off until X-RateLimit-Reset / Retry-After, then retry.",
    ),
    "TARGET_BLOCKED": ErrorDef(
        code="TARGET_BLOCKED",
        http_status=422,
        message="Target is blocked by SSRF / private-network policy.",
        retryable=False,
        agent_action="Do not treat the URL as safe. Do not retry the same target.",
    ),
    "INVALID_TARGET": ErrorDef(
        code="INVALID_TARGET",
        http_status=400,
        message="Target URL is malformed or unsupported.",
        retryable=False,
        agent_action="Correct the URL syntax and scheme (http/https only).",
    ),
    "INVALID_REQUEST": ErrorDef(
        code="INVALID_REQUEST",
        http_status=400,
        message="Request validation failed.",
        retryable=False,
        agent_action="Fix request body/parameters against the OpenAPI schema.",
    ),
    "NOT_FOUND": ErrorDef(
        code="NOT_FOUND",
        http_status=404,
        message="Resource not found.",
        retryable=False,
        agent_action="Verify the verification_id or resource identifier.",
    ),
    "INTERNAL_ERROR": ErrorDef(
        code="INTERNAL_ERROR",
        http_status=500,
        message="An internal error occurred.",
        retryable=True,
        agent_action="Retry with exponential backoff; if persistent, fail closed.",
    ),
    "INSUFFICIENT_CREDITS": ErrorDef(
        code="INSUFFICIENT_CREDITS",
        http_status=402,
        message="Insufficient verification credits.",
        retryable=False,
        agent_action="Purchase or top up credits; do not retry until entitlement is restored.",
    ),
    "ACCOUNT_SUSPENDED": ErrorDef(
        code="ACCOUNT_SUSPENDED",
        http_status=403,
        message="Account is suspended.",
        retryable=False,
        agent_action="Contact operator; do not retry.",
    ),
    "PAYMENT_INVALID": ErrorDef(
        code="PAYMENT_INVALID",
        http_status=400,
        message="Payment could not be created or is invalid.",
        retryable=False,
        agent_action="Correct plan_code and retry checkout. Do not claim payment succeeded from the client.",
    ),
    "WEBHOOK_REJECTED": ErrorDef(
        code="WEBHOOK_REJECTED",
        http_status=401,
        message="Webhook signature or payload was rejected.",
        retryable=False,
        agent_action="Do not retry with a forged or unsigned payload.",
    ),
    "PAYMENT_NOT_CONFIRMED": ErrorDef(
        code="PAYMENT_NOT_CONFIRMED",
        http_status=402,
        message="Payment is not confirmed. No credits granted.",
        retryable=False,
        agent_action="Wait for a valid provider confirmation. Client-reported payment status is ignored.",
    ),
    "SERVICE_UNAVAILABLE": ErrorDef(
        code="SERVICE_UNAVAILABLE",
        http_status=503,
        message="Service temporarily unavailable.",
        retryable=True,
        agent_action="Retry after Retry-After if present; otherwise backoff.",
    ),
}


def error_body(
    code: str,
    message: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    meta = ERROR_CATALOG.get(code)
    msg = message or (meta.message if meta else "An error occurred.")
    err: Dict[str, Any] = {"code": code, "message": msg}
    if request_id:
        err["request_id"] = request_id
    return {"error": err}


def error_response(
    code: str,
    message: Optional[str] = None,
    status_code: Optional[int] = None,
    request_id: str = "",
    extra_headers: Optional[Mapping[str, str]] = None,
) -> ORJSONResponse:
    meta = ERROR_CATALOG.get(code)
    http_status = status_code or (meta.http_status if meta else 500)
    headers: Dict[str, str] = {}
    if request_id:
        headers["X-Request-ID"] = request_id
    if extra_headers:
        headers.update({k: str(v) for k, v in extra_headers.items()})
    return ORJSONResponse(
        status_code=http_status,
        content=error_body(code, message, request_id or None),
        headers=headers,
    )


def catalog_public() -> Dict[str, Any]:
    """Machine-readable catalog for agents and integrators."""
    return {
        "envelope": {
            "error": {
                "code": "string",
                "message": "string",
                "request_id": "string",
            }
        },
        "errors": [
            {
                "code": e.code,
                "http_status": e.http_status,
                "message": e.message,
                "retryable": e.retryable,
                "agent_action": e.agent_action,
            }
            for e in ERROR_CATALOG.values()
        ],
    }


# OpenAPI response fragments shared by routes
def openapi_error_content() -> dict:
    return {
        "application/json": {
            "schema": {
                "type": "object",
                "required": ["error"],
                "properties": {
                    "error": {
                        "type": "object",
                        "required": ["code", "message"],
                        "properties": {
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                            "request_id": {"type": "string"},
                        },
                    }
                },
            }
        }
    }


OPENAPI_ERROR_RESPONSES = {
    400: {"description": "INVALID_REQUEST or INVALID_TARGET", "content": openapi_error_content()},
    401: {"description": "UNAUTHORIZED", "content": openapi_error_content()},
    403: {"description": "KEY_REVOKED, KEY_EXPIRED, or FORBIDDEN", "content": openapi_error_content()},
    404: {"description": "NOT_FOUND", "content": openapi_error_content()},
    422: {"description": "TARGET_BLOCKED", "content": openapi_error_content()},
    429: {
        "description": "RATE_LIMITED",
        "content": openapi_error_content(),
        "headers": {
            "Retry-After": {
                "description": "Seconds until the rate-limit window resets",
                "schema": {"type": "integer"},
            },
            "X-RateLimit-Limit": {"schema": {"type": "integer"}},
            "X-RateLimit-Remaining": {"schema": {"type": "integer"}},
            "X-RateLimit-Reset": {
                "description": "Unix timestamp when the window resets",
                "schema": {"type": "integer"},
            },
        },
    },
    500: {"description": "INTERNAL_ERROR", "content": openapi_error_content()},
    503: {"description": "SERVICE_UNAVAILABLE", "content": openapi_error_content()},
}
