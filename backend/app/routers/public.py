from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
import time
from sqlalchemy import select, text

from app.database import get_db
from app.middleware.auth import require_api_key, get_or_create_request_id, AuthError
from app.models.db import APIKey
from app.models.schemas import (
    WebsiteVerifyRequest, WebsiteVerifyResponse, HealthResponse, ErrorResponse,
    BatchVerifyRequest, BatchVerifyResponse, BatchItemResult,
)
from app.services.orchestrator import run_website_verification, get_verification
from app.services.auth import record_usage
from app.services.rate_limit import check_and_increment, RateLimitExceeded
from app.security.ssrf import TargetBlockedError, InvalidTargetError
from app.config import settings
from app.errors import error_response, catalog_public, OPENAPI_ERROR_RESPONSES, ERROR_CATALOG
from app.services.billing import (
    consume_credit,
    InsufficientCreditsError,
    AccountSuspendedError,
    EntitlementInactiveError,
)
import structlog
import time as _time

logger = structlog.get_logger()

router = APIRouter(prefix="/api/public/v1", tags=["Public API"])



@router.post(
    "/verify/website",
    response_model=WebsiteVerifyResponse,
    responses={**OPENAPI_ERROR_RESPONSES},
    summary="Verify a website",
)
async def verify_website(
    body: WebsiteVerifyRequest,
    request: Request,
    response: Response,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    request_id = get_or_create_request_id(request)
    response.headers["X-Request-ID"] = request_id
    start = time.perf_counter()

    # P0-1: real per-key rate limit
    try:
        limit, remaining, reset = await check_and_increment(db, api_key)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset)
    except RateLimitExceeded as e:
        retry_after = max(1, int(e.reset - _time.time()))
        return error_response(
            "RATE_LIMITED",
            "API rate limit exceeded.",
            429,
            request_id,
            {
                "X-RateLimit-Limit": str(e.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(e.reset),
                "Retry-After": str(retry_after),
            },
        )

    # Monetization: entitlement check + atomic credit consume (does not touch risk engine)
    try:
        await consume_credit(db, api_key)
    except InsufficientCreditsError as e:
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 402, (time.perf_counter()-start)*1000)
        return error_response("INSUFFICIENT_CREDITS", e.message, 402, request_id)
    except AccountSuspendedError as e:
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 403, (time.perf_counter()-start)*1000)
        return error_response("ACCOUNT_SUSPENDED", e.message, 403, request_id)
    except EntitlementInactiveError as e:
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 403, (time.perf_counter()-start)*1000)
        return error_response("FORBIDDEN", e.message, 403, request_id)

    try:
        result = await run_website_verification(
            db=db,
            target=body.target,
            request_id=request_id,
            api_key_id=api_key.id,
        )
        latency = (time.perf_counter() - start) * 1000
        await record_usage(
            db, api_key, request_id, "/api/public/v1/verify/website",
            status_code=200, latency_ms=latency, verification_id=result.verification_id,
        )
        return result
    except AuthError as e:
        return error_response(e.code, e.message, e.status_code, request_id)
    except TargetBlockedError as e:
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 422, (time.perf_counter()-start)*1000)
        return error_response("TARGET_BLOCKED", str(e), 422, request_id)
    except InvalidTargetError as e:
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 400, (time.perf_counter()-start)*1000)
        return error_response("INVALID_TARGET", str(e), 400, request_id)
    except ValueError as e:
        msg = str(e)
        if msg.startswith("TARGET_BLOCKED:"):
            await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 422, (time.perf_counter()-start)*1000)
            return error_response("TARGET_BLOCKED", msg.split(":", 1)[1].strip(), 422, request_id)
        if msg.startswith("INVALID_TARGET:"):
            await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 400, (time.perf_counter()-start)*1000)
            return error_response("INVALID_TARGET", msg.split(":", 1)[1].strip(), 400, request_id)
        return error_response("INVALID_REQUEST", msg, 400, request_id)
    except Exception as e:
        logger.exception("verify_error", error=str(e), request_id=request_id)
        await record_usage(db, api_key, request_id, "/api/public/v1/verify/website", 500, (time.perf_counter()-start)*1000)
        return error_response("INTERNAL_ERROR", "An internal error occurred.", 500, request_id)


@router.get(
    "/verifications/{verification_id}",
    responses={**OPENAPI_ERROR_RESPONSES},
    response_model=WebsiteVerifyResponse,
    summary="Retrieve a stored verification",
)
async def retrieve_verification(
    verification_id: str,
    request: Request,
    response: Response,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    request_id = get_or_create_request_id(request)
    response.headers["X-Request-ID"] = request_id
    start = time.perf_counter()

    try:
        limit, remaining, reset = await check_and_increment(db, api_key)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset)
    except RateLimitExceeded as e:
        retry_after = max(1, int(e.reset - _time.time()))
        return error_response(
            "RATE_LIMITED",
            "API rate limit exceeded.",
            429,
            request_id,
            {
                "X-RateLimit-Limit": str(e.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(e.reset),
                "Retry-After": str(retry_after),
            },
        )

    result = await get_verification(db, verification_id)
    if not result:
        await record_usage(db, api_key, request_id, f"/api/public/v1/verifications/{verification_id}", 404, (time.perf_counter()-start)*1000)
        return error_response("NOT_FOUND", "Verification not found.", 404, request_id)
    await record_usage(db, api_key, request_id, f"/api/public/v1/verifications/{verification_id}", 200, (time.perf_counter()-start)*1000, verification_id)
    return result


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
)
async def health(db: AsyncSession = Depends(get_db)):
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    # Phase A/C: source capability registry
    rep_active = bool(
        settings.GOOGLE_SAFE_BROWSING_API_KEY
        or settings.VIRUSTOTAL_API_KEY
        or getattr(settings, "URLHAUS_ENABLED", True)
        or getattr(settings, "OPENPHISH_ENABLED", True)
    )
    sources = {
        "http": "ACTIVE",
        "tls": "ACTIVE",
        "dns": "ACTIVE",
        "whois": "ACTIVE",
        "content": "ACTIVE",
        "reputation": "ACTIVE" if rep_active else "UNAVAILABLE",
        "ct": "ACTIVE",
        "safe_browsing": "ACTIVE" if settings.GOOGLE_SAFE_BROWSING_API_KEY else "UNAVAILABLE",
        "urlhaus": "ACTIVE" if getattr(settings, "URLHAUS_ENABLED", True) else "UNAVAILABLE",
        "openphish": "ACTIVE" if getattr(settings, "OPENPHISH_ENABLED", True) else "UNAVAILABLE",
        "virustotal": "ACTIVE" if settings.VIRUSTOTAL_API_KEY else "UNAVAILABLE",
    }

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        api_version=settings.APP_VERSION,
        engine=settings.ENGINE_VERSION,
        sources=sources,
        database=db_status,
        timestamp=datetime.now(timezone.utc),
    )


@router.post(
    "/verify/website/batch",
    response_model=BatchVerifyResponse,
    summary="Verify up to 20 websites in one request",
)
async def verify_website_batch(
    body: BatchVerifyRequest,
    request: Request,
    response: Response,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Phase B: batch verify. Each target is independently validated (SSRF, rate limit once)."""
    from app.config import settings as _settings
    request_id = get_or_create_request_id(request)
    response.headers["X-Request-ID"] = request_id
    start = time.perf_counter()

    try:
        limit, remaining, reset = await check_and_increment(db, api_key)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset)
    except RateLimitExceeded as e:
        retry_after = max(1, int(e.reset - _time.time()))
        return error_response(
            "RATE_LIMITED",
            "API rate limit exceeded.",
            429,
            request_id,
            {
                "X-RateLimit-Limit": str(e.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(e.reset),
                "Retry-After": str(retry_after),
            },
        )

    max_n = getattr(_settings, "BATCH_MAX_TARGETS", 20)
    targets = body.targets[:max_n]
    results = []
    for target in targets:
        try:
            result = await run_website_verification(
                db=db,
                target=target,
                request_id=request_id,
                api_key_id=api_key.id,
            )
            results.append(BatchItemResult(target=target, ok=True, result=result))
        except TargetBlockedError as e:
            results.append(BatchItemResult(target=target, ok=False, error={"code": "TARGET_BLOCKED", "message": str(e)}))
        except InvalidTargetError as e:
            results.append(BatchItemResult(target=target, ok=False, error={"code": "INVALID_TARGET", "message": str(e)}))
        except Exception as e:
            logger.exception("batch_item_failed", target=target)
            results.append(BatchItemResult(target=target, ok=False, error={"code": "INTERNAL_ERROR", "message": type(e).__name__}))

    latency = (time.perf_counter() - start) * 1000
    await record_usage(db, api_key, request_id, "/api/public/v1/verify/website/batch", 200, latency)
    return BatchVerifyResponse(results=results, engine=_settings.ENGINE_VERSION, request_id=request_id)



@router.get(
    "/errors",
    summary="Error catalog for machine callers",
    tags=["Public API"],
)
async def list_errors():
    """Canonical error codes, HTTP statuses, retryability, and agent actions."""
    return catalog_public()
