"""
NOVAIN TRUST FastAPI application — production entrypoint.
"""
from __future__ import annotations

import structlog
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.database import init_db
from app.routers import public, admin, billing
from app.middleware.auth import AuthError
from app.services import metrics as metrics_svc

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(10 if settings.DEBUG else 20),
)
logger = structlog.get_logger()




class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies (default 1 MiB)."""

    MAX_BODY = 1_048_576

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.MAX_BODY:
                    from app.errors import error_response
                    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
                    return error_response(
                        "INVALID_REQUEST",
                        "Request body too large.",
                        400,
                        rid,
                    )
            except ValueError:
                pass
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_for_runtime()
    logger.info(
        "starting",
        app=settings.APP_NAME,
        engine=settings.ENGINE_VERSION,
        environment=settings.ENVIRONMENT,
        production=settings.is_production,
    )
    await init_db()
    yield
    logger.info("shutdown")


_docs = "/docs" if settings.docs_enabled else None
_redoc = "/redoc" if settings.docs_enabled else None
_openapi = "/api/public/v1/openapi.json"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
    docs_url=_docs,
    redoc_url=_redoc,
    openapi_url=_openapi,
    contact={"name": "NOVAIN TRUST", "url": "https://api.novain.trust"},
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)

if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Admin-Token"],
    )


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = rid
    # Never log Authorization or raw tokens
    logger.debug(
        "request",
        method=request.method,
        path=request.url.path,
        request_id=rid,
    )
    try:
        response = await call_next(request)
    except AuthError as e:
        return ORJSONResponse(
            status_code=e.status_code,
            content={"error": {"code": e.code, "message": e.message, "request_id": rid}},
            headers={"X-Request-ID": rid},
        )
    except Exception:
        logger.exception("unhandled_error", request_id=rid, path=request.url.path)
        metrics_svc.incr("http.5xx")
        return ORJSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An internal error occurred.",
                    "request_id": rid,
                }
            },
            headers={"X-Request-ID": rid},
        )
    response.headers["X-Request-ID"] = rid
    response.headers["X-Engine"] = settings.ENGINE_VERSION
    if response.status_code >= 500:
        metrics_svc.incr("http.5xx")
    elif response.status_code == 429:
        metrics_svc.incr("http.429")
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    rid = getattr(request.state, "request_id", str(uuid.uuid4()))
    return ORJSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "INVALID_REQUEST",
                "message": "Request validation failed.",
                "request_id": rid,
            }
        },
        headers={"X-Request-ID": rid},
    )


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    rid = getattr(request.state, "request_id", str(uuid.uuid4()))
    return ORJSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "request_id": rid}},
        headers={"X-Request-ID": rid},
    )


@app.exception_handler(StarletteHTTPException)
async def http_handler(request: Request, exc: StarletteHTTPException):
    from app.errors import error_body
    rid = getattr(request.state, "request_id", str(uuid.uuid4()))
    detail = exc.detail
    # Prefer structured detail from auth layer (preserves KEY_EXPIRED vs KEY_REVOKED)
    if isinstance(detail, dict) and "error" in detail:
        body = detail
        err = body.get("error") or {}
        if "request_id" not in err:
            body = {"error": {**err, "request_id": rid}}
        return ORJSONResponse(status_code=exc.status_code, content=body, headers={"X-Request-ID": rid})
    # Fallback mapping only when detail is unstructured
    code = "INTERNAL_ERROR"
    if exc.status_code == 401:
        code = "UNAUTHORIZED"
    elif exc.status_code == 403:
        code = "FORBIDDEN"
    elif exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code == 422:
        code = "TARGET_BLOCKED"
    elif exc.status_code == 429:
        code = "RATE_LIMITED"
    elif exc.status_code == 503:
        code = "SERVICE_UNAVAILABLE"
    return ORJSONResponse(
        status_code=exc.status_code,
        content=error_body(code, str(exc.detail), rid),
        headers={"X-Request-ID": rid},
    )


app.include_router(public.router)
app.include_router(admin.router)
app.include_router(billing.router)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.APP_NAME,
        "engine": settings.ENGINE_VERSION,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "openapi": _openapi,
        "health": "/api/public/v1/health",
    }


@app.get("/api/public/v1/version", include_in_schema=True, tags=["Public API"])
async def version():
    return {
        "name": settings.APP_NAME,
        "api_version": settings.APP_VERSION,
        "engine": settings.ENGINE_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/api/public/v1/ready", include_in_schema=False)
async def ready():
    """Kubernetes-style readiness: DB must answer."""
    from app.database import engine
    from sqlalchemy import text

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ready", "engine": settings.ENGINE_VERSION}
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "engine": settings.ENGINE_VERSION},
        )
