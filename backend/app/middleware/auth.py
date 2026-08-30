from fastapi import Request, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services.auth import authenticate
from app.models.db import APIKey
from typing import Optional
import uuid

security = HTTPBearer(auto_error=False)


class AuthError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 401):
        self.code = code
        self.message = message
        self.status_code = status_code


def _auth_http_exception(code: str, message: str, status_code: int) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error": {"code": code, "message": message}},
    )


async def require_api_key(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    header = None
    if creds:
        header = f"Bearer {creds.credentials}"
    elif request.headers.get("authorization"):
        header = request.headers.get("authorization")

    key, err = await authenticate(db, header)
    if err == "KEY_REVOKED":
        raise _auth_http_exception("KEY_REVOKED", "API key has been revoked.", 403)
    if err == "KEY_EXPIRED":
        raise _auth_http_exception("KEY_EXPIRED", "API key has expired.", 403)
    if err == "UNAUTHORIZED" or key is None:
        raise _auth_http_exception("UNAUTHORIZED", "Invalid or missing API key.", 401)

    request.state.api_key = key
    return key


def get_or_create_request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id")
    if rid:
        return rid
    return str(uuid.uuid4())
