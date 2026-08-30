"""Enterprise error contract tests."""
import pytest
from app.errors import ERROR_CATALOG, error_body, error_response, catalog_public


def test_catalog_has_required_codes():
    required = {
        "UNAUTHORIZED",
        "KEY_REVOKED",
        "KEY_EXPIRED",
        "RATE_LIMITED",
        "TARGET_BLOCKED",
        "INVALID_TARGET",
        "INVALID_REQUEST",
        "NOT_FOUND",
        "INTERNAL_ERROR",
        "INSUFFICIENT_CREDITS",
        "PAYMENT_INVALID",
        "WEBHOOK_REJECTED",
        "PAYMENT_NOT_CONFIRMED",
        "SERVICE_UNAVAILABLE",
    }
    assert required <= set(ERROR_CATALOG.keys())


def test_error_body_shape():
    body = error_body("UNAUTHORIZED", request_id="rid-1")
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["request_id"] == "rid-1"
    assert "message" in body["error"]


def test_error_response_status():
    r = error_response("RATE_LIMITED", request_id="x", extra_headers={"Retry-After": "30"})
    assert r.status_code == 429
    # headers may be in raw form
    headers = {k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v for k, v in r.headers.items()}
    assert headers.get("retry-after") == "30" or "Retry-After" in str(r.headers)


def test_catalog_public_machine_readable():
    cat = catalog_public()
    assert "errors" in cat
    assert any(e["code"] == "KEY_REVOKED" for e in cat["errors"])
    assert all("retryable" in e and "agent_action" in e for e in cat["errors"])


def test_rate_limited_is_retryable():
    assert ERROR_CATALOG["RATE_LIMITED"].retryable is True
    assert ERROR_CATALOG["KEY_REVOKED"].retryable is False
    assert ERROR_CATALOG["TARGET_BLOCKED"].http_status == 422


def test_hash_secret_is_hmac_not_plain_sha256():
    from app.services.auth import hash_secret
    import hashlib
    secret = "test-secret-value"
    h = hash_secret(secret)
    plain = hashlib.sha256(secret.encode()).hexdigest()
    assert h != plain
    assert len(h) == 64


def test_constant_time_compare():
    from app.services.auth import constant_time_compare
    assert constant_time_compare("abc", "abc") is True
    assert constant_time_compare("abc", "abd") is False
