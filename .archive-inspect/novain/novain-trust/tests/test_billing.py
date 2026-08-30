"""Billing foundation — unit checks (no risk-engine coupling)."""
import pytest
from app.errors import ERROR_CATALOG
from app.services.billing import InsufficientCreditsError, AccountSuspendedError


def test_insufficient_credits_error_code():
    assert ERROR_CATALOG["INSUFFICIENT_CREDITS"].http_status == 402
    assert ERROR_CATALOG["INSUFFICIENT_CREDITS"].retryable is False
    assert ERROR_CATALOG["ACCOUNT_SUSPENDED"].http_status == 403


def test_billing_errors_are_exceptions():
    with pytest.raises(InsufficientCreditsError):
        raise InsufficientCreditsError()
    with pytest.raises(AccountSuspendedError):
        raise AccountSuspendedError()


def test_billing_does_not_import_risk_engine():
    import app.services.billing as b
    assert not hasattr(b, "run_engine")
    src = open(b.__file__).read()
    assert "risk_engine" not in src
    assert "ssrf" not in src
