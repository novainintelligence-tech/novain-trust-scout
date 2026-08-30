"""
NOVAIN TRUST configuration.

Production fails closed on weak secrets, SQLite, or DEBUG=true with ENVIRONMENT=production.
"""
from __future__ import annotations

from typing import List, Optional
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_WEAK_SECRETS = {
    "",
    "change-me",
    "change-me-in-production",
    "change-me-in-production-use-openssl-rand-hex-32",
    "change-me-admin-token",
    "change-me-admin",
    "replace-with-strong-secret",
    "replace-with-strong-admin-token",
    "secret",
    "admin",
    "password",
    "test",
    "novain-test-secret-key-32chars",
    "novain-test-admin-token",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "NOVAIN TRUST"
    APP_VERSION: str = "1.1.0"
    ENGINE_VERSION: str = "novain-risk-2.0"
    APP_DESCRIPTION: str = (
        "Trust and risk intelligence for machine callers. "
        "Every point of a score maps to a stored evidence record. "
        "Signals that cannot be observed are returned as unknown and are never scored."
    )

    DEBUG: bool = False
    # development | test | production
    ENVIRONMENT: str = "development"

    SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    ADMIN_TOKEN: str = "change-me-admin-token"

    # Development may use SQLite. Production MUST use PostgreSQL.
    DATABASE_URL: str = "sqlite+aiosqlite:///./novain_trust.db"

    # Connection pool (PostgreSQL production)
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    RATE_LIMIT_PER_MINUTE: int = 60

    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    HTTP_TIMEOUT_SECONDS: float = 10.0
    MAX_REDIRECTS: int = 5

    VERIFY_CACHE_TTL_SECONDS: int = 300
    BATCH_MAX_TARGETS: int = 20
    OPENPHISH_ENABLED: bool = True
    URLHAUS_ENABLED: bool = True

    # Comma-separated origins; empty = deny browser CORS in production
    CORS_ORIGINS: str = ""

    # Disable interactive docs in production by default
    ENABLE_DOCS: bool = False

    # Monetization (access layer only — does not affect risk engine)
    # false = legacy keys work without credits (default until Phase 3 rollout)
    BILLING_ENFORCE: bool = False
    BILLING_REQUIRE_ACCOUNT: bool = False

    # Provider-agnostic payment layer. Live PSPs are adapters; default is "fake" for tests.
    # Production MUST NOT use PAYMENT_PROVIDER=fake.
    PAYMENT_PROVIDER: str = "fake"
    PAYMENT_WEBHOOK_SECRET: str = "change-me-payment-webhook-secret"
    PAYMENT_WEBHOOK_MAX_AGE_SECONDS: int = 300
    PAYMENT_CHECKOUT_BASE_URL: str = "https://pay.novain.test"

    # Trusted proxy / host headers (optional)
    TRUSTED_HOSTS: str = ""

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_sqlite(self) -> bool:
        return "sqlite" in self.DATABASE_URL.lower()

    @property
    def cors_origin_list(self) -> List[str]:
        if self.CORS_ORIGINS.strip():
            return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
        if self.DEBUG and not self.is_production:
            return ["*"]
        return []

    @property
    def docs_enabled(self) -> bool:
        if self.is_production:
            return self.ENABLE_DOCS
        return True

    def validate_for_runtime(self) -> None:
        """Call at process start. Raises RuntimeError if production config is unsafe."""
        errors: List[str] = []

        if self.is_production:
            if self.is_sqlite:
                errors.append(
                    "Production requires PostgreSQL. "
                    "Set DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname"
                )
            if self.DEBUG:
                errors.append("DEBUG must be false when ENVIRONMENT=production")
            sk = (self.SECRET_KEY or "").strip()
            at = (self.ADMIN_TOKEN or "").strip()
            if sk.lower() in _WEAK_SECRETS or len(sk) < 32:
                errors.append(
                    "SECRET_KEY is missing, weak, or shorter than 32 characters. "
                    "Generate with: openssl rand -hex 32"
                )
            if at.lower() in _WEAK_SECRETS or len(at) < 24:
                errors.append(
                    "ADMIN_TOKEN is missing, weak, or shorter than 24 characters. "
                    "Generate with: openssl rand -hex 24"
                )
            if not self.DATABASE_URL.startswith(("postgresql+asyncpg://", "postgresql://")):
                errors.append("DATABASE_URL must use postgresql+asyncpg:// in production")

        if errors:
            raise RuntimeError(
                "NOVAIN TRUST refused to start due to unsafe configuration:\n- "
                + "\n- ".join(errors)
            )


settings = Settings()
# Fail fast on import for production misconfiguration
settings.validate_for_runtime()
