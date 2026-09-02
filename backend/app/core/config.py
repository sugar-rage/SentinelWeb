"""
Application settings loaded from environment variables.

Uses python-dotenv to read .env file at project root.
All settings have sensible defaults matching the development environment.
"""

import os
import ipaddress
from typing import Final
from urllib.parse import urlsplit
from dotenv import load_dotenv

load_dotenv()


_DEVELOPMENT_JWT_SECRET: Final = "sentinelweb-development-only-secret-not-for-production"
_INSECURE_JWT_SECRETS: Final = {
    "",
    "sentinelweb-jwt-secret-key-change-in-production",
    _DEVELOPMENT_JWT_SECRET,
}


class Settings:
    """Centralized configuration with production-safe validation."""

    def __init__(self) -> None:
        self.ENVIRONMENT = os.getenv("SENTINELWEB_ENV", "development").strip().lower()
        configured_database_url = os.getenv("DATABASE_URL", "").strip()
        self.DATABASE_URL = configured_database_url or "postgresql://localhost:5432/sentinelweb"
        self._database_url_configured = bool(configured_database_url)
        self.JWT_SECRET = os.getenv("JWT_SECRET", _DEVELOPMENT_JWT_SECRET)
        self.JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
        self.JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
        self.RISK_BLOCK_THRESHOLD = int(os.getenv("RISK_BLOCK_THRESHOLD", "80"))
        self.ADMIN_BOOTSTRAP_SECRET = os.getenv("ADMIN_BOOTSTRAP_SECRET", "")
        self.AUTH_RATE_LIMIT_ATTEMPTS = int(os.getenv("AUTH_RATE_LIMIT_ATTEMPTS", "5"))
        self.AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
        self.AUTH_LOCKOUT_SECONDS = int(os.getenv("AUTH_LOCKOUT_SECONDS", "900"))
        self.ATTACK_PAYLOAD_EVIDENCE_CHARS = int(os.getenv("ATTACK_PAYLOAD_EVIDENCE_CHARS", "4096"))
        self.WAF_UPSTREAM_URL = os.getenv("WAF_UPSTREAM_URL", "http://127.0.0.1:9000").strip()
        self.WAF_UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("WAF_UPSTREAM_TIMEOUT_SECONDS", "5"))
        self.WAF_MAX_REQUEST_BODY_BYTES = int(os.getenv("WAF_MAX_REQUEST_BODY_BYTES", "65536"))
        self.WAF_MAX_UPSTREAM_RESPONSE_BYTES = int(os.getenv("WAF_MAX_UPSTREAM_RESPONSE_BYTES", "1048576"))
        self.WAF_MAX_URL_BYTES = int(os.getenv("WAF_MAX_URL_BYTES", "8192"))
        self.WAF_MAX_HEADER_BYTES = int(os.getenv("WAF_MAX_HEADER_BYTES", "32768"))
        self.WAF_MAX_JSON_DEPTH = int(os.getenv("WAF_MAX_JSON_DEPTH", "20"))
        self.WAF_MAX_FORM_FIELDS = int(os.getenv("WAF_MAX_FORM_FIELDS", "200"))
        self.WAF_MAX_CONCURRENT_REQUESTS = int(os.getenv("WAF_MAX_CONCURRENT_REQUESTS", "100"))
        self.ADAPTIVE_RISK_WINDOW_MINUTES = int(os.getenv("ADAPTIVE_RISK_WINDOW_MINUTES", "15"))
        self.ADAPTIVE_RISK_MAX_HISTORY = int(os.getenv("ADAPTIVE_RISK_MAX_HISTORY", "200"))
        self.REPORT_MAX_ENTRIES = int(os.getenv("REPORT_MAX_ENTRIES", "5000"))
        self.WAF_UPSTREAM_ALLOWED_HOSTS = {
            host.strip().lower()
            for host in os.getenv("WAF_UPSTREAM_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
            if host.strip()
        }
        self.TRUSTED_PROXY_NETWORKS = tuple(
            ipaddress.ip_network(value.strip(), strict=False)
            for value in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
            if value.strip()
        )

        configured_origins = os.getenv("CORS_ORIGINS", "")
        self.CORS_ORIGINS = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
        if not self.CORS_ORIGINS and self.is_development:
            self.CORS_ORIGINS = [
                "http://localhost:3000",
                "http://localhost:5173",
                "http://localhost:5174",
            ]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return not self.is_production

    def validate_runtime_configuration(self) -> None:
        """Reject unsafe or incomplete configuration before production startup."""
        self.validate_waf_configuration()
        if not self.is_production:
            return

        if not self._database_url_configured:
            raise RuntimeError("DATABASE_URL must be configured in production")
        if self.JWT_SECRET in _INSECURE_JWT_SECRETS or len(self.JWT_SECRET) < 32:
            raise RuntimeError("A strong JWT_SECRET (at least 32 characters) is required in production")
        if not self.CORS_ORIGINS:
            raise RuntimeError("CORS_ORIGINS must be configured in production")
        if self.ADMIN_BOOTSTRAP_SECRET and len(self.ADMIN_BOOTSTRAP_SECRET) < 32:
            raise RuntimeError("ADMIN_BOOTSTRAP_SECRET must be at least 32 characters when configured")

    def validate_waf_configuration(self) -> None:
        """Validate the fixed upstream and resource limits used by the reverse proxy."""
        parsed = urlsplit(self.WAF_UPSTREAM_URL)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("WAF_UPSTREAM_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RuntimeError("WAF_UPSTREAM_URL must not contain credentials, a query, or a fragment")
        if parsed.hostname.lower() not in self.WAF_UPSTREAM_ALLOWED_HOSTS:
            raise RuntimeError("WAF_UPSTREAM_URL host is not in WAF_UPSTREAM_ALLOWED_HOSTS")
        if not 0.1 <= self.WAF_UPSTREAM_TIMEOUT_SECONDS <= 60:
            raise RuntimeError("WAF_UPSTREAM_TIMEOUT_SECONDS must be between 0.1 and 60")
        if not 1024 <= self.WAF_MAX_REQUEST_BODY_BYTES <= 10 * 1024 * 1024:
            raise RuntimeError("WAF_MAX_REQUEST_BODY_BYTES must be between 1024 and 10485760")
        if not 1024 <= self.WAF_MAX_UPSTREAM_RESPONSE_BYTES <= 50 * 1024 * 1024:
            raise RuntimeError("WAF_MAX_UPSTREAM_RESPONSE_BYTES must be between 1024 and 52428800")
        if not 1024 <= self.WAF_MAX_URL_BYTES <= 65536:
            raise RuntimeError("WAF_MAX_URL_BYTES must be between 1024 and 65536")
        if not 1024 <= self.WAF_MAX_HEADER_BYTES <= 1024 * 1024:
            raise RuntimeError("WAF_MAX_HEADER_BYTES must be between 1024 and 1048576")
        if not 2 <= self.WAF_MAX_JSON_DEPTH <= 100:
            raise RuntimeError("WAF_MAX_JSON_DEPTH must be between 2 and 100")
        if not 1 <= self.WAF_MAX_FORM_FIELDS <= 1000:
            raise RuntimeError("WAF_MAX_FORM_FIELDS must be between 1 and 1000")
        if not 1 <= self.WAF_MAX_CONCURRENT_REQUESTS <= 10000:
            raise RuntimeError("WAF_MAX_CONCURRENT_REQUESTS must be between 1 and 10000")
        if not 1 <= self.ADAPTIVE_RISK_WINDOW_MINUTES <= 1440:
            raise RuntimeError("ADAPTIVE_RISK_WINDOW_MINUTES must be between 1 and 1440")
        if not 10 <= self.ADAPTIVE_RISK_MAX_HISTORY <= 10000:
            raise RuntimeError("ADAPTIVE_RISK_MAX_HISTORY must be between 10 and 10000")
        if not 100 <= self.REPORT_MAX_ENTRIES <= 50000:
            raise RuntimeError("REPORT_MAX_ENTRIES must be between 100 and 50000")


settings = Settings()
