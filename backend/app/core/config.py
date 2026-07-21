"""
Application settings loaded from environment variables.

Uses python-dotenv to read .env file at project root.
All settings have sensible defaults matching the development environment.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Centralized configuration for the SentinelWeb backend."""

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:MasterKey@localhost:5432/sentinelweb",
    )
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "sentinelweb-jwt-secret-key-change-in-production",
    )
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_MINUTES: int = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

    # Risk threshold — requests at or above this score are blocked
    RISK_BLOCK_THRESHOLD: int = int(os.getenv("RISK_BLOCK_THRESHOLD", "80"))


settings = Settings()
