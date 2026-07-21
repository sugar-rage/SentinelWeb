"""
Shared utility helpers used across the backend.

Keeps small, reusable functions in one place.
"""

from datetime import datetime


def get_client_ip(request) -> str:
    """Extract the client IP from a FastAPI/Starlette Request object."""
    if request.client:
        return request.client.host
    return "unknown"


def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.utcnow()
