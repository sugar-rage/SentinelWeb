"""
JWT token creation and verification.

Uses python-jose with HS256 algorithm.
Token payload contains: sub (user id), role, exp (expiry).
"""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from jose import jwt, JWTError
from app.core.config import settings


def new_token_identifier() -> str:
    return secrets.token_urlsafe(32)


def hash_token_identifier(identifier: str) -> str:
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: int,
    role: str,
    session_identifier: str | None = None,
    token_identifier: str | None = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id: The database ID of the user.
        role: The user's role (admin / user).

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRY_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
    }
    if session_identifier:
        payload["sid"] = session_identifier
    if token_identifier:
        payload["jti"] = token_identifier
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT access token.

    Args:
        token: The raw JWT string.

    Returns:
        Decoded payload dict.

    Raises:
        JWTError: If the token is invalid or expired.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
    )
