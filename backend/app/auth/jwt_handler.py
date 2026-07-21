"""
JWT token creation and verification.

Uses python-jose with HS256 algorithm.
Token payload contains: sub (user id), role, exp (expiry).
"""

from datetime import datetime, timedelta
from jose import jwt, JWTError
from app.core.config import settings


def create_access_token(user_id: int, role: str) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id: The database ID of the user.
        role: The user's role (admin / user).

    Returns:
        Encoded JWT string.
    """
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRY_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
    }
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
