"""
Password hashing utilities using bcrypt directly.

Uses the `bcrypt` package directly instead of passlib, which has a
Python 3.14 incompatibility in its bcrypt wrap-bug detection routine
(raises ValueError on startup).  The bcrypt package itself works fine.
"""

import bcrypt


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt and return a UTF-8 string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )
