"""
FastAPI dependencies for JWT-based authentication.

get_current_user  — extracts and validates the JWT from the
                    Authorization header, returns the user row.
require_admin     — wraps get_current_user and enforces role == "admin".
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError

from app.auth.jwt_handler import decode_access_token
from app.database.database import get_db
from app.database.models.administrator import Administrator

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> Administrator:
    """
    Dependency that validates the Bearer token and returns the
    authenticated user ORM object.
    """
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(Administrator).filter(
        Administrator.id == int(user_id)
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


def require_admin(
    user: Administrator = Depends(get_current_user),
) -> Administrator:
    """Dependency that enforces admin-level access."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
