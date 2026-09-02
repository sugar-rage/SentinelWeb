"""
FastAPI dependencies for JWT-based authentication.

get_current_user  — extracts and validates the JWT from the
                    Authorization header, returns the user row.
require_admin     — wraps get_current_user and enforces role == "admin".
"""

import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError

from app.auth.jwt_handler import decode_access_token
from app.database.database import get_db
from app.database.models.administrator import Administrator
from app.database.models.session_log import SessionLog
from app.services.security_audit_service import record_security_event
from app.services.session_service import find_active_session
from app.utils.helpers import get_client_ip

logger = logging.getLogger("sentinelweb.authorization")

security = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "user": frozenset({"scan"}),
    "developer": frozenset({"scan", "view_diagnostics"}),
    "security_analyst": frozenset({
        "scan", "view_security_events", "view_analytics",
    }),
    "admin": frozenset({
        "scan", "view_security_events", "view_analytics", "generate_reports",
        "manage_sessions", "manage_users", "view_diagnostics",
    }),
}


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> Administrator:
    """
    Dependency that validates the Bearer token and returns the
    authenticated user ORM object.
    """
    if credentials is None:
        _audit_denial(request, db, "missing_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id: str | None = payload.get("sub")
        session_identifier: str | None = payload.get("sid")
        token_identifier: str | None = payload.get("jti")
        if user_id is None or session_identifier is None or token_identifier is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token claims",
            )
        user_id_int = int(user_id)
    except (JWTError, TypeError, ValueError):
        _audit_denial(request, db, "invalid_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(Administrator).filter(
        Administrator.id == user_id_int
    ).first()

    if user is None:
        _audit_denial(request, db, "unknown_user")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    session = find_active_session(
        db,
        session_identifier=session_identifier,
        token_identifier=token_identifier,
    )
    if session is None or session.user_id != user.id:
        _audit_denial(request, db, "revoked_or_expired_session", user_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is expired or revoked",
        )

    request.state.session_id = session.id
    request.state.auth_session = session
    request.state.user_id = user.id
    return user


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    user: Administrator = Depends(get_current_user),
) -> Administrator:
    """Dependency that enforces admin-level access."""
    if user.role != "admin":
        _audit_denial(
            request,
            db,
            "admin_access_denied",
            user_id=user.id,
            session_id=getattr(request.state, "session_id", None),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    try:
        record_security_event(
            db,
            event_type="admin_access",
            outcome="success",
            user_id=user.id,
            session_id=getattr(request.state, "session_id", None),
            correlation_id=getattr(request.state, "correlation_id", None),
            ip_address=get_client_ip(request),
            details={"path": request.url.path},
        )
    except Exception:
        logger.exception("Unable to persist admin access audit event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to audit privileged operation",
        )
    return user


def require_permission(permission: str):
    """Build an audited dependency enforcing one explicit role permission."""
    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        user: Administrator = Depends(get_current_user),
    ) -> Administrator:
        if permission not in ROLE_PERMISSIONS.get(user.role, frozenset()):
            _audit_denial(
                request,
                db,
                f"permission_denied:{permission}",
                user_id=user.id,
                session_id=getattr(request.state, "session_id", None),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        try:
            record_security_event(
                db,
                event_type="admin_access" if user.role == "admin" else "authorized_access",
                outcome="success",
                user_id=user.id,
                session_id=getattr(request.state, "session_id", None),
                correlation_id=getattr(request.state, "correlation_id", None),
                ip_address=get_client_ip(request),
                details={"path": request.url.path, "permission": permission},
            )
        except Exception:
            logger.exception("Unable to persist permission audit event")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to audit privileged operation",
            )
        return user

    return dependency


def get_current_session(request: Request, user: Administrator = Depends(get_current_user)) -> SessionLog:
    """Return the validated session established by get_current_user."""
    return request.state.auth_session


def _audit_denial(
    request: Request,
    db: Session,
    reason: str,
    *,
    user_id: int | None = None,
    session_id: int | None = None,
) -> None:
    try:
        record_security_event(
            db,
            event_type="authorization_failure",
            outcome="denied",
            user_id=user_id,
            session_id=session_id,
            correlation_id=getattr(request.state, "correlation_id", None),
            ip_address=get_client_ip(request),
            details={"reason": reason, "path": request.url.path},
        )
    except Exception:
        logger.exception("Unable to persist authorization failure audit event")
