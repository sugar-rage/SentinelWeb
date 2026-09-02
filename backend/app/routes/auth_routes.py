"""
Authentication routes.

POST /api/auth/register  — create a new user account.
POST /api/auth/login     — authenticate and receive a JWT.
GET  /api/auth/me        — return the currently authenticated user.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.auth import LogoutResponse, RoleUpdate, UserRegister, UserLogin, UserResponse, TokenResponse
from app.services.auth_service import register_user, authenticate_user, logout_user
from app.auth.dependencies import get_current_session, get_current_user, require_permission
from app.database.models.administrator import Administrator
from app.database.models.session_log import SessionLog
from app.utils.helpers import get_client_ip
from app.auth.rate_limiter import auth_rate_limiter
from fastapi import HTTPException, status
from app.services.security_audit_service import record_security_event

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
manage_users = require_permission("manage_users")


@router.post("/register", response_model=UserResponse, status_code=201)
def register(data: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Register a new user."""
    ip_address = get_client_ip(request)
    rate_key = f"registration:{ip_address}"
    decision = auth_rate_limiter.check(rate_key)
    if not decision.allowed:
        record_security_event(
            db,
            event_type="registration_rate_limited",
            outcome="denied",
            correlation_id=getattr(request.state, "correlation_id", None),
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Try again later.",
            headers={"Retry-After": str(decision.retry_after)},
        )
    auth_rate_limiter.record_failure(rate_key)
    return register_user(
        data,
        db,
        ip_address=ip_address,
        correlation_id=getattr(request.state, "correlation_id", None),
    )


@router.post("/login", response_model=TokenResponse)
def login(data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate and return a JWT access token."""
    return authenticate_user(
        data,
        db,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        correlation_id=getattr(request.state, "correlation_id", None),
    )


@router.get("/me", response_model=UserResponse)
def me(current_user: Administrator = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Administrator = Depends(get_current_user),
    current_session: SessionLog = Depends(get_current_session),
):
    """Terminate the current server-side session and revoke its JWT."""
    logout_user(
        db,
        session=current_session,
        user=current_user,
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=get_client_ip(request),
    )
    return LogoutResponse()


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    body: RoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: Administrator = Depends(manage_users),
):
    """Assign an SRS role; public registration can never call this permission."""
    user = db.query(Administrator).filter(Administrator.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and body.role != "admin":
        raise HTTPException(status_code=400, detail="Administrators cannot demote their active account")
    previous_role = user.role
    user.role = body.role
    record_security_event(
        db,
        event_type="role_changed",
        outcome="success",
        user_id=admin.id,
        session_id=getattr(request.state, "session_id", None),
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=get_client_ip(request),
        details={"target_user_id": user.id, "previous_role": previous_role, "new_role": body.role},
    )
    db.refresh(user)
    return UserResponse.model_validate(user)
