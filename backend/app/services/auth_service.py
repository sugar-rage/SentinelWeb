"""
Authentication service — business logic for registration and login.

Keeps HTTP/FastAPI concerns out; this module only knows about
the ORM session, the Administrator model, and password hashing.
"""

import logging
from functools import wraps

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.database.models.administrator import Administrator
from app.auth.password import hash_password, verify_password
from app.auth.jwt_handler import create_access_token
from app.auth.rate_limiter import auth_rate_limiter
from app.services.security_audit_service import add_security_event
from app.services.session_service import create_session, terminate_session
from app.database.models.session_log import SessionLog
from app.schemas.auth import UserRegister, UserLogin, UserResponse, TokenResponse

logger = logging.getLogger("sentinelweb.auth")
_DUMMY_PASSWORD_HASH = hash_password("TimingDefenseOnly123!")


def _handle_database_failure(operation):
    @wraps(operation)
    def wrapped(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except SQLAlchemyError:
            db = kwargs.get("db")
            if db is None and len(args) >= 2:
                db = args[1]
            if db is not None:
                db.rollback()
            logger.exception("Database failure during %s", operation.__name__)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service is temporarily unavailable",
            )
    return wrapped


@_handle_database_failure
def register_user(
    data: UserRegister,
    db: Session,
    *,
    ip_address: str | None = None,
    correlation_id: str | None = None,
) -> UserResponse:
    """
    Create a new user account.

    Public registration always creates a standard 'user' account
    to prevent privilege escalation.
    Raises HTTPException 400 if username or email already exists.
    """
    # Check for duplicate username
    if db.query(Administrator).filter(
        Administrator.username == data.username
    ).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    # Check for duplicate email
    if db.query(Administrator).filter(
        Administrator.email == data.email
    ).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = Administrator(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role="user",
    )
    try:
        db.add(user)
        db.flush()
        add_security_event(
            db,
            event_type="account_created",
            outcome="success",
            user_id=user.id,
            correlation_id=correlation_id,
            ip_address=ip_address,
            details={"role": "user"},
        )
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        # Covers a duplicate inserted concurrently after the pre-flight checks.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to register user")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to register user",
        )

    return UserResponse.model_validate(user)


@_handle_database_failure
def authenticate_user(
    data: UserLogin,
    db: Session,
    *,
    ip_address: str,
    user_agent: str | None = None,
    correlation_id: str | None = None,
) -> TokenResponse:
    """
    Validate credentials and return a JWT token.

    Raises HTTPException 401 on invalid username or password.
    """
    rate_key = f"{ip_address}:{data.username.casefold()}"
    decision = auth_rate_limiter.check(rate_key)
    if not decision.allowed:
        add_security_event(
            db,
            event_type="login_rate_limited",
            outcome="denied",
            correlation_id=correlation_id,
            ip_address=ip_address,
            details={"username": data.username[:50]},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(decision.retry_after)},
        )

    user = db.query(Administrator).filter(
        Administrator.username == data.username
    ).first()

    password_valid = verify_password(
        data.password,
        user.password_hash if user else _DUMMY_PASSWORD_HASH,
    )
    if not user or not password_valid:
        auth_rate_limiter.record_failure(rate_key)
        add_security_event(
            db,
            event_type="login_failure",
            outcome="failure",
            user_id=user.id if user else None,
            correlation_id=correlation_id,
            ip_address=ip_address,
            details={"username": data.username[:50]},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    auth_rate_limiter.reset(rate_key)
    session, token_identifier = create_session(
        db,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    add_security_event(
        db,
        event_type="admin_login" if user.role == "admin" else "login_success",
        outcome="success",
        user_id=user.id,
        session_id=session.id,
        correlation_id=correlation_id,
        ip_address=ip_address,
        details={"role": user.role},
    )
    db.commit()
    token = create_access_token(
        user_id=user.id,
        role=user.role,
        session_identifier=session.session_identifier,
        token_identifier=token_identifier,
    )
    user_resp = UserResponse.model_validate(user)

    return TokenResponse(access_token=token, user=user_resp)


@_handle_database_failure
def logout_user(
    db: Session,
    *,
    session: SessionLog,
    user: Administrator,
    correlation_id: str | None,
    ip_address: str | None,
) -> None:
    terminate_session(session)
    add_security_event(
        db,
        event_type="logout",
        outcome="success",
        user_id=user.id,
        session_id=session.id,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    db.commit()
