"""
Authentication service — business logic for registration and login.

Keeps HTTP/FastAPI concerns out; this module only knows about
the ORM session, the Administrator model, and password hashing.
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.database.models.administrator import Administrator
from app.auth.password import hash_password, verify_password
from app.auth.jwt_handler import create_access_token
from app.schemas.auth import UserRegister, UserLogin, UserResponse, TokenResponse


def register_user(data: UserRegister, db: Session) -> UserResponse:
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
    db.add(user)
    db.commit()
    db.refresh(user)

    return UserResponse.model_validate(user)


def authenticate_user(data: UserLogin, db: Session) -> TokenResponse:
    """
    Validate credentials and return a JWT token.

    Raises HTTPException 401 on invalid username or password.
    """
    user = db.query(Administrator).filter(
        Administrator.username == data.username
    ).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(user_id=user.id, role=user.role)
    user_resp = UserResponse.model_validate(user)

    return TokenResponse(access_token=token, user=user_resp)
