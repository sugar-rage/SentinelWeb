"""
Authentication routes.

POST /api/auth/register  — create a new user account.
POST /api/auth/login     — authenticate and receive a JWT.
GET  /api/auth/me        — return the currently authenticated user.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.auth import UserRegister, UserLogin, UserResponse, TokenResponse
from app.services.auth_service import register_user, authenticate_user
from app.auth.dependencies import get_current_user
from app.database.models.administrator import Administrator

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=201)
def register(data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user."""
    return register_user(data, db)


@router.post("/login", response_model=TokenResponse)
def login(data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate and return a JWT access token."""
    return authenticate_user(data, db)


@router.get("/me", response_model=UserResponse)
def me(current_user: Administrator = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)
