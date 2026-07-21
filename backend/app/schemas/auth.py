"""
Pydantic schemas for authentication endpoints.

Separates request validation (UserRegister, UserLogin) from
response serialization (UserResponse, TokenResponse).
"""

from pydantic import BaseModel


class UserRegister(BaseModel):
    """Schema for POST /api/auth/register."""
    username: str
    email: str
    password: str
    role: str = "user"  # default role; admin must be set explicitly


class UserLogin(BaseModel):
    """Schema for POST /api/auth/login."""
    username: str
    password: str


class UserResponse(BaseModel):
    """Schema returned when exposing user data (never includes password)."""
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Schema returned on successful login."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
