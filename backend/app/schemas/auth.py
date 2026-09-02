"""
Pydantic schemas for authentication endpoints.

Separates request validation (UserRegister, UserLogin) from
response serialization (UserResponse, TokenResponse).
"""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_PASSWORD_SPECIAL = re.compile(r"[^A-Za-z0-9]")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class UserRegister(BaseModel):
    """Schema for POST /api/auth/register."""
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: str = "user"  # accepted only for compatibility; service always enforces user

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL.fullmatch(value):
            raise ValueError("email must be a valid address")
        return value

    @field_validator("password")
    @classmethod
    def validate_password_policy(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 UTF-8 bytes for bcrypt")
        if not any(char.isupper() for char in value):
            raise ValueError("password must contain an uppercase letter")
        if not any(char.islower() for char in value):
            raise ValueError("password must contain a lowercase letter")
        if not any(char.isdigit() for char in value):
            raise ValueError("password must contain a digit")
        if not _PASSWORD_SPECIAL.search(value):
            raise ValueError("password must contain a special character")
        return value


class UserLogin(BaseModel):
    """Schema for POST /api/auth/login."""
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    """Schema returned when exposing user data (never includes password)."""
    id: int
    username: str
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Schema returned on successful login."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class LogoutResponse(BaseModel):
    message: str = "Logged out successfully"


class RoleUpdate(BaseModel):
    role: Literal["user", "admin", "security_analyst", "developer"]
