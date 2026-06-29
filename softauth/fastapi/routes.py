"""Auto-generated FastAPI auth router.

Provides:  POST /register  POST /login  POST /refresh  GET /me  POST /logout
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    UserAlreadyExistsError,
)

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth
    from softauth.fastapi.dependencies import DependencyFactory


# ── Request / Response Schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str = "user"


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool
    role: str
    created_at: str
    updated_at: str


# ── Router factory ────────────────────────────────────────────────────────────

def create_auth_router(
    auth: "SoftAuth",
    config: SoftAuthConfig,
    deps: "DependencyFactory",
) -> APIRouter:
    """Build and return a configured APIRouter."""

    router = APIRouter()

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    def register(body: RegisterRequest) -> dict[str, Any]:
        """Create a new user account."""
        try:
            with auth._db.session() as s:
                from softauth.database.repository import UserRepository
                user = UserRepository(s).create(
                    email=body.email,
                    hashed_password=auth.passwords.hash_password(body.password),
                    role=body.role,
                )
                return {"message": "User registered successfully", "id": user.id}
        except UserAlreadyExistsError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    @router.post("/login", response_model=LoginResponse)
    def login(form: OAuth2PasswordRequestForm = Depends()) -> LoginResponse:
        """Exchange credentials for a JWT token pair.

        Accepts ``application/x-www-form-urlencoded`` with ``username`` and
        ``password`` fields (standard OAuth2 password flow, shown in Swagger UI).
        """
        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_email(form.username)

        if user is None or not auth.passwords.verify_password(form.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

        access_token = auth.jwt.create_access_token(subject=user.id, role=user.role)
        refresh_token = auth.jwt.create_refresh_token(subject=user.id)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=config.access_expiry_minutes * 60,
        )

    @router.post("/refresh")
    def refresh(body: RefreshRequest) -> dict[str, Any]:
        """Exchange a refresh token for a new access token."""
        try:
            payload = auth.jwt.decode_token(body.refresh_token)
        except TokenExpiredError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
        except InvalidTokenError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

        user_id: str = payload["sub"]
        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

        new_token = auth.jwt.create_access_token(subject=user_id, role=user.role)
        return {"access_token": new_token, "token_type": "bearer", "expires_in": config.access_expiry_minutes * 60}

    @router.get("/me", response_model=UserResponse)
    def get_me(current_user: Any = Depends(deps.current_user)) -> dict[str, Any]:
        """Return the profile of the authenticated user."""
        return current_user.to_dict()

    @router.post("/logout")
    def logout() -> dict[str, str]:
        """Invalidate the client-side session.

        Stateless logout: instructs the client to discard its tokens.
        Plug in a TokenStore to add server-side blacklisting.
        """
        return {"message": "Logged out successfully"}

    return router
