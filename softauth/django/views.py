"""Django view functions for the auto-generated auth endpoints.

Provides: POST /register  POST /login  POST /refresh  GET /me  POST /logout
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError, UserAlreadyExistsError

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


def create_auth_views(auth: "SoftAuth", config: SoftAuthConfig) -> dict[str, Any]:
    """Return a dict of Django view callables, one per auth endpoint."""

    def _body(request: Any) -> dict[str, Any]:
        try:
            return json.loads(request.body or b"{}") or {}
        except (json.JSONDecodeError, ValueError):
            return {}

    @csrf_exempt
    def register(request: Any) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)
        body = _body(request)
        email: str = body.get("email", "")
        password: str = body.get("password", "")
        role: str = body.get("role", "user")

        if not email or not password:
            return JsonResponse({"error": "email and password are required"}, status=400)

        try:
            with auth._db.session() as s:
                from softauth.database.repository import UserRepository
                user = UserRepository(s).create(
                    email=email,
                    hashed_password=auth.passwords.hash_password(password),
                    role=role,
                )
            return JsonResponse({"message": "User registered successfully", "id": user.id}, status=201)
        except UserAlreadyExistsError as exc:
            return JsonResponse({"error": str(exc)}, status=409)

    @csrf_exempt
    def login(request: Any) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)
        body = _body(request)
        email: str = body.get("email", "")
        password: str = body.get("password", "")

        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_email(email)

        if user is None or not auth.passwords.verify_password(password, user.hashed_password):
            return JsonResponse({"error": "Invalid credentials"}, status=401)
        if not user.is_active:
            return JsonResponse({"error": "Inactive user"}, status=400)

        access_token = auth.jwt.create_access_token(subject=user.id, role=user.role)
        refresh_token = auth.jwt.create_refresh_token(subject=user.id)

        return JsonResponse({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": config.access_expiry_minutes * 60,
        })

    @csrf_exempt
    def refresh(request: Any) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method not allowed"}, status=405)
        body = _body(request)
        token: str = body.get("refresh_token", "")

        try:
            payload = auth.jwt.decode_token(token)
        except TokenExpiredError:
            return JsonResponse({"error": "Refresh token expired"}, status=401)
        except InvalidTokenError:
            return JsonResponse({"error": "Invalid refresh token"}, status=401)

        if payload.get("type") != "refresh":
            return JsonResponse({"error": "Not a refresh token"}, status=401)

        user_id: str = payload["sub"]
        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None or not user.is_active:
            return JsonResponse({"error": "User not found or inactive"}, status=401)

        new_token = auth.jwt.create_access_token(subject=user_id, role=user.role)
        return JsonResponse({
            "access_token": new_token,
            "token_type": "bearer",
            "expires_in": config.access_expiry_minutes * 60,
        })

    @csrf_exempt
    def me(request: Any) -> JsonResponse:
        if request.method != "GET":
            return JsonResponse({"error": "Method not allowed"}, status=405)
        user_id = getattr(request, "softauth_user_id", None)
        if not user_id:
            return JsonResponse({"error": "Authentication required"}, status=401)

        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None:
            return JsonResponse({"error": "User not found"}, status=404)
        return JsonResponse(user.to_dict())

    @csrf_exempt
    def logout(request: Any) -> JsonResponse:
        return JsonResponse({"message": "Logged out successfully"})

    return {
        "register": register,
        "login": login,
        "refresh": refresh,
        "me": me,
        "logout": logout,
    }
