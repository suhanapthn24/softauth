"""Auto-generated Flask authentication Blueprint.

Provides:  POST /register  POST /login  POST /refresh  GET /me  POST /logout
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flask import Blueprint, g, jsonify, request

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    UserAlreadyExistsError,
)

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


def create_auth_blueprint(auth: "SoftAuth", config: SoftAuthConfig) -> Blueprint:
    bp = Blueprint("softauth", __name__)

    @bp.route("/register", methods=["POST"])
    def register() -> Any:
        body = request.get_json(silent=True) or {}
        email: str = body.get("email", "")
        password: str = body.get("password", "")
        role: str = body.get("role", "user")

        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with auth._db.session() as s:
                from softauth.database.repository import UserRepository
                user = UserRepository(s).create(
                    email=email,
                    hashed_password=auth.passwords.hash_password(password),
                    role=role,
                )
                return jsonify({"message": "User registered successfully", "id": user.id}), 201
        except UserAlreadyExistsError as exc:
            return jsonify({"error": str(exc)}), 409

    @bp.route("/login", methods=["POST"])
    def login() -> Any:
        body = request.get_json(silent=True) or {}
        email: str = body.get("email", "")
        password: str = body.get("password", "")

        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_email(email)

        if user is None or not auth.passwords.verify_password(password, user.hashed_password):
            return jsonify({"error": "Invalid credentials"}), 401
        if not user.is_active:
            return jsonify({"error": "Inactive user"}), 400

        access_token = auth.jwt.create_access_token(subject=user.id, role=user.role)
        refresh_token = auth.jwt.create_refresh_token(subject=user.id)

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": config.access_expiry_minutes * 60,
        })

    @bp.route("/refresh", methods=["POST"])
    def refresh() -> Any:
        body = request.get_json(silent=True) or {}
        token: str = body.get("refresh_token", "")

        try:
            payload = auth.jwt.decode_token(token)
        except TokenExpiredError:
            return jsonify({"error": "Refresh token expired"}), 401
        except InvalidTokenError:
            return jsonify({"error": "Invalid refresh token"}), 401

        if payload.get("type") != "refresh":
            return jsonify({"error": "Not a refresh token"}), 401

        user_id: str = payload["sub"]
        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        new_token = auth.jwt.create_access_token(subject=user_id, role=user.role)
        return jsonify({"access_token": new_token, "token_type": "bearer",
                        "expires_in": config.access_expiry_minutes * 60})

    @bp.route("/me", methods=["GET"])
    def get_me() -> Any:
        user_id = g.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        with auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user.to_dict())

    @bp.route("/logout", methods=["POST"])
    def logout() -> Any:
        return jsonify({"message": "Logged out successfully"})

    return bp
