"""softauth — Zero-setup JWT authentication for FastAPI and Flask.

Quick start (FastAPI)::

    from fastapi import FastAPI, Depends
    from softauth import SoftAuth

    auth = SoftAuth(secret_key="your-secret", framework="fastapi")
    app = FastAPI()
    auth.init_app(app)
    auth.init_db()

    @app.get("/me")
    def me(user=Depends(auth.current_user)):
        return user.to_dict()

Quick start (Flask)::

    from flask import Flask, g
    from softauth import SoftAuth

    auth = SoftAuth(secret_key="your-secret", framework="flask")
    app = Flask(__name__)
    auth.init_app(app)
    auth.init_db()

    @app.route("/me")
    @auth.login_required
    def me():
        return g.user.to_dict()
"""

from softauth.core.auth import SoftAuth
from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import (
    AdapterNotInitializedError,
    AuthError,
    ConfigurationError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
    SoftAuthError,
    TokenError,
    TokenExpiredError,
    TokenTypeMismatchError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from softauth.jwt.handler import JWTHandler
from softauth.security.password import PasswordHandler

__version__ = "0.1.0"
__all__ = [
    "SoftAuth",
    "SoftAuthConfig",
    "JWTHandler",
    "PasswordHandler",
    # Exceptions
    "SoftAuthError",
    "AuthError",
    "TokenError",
    "TokenExpiredError",
    "InvalidTokenError",
    "TokenTypeMismatchError",
    "InvalidCredentialsError",
    "InactiveUserError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "PermissionDeniedError",
    "ConfigurationError",
    "AdapterNotInitializedError",
]
