"""JWT handler tests."""

from __future__ import annotations

import time

import pytest

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError
from softauth.jwt.handler import JWTHandler

_SECRET = "test-secret-key-min-16-chars"


class TestCreateTokens:
    def test_access_token_is_string(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_access_token("user-1")
        assert isinstance(token, str) and len(token) > 0

    def test_refresh_token_is_string(self, jwt_handler: JWTHandler) -> None:
        token = jwt_handler.create_refresh_token("user-1")
        assert isinstance(token, str) and len(token) > 0

    def test_access_token_has_type_claim(self, jwt_handler: JWTHandler) -> None:
        payload = jwt_handler.decode_token(jwt_handler.create_access_token("u"))
        assert payload["type"] == "access"

    def test_refresh_token_has_type_claim(self, jwt_handler: JWTHandler) -> None:
        payload = jwt_handler.decode_token(jwt_handler.create_refresh_token("u"))
        assert payload["type"] == "refresh"

    def test_subject_round_trips(self, jwt_handler: JWTHandler) -> None:
        payload = jwt_handler.decode_token(jwt_handler.create_access_token("user-42"))
        assert payload["sub"] == "user-42"

    def test_role_is_embedded(self, jwt_handler: JWTHandler) -> None:
        payload = jwt_handler.decode_token(
            jwt_handler.create_access_token("u", role="admin")
        )
        assert payload["role"] == "admin"

    def test_extra_claims_survive(self, jwt_handler: JWTHandler) -> None:
        payload = jwt_handler.decode_token(
            jwt_handler.create_access_token("u", extra={"tenant": "acme"})
        )
        assert payload["tenant"] == "acme"

    def test_jti_is_unique(self, jwt_handler: JWTHandler) -> None:
        t1 = jwt_handler.decode_token(jwt_handler.create_access_token("u"))["jti"]
        t2 = jwt_handler.decode_token(jwt_handler.create_access_token("u"))["jti"]
        assert t1 != t2


class TestVerifyToken:
    def test_verify_valid_returns_true(self, jwt_handler: JWTHandler) -> None:
        assert jwt_handler.verify_token(jwt_handler.create_access_token("u")) is True

    def test_verify_garbage_returns_false(self, jwt_handler: JWTHandler) -> None:
        assert jwt_handler.verify_token("not.a.token") is False

    def test_verify_wrong_secret_returns_false(self, jwt_handler: JWTHandler) -> None:
        other = JWTHandler(SoftAuthConfig(secret_key="different-secret-16+", framework="fastapi"))
        token = other.create_access_token("u")
        assert jwt_handler.verify_token(token) is False


class TestDecodeToken:
    def test_wrong_secret_raises_invalid_token(self) -> None:
        h1 = JWTHandler(SoftAuthConfig(secret_key="secret-one-1234567", framework="fastapi"))
        h2 = JWTHandler(SoftAuthConfig(secret_key="secret-two-1234567", framework="fastapi"))
        with pytest.raises(InvalidTokenError):
            h2.decode_token(h1.create_access_token("u"))

    def test_malformed_token_raises_invalid_token(self, jwt_handler: JWTHandler) -> None:
        with pytest.raises(InvalidTokenError):
            jwt_handler.decode_token("bad.token.value")

    def test_expired_token_raises_expired(self) -> None:
        # Bypass config validation by manually encoding a token with a past exp.
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "u",
            "type": "access",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),  # 1 hour in the past
            "jti": "test-expired",
        }
        expired_token = pyjwt.encode(payload, _SECRET, algorithm="HS256")
        handler = JWTHandler(SoftAuthConfig(secret_key=_SECRET, framework="fastapi"))
        with pytest.raises(TokenExpiredError):
            handler.decode_token(expired_token)


class TestExtractFromHeader:
    def test_extracts_bearer_token(self, jwt_handler: JWTHandler) -> None:
        raw = jwt_handler.create_access_token("u")
        assert jwt_handler.extract_token_from_header(f"Bearer {raw}") == raw

    def test_returns_none_for_missing_header(self, jwt_handler: JWTHandler) -> None:
        assert jwt_handler.extract_token_from_header("") is None

    def test_returns_none_for_wrong_prefix(self, jwt_handler: JWTHandler) -> None:
        assert jwt_handler.extract_token_from_header("Token abc") is None
