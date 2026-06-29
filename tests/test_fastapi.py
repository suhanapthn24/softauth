"""FastAPI integration tests — routes, middleware, RBAC."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from softauth import SoftAuth

_SECRET = "test-secret-key-min-16-chars"
_DB = "sqlite:///:memory:"


def _make_client(auth: SoftAuth) -> TestClient:
    app = FastAPI()
    auth.init_app(app)
    return TestClient(app)


def _register(client: TestClient, email: str, password: str, role: str = "user") -> dict[str, Any]:
    r = client.post("/auth/register", json={"email": email, "password": password, "role": role})
    assert r.status_code == 201, r.text
    return r.json()


def _login(client: TestClient, email: str, password: str) -> dict[str, Any]:
    r = client.post(
        "/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 200, r.text
    return r.json()


# ── Route tests ────────────────────────────────────────────────────────────────

class TestRegister:
    def test_success(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        r = client.post("/auth/register", json={"email": "reg@test.com", "password": "pass123"})
        assert r.status_code == 201
        assert "id" in r.json()

    def test_duplicate_email(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        data = {"email": "dup@test.com", "password": "p"}
        client.post("/auth/register", json=data)
        r = client.post("/auth/register", json=data)
        assert r.status_code == 409

    def test_custom_role(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "mgr@test.com", "p", role="manager")
        tokens = _login(client, "mgr@test.com", "p")
        payload = fastapi_auth.decode_token(tokens["access_token"])
        assert payload["role"] == "manager"


class TestLogin:
    def test_returns_token_pair(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "login@test.com", "pass")
        data = _login(client, "login@test.com", "pass")
        assert "access_token" in data and "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert isinstance(data["expires_in"], int)

    def test_wrong_password(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "wp@test.com", "correct")
        r = client.post(
            "/auth/login",
            data={"username": "wp@test.com", "password": "wrong"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 401

    def test_unknown_user(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        r = client.post(
            "/auth/login",
            data={"username": "ghost@test.com", "password": "x"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 401


class TestRefresh:
    def test_returns_new_access_token(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "rfr@test.com", "p")
        tokens = _login(client, "rfr@test.com", "p")
        r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_access_token_as_refresh_fails(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "wrong_type@test.com", "p")
        tokens = _login(client, "wrong_type@test.com", "p")
        r = client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
        assert r.status_code == 401

    def test_invalid_token_fails(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        r = client.post("/auth/refresh", json={"refresh_token": "bad.token"})
        assert r.status_code == 401


class TestGetMe:
    def test_returns_user_profile(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        _register(client, "me@test.com", "p")
        token = _login(client, "me@test.com", "p")["access_token"]
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["email"] == "me@test.com"

    def test_no_token_returns_401(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        r = client.get("/auth/me")
        assert r.status_code == 401


class TestLogout:
    def test_logout_returns_200(self, fastapi_auth: SoftAuth) -> None:
        client = _make_client(fastapi_auth)
        r = client.post("/auth/logout")
        assert r.status_code == 200


# ── Dependency / RBAC tests ────────────────────────────────────────────────────

class TestCurrentUserDependency:
    def test_protected_route_requires_token(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/protected")
        def protected(user: Any = Depends(fastapi_auth.current_user)) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        assert client.get("/protected").status_code == 401

    def test_protected_route_with_valid_token(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/protected")
        def protected(user: Any = Depends(fastapi_auth.current_user)) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "dep@test.com", "p")
        token = _login(client, "dep@test.com", "p")["access_token"]
        r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["email"] == "dep@test.com"


class TestCurrentAdminDependency:
    def test_non_admin_gets_403(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/admin")
        def admin_only(user: Any = Depends(fastapi_auth.current_admin)) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "plain@test.com", "p")
        token = _login(client, "plain@test.com", "p")["access_token"]
        r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_admin_gets_200(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/admin")
        def admin_only(user: Any = Depends(fastapi_auth.current_admin)) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "admin@test.com", "p", role="admin")
        token = _login(client, "admin@test.com", "p")["access_token"]
        r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


class TestRequireRoleDependency:
    def test_correct_role_allowed(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/editor")
        def editor_page(user: Any = Depends(fastapi_auth.require_role("editor"))) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "editor@test.com", "p", role="editor")
        token = _login(client, "editor@test.com", "p")["access_token"]
        r = client.get("/editor", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_admin_bypasses_role_check(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/editor2")
        def editor_page(user: Any = Depends(fastapi_auth.require_role("editor"))) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "superadmin@test.com", "p", role="admin")
        token = _login(client, "superadmin@test.com", "p")["access_token"]
        r = client.get("/editor2", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_wrong_role_gets_403(self, fastapi_auth: SoftAuth) -> None:
        app = FastAPI()
        fastapi_auth.init_app(app)

        @app.get("/editor3")
        def editor_page(user: Any = Depends(fastapi_auth.require_role("editor"))) -> dict[str, Any]:
            return {"email": user.email}

        client = TestClient(app)
        _register(client, "viewer@test.com", "p", role="viewer")
        token = _login(client, "viewer@test.com", "p")["access_token"]
        r = client.get("/editor3", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


class TestMiddleware:
    def test_malformed_token_handled_gracefully(self, fastapi_auth: SoftAuth) -> None:
        """Middleware swallows decode errors; unauthenticated routes still return 200."""
        client = _make_client(fastapi_auth)
        r = client.post(
            "/auth/logout",
            headers={"Authorization": "Bearer this.is.not.a.valid.jwt"},
        )
        # Middleware caught InvalidTokenError, set state.user_id = None,
        # and let the (unprotected) logout route complete normally.
        assert r.status_code == 200

    def test_expired_token_handled_gracefully(self, fastapi_auth: SoftAuth) -> None:
        """Middleware swallows TokenExpiredError; route still responds."""
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expired_token = pyjwt.encode(
            {
                "sub": "u",
                "type": "access",
                "exp": now - timedelta(hours=1),
                "iat": now - timedelta(hours=2),
                "jti": "expired-jti",
            },
            _SECRET,
            algorithm="HS256",
        )
        client = _make_client(fastapi_auth)
        r = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert r.status_code == 200

    def test_no_auth_header_accepted_by_unprotected_routes(self, fastapi_auth: SoftAuth) -> None:
        """Middleware is a no-op when Authorization header is absent."""
        client = _make_client(fastapi_auth)
        assert client.post("/auth/logout").status_code == 200

    def test_bad_token_rejected_by_protected_routes(self, fastapi_auth: SoftAuth) -> None:
        """Protected routes still return 401 when middleware sets user_id=None."""
        client = _make_client(fastapi_auth)
        r = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer garbage.token.value"},
        )
        assert r.status_code == 401
