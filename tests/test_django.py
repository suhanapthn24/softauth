"""Django adapter integration tests — middleware, views, decorators, RBAC."""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("django")

from django.http import HttpRequest, HttpResponse  # noqa: E402

from softauth import SoftAuth  # noqa: E402

_SECRET = "test-secret-key-min-16-chars"
_DB = "sqlite:///:memory:"


# ── Request helpers ────────────────────────────────────────────────────────────

def _post(path: str, body: dict[str, Any] | None = None, token: str | None = None) -> HttpRequest:
    req = HttpRequest()
    req.method = "POST"
    req.path = path
    req._body = json.dumps(body or {}).encode()
    req.content_type = "application/json"
    req.META["CONTENT_TYPE"] = "application/json"
    if token:
        req.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return req


def _get(path: str, token: str | None = None) -> HttpRequest:
    req = HttpRequest()
    req.method = "GET"
    req.path = path
    req._body = b""
    if token:
        req.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return req


def _apply_middleware(request: HttpRequest, auth: SoftAuth) -> HttpRequest:
    """Run SoftAuthMiddleware on the request to populate softauth_* attributes."""
    from softauth.django.middleware import SoftAuthMiddleware

    def get_response(r: Any) -> HttpResponse:
        return HttpResponse("ok")

    SoftAuthMiddleware(get_response)(request)
    return request


def _register(views: dict[str, Any], email: str, password: str, role: str = "user") -> dict[str, Any]:
    r = views["register"](_post("/auth/register", {"email": email, "password": password, "role": role}))
    assert r.status_code == 201, r.content
    return json.loads(r.content)


def _login(views: dict[str, Any], email: str, password: str) -> dict[str, Any]:
    r = views["login"](_post("/auth/login", {"email": email, "password": password}))
    assert r.status_code == 200, r.content
    return json.loads(r.content)


def _views(auth: SoftAuth) -> dict[str, Any]:
    from softauth.django.views import create_auth_views
    return create_auth_views(auth, auth.config)


# ── Middleware ─────────────────────────────────────────────────────────────────

class TestDjangoMiddleware:
    def test_no_auth_header_sets_none(self, django_auth: SoftAuth) -> None:
        req = _apply_middleware(_get("/"), django_auth)
        assert req.softauth_user_id is None
        assert req.softauth_role is None
        assert req.softauth_payload is None

    def test_valid_token_populates_attributes(self, django_auth: SoftAuth) -> None:
        token = django_auth.create_access_token("user-42", role="manager")
        req = _apply_middleware(_get("/", token=token), django_auth)
        assert req.softauth_user_id == "user-42"
        assert req.softauth_role == "manager"
        assert req.softauth_payload is not None

    def test_malformed_token_sets_none(self, django_auth: SoftAuth) -> None:
        req = _get("/")
        req.META["HTTP_AUTHORIZATION"] = "Bearer this.is.garbage"
        req = _apply_middleware(req, django_auth)
        assert req.softauth_user_id is None

    def test_expired_token_sets_none(self, django_auth: SoftAuth) -> None:
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expired = pyjwt.encode(
            {"sub": "u", "type": "access", "exp": now - timedelta(hours=1),
             "iat": now - timedelta(hours=2), "jti": "x"},
            _SECRET,
            algorithm="HS256",
        )
        req = _get("/")
        req.META["HTTP_AUTHORIZATION"] = f"Bearer {expired}"
        req = _apply_middleware(req, django_auth)
        assert req.softauth_user_id is None

    def test_missing_bearer_prefix_sets_none(self, django_auth: SoftAuth) -> None:
        token = django_auth.create_access_token("user-1")
        req = _get("/")
        req.META["HTTP_AUTHORIZATION"] = token  # no "Bearer " prefix
        req = _apply_middleware(req, django_auth)
        assert req.softauth_user_id is None


# ── Register ───────────────────────────────────────────────────────────────────

class TestDjangoRegister:
    def test_success(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["register"](_post("/auth/register", {"email": "r@test.com", "password": "pass"}))
        assert r.status_code == 201
        data = json.loads(r.content)
        assert "id" in data

    def test_duplicate_email_returns_409(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        body = {"email": "dup@test.com", "password": "p"}
        v["register"](_post("/auth/register", body))
        r = v["register"](_post("/auth/register", body))
        assert r.status_code == 409

    def test_missing_email_returns_400(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["register"](_post("/auth/register", {"password": "p"}))
        assert r.status_code == 400

    def test_wrong_method_returns_405(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["register"](_get("/auth/register"))
        assert r.status_code == 405

    def test_custom_role_stored(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "mgr@test.com", "p", role="manager")
        tokens = _login(v, "mgr@test.com", "p")
        payload = django_auth.decode_token(tokens["access_token"])
        assert payload["role"] == "manager"


# ── Login ──────────────────────────────────────────────────────────────────────

class TestDjangoLogin:
    def test_returns_token_pair(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "login@test.com", "pass")
        data = _login(v, "login@test.com", "pass")
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert isinstance(data["expires_in"], int)

    def test_wrong_password_returns_401(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "wp@test.com", "correct")
        r = v["login"](_post("/auth/login", {"email": "wp@test.com", "password": "wrong"}))
        assert r.status_code == 401

    def test_unknown_user_returns_401(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["login"](_post("/auth/login", {"email": "ghost@test.com", "password": "x"}))
        assert r.status_code == 401


# ── Refresh ────────────────────────────────────────────────────────────────────

class TestDjangoRefresh:
    def test_returns_new_access_token(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "rfr@test.com", "p")
        tokens = _login(v, "rfr@test.com", "p")
        r = v["refresh"](_post("/auth/refresh", {"refresh_token": tokens["refresh_token"]}))
        assert r.status_code == 200
        assert "access_token" in json.loads(r.content)

    def test_access_token_as_refresh_fails(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "wt@test.com", "p")
        tokens = _login(v, "wt@test.com", "p")
        r = v["refresh"](_post("/auth/refresh", {"refresh_token": tokens["access_token"]}))
        assert r.status_code == 401

    def test_invalid_token_returns_401(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["refresh"](_post("/auth/refresh", {"refresh_token": "bad.token"}))
        assert r.status_code == 401


# ── Me ─────────────────────────────────────────────────────────────────────────

class TestDjangoMe:
    def test_returns_user_profile(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "me@test.com", "p")
        tokens = _login(v, "me@test.com", "p")
        req = _apply_middleware(_get("/auth/me", token=tokens["access_token"]), django_auth)
        r = v["me"](req)
        assert r.status_code == 200
        assert json.loads(r.content)["email"] == "me@test.com"

    def test_no_token_returns_401(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        req = _apply_middleware(_get("/auth/me"), django_auth)
        r = v["me"](req)
        assert r.status_code == 401


# ── Logout ─────────────────────────────────────────────────────────────────────

class TestDjangoLogout:
    def test_returns_200(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        r = v["logout"](_post("/auth/logout"))
        assert r.status_code == 200


# ── Decorators / RBAC ─────────────────────────────────────────────────────────

class TestDjangoDecorators:
    def _adapter(self, auth: SoftAuth) -> Any:
        return auth._adapter

    def test_login_required_no_token(self, django_auth: SoftAuth) -> None:
        @django_auth.login_required
        def view(request: Any) -> HttpResponse:
            return HttpResponse("ok")

        req = _apply_middleware(_get("/"), django_auth)
        r = view(req)
        assert r.status_code == 401

    def test_login_required_with_valid_user(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "dec@test.com", "p")
        tokens = _login(v, "dec@test.com", "p")

        @django_auth.login_required
        def view(request: Any) -> HttpResponse:
            return HttpResponse(request.softauth_user.email)

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 200
        assert b"dec@test.com" in r.content

    def test_admin_required_non_admin_returns_403(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "plain@test.com", "p")
        tokens = _login(v, "plain@test.com", "p")

        @django_auth.admin_required
        def view(request: Any) -> HttpResponse:
            return HttpResponse("admin")

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 403

    def test_admin_required_admin_passes(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "adm@test.com", "p", role="admin")
        tokens = _login(v, "adm@test.com", "p")

        @django_auth.admin_required
        def view(request: Any) -> HttpResponse:
            return HttpResponse("admin")

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 200

    def test_require_role_correct(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "editor@test.com", "p", role="editor")
        tokens = _login(v, "editor@test.com", "p")

        @django_auth.require_role("editor")
        def view(request: Any) -> HttpResponse:
            return HttpResponse("editor")

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 200

    def test_require_role_wrong_role_returns_403(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "viewer@test.com", "p", role="viewer")
        tokens = _login(v, "viewer@test.com", "p")

        @django_auth.require_role("editor")
        def view(request: Any) -> HttpResponse:
            return HttpResponse("editor")

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 403

    def test_admin_bypasses_require_role(self, django_auth: SoftAuth) -> None:
        v = _views(django_auth)
        _register(v, "superadmin@test.com", "p", role="admin")
        tokens = _login(v, "superadmin@test.com", "p")

        @django_auth.require_role("editor")
        def view(request: Any) -> HttpResponse:
            return HttpResponse("ok")

        req = _apply_middleware(_get("/", token=tokens["access_token"]), django_auth)
        r = view(req)
        assert r.status_code == 200


# ── Adapter wiring ─────────────────────────────────────────────────────────────

class TestDjangoAdapter:
    def test_init_app_appends_url_patterns(self, django_auth: SoftAuth) -> None:
        auth = SoftAuth(secret_key=_SECRET, framework="django", database_url=_DB)
        auth.init_db()
        urlpatterns: list = []
        auth.init_app(urlpatterns)
        names = [p.name for p in urlpatterns]
        assert "softauth-register" in names
        assert "softauth-login" in names
        assert "softauth-me" in names
        assert "softauth-refresh" in names
        assert "softauth-logout" in names

    def test_django_framework_recognized_by_init_app(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, framework="django", database_url=_DB)
        auth.init_db()
        urlpatterns: list = []
        auth.init_app(urlpatterns)  # must not raise
        assert len(urlpatterns) == 5
