"""Flask integration tests — routes, middleware, decorators, RBAC."""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask, g, jsonify
from flask.testing import FlaskClient

from softauth import SoftAuth


def _make_app(auth: SoftAuth) -> Flask:
    app = Flask(__name__)
    auth.init_app(app)

    @app.route("/profile")
    @auth.login_required
    def profile() -> Any:
        return jsonify(g.user.to_dict())

    @app.route("/admin-only")
    @auth.admin_required
    def admin_only() -> Any:
        return jsonify({"msg": "admin"})

    @app.route("/manager-only")
    @auth.require_role("manager")
    def manager_only() -> Any:
        return jsonify({"msg": "manager"})

    return app


def _register(client: FlaskClient, email: str, password: str, role: str = "user") -> None:
    r = client.post("/auth/register", json={"email": email, "password": password, "role": role})
    assert r.status_code == 201, r.get_json()


def _login(client: FlaskClient, email: str, password: str) -> dict[str, Any]:
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


class TestRegister:
    def test_success(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        r = client.post("/auth/register", json={"email": "fr@test.com", "password": "pw"})
        assert r.status_code == 201
        assert "id" in r.get_json()

    def test_duplicate_email(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        data = {"email": "fdup@test.com", "password": "pw"}
        client.post("/auth/register", json=data)
        r = client.post("/auth/register", json=data)
        assert r.status_code == 409

    def test_missing_fields(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        r = client.post("/auth/register", json={"email": "only@test.com"})
        assert r.status_code == 400


class TestLogin:
    def test_returns_tokens(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "flog@test.com", "pw")
        data = _login(client, "flog@test.com", "pw")
        assert "access_token" in data and "refresh_token" in data

    def test_wrong_password(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fwp@test.com", "correct")
        r = client.post("/auth/login", json={"email": "fwp@test.com", "password": "wrong"})
        assert r.status_code == 401

    def test_unknown_user(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        r = client.post("/auth/login", json={"email": "nobody@test.com", "password": "x"})
        assert r.status_code == 401


class TestRefresh:
    def test_new_access_token_issued(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "frf@test.com", "p")
        tokens = _login(client, "frf@test.com", "p")
        r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 200
        assert "access_token" in r.get_json()

    def test_invalid_refresh_token(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        r = client.post("/auth/refresh", json={"refresh_token": "garbage"})
        assert r.status_code == 401


class TestGetMe:
    def test_returns_profile(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fme@test.com", "p")
        token = _login(client, "fme@test.com", "p")["access_token"]
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.get_json()["email"] == "fme@test.com"

    def test_no_token_401(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        assert client.get("/auth/me").status_code == 401


class TestDecorators:
    def test_login_required_no_token(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        assert client.get("/profile").status_code == 401

    def test_login_required_valid_token(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "dec@test.com", "p")
        token = _login(client, "dec@test.com", "p")["access_token"]
        r = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.get_json()["email"] == "dec@test.com"

    def test_admin_required_non_admin(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "plain2@test.com", "p")
        token = _login(client, "plain2@test.com", "p")["access_token"]
        r = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_admin_required_admin_user(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fadm@test.com", "p", role="admin")
        token = _login(client, "fadm@test.com", "p")["access_token"]
        r = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_require_role_correct_role(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fmgr@test.com", "p", role="manager")
        token = _login(client, "fmgr@test.com", "p")["access_token"]
        r = client.get("/manager-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_require_role_wrong_role(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fviewer@test.com", "p", role="viewer")
        token = _login(client, "fviewer@test.com", "p")["access_token"]
        r = client.get("/manager-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_admin_bypasses_require_role(self, flask_auth: SoftAuth) -> None:
        client = _make_app(flask_auth).test_client()
        _register(client, "fadm2@test.com", "p", role="admin")
        token = _login(client, "fadm2@test.com", "p")["access_token"]
        r = client.get("/manager-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
