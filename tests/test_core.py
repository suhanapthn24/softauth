"""Tests for SoftAuth facade, config, and CLI."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest

from softauth import SoftAuth
from softauth.core.auth import SoftAuth
from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import AdapterNotInitializedError, ConfigurationError

_SECRET = "test-secret-key-min-16-chars"
_DB = "sqlite:///:memory:"


class TestSoftAuthConfig:
    def test_from_env(self) -> None:
        with patch.dict(os.environ, {"SOFTAUTH_SECRET": _SECRET, "SOFTAUTH_DB_URL": _DB}):
            cfg = SoftAuthConfig.from_env(framework="fastapi")
        assert cfg.secret_key == _SECRET
        assert cfg.database_url == _DB

    def test_from_env_with_override(self) -> None:
        with patch.dict(os.environ, {"SOFTAUTH_SECRET": "env-secret-key-16+chars"}):
            cfg = SoftAuthConfig.from_env(secret_key=_SECRET, framework="fastapi")
        assert cfg.secret_key == _SECRET  # override wins

    def test_invalid_expiry(self) -> None:
        with pytest.raises(Exception):
            SoftAuthConfig(secret_key=_SECRET, access_expiry_minutes=0)


class TestSoftAuthFacade:
    def test_adapter_not_initialized_raises(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, framework="fastapi", database_url=_DB)
        with pytest.raises(AdapterNotInitializedError):
            _ = auth.current_user

    def test_unknown_framework_raises(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, framework="litestar", database_url=_DB)  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError):
            from fastapi import FastAPI
            auth.init_app(FastAPI())

    def test_none_framework_raises_on_init_app(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, framework=None, database_url=_DB)
        with pytest.raises(ConfigurationError):
            from fastapi import FastAPI
            auth.init_app(FastAPI())

    def test_hash_and_verify_password(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, database_url=_DB)
        h = auth.hash_password("mypassword")
        assert auth.verify_password("mypassword", h) is True
        assert auth.verify_password("wrong", h) is False

    def test_create_and_decode_access_token(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, database_url=_DB)
        token = auth.create_access_token("user-1", role="admin")
        payload = auth.decode_token(token)
        assert payload["sub"] == "user-1"
        assert payload["role"] == "admin"

    def test_create_refresh_token(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, database_url=_DB)
        token = auth.create_refresh_token("user-1")
        payload = auth.decode_token(token)
        assert payload["type"] == "refresh"

    def test_verify_token_true(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, database_url=_DB)
        token = auth.create_access_token("u")
        assert auth.verify_token(token) is True

    def test_verify_token_false(self) -> None:
        auth = SoftAuth(secret_key=_SECRET, database_url=_DB)
        assert auth.verify_token("garbage") is False

    def test_use_adapter(self) -> None:
        """use_adapter() accepts custom BaseAdapter implementations."""
        from softauth.interfaces.adapter import BaseAdapter
        from fastapi import FastAPI

        class NoOpAdapter(BaseAdapter):
            initialized = False

            def init_app(self, app: Any) -> None:
                NoOpAdapter.initialized = True

            def get_current_user_dependency(self) -> Any:
                return lambda: None

            def get_current_admin_dependency(self) -> Any:
                return lambda: None

            def get_require_role_dependency(self, role: str) -> Any:
                return lambda: None

        auth = SoftAuth(secret_key=_SECRET, framework=None, database_url=_DB)
        adapter = NoOpAdapter()
        app = FastAPI()
        auth.use_adapter(adapter, app)
        assert NoOpAdapter.initialized is True


class TestCLI:
    def test_secret_command(self, tmp_path: Any) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["secret"])
        assert result.exit_code == 0
        assert len(result.output.strip()) == 64  # 32 bytes hex = 64 chars

    def test_secret_custom_length(self) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["secret", "--length", "16"])
        assert result.exit_code == 0
        assert len(result.output.strip()) == 32  # 16 bytes = 32 hex chars

    def test_init_command(self, tmp_path: Any) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["init"], catch_exceptions=False)
        # In the actual invocation, cwd is project root — just check exit code
        assert result.exit_code == 0

    def test_setup_fastapi(self) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["setup", "fastapi"])
        assert result.exit_code == 0

    def test_setup_flask(self) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["setup", "flask"])
        assert result.exit_code == 0

    def test_setup_unknown_framework(self) -> None:
        from typer.testing import CliRunner
        from softauth.cli.commands import app as cli_app

        runner = CliRunner()
        result = runner.invoke(cli_app, ["setup", "litestar"])
        assert result.exit_code != 0
