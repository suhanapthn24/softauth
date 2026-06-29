"""Password handler tests."""

from __future__ import annotations

import pytest

from softauth.security.password import PasswordHandler


@pytest.fixture(scope="module")
def ph() -> PasswordHandler:
    return PasswordHandler()


class TestHashPassword:
    def test_returns_string(self, ph: PasswordHandler) -> None:
        assert isinstance(ph.hash_password("secret"), str)

    def test_not_plaintext(self, ph: PasswordHandler) -> None:
        plain = "mysecret"
        assert ph.hash_password(plain) != plain

    def test_unique_salts(self, ph: PasswordHandler) -> None:
        h1 = ph.hash_password("same")
        h2 = ph.hash_password("same")
        assert h1 != h2

    def test_bcrypt_prefix(self, ph: PasswordHandler) -> None:
        assert ph.hash_password("x").startswith("$2b$")

    def test_empty_string(self, ph: PasswordHandler) -> None:
        hashed = ph.hash_password("")
        assert isinstance(hashed, str)


class TestVerifyPassword:
    def test_correct_password(self, ph: PasswordHandler) -> None:
        hashed = ph.hash_password("correct")
        assert ph.verify_password("correct", hashed) is True

    def test_wrong_password(self, ph: PasswordHandler) -> None:
        hashed = ph.hash_password("correct")
        assert ph.verify_password("wrong", hashed) is False

    def test_empty_password(self, ph: PasswordHandler) -> None:
        hashed = ph.hash_password("")
        assert ph.verify_password("", hashed) is True
        assert ph.verify_password("notempty", hashed) is False


class TestNeedsRehash:
    def test_fresh_hash_does_not_need_rehash(self, ph: PasswordHandler) -> None:
        hashed = ph.hash_password("x")
        assert ph.needs_rehash(hashed) is False
