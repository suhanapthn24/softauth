"""Hierarchy of SoftAuth exceptions.

Every exception the library raises is a subclass of SoftAuthError so callers
can catch the whole tree with a single ``except SoftAuthError`` if they need to.
"""


class SoftAuthError(Exception):
    """Root exception for all softauth errors."""


# ── Authentication ────────────────────────────────────────────────────────────

class AuthError(SoftAuthError):
    """Raised for general authentication failures."""


class InvalidCredentialsError(AuthError):
    """Wrong email / password combination."""


class InactiveUserError(AuthError):
    """Account exists but has been deactivated."""


# ── Token ─────────────────────────────────────────────────────────────────────

class TokenError(SoftAuthError):
    """Base class for all token-related errors."""


class TokenExpiredError(TokenError):
    """JWT has passed its expiry timestamp."""


class InvalidTokenError(TokenError):
    """JWT signature is bad, format is wrong, or claims are missing."""


class TokenTypeMismatchError(TokenError):
    """e.g. a refresh token was presented where an access token is expected."""


# ── User / identity ───────────────────────────────────────────────────────────

class UserNotFoundError(SoftAuthError):
    """No user record matches the given identifier."""


class UserAlreadyExistsError(SoftAuthError):
    """A user with this email already exists."""


# ── Authorisation ─────────────────────────────────────────────────────────────

class PermissionDeniedError(SoftAuthError):
    """Authenticated user lacks the required role."""


# ── Configuration ─────────────────────────────────────────────────────────────

class ConfigurationError(SoftAuthError):
    """Invalid or missing SoftAuth configuration."""


class AdapterNotInitializedError(SoftAuthError):
    """init_app() has not been called yet."""
