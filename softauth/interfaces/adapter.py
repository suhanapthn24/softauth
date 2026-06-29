"""BaseAdapter — the contract every framework adapter must fulfil.

Adding Django, Litestar, Quart, or any other framework means creating a new
class that inherits from BaseAdapter and implements each abstract method.
The core SoftAuth class only ever calls the methods declared here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable


class BaseAdapter(ABC):
    """Framework-agnostic adapter interface.

    Concrete implementations live in ``softauth.fastapi`` and
    ``softauth.flask``.  Third-party framework support can be added by
    publishing a package that ships its own ``BaseAdapter`` subclass.
    """

    @abstractmethod
    def init_app(self, app: Any) -> None:
        """Attach SoftAuth routes and middleware to the application object."""

    # ── Route / middleware integration ────────────────────────────────────

    @abstractmethod
    def get_current_user_dependency(self) -> Any:
        """Return a framework-native dependency for the current user.

        FastAPI: returns a callable suitable for ``Depends()``.
        Flask: returns a decorator.
        Other: whatever the framework needs.
        """

    @abstractmethod
    def get_current_admin_dependency(self) -> Any:
        """Like get_current_user_dependency but restricted to admin role."""

    @abstractmethod
    def get_require_role_dependency(self, role: str) -> Any:
        """Return a dependency/decorator that enforces ``role``."""

    # ── Optional hook: called by SoftAuth before init_app ─────────────────

    def on_startup(self) -> None:
        """Override to run adapter-specific startup logic."""
