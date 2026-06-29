"""Abstract extension interfaces.

Import from here to build custom providers, token stores, user stores, or
framework adapters without touching the core library.
"""

from softauth.interfaces.adapter import BaseAdapter
from softauth.interfaces.auth_provider import AuthProvider
from softauth.interfaces.token_store import TokenStore
from softauth.interfaces.user_store import UserStore

__all__ = ["BaseAdapter", "AuthProvider", "TokenStore", "UserStore"]
