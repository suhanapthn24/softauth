"""Full-featured FastAPI example using softauth.

Run:
    pip install "softauth[fastapi]" uvicorn
    uvicorn main:app --reload

Then visit http://127.0.0.1:8000/docs for the interactive Swagger UI.
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI

from softauth import SoftAuth

load_dotenv()

# ── Bootstrap ──────────────────────────────────────────────────────────────────

auth = SoftAuth(
    secret_key=os.environ.get("SOFTAUTH_SECRET", "dev-secret-change-in-prod-1234"),
    framework="fastapi",
    database_url=os.environ.get("SOFTAUTH_DB_URL", "sqlite:///example.db"),
    access_expiry_minutes=15,
    refresh_expiry_days=7,
)

app = FastAPI(
    title="softauth FastAPI Example",
    description="Demonstrates zero-setup JWT auth",
    version="0.1.0",
)

auth.init_app(app)   # registers /auth/* routes + JWT middleware
auth.init_db()       # creates softauth_users table


# ── Public routes ──────────────────────────────────────────────────────────────

@app.get("/", tags=["Public"])
def root() -> dict[str, str]:
    return {"message": "softauth example — visit /docs"}


# ── Protected routes ───────────────────────────────────────────────────────────

@app.get("/profile", tags=["Protected"])
def profile(user: Any = Depends(auth.current_user)) -> dict[str, Any]:
    """Return the current user's profile."""
    return user.to_dict()


@app.get("/admin/dashboard", tags=["Admin"])
def admin_dashboard(user: Any = Depends(auth.current_admin)) -> dict[str, Any]:
    """Admin-only endpoint."""
    return {"message": f"Welcome, admin {user.email}!", "id": user.id}


@app.get("/manager/reports", tags=["Manager"])
def manager_reports(user: Any = Depends(auth.require_role("manager"))) -> dict[str, Any]:
    """Manager-or-admin endpoint."""
    return {"message": f"Reports for {user.email}", "role": user.role}


@app.get("/editor/content", tags=["Editor"])
def editor_content(user: Any = Depends(auth.require_role("editor"))) -> dict[str, Any]:
    """Editor-or-admin endpoint."""
    return {"message": f"Content panel for {user.email}"}
