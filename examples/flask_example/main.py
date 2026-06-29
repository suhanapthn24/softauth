"""Full-featured Flask example using softauth.

Run:
    pip install "softauth[flask]"
    python main.py

Or with the Flask CLI:
    FLASK_APP=main flask run --debug
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from flask import Flask, g, jsonify

from softauth import SoftAuth

load_dotenv()

# ── Bootstrap ──────────────────────────────────────────────────────────────────

auth = SoftAuth(
    secret_key=os.environ.get("SOFTAUTH_SECRET", "dev-secret-change-in-prod-1234"),
    framework="flask",
    database_url=os.environ.get("SOFTAUTH_DB_URL", "sqlite:///example.db"),
    access_expiry_minutes=15,
    refresh_expiry_days=7,
)

app = Flask(__name__)
auth.init_app(app)   # registers /auth/* blueprint + before_request hook
auth.init_db()       # creates softauth_users table


# ── Public routes ──────────────────────────────────────────────────────────────

@app.route("/")
def root() -> Any:
    return jsonify({"message": "softauth Flask example"})


# ── Protected routes ───────────────────────────────────────────────────────────

@app.route("/profile")
@auth.login_required
def profile() -> Any:
    """Return the current user's profile (any authenticated user)."""
    return jsonify(g.user.to_dict())


@app.route("/admin/dashboard")
@auth.admin_required
def admin_dashboard() -> Any:
    """Admin-only endpoint."""
    return jsonify({"message": f"Welcome, admin {g.user.email}!"})


@app.route("/manager/reports")
@auth.require_role("manager")
def manager_reports() -> Any:
    """Manager-or-admin endpoint."""
    return jsonify({"message": f"Reports for {g.user.email}", "role": g.user.role})


@app.route("/editor/content")
@auth.require_role("editor")
def editor_content() -> Any:
    """Editor-or-admin endpoint."""
    return jsonify({"message": f"Content panel for {g.user.email}"})


if __name__ == "__main__":
    app.run(debug=True)
