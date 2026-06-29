"""Typer CLI for softauth.

Commands:
    softauth init            — scaffold .env and auth/ directory
    softauth setup fastapi   — generate a ready-to-run FastAPI main.py
    softauth setup flask     — generate a ready-to-run Flask app.py
    softauth secret          — print a cryptographically secure key
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="softauth",
    help="softauth — zero-setup JWT authentication CLI",
    add_completion=False,
)

setup_app = typer.Typer(help="Generate framework-specific boilerplate.")
app.add_typer(setup_app, name="setup")


# ── softauth init ──────────────────────────────────────────────────────────────

@app.command()
def init() -> None:
    """Scaffold the auth/ directory and a .env file with a fresh secret key."""
    auth_dir = Path("auth")
    auth_dir.mkdir(exist_ok=True)
    (auth_dir / "__init__.py").touch()

    env_path = Path(".env")
    if env_path.exists():
        typer.echo(".env already exists — skipping.")
    else:
        secret = secrets.token_hex(32)
        env_path.write_text(
            f"# SoftAuth — do NOT commit this file\n"
            f"SOFTAUTH_SECRET={secret}\n"
            f"SOFTAUTH_DB_URL=sqlite:///auth.db\n"
            f"SOFTAUTH_ALGORITHM=HS256\n",
            encoding="utf-8",
        )
        typer.echo(f"Created .env with a fresh secret key.")

    typer.echo(f"Initialised auth/ directory.")
    typer.echo("Next steps:")
    typer.echo("  softauth setup fastapi   (or flask)")
    typer.echo("  python -m uvicorn main:app --reload")


# ── softauth setup fastapi ─────────────────────────────────────────────────────

@setup_app.command("fastapi")
def setup_fastapi() -> None:
    """Generate a ready-to-run FastAPI application with softauth wired in."""
    target = Path("main.py")
    if target.exists():
        typer.echo("main.py already exists — skipping.")
        raise typer.Exit()

    target.write_text(
        '''\
from fastapi import FastAPI, Depends
from softauth import SoftAuth
from dotenv import load_dotenv
import os

load_dotenv()

auth = SoftAuth(
    secret_key=os.environ["SOFTAUTH_SECRET"],
    framework="fastapi",
    database_url=os.getenv("SOFTAUTH_DB_URL", "sqlite:///auth.db"),
)

app = FastAPI(title="My App")
auth.init_app(app)
auth.init_db()


# ── Protected routes ──────────────────────────────────────────────────────────

@app.get("/profile")
def profile(user=Depends(auth.current_user)):
    return user.to_dict()


@app.get("/admin")
def admin_dashboard(user=Depends(auth.current_admin)):
    return {"message": f"Welcome, admin {user.email}"}


@app.get("/manager")
def manager_page(user=Depends(auth.require_role("manager"))):
    return {"message": f"Welcome, manager {user.email}"}
''',
        encoding="utf-8",
    )
    typer.echo("Created main.py — run with:  uvicorn main:app --reload")


# ── softauth setup flask ───────────────────────────────────────────────────────

@setup_app.command("flask")
def setup_flask() -> None:
    """Generate a ready-to-run Flask application with softauth wired in."""
    target = Path("app.py")
    if target.exists():
        typer.echo("app.py already exists — skipping.")
        raise typer.Exit()

    target.write_text(
        '''\
from flask import Flask, g, jsonify
from softauth import SoftAuth
from dotenv import load_dotenv
import os

load_dotenv()

auth = SoftAuth(
    secret_key=os.environ["SOFTAUTH_SECRET"],
    framework="flask",
    database_url=os.getenv("SOFTAUTH_DB_URL", "sqlite:///auth.db"),
)

app = Flask(__name__)
auth.init_app(app)
auth.init_db()


# ── Protected routes ──────────────────────────────────────────────────────────

@app.route("/profile")
@auth.login_required
def profile():
    return jsonify(g.user.to_dict())


@app.route("/admin")
@auth.admin_required
def admin_dashboard():
    return jsonify({"message": f"Welcome, admin {g.user.email}"})


@app.route("/manager")
@auth.require_role("manager")
def manager_page():
    return jsonify({"message": f"Welcome, manager {g.user.email}"})


if __name__ == "__main__":
    app.run(debug=True)
''',
        encoding="utf-8",
    )
    typer.echo("Created app.py — run with:  flask run")


# ── softauth setup django ─────────────────────────────────────────────────────

@setup_app.command("django")
def setup_django() -> None:
    """Generate a ready-to-run Django application with softauth wired in."""
    target = Path("views.py")
    if target.exists():
        typer.echo("views.py already exists — skipping.")
        raise typer.Exit()

    target.write_text(
        '''\
from django.http import JsonResponse
from softauth import SoftAuth
from dotenv import load_dotenv
import os

load_dotenv()

auth = SoftAuth(
    secret_key=os.environ["SOFTAUTH_SECRET"],
    framework="django",
    database_url=os.getenv("SOFTAUTH_DB_URL", "sqlite:///auth.db"),
)
auth.init_db()


# ── In urls.py ────────────────────────────────────────────────────────────────
#
# from django.urls import path
# from .views import auth
#
# urlpatterns = []
# auth.init_app(urlpatterns)   # appends /auth/* routes
#
# Also add to settings.py MIDDLEWARE:
#   "softauth.django.middleware.SoftAuthMiddleware",


# ── Protected views ───────────────────────────────────────────────────────────

@auth.login_required
def profile(request):
    return JsonResponse(request.softauth_user.to_dict())


@auth.admin_required
def admin_dashboard(request):
    return JsonResponse({"message": f"Welcome, admin {request.softauth_user.email}"})


@auth.require_role("manager")
def manager_page(request):
    return JsonResponse({"message": f"Welcome, manager {request.softauth_user.email}"})
''',
        encoding="utf-8",
    )
    typer.echo("Created views.py — wire it into urls.py and add SoftAuthMiddleware to MIDDLEWARE.")


# ── softauth secret ────────────────────────────────────────────────────────────

@app.command()
def secret(
    length: int = typer.Option(32, "--length", "-l", help="Number of random bytes (hex output is 2× longer)"),
) -> None:
    """Print a cryptographically secure random secret key."""
    typer.echo(secrets.token_hex(length))
