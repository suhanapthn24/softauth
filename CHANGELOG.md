# Changelog

All notable changes to softauth are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Redis `TokenStore` implementation for server-side logout
- OAuth2 `AuthProvider` base + Google / GitHub stubs
- Django adapter
- Litestar adapter
- Multi-factor authentication hooks
- Audit-log middleware

---

## [0.1.0] — 2026-06-29

### Added
- `SoftAuth` facade with `init_app()`, `init_db()`, `use_adapter()` API
- Framework-agnostic core: `JWTHandler`, `PasswordHandler`, `SoftAuthConfig`
- FastAPI adapter (`FastAPIAdapter`) with:
  - Auto-generated `APIRouter` on `/auth` prefix
  - `POST /register`, `POST /login` (OAuth2 form), `POST /refresh`, `GET /me`, `POST /logout`
  - `current_user`, `current_admin`, `require_role()` as `Depends()`-ready callables
  - `JWTMiddleware` populating `request.state.user_id / user_role / token_payload`
  - Swagger UI shows all routes and login form automatically
- Flask adapter (`FlaskAdapter`) with:
  - Auto-generated Blueprint on `/auth` prefix
  - `POST /register`, `POST /login` (JSON), `POST /refresh`, `GET /me`, `POST /logout`
  - `@login_required`, `@admin_required`, `@require_role("role")` decorators
  - `before_request` hook populating `g.user_id / g.user_role / g.token_payload`
- Default SQLAlchemy 2.0 `User` model (`softauth_users` table)
- `UserRepository` with `create`, `get_by_id`, `get_by_email`, `update`, `deactivate`
- `DatabaseSession` with `session()` context manager (commit / rollback / close)
- `BaseAdapter`, `AuthProvider`, `TokenStore`, `UserStore` ABCs for future extension
- Typer CLI: `softauth init`, `softauth setup fastapi`, `softauth setup flask`, `softauth secret`
- bcrypt password hashing via `passlib[bcrypt]`
- Access tokens (default 15 min) + refresh tokens (default 7 days)
- RBAC: `user`, `manager`, `admin` built-in; any custom string role supported
- Admin users bypass all `require_role()` checks
- `SoftAuth.use_adapter()` for custom framework adapters
- `from_env()` classmethod on `SoftAuthConfig`
- Environment variable support: `SOFTAUTH_SECRET`, `SOFTAUTH_DB_URL`, `SOFTAUTH_ALGORITHM`
- Test suite with ≥ 90 % coverage (JWT, security, database, FastAPI, Flask)
- GitHub Actions CI (Python 3.9–3.12) and release workflow (PyPI trusted publishing)
- Example apps: `examples/fastapi_example/`, `examples/flask_example/`

[Unreleased]: https://github.com/your-org/softauth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/softauth/releases/tag/v0.1.0
