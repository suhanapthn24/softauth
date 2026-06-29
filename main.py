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
