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
