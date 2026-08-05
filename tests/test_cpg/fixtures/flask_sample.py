"""Flask test fixture for framework extractor tests."""

from flask import Flask, request
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/")
def index():
    return "Hello"


@app.route("/users", methods=["GET"])
def list_users():
    page = request.args.get("page", 1)
    return f"Users page {page}"


@app.route("/users/<int:user_id>", methods=["GET", "POST"])
@login_required
def get_user(user_id):
    name = request.form.get("name")
    return {"id": user_id, "name": name or "unknown"}


@app.route("/admin/stats")
@login_required
def admin_stats():
    data = request.json
    return {"status": "ok", "data": data}
