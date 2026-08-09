"""Cross-language auth bypass fixture — Python (Flask).

Missing @login_required on sensitive admin endpoints.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/public")
def public():
    return "public data"


@app.route("/admin/delete_user")
def delete_user():
    """VULNERABLE: no @login_required decorator on sensitive admin endpoint."""
    user_id = request.args.get("user_id")  # $ source=auth_bypass
    # Delete user — no authentication check
    return f"User {user_id} deleted"


@app.route("/admin/settings", methods=["POST"])
def update_settings():
    """VULNERABLE: admin endpoint without authentication."""
    setting = request.form.get("setting")  # $ source=auth_bypass
    value = request.form.get("value")  # $ source=auth_bypass
    # Apply setting — no auth check
    return f"Set {setting} = {value}"
