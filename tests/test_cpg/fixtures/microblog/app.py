"""microblog/app.py — Flask blog with intentional vulnerabilities.  # noqa: S608

Contains four CWE-class vulnerabilities for end-to-end CPG validation:

* CWE-89  SQL Injection      — /search, /user/<id>
* CWE-78  Command Injection  — /admin/ping
* CWE-79  Cross-Site Scripting — /hello
* CWE-639 IDOR (Insecure Direct Object Reference) — /user/<id> with no auth
"""

import os
from flask import Flask, request, render_template_string
from flask_login import login_required, current_user

from db import Database

app = Flask(__name__)
db = Database()


# ── Public endpoints ─────────────────────────────────────────────────────────


@app.route("/")
def index():
    """Home page — safe."""
    return "<h1>MicroBlog</h1><p>Welcome!</p>"


@app.route("/hello")
def hello():
    """CWE-79: Reflected XSS — user input reflected to HTML without escaping."""
    name = request.args.get("name", "World")
    return f"<h1>Hello {name}</h1>"


@app.route("/search")
def search():
    """CWE-89: SQL Injection — user input concatenated into SQL LIKE clause."""
    keyword = request.args.get("q", "")
    posts = db.search_posts(keyword)
    return str(posts)


@app.route("/user/<int:user_id>")
def user_profile(user_id):
    """CWE-639: IDOR — no authentication, any user can access any profile."""
    user = db.fetch_user_by_id(str(user_id))
    if user is None:
        return "User not found", 404
    return f"<h1>{user[1]}</h1>"


@app.route("/post/<int:post_id>")
@login_required
def view_post(post_id):
    """Authenticated endpoint — DB call still tainted despite @login_required."""
    import sqlite3

    try:
        post = db.cursor.execute(f"SELECT * FROM posts WHERE id = {post_id}").fetchone()
    except sqlite3.Error:
        return "Error", 500
    if post is None:
        return "Post not found", 404
    return f"<h1>{post[1]}</h1><p>{post[2]}</p>"


# ── Admin endpoints ──────────────────────────────────────────────────────────


@app.route("/admin/ping", methods=["GET", "POST"])
@login_required
def admin_ping():
    """CWE-78: Command Injection — user-supplied host passed to os.system()."""
    host = request.form.get("host") or request.args.get("host", "127.0.0.1")
    command = f"ping -c 1 {host}"
    os.system(command)
    return f"Pinged {host}"


@app.route("/admin/exec")
@login_required
def admin_exec():
    """CWE-78: Command Injection — user-supplied cmd passed to os.popen()."""
    cmd = request.args.get("cmd", "ls")
    output = os.popen(cmd).read()
    return f"<pre>{output}</pre>"


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
