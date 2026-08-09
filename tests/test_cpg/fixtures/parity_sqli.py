"""Cross-language SQL injection fixture — Python (Flask)."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    keyword = request.args.get("q", "")  # $ source=sql_injection
    cursor.execute(
        "SELECT * FROM posts WHERE title LIKE '%" + keyword + "%'"
    )  # $ sink=sql_injection


@app.route("/user/<int:user_id>")
def get_user(user_id):
    uid = request.args.get("uid")  # $ source=sql_injection
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # $ sink=sql_injection
