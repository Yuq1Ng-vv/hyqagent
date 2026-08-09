"""Cross-language SQL injection NEGATIVE fixture — Python (Flask).

SAFE implementation that MUST NOT trigger any SQL injection finding.
Uses parameterized queries — the correct way.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user/<int:user_id>")
def get_user(user_id):
    """SAFE: parameterized query — should NOT be flagged as SQLi."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Proper parameterization with ? placeholder
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchone())
