"""microblog/db.py — Database layer with intentional SQL injection vulnerabilities.  # noqa: S608

This module simulates a raw database layer that concatenates user input
directly into SQL queries — no parameterization, no ORM escaping.
Equivalent to CWE-89 (SQL Injection).
"""

import sqlite3


class Database:
    """Thin wrapper around sqlite3 with deliberately unsafe query methods."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def execute(self, sql: str):
        """Execute raw SQL — VULNERABLE: no parameterization."""
        return self.cursor.execute(sql)

    def fetch_user_by_name(self, name: str):
        """VULNERABLE: string interpolation into SQL query."""
        query = f"SELECT * FROM users WHERE name = '{name}'"
        return self.cursor.execute(query).fetchone()

    def fetch_user_by_id(self, user_id: str):
        """VULNERABLE: string interpolation into SQL query."""
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.cursor.execute(query).fetchone()

    def search_posts(self, keyword: str):
        """VULNERABLE: LIKE clause with string interpolation."""
        query = f"SELECT * FROM posts WHERE title LIKE '%{keyword}%'"
        return self.cursor.execute(query).fetchall()
