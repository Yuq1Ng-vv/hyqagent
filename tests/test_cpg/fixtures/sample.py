# Sample Python file for parser testing
import os
import sys as system
from flask import Flask, request
from .utils import helper as h
from typing import *

app = Flask(__name__)


@app.route("/login")
def login():
    """Handle user login."""
    user = request.args.get("user")
    return f"Hello {user}"


class UserService:
    """User management service."""

    def __init__(self, db, config):
        self.db = db
        self.config = config

    def get_user(self, user_id: int) -> dict:
        """Fetch a user by ID."""
        return self.db.query(user_id)

    def list_users(self, limit: int = 100) -> list:
        """List all users with a limit."""
        return self.db.query_all(limit)


class AdminService(UserService):
    """Admin-specific operations."""

    def delete_all(self) -> None:
        """Delete all users — dangerous!"""
        self.db.execute("DELETE FROM users")
