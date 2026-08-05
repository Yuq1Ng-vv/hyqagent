# Data flow test fixture — Python
# Simple variable assignments and uses for def-use chain testing

import os
from flask import request

CONFIG_KEY = "secret"  # Module-level — not in a function


def process_request():
    """Simple function with def-use chains."""
    user_input = request.args.get("id")  # def: user_input
    sanitized = int(user_input)  # def: sanitized, use: user_input
    result = lookup(sanitized)  # def: result, use: sanitized
    return result  # use: result


def lookup(item_id):
    """Another function for cross-function tracing."""
    query = f"SELECT * FROM users WHERE id={item_id}"  # def: query, use: item_id (param)
    data = db_execute(query)  # def: data, use: query
    return data  # use: data


def db_execute(sql):
    """Simulated database call — a taint sink."""
    print(f"Executing: {sql}")  # use: sql (param)
    return {"rows": []}


def multi_assign():
    """Function with multiple assignments to the same variable."""
    x = 1  # def: x
    y = x + 1  # def: y, use: x
    x = y * 2  # def: x (re-definition), use: y
    return x  # use: x


def no_assignments():
    """Function that only reads, never assigns."""
    return CONFIG_KEY + "suffix"


def conditional_def():
    """Function with conditional assignment."""
    flag = True  # def: flag
    if flag:  # use: flag
        value = "yes"  # def: value
    else:
        value = "no"  # def: value
    return value  # use: value


class DataService:
    """Class with methods for data-flow testing."""

    def __init__(self, db_url):
        self.db_url = db_url  # def: self.db_url (attribute — not a simple variable)

    def fetch(self, user_id):
        """Method with parameter and local variable."""
        conn = self.connect()  # def: conn
        row = conn.query(user_id)  # def: row, use: conn
        return row  # use: row

    def connect(self):
        """Helper method."""
        return f"connected to {self.db_url}"
