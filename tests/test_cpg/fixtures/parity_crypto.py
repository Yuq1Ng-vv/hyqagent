"""Cross-language crypto weakness fixture — Python."""

import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password", "")  # $ source=crypto_weakness
    h = hashlib.md5(password.encode()).hexdigest()  # $ sink=crypto_weakness
    return f"Hash: {h}"


@app.route("/hash_data")
def hash_data():
    data = request.args.get("data", "")  # $ source=crypto_weakness
    h = hashlib.sha1(data.encode()).hexdigest()  # $ sink=crypto_weakness
    return h
