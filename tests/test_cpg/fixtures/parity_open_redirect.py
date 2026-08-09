"""Cross-language open redirect fixture — Python (Flask)."""

from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/login")
def login():
    next_url = request.args.get("next", "/")  # $ source=open_redirect
    return redirect(next_url)  # $ sink=open_redirect


@app.route("/goto")
def goto():
    target = request.args.get("url", "/")  # $ source=open_redirect
    return redirect(target, code=302)  # $ sink=open_redirect
