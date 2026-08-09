"""Cross-language SSRF fixture — Python."""

from flask import Flask, request

import requests

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")  # $ source=ssrf
    resp = requests.get(url)  # $ sink=ssrf
    return resp.text


@app.route("/fetch")
def fetch():
    target = request.args.get("target", "")  # $ source=ssrf
    resp = requests.post(target, json={"data": "test"})  # $ sink=ssrf
    return resp.json()
