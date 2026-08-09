"""Cross-language XSS fixture — Python (Flask)."""

from flask import Flask, Response, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "World")  # $ source=xss
    return Response(f"<h1>Hello {name}</h1>")  # $ sink=xss


@app.route("/reflect")
def reflect():
    user_input = request.args.get("msg", "")  # $ source=xss
    return Response("<div>" + user_input + "</div>")  # $ sink=xss
