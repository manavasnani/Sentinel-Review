from urllib.parse import urlparse, urljoin
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/logout")
def logout():
    return_to = request.args.get("return_to", "/")
    return redirect(return_to)


@app.route("/safe-login")
def safe_login():
    next_url = request.args.get("next", "/")
    parsed = urlparse(urljoin(request.host_url, next_url))
    if parsed.netloc != request.host:
        return redirect("/")
    return redirect(next_url)

if __name__ == "__main__":
    app.run()
