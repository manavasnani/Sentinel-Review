import requests
from urllib.parse import urlparse
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=5)
    return response.text


@app.route("/webhook-proxy", methods=["POST"])
def webhook_proxy():
    target = request.json.get("target_url")
    payload = request.json.get("payload")
    requests.post(target, json=payload, timeout=10)
    return {"status": "sent"}


ALLOWED_HOSTS = {"api.partner1.com", "api.partner2.com"}


@app.route("/safe-fetch")
def safe_fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Invalid scheme", 400
    if parsed.hostname not in ALLOWED_HOSTS:
        return "Host not allowed", 403
    return requests.get(url, timeout=5).text


if __name__ == "__main__":
    app.run()
