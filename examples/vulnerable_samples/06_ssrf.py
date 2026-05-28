"""
Vulnerable sample: Server-Side Request Forgery (SSRF).

Expected findings:
    - CWE-918 (SSRF) at line 23 (fetch_url endpoint)
    - CWE-918 (SSRF) at line 35 (webhook proxy)
    - Severity: high
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import requests
from urllib.parse import urlparse
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    """Fetch a user-supplied URL. VULNERABLE: no allowlist."""
    url = request.args.get("url", "")
    # Attacker can request http://169.254.169.254/latest/meta-data/ on AWS
    # to exfiltrate cloud metadata, or http://localhost:6379 to talk to Redis.
    response = requests.get(url, timeout=5)
    return response.text


@app.route("/webhook-proxy", methods=["POST"])
def webhook_proxy():
    """Proxy a webhook payload. VULNERABLE: target URL fully controlled."""
    target = request.json.get("target_url")
    payload = request.json.get("payload")
    # No validation of target - attacker can hit internal services
    requests.post(target, json=payload, timeout=10)
    return {"status": "sent"}


ALLOWED_HOSTS = {"api.partner1.com", "api.partner2.com"}


@app.route("/safe-fetch")
def safe_fetch():
    """Not vulnerable: validates host against allowlist."""
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Invalid scheme", 400
    if parsed.hostname not in ALLOWED_HOSTS:
        return "Host not allowed", 403
    return requests.get(url, timeout=5).text


if __name__ == "__main__":
    app.run()
