"""
Clean sample: URL fetching with allowlist validation.

This file SHOULD produce ZERO findings. The URLs are validated against an
allowlist before any network call, preventing SSRF.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_HOSTS = frozenset({
    "api.partner1.example.com",
    "api.partner2.example.com",
    "webhooks.example.com",
})


def is_safe_url(url: str) -> bool:
    """Validate that a URL points to an allowed host on http(s)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    # Additionally reject if the hostname resolves to a private IP range,
    # to prevent DNS rebinding attacks.
    try:
        resolved = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(resolved)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except (socket.gaierror, ValueError):
        return False
    return True


@app.route("/proxy")
def proxy():
    """Safe: validates URL against allowlist before fetching."""
    url = request.args.get("url", "")
    if not is_safe_url(url):
        return "URL not allowed", 403
    response = requests.get(url, timeout=5)
    return response.text


@app.route("/static-fetch")
def static_fetch():
    """Safe: URL is hardcoded, no user input reaches the URL."""
    response = requests.get(
        "https://api.partner1.example.com/status",
        timeout=5,
    )
    return response.text


if __name__ == "__main__":
    app.run()
