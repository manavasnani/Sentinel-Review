"""
Vulnerable sample: Open redirect.

Expected findings:
    - CWE-601 (Open Redirect) at line 25 (login redirect)
    - CWE-601 (Open Redirect) at line 36 (logout redirect)
    - Severity: medium
    - Confidence: high

An open redirect allows an attacker to craft a link that appears to be on the
trusted site but redirects to an attacker-controlled site, useful for phishing.

DO NOT use any pattern in this file in production code.
"""

from urllib.parse import urlparse, urljoin
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/login")
def login():
    """
    Log in and redirect. VULNERABLE: returns wherever the `next` param points.

    Attacker can craft https://yoursite.com/login?next=https://evil.com to make
    a phishing link that looks legitimate.
    """
    next_url = request.args.get("next", "/")
    # ... authentication happens here ...
    return redirect(next_url)


@app.route("/logout")
def logout():
    """VULNERABLE: same open-redirect pattern."""
    return_to = request.args.get("return_to", "/")
    # ... session cleanup ...
    return redirect(return_to)


@app.route("/safe-login")
def safe_login():
    """Not vulnerable: validates the redirect target stays on this host."""
    next_url = request.args.get("next", "/")
    parsed = urlparse(urljoin(request.host_url, next_url))
    if parsed.netloc != request.host:
        return redirect("/")
    return redirect(next_url)


if __name__ == "__main__":
    app.run()
