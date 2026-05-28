"""
Vulnerable sample: Path traversal.

Expected finding:
    - CWE-22 (Path Traversal) at line 26 (download endpoint)
    - CWE-22 (Path Traversal) at line 38 (read_log)
    - Severity: high
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
UPLOAD_DIR = "/var/app/uploads"
LOG_DIR = "/var/log/app"


@app.route("/download")
def download_file():
    """Download a user-requested file. VULNERABLE: no path sanitization."""
    filename = request.args.get("file", "")
    # Attacker can submit ?file=../../../etc/passwd
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)


@app.route("/logs/<log_name>")
def read_log(log_name):
    """Read a log file. VULNERABLE: directly concatenating user input to a path."""
    # Attacker can submit log_name=../../etc/shadow
    log_path = LOG_DIR + "/" + log_name
    with open(log_path, "r") as f:
        return f.read()


@app.route("/static-info")
def static_info():
    """Returns static info. Not vulnerable — no user-controlled path."""
    with open(os.path.join(UPLOAD_DIR, "info.txt")) as f:
        return f.read()


if __name__ == "__main__":
    app.run()
