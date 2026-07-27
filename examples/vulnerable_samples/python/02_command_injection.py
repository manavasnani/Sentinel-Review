"""
Vulnerable sample: OS command injection.

Expected findings:
    - CWE-78 (OS Command Injection) at line 27 (os.system)
    - CWE-78 (OS Command Injection) at line 38 (subprocess shell=True)
    - Severity: critical or high
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    """Ping a host. VULNERABLE: passes user input directly to os.system."""
    host = request.args.get("host", "127.0.0.1")
    # Attacker can submit ?host=1.1.1.1;rm -rf /
    os.system(f"ping -c 1 {host}")
    return f"Pinged {host}"


@app.route("/backup")
def backup_file():
    """Back up a file. VULNERABLE: subprocess with shell=True and untrusted input."""
    filename = request.args.get("file", "")
    # shell=True is the issue; filename is interpolated into a shell command
    result = subprocess.check_output(
        f"tar -czf /backups/{filename}.tar.gz /data/{filename}",
        shell=True,
    )
    return result


@app.route("/whoami")
def whoami():
    """Return the current process user. Not vulnerable — fixed command, no user input."""
    return subprocess.check_output(["whoami"]).decode().strip()


if __name__ == "__main__":
    app.run()
