import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Attacker can submit ?host=1.1.1.1;rm -rf /
    os.system(f"ping -c 1 {host}")
    return f"Pinged {host}"


@app.route("/backup")
def backup_file():
    filename = request.args.get("file", "")
    # shell=True is the issue; filename is interpolated into a shell command
    result = subprocess.check_output(
        f"tar -czf /backups/{filename}.tar.gz /data/{filename}",
        shell=True,
    )
    return result


@app.route("/whoami")
def whoami():
    return subprocess.check_output(["whoami"]).decode().strip()


if __name__ == "__main__":
    app.run()
