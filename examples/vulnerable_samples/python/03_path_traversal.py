import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
UPLOAD_DIR = "/var/app/uploads"
LOG_DIR = "/var/log/app"


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)


@app.route("/logs/<log_name>")
def read_log(log_name):
    log_path = LOG_DIR + "/" + log_name
    with open(log_path, "r") as f:
        return f.read()


@app.route("/static-info")
def static_info():
    with open(os.path.join(UPLOAD_DIR, "info.txt")) as f:
        return f.read()

if __name__ == "__main__":
    app.run()
