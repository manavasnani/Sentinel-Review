import pickle
import base64
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    encoded = request.form.get("session_blob", "")
    session_data = pickle.loads(base64.b64decode(encoded))
    return {"restored": list(session_data.keys())}


@app.route("/config", methods=["POST"])
def load_config():
    raw = request.data
    config = yaml.load(raw)
    return {"keys": list(config.keys())}


@app.route("/config-safe", methods=["POST"])
def load_config_safe():
    config = yaml.safe_load(request.data)
    return {"keys": list(config.keys())}


if __name__ == "__main__":
    app.run()
