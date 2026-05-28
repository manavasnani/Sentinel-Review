"""
Vulnerable sample: Insecure deserialization.

Expected findings:
    - CWE-502 (Insecure Deserialization) at line 25 (pickle.loads on request data)
    - CWE-502 (Insecure Deserialization) at line 36 (yaml.load without safe loader)
    - Severity: critical (pickle is RCE)
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import pickle
import base64
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    """Restore session state. VULNERABLE: pickle.loads on attacker data = RCE."""
    encoded = request.form.get("session_blob", "")
    # pickle.loads on any attacker-controlled bytes is remote code execution.
    # The attacker can craft a payload that runs arbitrary Python on load.
    session_data = pickle.loads(base64.b64decode(encoded))
    return {"restored": list(session_data.keys())}


@app.route("/config", methods=["POST"])
def load_config():
    """Load YAML config. VULNERABLE: yaml.load without SafeLoader."""
    raw = request.data
    # yaml.load without an explicit safe loader allows arbitrary object
    # construction, which can lead to code execution.
    config = yaml.load(raw)
    return {"keys": list(config.keys())}


@app.route("/config-safe", methods=["POST"])
def load_config_safe():
    """Not vulnerable: uses yaml.safe_load."""
    config = yaml.safe_load(request.data)
    return {"keys": list(config.keys())}


if __name__ == "__main__":
    app.run()
