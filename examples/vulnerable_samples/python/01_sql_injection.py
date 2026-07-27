"""
Vulnerable sample: SQL injection.

Expected finding:
    - CWE-89 (SQL Injection)
    - Severity: high
    - Confidence: high
    - Location: lines 28-29 (user lookup), lines 41-42 (search)

This is a deliberately vulnerable file for the Sentinel Review test corpus.
DO NOT use any pattern in this file in production code.
"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user/<user_id>")
def get_user(user_id):
    """Look up a user by ID. VULNERABLE: SQL injection via f-string."""
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT id, name, email FROM users WHERE id = {user_id}"
    cursor.execute(query)
    row = cursor.fetchone()
    return jsonify(dict(row)) if row else ("Not found", 404)


@app.route("/search")
def search_users():
    """Search users by name. VULNERABLE: SQL injection via string concatenation."""
    name = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE name LIKE '%" + name + "%'")
    rows = cursor.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/health")
def health():
    """Health check endpoint. Not vulnerable."""
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True)
