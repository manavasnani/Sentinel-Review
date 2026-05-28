"""
Clean sample: properly parameterized SQL queries.

This file SHOULD produce ZERO findings. The patterns here are explicitly
listed as safe in the system prompt's anti-pattern section. If the analyzer
flags any of these, that's a false positive and the prompt needs revision.

Tests:
    - sqlite3 with `?` parameters
    - psycopg2 with `%s` parameters
    - SQLAlchemy ORM
    - SQLAlchemy text() with bound parameters
"""

import sqlite3
import psycopg2
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/user/<int:user_id>")
def get_user_sqlite(user_id):
    """Safe: sqlite3 with positional placeholders."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    return jsonify(row)


@app.route("/search")
def search_users():
    """Safe: psycopg2 with %s placeholders. The driver handles escaping."""
    name = request.args.get("name", "")
    conn = psycopg2.connect("dbname=app user=app")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name FROM users WHERE name LIKE %s",
        (f"%{name}%",),
    )
    return jsonify(cursor.fetchall())


def get_user_orm(session: Session, user_id: int):
    """Safe: SQLAlchemy ORM. No raw SQL at all."""
    return session.query(User).filter_by(id=user_id).first()


def get_user_text(session: Session, user_id: int):
    """Safe: SQLAlchemy text() with bound parameters."""
    return session.execute(
        text("SELECT id, name FROM users WHERE id = :user_id"),
        {"user_id": user_id},
    ).first()


# Stub for example to be self-contained
class User:
    pass
