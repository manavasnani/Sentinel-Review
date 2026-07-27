"""
Vulnerable sample: Hardcoded credentials and secrets.

Expected findings:
    - CWE-798 (Use of Hard-coded Credentials) at lines 17-19
    - CWE-321 / CWE-798 for the AWS-style key at line 20
    - Severity: high (secrets in source)
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import requests
import psycopg2


# Hardcoded credentials - all of these are findings
DATABASE_PASSWORD = "Sup3rS3cret!2024"
API_TOKEN = "sk-live-9c8f7b2d3e4a5b6c7d8e9f0a1b2c3d4e"
JWT_SIGNING_KEY = "this-is-the-jwt-secret-do-not-share"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def connect_to_db():
    """Connect using hardcoded credentials."""
    return psycopg2.connect(
        host="prod-db.internal",
        database="users",
        user="app_admin",
        password=DATABASE_PASSWORD,
    )


def call_payment_api(amount):
    """Call third-party API with hardcoded token."""
    return requests.post(
        "https://api.payments.example.com/charge",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
        json={"amount": amount},
    )


def call_with_basic_auth():
    """Inline credentials in a URL - another anti-pattern."""
    return requests.get("https://admin:hunter2@internal.example.com/api/status")


def call_with_env_var():
    """This is correct - reads from environment. Not vulnerable."""
    import os
    token = os.environ["API_TOKEN"]
    return requests.get(
        "https://api.example.com/data",
        headers={"Authorization": f"Bearer {token}"},
    )
