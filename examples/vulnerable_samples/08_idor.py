"""
Vulnerable sample: Insecure Direct Object Reference (IDOR / broken access control).

Expected findings:
    - CWE-639 (Authorization Bypass Through User-Controlled Key) at lines 28-31
    - CWE-285 (Improper Authorization) at lines 42-45 (delete_invoice)
    - Severity: high
    - Confidence: medium to high

The pattern here is: the user is authenticated, but the handler does not check
that the requested resource actually belongs to the authenticated user.

DO NOT use any pattern in this file in production code.
"""

from flask import Flask, request, jsonify, g
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    """
    Return an invoice by ID. VULNERABLE: missing authorization check.

    Any authenticated user can read any other user's invoices by guessing
    or enumerating invoice_id. There is no check that current_user owns
    the invoice.
    """
    invoice = Invoice.query.get(invoice_id)
    if not invoice:
        return "Not found", 404
    return jsonify(invoice.to_dict())


@app.route("/invoices/<int:invoice_id>", methods=["DELETE"])
@login_required
def delete_invoice(invoice_id):
    """
    Delete an invoice. VULNERABLE: same IDOR pattern, but write-side.

    Any authenticated user can delete any invoice by ID.
    """
    invoice = Invoice.query.get(invoice_id)
    if not invoice:
        return "Not found", 404
    db.session.delete(invoice)
    db.session.commit()
    return "", 204


@app.route("/my-invoices/<int:invoice_id>")
@login_required
def get_my_invoice(invoice_id):
    """Not vulnerable: scopes the query to current_user."""
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        user_id=current_user.id,
    ).first()
    if not invoice:
        return "Not found", 404
    return jsonify(invoice.to_dict())


# Stubs for the example to be self-contained
class _DB:
    def __init__(self):
        self.session = self

    def delete(self, _): pass
    def commit(self): pass


class _Invoice:
    class _Query:
        def get(self, _): return None
        def filter_by(self, **kwargs): return self
        def first(self): return None

    query = _Query()


db = _DB()
Invoice = _Invoice
