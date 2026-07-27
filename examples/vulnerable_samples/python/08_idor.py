from flask import Flask, request, jsonify, g
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    if not invoice:
        return "Not found", 404
    return jsonify(invoice.to_dict())


@app.route("/invoices/<int:invoice_id>", methods=["DELETE"])
@login_required
def delete_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    if not invoice:
        return "Not found", 404
    db.session.delete(invoice)
    db.session.commit()
    return "", 204


@app.route("/my-invoices/<int:invoice_id>")
@login_required
def get_my_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        user_id=current_user.id,
    ).first()
    if not invoice:
        return "Not found", 404
    return jsonify(invoice.to_dict())

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
