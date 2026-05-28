"""
Vulnerable sample: XML External Entity (XXE) injection.

Expected findings:
    - CWE-611 (XXE) at line 27 (parse_xml with lxml default parser)
    - CWE-611 (XXE) at line 39 (xml.dom.minidom parseString)
    - Severity: high
    - Confidence: medium to high

An XXE-vulnerable parser will resolve external entity references in the input,
allowing attackers to read local files or trigger SSRF via the parser.

DO NOT use any pattern in this file in production code.
"""

from lxml import etree
from xml.dom import minidom
from defusedxml.ElementTree import fromstring as safe_fromstring
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    """
    VULNERABLE: lxml's default parser resolves external entities.

    An attacker can submit XML referencing file:///etc/passwd or an internal
    URL to trigger SSRF.
    """
    xml_input = request.data
    tree = etree.fromstring(xml_input)
    return etree.tostring(tree).decode()


@app.route("/parse-dom", methods=["POST"])
def parse_dom():
    """
    VULNERABLE: xml.dom.minidom does not disable entity expansion by default.
    """
    xml_input = request.data.decode()
    dom = minidom.parseString(xml_input)
    return dom.toxml()


@app.route("/parse-safe", methods=["POST"])
def parse_safe():
    """Not vulnerable: defusedxml rejects external entities."""
    xml_input = request.data
    tree = safe_fromstring(xml_input)
    return etree.tostring(tree).decode()


if __name__ == "__main__":
    app.run()
