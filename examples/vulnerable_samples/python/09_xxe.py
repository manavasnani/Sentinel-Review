from lxml import etree
from xml.dom import minidom
from defusedxml.ElementTree import fromstring as safe_fromstring
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_input = request.data
    tree = etree.fromstring(xml_input)
    return etree.tostring(tree).decode()


@app.route("/parse-dom", methods=["POST"])
def parse_dom():
    xml_input = request.data.decode()
    dom = minidom.parseString(xml_input)
    return dom.toxml()


@app.route("/parse-safe", methods=["POST"])
def parse_safe():
    xml_input = request.data
    tree = safe_fromstring(xml_input)
    return etree.tostring(tree).decode()


if __name__ == "__main__":
    app.run()
