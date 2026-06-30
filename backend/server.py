from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

import database
import enrich
import extractor
import playbook


_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_ROOT_DIR, ".env"))

NOTABLE_RISK_THRESHOLD = int(os.getenv("NOTABLE_RISK_THRESHOLD", "50"))

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Expected JSON body"}), 400

    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Missing or empty 'text' field"}), 400

    database.init_db()

    results = []
    for ioc_value, ioc_type in extractor.extract_iocs(text):
        if ioc_type == "ip":
            enrichment = enrich.enrich_ip(ioc_value)
        elif ioc_type == "domain":
            enrichment = enrich.enrich_domain(ioc_value)
        else:
            continue

        cached = enrichment.get("source") == "cache"
        risk_score = enrichment.get("risk_score")
        source = enrichment.get("source")

        playbook_text = None
        if (
            isinstance(risk_score, (int, float))
            and risk_score > NOTABLE_RISK_THRESHOLD
        ):
            playbook_text = playbook.generate_playbook(text, ioc_value, enrichment)

        results.append(
            {
                "ioc": ioc_value,
                "ioc_type": ioc_type,
                "risk_score": risk_score,
                "source": source,
                "playbook": playbook_text,
                "cached": cached,
            }
        )

    return jsonify({"iocs": results})


if __name__ == "__main__":
    database.init_db()
    app.run(port=5000, debug=True)
