from flask import Flask, jsonify
import json
import os
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


@app.route("/api/resultat", methods=["GET"])
def get_resultat():
    """
    Récupère les informations extraites de la machine analysée
    ---
    responses:
      200:
        description: Informations hôte analysé
        content:
          application/json:
            example:
              Host Information:
                mac: "00:11:22:33:44:55"
                ip: "192.168.1.10"
                hostname: "DESKTOP-MACHINE"
                username: "user1"
    """
    path = os.path.join(DATA_DIR, "resultat.json")
    if os.path.exists(path):
        with open(path) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "resultat.json not found"}), 404


@app.route("/api/flag", methods=["GET"])
def get_flag():
    """
    Récupère le flag extrait de l'analyse
    ---
    responses:
      200:
        description: Flag de validation capturé
        content:
          application/json:
            example:
              flag: "HACK{abcd1234efgh}"
    """
    path = os.path.join(DATA_DIR, "flag.json")
    if os.path.exists(path):
        with open(path) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "flag.json not found"}), 404


@app.route("/api/enriched", methods=["GET"])
def get_enriched():
    """
    Retourne le résumé IA de l'activité réseau (texte libre)
    ---
    responses:
      200:
        description: Analyse IA enrichie
        content:
          application/json:
            example:
              text: "Cette machine a présenté un comportement suspect vers un domaine classé comme malveillant..."
    """
    path = os.path.join(DATA_DIR, "enriched.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return jsonify({"text": f.read()})
    return jsonify({"error": "enriched.txt not found"}), 404


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Liste des alertes réseau simples (classiques)
    ---
    responses:
      200:
        description: Liste des alertes réseau
        content:
          application/json:
            example:
              alerts: ["Suspicious DNS request to unknown domain"]
    """
    path = os.path.join(DATA_DIR, "alerts.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return jsonify({"alerts": f.read().splitlines()})
    return jsonify({"alerts": []})


@app.route("/api/deep_alerts", methods=["GET"])
def get_deep_alerts():
    """
    Liste des alertes comportementales avancées (ex : regroupements DNS suspects)
    ---
    responses:
      200:
        description: Alertes PyShark ou NLP DNS avancées
        content:
          application/json:
            example:
              deep_alerts: ["Groupe 1", "domain1.bad.com", "domain2.bad.com"]
    """
    path = os.path.join(DATA_DIR, "deep_alerts.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return jsonify({"deep_alerts": f.read().splitlines()})
    return jsonify({"deep_alerts": []})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
