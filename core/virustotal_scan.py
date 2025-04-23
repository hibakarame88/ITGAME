#!/usr/bin/env python3
import os
import json
import time
from datetime import datetime
import pandas as pd
import requests

API_KEY = "1d62c8ca6cd43f54c022ee9674e1c52e56b2f45092b8c7bbfcfdd142da0a744e"
VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}

def load_target_ip():
    try:
        with open("data/resultat.json") as f:
            return json.load(f)["Host Information"]["ip"]
    except Exception as e:
        print(f"❌ Erreur chargement IP victime : {e}")
        return None

def load_suspicious_domains():
    try:
        df = pd.read_csv("data/deep_enriched.csv")
        return df["domain"].dropna().unique().tolist()
    except Exception as e:
        print(f"⚠️ Erreur chargement domaines : {e}")
        return []

def vt_get(endpoint):
    """Fait une requête GET vers l'API VirusTotal"""
    try:
        response = requests.get(f"{VT_BASE}/{endpoint}", headers=HEADERS)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"⚠️ Erreur API ({response.status_code}) → {endpoint}")
    except Exception as e:
        print(f"❌ Exception requête VT : {e}")
    return None

def extract_communications(ip):
    """Extrait les flux liés à l'IP cible depuis summary.csv"""
    try:
        df = pd.read_csv("data/summary.csv")
        comms = []

        for _, row in df.iterrows():
            src_ip = row.get("source_ip") or row.get("src_ip")
            dst_ip = row.get("destination_ip") or row.get("dst_ip")
            if ip in (src_ip, dst_ip):
                comms.append({
                    "timestamp": row.get("timestamp", "N/A"),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": row.get("source_port", "N/A"),
                    "destination_port": row.get("destination_port", "N/A"),
                    "protocol": row.get("protocol") or row.get("proto", "unknown")
                })
        return comms
    except Exception as e:
        print(f"⚠️ Erreur extraction communications : {e}")
        return []

def save_report(ip_result, domains_result, comms):
    os.makedirs("data", exist_ok=True)
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_analysis": ip_result,
        "domain_analyses": domains_result,
        "communications": comms
    }
    with open("data/virustotal_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print("✅ Rapport complet sauvegardé → data/virustotal_report.json")

def main():
    print("🔎 Lancement de l’analyse complète VirusTotal...")
    ip = load_target_ip()
    domains = load_suspicious_domains()

    ip_result = None
    domains_result = {}
    comms = []

    if ip:
        print(f"📡 Analyse IP cible : {ip}")
        ip_result = vt_get(f"ip_addresses/{ip}")
        time.sleep(15)  # pour ne pas saturer l'API gratuite
        comms = extract_communications(ip)
    else:
        print("❌ Aucune IP trouvée dans resultat.json")

    for domain in domains[:5]:
        print(f"🌐 Analyse domaine suspect : {domain}")
        result = vt_get(f"domains/{domain}")
        if result:
            domains_result[domain] = result
        time.sleep(15)

    save_report(ip_result, domains_result, comms)

if __name__ == "__main__":
    main()
