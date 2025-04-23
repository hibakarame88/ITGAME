import sys
import io
import os
import json
import argparse
from core.downloader import download_pcap
from core.detector import detect_threats
from core.analyzer import NetworkAnalyzer
from core.ai_enrichment import enrich_with_ai
from core.ip_enrichment import enrich_ips
import pandas as pd

# Pour affichage emojis sur Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def soumettre_resultats(json_file_path, user_id, api_url='http://localhost:5000/pcap/submit'):
    """Soumet les informations extraites du fichier PCAP au point d'API /pcap/submit"""
    try:
        import requests
        
        if not os.path.exists(json_file_path):
            print(f"⚠️ Erreur: Le fichier {json_file_path} n'existe pas.")
            return None
        
        with open(json_file_path, 'r') as file:
            data = json.load(file)
            
        if 'Host Information' not in data:
            print("⚠️ Erreur: Format de données incorrect. 'Host Information' manquant.")
            return None
            
        host_info = data['Host Information']
        
        payload = {
            "user_id": user_id,
            "lines": [
                host_info.get('mac', ''),
                host_info.get('ip', ''),
                host_info.get('hostname', ''),
                host_info.get('username', '')
            ]
        }
        
        for i, field in enumerate(['mac', 'ip', 'hostname', 'username']):
            if not payload["lines"][i]:
                print(f"⚠️ Avertissement: Le champ '{field}' est vide.")
        
        print(f"📤 Soumission des données à {api_url}...")
        print(json.dumps(payload, indent=2))
        
        response = requests.post(api_url, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            flag = result.get("flag", "Non trouvé")

            # 🔐 Sauvegarder le flag localement
            with open("data/flag.json", "w", encoding="utf-8") as f:
                json.dump({"flag": flag}, f, indent=4)
            print(f"🏁 Flag obtenu : {flag}")
            print(f"📁 Flag sauvegardé dans data/flag.json")
            return result
        else:
            print(f"❌ Erreur (code {response.status_code}): {response.text}")
            return {"error": response.text}
            
    except json.JSONDecodeError:
        print(f"⚠️ Erreur: Le fichier {json_file_path} n'est pas un JSON valide.")
        return None
    except requests.RequestException as e:
        print(f"⚠️ Erreur de connexion à l'API: {e}")
        return None
    except Exception as e:
        print(f"⚠️ Erreur inattendue: {e}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyse de trafic réseau et détection de menaces')
    parser.add_argument('-u', '--user', help='Identifiant utilisateur (par défaut : hiba)')
    parser.add_argument('--url', default='http://93.127.203.48:5000/pcap/submit',
                        help='URL de l\'API (défaut: http://93.127.203.48:5000/pcap/submit)')
    args = parser.parse_args()

    print("📥 Téléchargement du fichier PCAP...")
    download_pcap()

    print("🔍 Analyse du trafic avec Scapy...")
    analyzer = NetworkAnalyzer(
        pcap_file="data/latest.pcap",
        output_file="data/resultat.json"
    )
    analyzer.analyze_pcap()

    print("🚨 Détection d'activités malveillantes...")
    try:
        df = pd.read_csv("data/summary.csv")
        detect_threats(df)
    except Exception as e:
        print(f"⚠️ Erreur de détection : {e}")

    print("🧠 Enrichissement IA avec Mistral...")
    try:
        enrich_with_ai()
    except Exception as e:
        print(f"⚠️ Erreur enrichissement IA : {e}")

    print("🌍 Enrichissement géographique des IPs...")
    try:
        enrich_ips()
    except Exception as e:
        print(f"⚠️ Erreur enrichissement IPs : {e}")

    print("\n📤 Soumission automatique des résultats à l'API...")
    default_user = args.user or "hiba"
    try:
        soumettre_resultats("data/resultat.json", default_user, args.url)
    except Exception as e:
        print(f"⚠️ Impossible de soumettre automatiquement le flag : {e}")

    print("\n✅ Analyse complète terminée.")
    print("👉 Lance le dashboard avec :")
    print("   streamlit run dashboard/dashboard.py")
