import sys
import io
import os
import json
import argparse
from core.downloader import download_pcap
from core.detector import detect_threats
# Correction ici : nous allons importer directement NetworkAnalyzer du module analyzer.py
from core.analyzer import NetworkAnalyzer
from core.ai_enrichment import enrich_with_ai
from core.ip_enrichment import enrich_ips
import pandas as pd

# Pour affichage emojis sur Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def soumettre_resultats(json_file_path, user_id, api_url='http://localhost:5000/pcap/submit'):
    """Soumet les informations extraites du fichier PCAP au point d'API /pcap/submit"""
    try:
        import requests  # Import ici pour ne pas obliger l'installation si non utilisé
        
        # Vérifier si le fichier existe
        if not os.path.exists(json_file_path):
            print(f"⚠️ Erreur: Le fichier {json_file_path} n'existe pas.")
            return None
        
        # Charger les données du fichier JSON
        with open(json_file_path, 'r') as file:
            data = json.load(file)
            
        # Vérifier que les données sont dans le format attendu
        if 'Host Information' not in data:
            print("⚠️ Erreur: Format de données incorrect. 'Host Information' manquant.")
            return None
            
        host_info = data['Host Information']
        
        # Préparer les données au format attendu par l'API
        payload = {
            "user_id": user_id,
            "lines": [
                host_info.get('mac', ''),
                host_info.get('ip', ''),
                host_info.get('hostname', ''),
                host_info.get('username', '')
            ]
        }
        
        # Vérifier que toutes les données sont présentes
        for i, field in enumerate(['mac', 'ip', 'hostname', 'username']):
            if not payload["lines"][i]:
                print(f"⚠️ Avertissement: Le champ '{field}' est vide.")
        
        # Soumettre les données à l'API
        print(f"📤 Soumission des données à {api_url}...")
        print(json.dumps(payload, indent=2))
        
        response = requests.post(api_url, json=payload)
        
        # Traiter la réponse
        if response.status_code == 200:
            result = response.json()
            print(f"🏆 Flag obtenu: {result.get('flag', 'Non trouvé')}")
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
    # Analyse des arguments
    parser = argparse.ArgumentParser(description='Analyse de trafic réseau et détection de menaces')
    parser.add_argument('-u', '--user', help='Identifiant utilisateur (votre prénom) pour la soumission à l\'API')
    parser.add_argument('--submit', action='store_true', help='Soumettre les résultats à l\'API après analyse')
    parser.add_argument('--url', default='http://localhost:5000/pcap/submit',
                        help='URL de l\'API (défaut: http://localhost:5000/pcap/submit)')
    parser.add_argument('--only-submit', action='store_true', 
                        help='Uniquement soumettre les résultats sans refaire l\'analyse')
    
    args = parser.parse_args()
    
    # Si l'utilisateur veut seulement soumettre les résultats existants
    if args.only_submit:
        if not args.user:
            print("⚠️ Erreur: L'option --user est requise pour soumettre les résultats à l'API.")
            sys.exit(1)
        
        soumettre_resultats("data/resultat.json", args.user, args.url)
        sys.exit(0)
    
    print("📥 Téléchargement du fichier PCAP...")
    download_pcap()
    
    print("🔍 Analyse du trafic avec Scapy...")
    # Correction ici : utiliser NetworkAnalyzer au lieu de PacketAnalyzer
    analyzer = NetworkAnalyzer(
        pcap_file="data/latest.pcap",
        output_file="data/resultat.json"  # ✅ Le fichier voulu
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
    
    # Si l'option de soumission est activée et que l'identifiant utilisateur est fourni
    if args.submit:
        if args.user:
            print("\n📤 Soumission des résultats à l'API...")
            soumettre_resultats("data/resultat.json", args.user, args.url)
        else:
            print("\n⚠️ L'option --user est requise pour soumettre les résultats à l'API.")
    
    print("\n✅ Analyse terminée avec succès.")
    print("👉 Lance le dashboard avec :")
    print("   streamlit run dashboard/dashboard.py")