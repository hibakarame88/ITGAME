import sys
import io
from core.downloader import download_pcap
from core.analyzer import analyze_pcap
from core.detector import detect_threats
from core.ai_enrichment import enrich_with_ai
from core.ip_enrichment import enrich_ips
from core.deep_analyzer import deep_analysis

# Pour gérer les caractères spéciaux sur Windows (emojis)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

if __name__ == "__main__":
    print("📥 Téléchargement du fichier PCAP...")
    download_pcap()

    print("🔍 Analyse du trafic...")
    df = analyze_pcap()

    print("🚨 Détection d'activités malveillantes...")
    detect_threats(df)

    print("🧠 Enrichissement IA avec Mistral...")
    enrich_with_ai()

    print("🌍 Enrichissement géographique et réseau des IPs...")
    enrich_ips()

    print("\n✅ Tout est prêt ! Lance le dashboard avec :")
    print("   👉 streamlit run dashboard/dashboard.py")


    print("🧠 Analyse approfondie PyShark...")
    deep_analysis()
