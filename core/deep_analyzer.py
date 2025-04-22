import pyshark
import socket
import requests
import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from openai import OpenAI

# 🔐 Configuration API Mistral
client = OpenAI(
    base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
    api_key="695f4799-c556-476c-9f04-25b7b192b4cd"
)

# 🌍 Résolution DNS + enrichissement IP
def resolve_and_enrich(domain):
    try:
        ip = socket.gethostbyname(domain)
    except:
        return domain, None, None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        if response.status_code == 200:
            info = response.json()
            return domain, ip, {
                "country": info.get("country"),
                "region": info.get("regionName"),
                "city": info.get("city"),
                "org": info.get("org"),
                "isp": info.get("isp"),
                "asn": info.get("as"),
                "proxy": info.get("proxy"),
                "hosting": info.get("hosting")
            }
    except:
        pass
    return domain, ip, None

# 🧠 Analyse IA avec Mistral
def ask_mistral_about_domains(domains):
    prompt = f"""Voici une liste de domaines DNS suspects détectés dans un fichier PCAP :

{chr(10).join(domains)}

Analyse chacun d’eux en tant qu'analyste cybersécurité SOC. Pour chaque domaine :
- Donne-moi le type d’activité malveillante potentielle (ex: DGA, tunneling DNS, AD reconnaissance, C2...)
- Dis-moi pourquoi il est suspect
- Donne un score de dangerosité de 0 à 100

Format : 
Domaine → Type : ..., Raisons : ..., Score : ...
"""
    try:
        response = client.chat.completions.create(
            model="mistral-nemo-instruct-2407",
            messages=[
                {"role": "system", "content": "Tu es un analyste SOC expert en cybersécurité."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0.4
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ Erreur IA : {e}"

# 🔬 NLP : groupement par similarité
def detect_nlp_patterns(domains):
    vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))
    X = vectorizer.fit_transform(domains)
    model = KMeans(n_clusters=min(3, len(domains)))
    model.fit(X)
    clusters = model.labels_
    clustered = {}
    for i, label in enumerate(clusters):
        clustered.setdefault(label, []).append(domains[i])
    return clustered

# 🔎 Parsing du texte IA Mistral
def parse_mistral_output(raw_text):
    domains = []
    lines = raw_text.split("\n")
    for line in lines:
        if "→ Type" in line and "→" in line:
            parts = line.split("→")
            if len(parts) >= 4:
                dom = parts[0].strip()
                type_ = parts[1].split(":", 1)[-1].strip()
                reason = parts[2].split(":", 1)[-1].strip()
                score_part = parts[3].split(":", 1)[-1].strip()
                try:
                    score = int(re.findall(r'\d+', score_part)[0])
                except:
                    score = 0
                domains.append({
                    "domaine": dom,
                    "type_attaque": type_,
                    "raison": reason,
                    "score": score
                })
    return domains

# 🧠 Analyse complète : PCAP + IA + enrichissement + NLP
def deep_analysis(pcap_file="data/latest.pcap", max_packets=5000):
    print("🧠 Analyse approfondie PyShark...")
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    suspicious_domains = []

    for i, pkt in enumerate(cap):
        if i >= max_packets:
            break
        try:
            if "DNS" in pkt and hasattr(pkt.dns, "qry_name"):
                qname = pkt.dns.qry_name
                if len(qname) > 50 and qname not in suspicious_domains:
                    suspicious_domains.append(qname)
        except:
            continue
    cap.close()

    alerts_txt = []
    rows = []

    if suspicious_domains:
        alerts_txt.append("⚠️ Requêtes DNS suspectes détectées :\n")

        mistral_raw = ask_mistral_about_domains(suspicious_domains)
        mistral_structured = parse_mistral_output(mistral_raw)

        for entry in mistral_structured:
            dom_ia = entry["domaine"]
            closest = next((d for d in suspicious_domains if dom_ia in d or d in dom_ia), None)
            if not closest:
                continue

            ip = None
            details = None
            closest, ip, details = resolve_and_enrich(closest)

            alerts_txt.append(f"- Domaine : {closest}")
            alerts_txt.append(f"  → Type d'attaque : {entry['type_attaque']}")
            alerts_txt.append(f"  → Raisons : {entry['raison']}")
            alerts_txt.append(f"  → Score de dangerosité : {entry['score']}")
            if ip:
                alerts_txt.append(f"  → Résolu vers : {ip}")
            if details:
                alerts_txt.append(f"  🌍 Pays : {details.get('country')} ({details.get('city')})")
                alerts_txt.append(f"  🏢 Fournisseur : {details.get('isp')} / {details.get('org')}")
                alerts_txt.append(f"  ASN : {details.get('asn')}")
                if details.get("proxy"):
                    alerts_txt.append("  🚩 Proxy détecté")
                if details.get("hosting"):
                    alerts_txt.append("  🖥️ Hébergement détecté")

                rows.append({
                    "domaine": closest,
                    "ip": ip,
                    "score": entry["score"],
                    "type_attaque": entry["type_attaque"],
                    "raison": entry["raison"],
                    "pays": details.get("country"),
                    "ville": details.get("city"),
                    "fournisseur": details.get("org"),
                    "ASN": details.get("asn"),
                    "proxy": details.get("proxy"),
                    "hosting": details.get("hosting")
                })

        alerts_txt.append("\n🧠 Groupement de noms de domaine suspects (NLP) :\n")
        clustered = detect_nlp_patterns(suspicious_domains)
        for cluster_id, group in clustered.items():
            alerts_txt.append(f"Groupe {cluster_id + 1} ({len(group)} domaines) :")
            for dom in group:
                alerts_txt.append(f"  - {dom}")
            alerts_txt.append("")
    else:
        alerts_txt.append("✅ Aucun domaine DNS suspect détecté.")

    with open("data/deep_alerts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(alerts_txt))

    if rows:
        df = pd.DataFrame(rows)
        df.to_csv("data/deep_enriched.csv", index=False)

    print("✅ Analyse PyShark enrichie terminée avec correspondance IP + détails.")
