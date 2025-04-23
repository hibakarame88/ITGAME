from openai import OpenAI
import json
import pandas as pd

def enrich_with_ai():
    try:
        # Charger les infos hôte
        with open("data/resultat.json", "r") as f:
            host_info = json.load(f)["Host Information"]
        mac = host_info.get("mac", "non détecté")
        ip = host_info.get("ip", "non détectée")
        hostname = host_info.get("hostname", "non détecté")
        username = host_info.get("username", "non détecté")

        # Charger alertes classiques
        try:
            with open("data/alerts.txt", "r", encoding="utf-8") as f:
                alerts = f.read().strip()
        except:
            alerts = "Aucune alerte détectée."

        # Charger alertes avancées (PyShark)
        try:
            with open("data/deep_alerts.txt", "r", encoding="utf-8") as f:
                deep_alerts = f.read().strip()
        except:
            deep_alerts = "Aucune alerte avancée détectée."

        # DNS suspects enrichis
        dns_summary = ""
        try:
            dns_df = pd.read_csv("data/deep_enriched.csv")
            top_dns = dns_df[["domain", "score"]].sort_values(by="score", ascending=False).head(5)
            dns_summary = "\n".join([f"- {row['domain']} (score : {row['score']})" for _, row in top_dns.iterrows()])
        except:
            dns_summary = "Aucun domaine suspect détecté."

        # Prompt structuré pour Mistral
        prompt = f"""
Tu es un assistant cybersécurité. Explique en langage accessible les éléments suivants pour une analyse réseau :

📌 Informations système :
- Adresse MAC : {mac}
- Adresse IP : {ip}
- Nom d'hôte : {hostname}
- Utilisateur : {username}

🚨 Alertes réseau détectées :
{alerts}

🧪 Alertes avancées (analyse comportementale) :
{deep_alerts}

🌐 Domaines DNS suspects détectés :
{dns_summary}

Ta mission :
1. Expliquer en quoi ces données révèlent une activité potentiellement malveillante.
2. Identifier les risques : infection, fuite, commande à distance, etc.
3. Donner des exemples de menaces possibles.
4. Proposer des actions concrètes : bloquer IP, isoler PC, informer utilisateur, changer mots de passe.
5. Écrire pour un lecteur non technique, avec des titres, des emojis et des phrases simples.
"""

        # Appel à l’API Mistral
        client = OpenAI(
            base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
            api_key="695f4799-c556-476c-9f04-25b7b192b4cd"
        )

        response = client.chat.completions.create(
            model="mistral-nemo-instruct-2407",
            messages=[
                {"role": "system", "content": "Tu es un assistant cybersécurité pédagogique."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1200,
            temperature=0.3
        )

        result_text = response.choices[0].message.content

        with open("data/enriched.txt", "w", encoding="utf-8") as f:
            f.write(result_text)

        print("✅ Explication IA enregistrée dans data/enriched.txt")

    except Exception as e:
        print(f"⚠️ Erreur IA : {e}")
