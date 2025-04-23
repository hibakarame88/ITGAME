from openai import OpenAI
import json

def enrich_with_ai():
    try:
        # Charger les infos de l'hôte
        with open("data/resultat.json", "r") as f:
            host_info = json.load(f)["Host Information"]
        mac = host_info.get("mac", "inconnu")
        ip = host_info.get("ip", "inconnu")
        hostname = host_info.get("hostname", "inconnu")
        username = host_info.get("username", "inconnu")

        # Charger les domaines DNS s'ils existent
        dns_domains_summary = "Aucun domaine suspect détecté."
        try:
            import pandas as pd
            dns_df = pd.read_csv("data/deep_enriched.csv")
            dns_domains = dns_df["domain"].unique().tolist()[:10]
            dns_domains_summary = "\n".join(dns_domains)
        except:
            pass

        # 👉 ICI on construit le prompt
        PROMPT_AI = f"""
Voici les informations extraites d'une analyse réseau :
- Adresse MAC : {mac}
- Adresse IP : {ip}
- Nom de l'hôte : {hostname}
- Nom d'utilisateur : {username}

Voici également une liste de domaines DNS suspects détectés (si disponibles) :
{dns_domains_summary}

Génère un résumé de l’activité réseau de cette machine, en expliquant :
1. Ce que ces informations révèlent sur la machine
2. Si un comportement malveillant peut être déduit
3. Quels éléments doivent être surveillés
4. Une recommandation pour un administrateur réseau

Sois concis mais précis.
"""

        # Appel à Mistral
        client = OpenAI(
            base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
            api_key="695f4799-c556-476c-9f04-25b7b192b4cd"
        )

        response = client.chat.completions.create(
            model="mistral-nemo-instruct-2407",
            messages=[
                {"role": "system", "content": "Tu es un assistant expert en cybersécurité."},
                {"role": "user", "content": PROMPT_AI}
            ],
            max_tokens=512,
            temperature=0.3
        )

        result_text = response.choices[0].message.content

        with open("data/enriched.txt", "w", encoding="utf-8") as f:
            f.write(result_text)

        print("🧠 Résumé IA enregistré dans data/enriched.txt")

    except Exception as e:
        print(f"⚠️ Erreur enrichissement IA : {e}")
