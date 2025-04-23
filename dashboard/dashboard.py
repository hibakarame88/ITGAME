import streamlit as st
import pandas as pd
import json

st.set_page_config(page_title="IT Game Master", layout="wide")
st.title("🛡️ IT Game Master - Analyse réseau enrichie & pédagogique")

# --- Résumé de trafic réseau ---
st.subheader("📊 Statistiques globales du trafic réseau")
try:
    df = pd.read_csv("data/summary.csv")
    st.dataframe(df)

    col1, col2 = st.columns(2)
    with col1:
        st.bar_chart(df["src_ip"].value_counts(), use_container_width=True)
    with col2:
        st.bar_chart(df["dst_ip"].value_counts(), use_container_width=True)

    st.subheader("📌 Protocoles analysés")
    st.bar_chart(df["proto"].value_counts())

except FileNotFoundError:
    st.warning("Fichier summary.csv introuvable. Lancez l'analyse d'abord.")

# --- Informations hôte & flag ---
st.subheader("🔎 Informations extraites de la machine analysée")
try:
    with open("data/resultat.json", "r") as f:
        host = json.load(f)["Host Information"]
    st.write(f"**👤 Utilisateur** : {host.get('username', 'N/A')}")
    st.write(f"**🖥️ Nom de l'hôte** : {host.get('hostname', 'N/A')}")
    st.write(f"**🌐 Adresse IP** : {host.get('ip', 'N/A')}")
    st.write(f"**🔗 Adresse MAC** : {host.get('mac', 'N/A')}")
except:
    st.warning("Aucune information d'hôte disponible.")

try:
    with open("data/flag.json", "r") as f:
        flag = json.load(f).get("flag")
        if flag:
            st.success(f"🏁 Flag obtenu : {flag}")
except:
    st.info("Flag non encore disponible.")

# --- Analyse IA enrichie ---
st.subheader("🧠 Analyse IA explicative (langage accessible)")
try:
    with open("data/enriched.txt", "r", encoding="utf-8") as f:
        content = f.read()
    st.markdown(content, unsafe_allow_html=True)
except:
    st.info("Aucune analyse IA disponible.")

# --- Alertes avancées ---
st.subheader("🚨 Alertes comportementales (analyse PyShark)")
try:
    with open("data/deep_alerts.txt", "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
        if lines:
            for line in lines:
                if line.startswith("Groupe"):
                    st.markdown(f"**🧩 {line}**")
                else:
                    st.markdown(f"- {line}")
        else:
            st.info("✅ Aucune alerte avancée n'a été détectée.")
except FileNotFoundError:
    st.info("Fichier deep_alerts.txt introuvable.")

# --- DNS enrichis ---
st.subheader("🌐 Analyse enrichie des domaines DNS suspects")
try:
    df_dns = pd.read_csv("data/deep_enriched.csv")
    if not df_dns.empty:
        score_min = st.slider("🎯 Score minimum de dangerosité", 0, 100, 50)
        filtered = df_dns[df_dns["score"] >= score_min]
        for _, row in filtered.iterrows():
            with st.expander(f"🌐 {row.get('domain')}"):
                st.markdown(f"""
- **Score** : {row.get('score')}
- **Pays** : {row.get('country')}
- **Fournisseur** : {row.get('org')}
- **ASN** : {row.get('asn')}
- **Type de menace** : {row.get('threat_type')}
- **IP cible** : {row.get('ip')}
""")
    else:
        st.info("Aucun domaine DNS dangereux détecté.")
except FileNotFoundError:
    st.info("Fichier de domaines enrichis non trouvé.")

# --- Rapport VirusTotal ---
st.subheader("🛡️ Rapport de sécurité externe (VirusTotal)")
try:
    with open("data/virustotal_report.json", "r", encoding="utf-8") as f:
        vt_data = json.load(f)

    ip_data = vt_data.get("ip_analysis", {})
    stats = ip_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    results = ip_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    ip_id = ip_data.get("data", {}).get("id", "")

    if ip_id:
        st.markdown(f"🔗 **Rapport IP VirusTotal** : [Voir en ligne](https://www.virustotal.com/gui/ip-address/{ip_id})")

    if stats:
        st.write("### Résumé des détections")
        st.json(stats)

    if results:
        st.write("### Détails des moteurs ayant détecté une menace")
        for engine, result in results.items():
            if result["category"] in ("malicious", "suspicious"):
                st.markdown(f"- {engine} → {result['result']}")

    if not stats and not results:
        st.info("Aucune donnée de détection exploitable dans le rapport.")
except FileNotFoundError:
    st.info("Aucun rapport VirusTotal disponible.")

# --- Communications réseau de la victime ---
st.subheader("📡 Communications de la machine cible")
try:
    with open("data/resultat.json", "r") as f:
        ip_victime = json.load(f)["Host Information"]["ip"]
except:
    ip_victime = None
    st.warning("Impossible de lire l'adresse IP de la victime.")

try:
    with open("data/virustotal_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)
        comms = report.get("communications", [])

        if ip_victime and comms:
            df_comms = pd.DataFrame(comms)
            df_filtered = df_comms[
                (df_comms["source_ip"] == ip_victime) | (df_comms["destination_ip"] == ip_victime)
            ]

            if not df_filtered.empty:
                st.markdown(f"**🎯 Adresse IP analysée : `{ip_victime}`**")
                st.dataframe(df_filtered[[
                    "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol"
                ]], use_container_width=True)
            else:
                st.info("Aucune communication trouvée pour cette IP.")
        else:
            st.warning("Pas de communications réseau disponibles dans le rapport.")
except FileNotFoundError:
    st.warning("Fichier `virustotal_report.json` manquant.")