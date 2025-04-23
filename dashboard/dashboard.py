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
    st.write(f"**👤 Utilisateur** : `{host.get('username', 'N/A')}`")
    st.write(f"**🖥️ Nom de l'hôte** : `{host.get('hostname', 'N/A')}`")
    st.write(f"**🌐 Adresse IP** : `{host.get('ip', 'N/A')}`")
    st.write(f"**🔗 Adresse MAC** : `{host.get('mac', 'N/A')}`")
except:
    st.warning("Aucune information d'hôte disponible.")

try:
    with open("data/flag.json", "r") as f:
        flag = json.load(f).get("flag")
        if flag:
            st.success(f"🏁 Flag obtenu : `{flag}`")
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
                    st.markdown(f"- `{line}`")
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
