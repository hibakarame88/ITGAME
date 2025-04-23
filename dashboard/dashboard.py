import streamlit as st
import pandas as pd
import base64
import io
import json
from fpdf import FPDF

st.set_page_config(page_title="IT Game Master", layout="wide")
st.title("🛡️ IT Game Master - Analyse de trafic réseau enrichie")

# 🏁 Flag et informations extraites
st.subheader("🏁 Résultat de l'analyse et soumission")
try:
    with open("data/resultat.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    host_info = data.get("Host Information", {})

    mac = host_info.get("mac", "N/A")
    ip = host_info.get("ip", "N/A")
    hostname = host_info.get("hostname", "N/A")
    username = host_info.get("username", "N/A")

    st.success(f"🧑‍💻 Utilisateur : **{username}**")
    st.info(f"💻 Hostname : **{hostname}**")
    st.warning(f"🌐 IP : **{ip}**")
    st.error(f"🔗 MAC : **{mac}**")

    if "flag" in host_info:
        st.success(f"🏁 Flag obtenu : `{host_info['flag']}`")
    else:
        try:
            with open("data/flag.json", "r", encoding="utf-8") as f:
                flag_data = json.load(f)
                flag = flag_data.get("flag")
                if flag:
                    st.success(f"🏁 Flag obtenu : `{flag}`")
        except FileNotFoundError:
            st.info("🕵️‍♀️ Aucune soumission de flag encore disponible.")

except FileNotFoundError:
    st.warning("Fichier 'resultat.json' manquant ou incorrect.")

# 📈 Résumé du trafic
st.subheader("📈 Résumé du trafic réseau")
try:
    df = pd.read_csv("data/summary.csv")
    st.dataframe(df)

    st.subheader("📌 Statistiques IP (source/destination)")
    col1, col2 = st.columns(2)
    with col1:
        st.bar_chart(df["src_ip"].value_counts())
    with col2:
        st.bar_chart(df["dst_ip"].value_counts())

    st.subheader("📌 Protocole utilisé")
    st.bar_chart(df["proto"].value_counts())
except FileNotFoundError:
    st.warning("Fichier 'summary.csv' non trouvé. Exécutez l'analyse d'abord.")

# 🧠 Résumé IA (simple)
st.subheader("🧠 Analyse IA du trafic (Mistral)")
try:
    with open("data/enriched.txt", "r") as f:
        st.text(f.read())
except FileNotFoundError:
    st.warning("Aucune analyse IA disponible.")

# 🚨 Alertes classiques
st.subheader("🚨 Alertes détectées")
try:
    with open("data/alerts.txt", "r", encoding="utf-8") as f:
        alerts = f.readlines()
    for alert in alerts:
        st.error(alert.strip())
except FileNotFoundError:
    st.info("Aucune alerte détectée pour le moment.")

# 🌍 IP enrichies
st.subheader("🌍 Informations IP enrichies")
try:
    ip_df = pd.read_csv("data/enriched_ips.csv")
    st.dataframe(ip_df)
except FileNotFoundError:
    st.info("Fichier 'enriched_ips.csv' non trouvé.")

# 🧪 Alertes avancées (PyShark)
st.subheader("🧪 Alertes avancées (PyShark)")
try:
    with open("data/deep_alerts.txt", "r", encoding="utf-8") as f:
        deep_alerts = f.readlines()
    for alert in deep_alerts:
        st.warning(alert.strip())
except FileNotFoundError:
    st.info("Aucune alerte PyShark détectée.")

# 🌐 Analyse DNS enrichie
st.subheader("🌐 Analyse enrichie des domaines DNS")
try:
    enriched_df = pd.read_csv("data/deep_enriched.csv")

    if "score" in enriched_df.columns:
        score_min = st.slider("🎯 Score minimum de dangerosité", 0, 100, 50)
        filtered_df = enriched_df[enriched_df["score"] >= score_min]
    else:
        filtered_df = enriched_df

    st.dataframe(filtered_df)

    # 📄 Export PDF
    if st.button("📄 Télécharger le rapport PDF"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="Rapport DNS Suspects - IT Game Master", ln=True, align="C")

        for _, row in filtered_df.iterrows():
            row_txt = "\n".join([f"{k}: {v}" for k, v in row.to_dict().items()])
            pdf.multi_cell(0, 10, txt=row_txt + "\n", border=0)

        pdf_output = io.BytesIO()
        pdf.output(pdf_output)
        b64 = base64.b64encode(pdf_output.getvalue()).decode()
        href = f'<a href="data:application/pdf;base64,{b64}" download="rapport_dns.pdf">📥 Télécharger le rapport PDF</a>'
        st.markdown(href, unsafe_allow_html=True)
except FileNotFoundError:
    st.info("Aucune analyse enrichie n’a encore été effectuée.")
