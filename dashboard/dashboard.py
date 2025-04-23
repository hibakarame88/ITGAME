import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="IT Game Master - Dashboard", layout="wide")
st.title("🛡️ IT Game Master - Analyse de trafic réseau")

# 📊 Résumé réseau CSV
st.subheader("📈 Résumé du trafic réseau")
csv_path = "data/summary.csv"
if os.path.exists(csv_path):
    df = pd.read_csv(csv_path)
    st.dataframe(df)

    col1, col2 = st.columns(2)
    with col1:
        st.bar_chart(df["src_ip"].value_counts(), use_container_width=True)
    with col2:
        st.bar_chart(df["dst_ip"].value_counts(), use_container_width=True)

    st.subheader("📌 Protocole utilisé")
    st.bar_chart(df["proto"].value_counts())
else:
    st.warning("⚠️ Fichier summary.csv non trouvé. Lance `main.py` d'abord.")

# 🌍 Infos enrichies JSON
st.subheader("🧠 Informations enrichies (Scapy)")
json_path = "data/enriched_hosts.json"
if os.path.exists(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        enriched = json.load(f)

    if "hosts" in enriched and enriched["hosts"]:
        for i, host in enumerate(enriched["hosts"]):
            with st.expander(f"🖥️ Hôte {i+1}"):
                st.write(f"**MAC :** {host.get('mac', 'N/A')}")
                st.write(f"**IP :** {host.get('ip', 'N/A')}")
                st.write(f"**Hostname :** {host.get('hostname', 'N/A')}")
                st.write(f"**Username :** {host.get('username', 'N/A')}")

    if "flag" in enriched:
        st.success(f"🚩 **FLAG détecté** : {enriched['flag']}")
else:
    st.info("ℹ️ Aucune information enrichie disponible. Lance `main.py`.")

st.markdown("---")
st.caption("👩‍💻 Dashboard généré à partir des analyses Scapy - Projet IT Game Master")
