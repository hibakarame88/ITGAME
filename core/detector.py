def detect_threats(df, output_path="data/alerts.txt"):
    alerts = []

    if df["src_ip"].value_counts().max() > 100:
        alerts.append("⚠️ IP avec trafic excessif détectée (possible scan)")

    if df["proto"].str.contains("UDP").sum() > 50:
        alerts.append("⚠️ Nombre élevé de paquets UDP détecté (potentiel flood)")

    if df["dst_ip"].nunique() > 100:
        alerts.append("⚠️ Nombre élevé de destinations uniques détecté (possible exfiltration ou botnet)")

    # ✅ CORRECTION ICI : on force l'encodage UTF-8 pour écrire le fichier
    with open(output_path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(a + "\n")

    return alerts
