import requests
import pandas as pd
import time

def enrich_ips(input_csv="data/summary.csv", output_csv="data/enriched_ips.csv"):
    df = pd.read_csv(input_csv)
    unique_ips = set(df["src_ip"]).union(set(df["dst_ip"]))
    
    enriched_data = []

    for ip in unique_ips:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719")
            if response.status_code == 200:
                info = response.json()
                enriched_data.append({
                    "ip": ip,
                    "country": info.get("country"),
                    "region": info.get("regionName"),
                    "city": info.get("city"),
                    "org": info.get("org"),
                    "isp": info.get("isp"),
                    "asn": info.get("as"),
                    "lat": info.get("lat"),
                    "lon": info.get("lon"),
                    "reverse": info.get("reverse"),
                    "mobile": info.get("mobile"),
                    "proxy": info.get("proxy"),
                    "hosting": info.get("hosting"),
                    "query": info.get("query")
                })
            time.sleep(0.5)  # éviter d’être bloqué
        except Exception as e:
            print(f"Erreur avec IP {ip}: {e}")
    
    pd.DataFrame(enriched_data).to_csv(output_csv, index=False)
    print(f"✅ Infos IP enrichies enregistrées dans {output_csv}")
