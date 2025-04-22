import requests
import os

def download_pcap(save_path="data/latest.pcap"):
    url = "http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)
    if response.status_code == 200:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(response.content)
        print("✅ PCAP téléchargé avec succès.")
    else:
        raise Exception("Erreur lors du téléchargement :", response.text)
