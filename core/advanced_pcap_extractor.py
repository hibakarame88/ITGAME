import pyshark
import requests
from collections import defaultdict

# Configuration
PCAP_URL = "http://93.127.203.48:5000/pcap/latest"
SUBMIT_URL = "http://93.127.203.48:5000/pcap/submit"
PCAP_FILE = "latest.pcap"
USER_ID = "dolores"

# Télécharger le fichier PCAP
def download_pcap():
    print("[*] Téléchargement du PCAP...")
    r = requests.get(PCAP_URL)
    if r.status_code == 200:
        with open(PCAP_FILE, "wb") as f:
            f.write(r.content)
        print("[+] PCAP téléchargé avec succès.")
    else:
        raise Exception("[-] Erreur lors du téléchargement du PCAP.")

# Extraire MAC, IP, Host, User avec fallback brut + brute-force
def extract_info():
    display_filter = "bootp || nbns || http.accept_language || kerberos.CNameString"
    cap = pyshark.FileCapture(PCAP_FILE, display_filter=display_filter, use_json=True)

    bruteforce_tracker = defaultdict(int)
    mac, ip, host, user = None, None, None, None

    print("[*] Analyse du trafic...")

    for packet in cap:
        try:
            if not mac and hasattr(packet, 'eth'):
                mac = packet.eth.src

            if not ip and hasattr(packet, 'ip') and packet.ip.src.startswith("10."):
                ip = packet.ip.src

            # Champs Kerberos standard
            if hasattr(packet, 'kerberos'):
                for field in packet.kerberos._all_fields_as_list:
                    if not user and "cname_string" in field:
                        user = field.split(":")[-1].strip().strip('"')
                    if not host and ("host_address" in field or "sname_string" in field):
                        host = field.split(":")[-1].strip().strip('"')

            # Bruteforce : compter les IP avec requêtes Kerberos/NTLM répétées
            if hasattr(packet, 'ntlmssp') or (hasattr(packet, 'kerberos') and 'AS-REQ' in str(packet.kerberos._all_fields_as_list)):
                if hasattr(packet, 'ip'):
                    bruteforce_tracker[packet.ip.src] += 1

            # Fallback brut
            if hasattr(packet, 'kerberos') and (not user or not host):
                raw = packet.get_raw_packet().decode('utf-8', errors='ignore')
                for line in raw.splitlines():
                    if not user and "cname-string" in line.lower():
                        user = line.split(":")[-1].strip().strip('"')
                    if not host and ("address" in line.lower() or "pc" in line.lower()):
                        possible = line.strip().split()[-1]
                        if "PC" in possible or "-" in possible:
                            host = possible.replace("<20>", "").strip()

            if all([mac, ip, host, user]):
                break

        except Exception:
            continue

    cap.close()

    print("[*] Résumé détection brute-force :")
    for ip_addr, count in bruteforce_tracker.items():
        if count > 5:
            print(f"[!] Tentatives suspectes depuis {ip_addr} : {count} connexions.")

    return {
        "mac": mac or "00:00:00:00:00:00",
        "ip": ip or "0.0.0.0",
        "host": host or "unknown-host",
        "user": user or "unknown-user"
    }

# Soumettre les infos et afficher la réponse
def submit_flag(info):
    payload = {
        "user_id": USER_ID,
        "lines": [info["mac"], info["ip"], info["host"], info["user"]]
    }

    print("[*] Données extraites :")
    for line in payload["lines"]:
        print(" -", line)

    print("[*] Envoi au serveur...")
    r = requests.post(SUBMIT_URL, json=payload)
    print("[*] Réponse serveur :")
    print(r.text)

# Programme principal
if __name__ == "__main__":
    download_pcap()
    infos = extract_info()
    submit_flag(infos)
