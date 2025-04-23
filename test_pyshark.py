import pyshark

try:
    cap = pyshark.FileCapture("data/latest.pcap", only_summaries=True)
    for pkt in cap.sniff_continuously(packet_count=3):
        print(pkt)
except Exception as e:
    print(f"Erreur PyShark : {e}")
