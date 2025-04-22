from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

def analyze_pcap(pcap_path="data/latest.pcap", csv_path="data/summary.csv"):
    packets = rdpcap(pcap_path)
    records = []
    for pkt in packets:
        if IP in pkt:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            records.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": proto,
                "size": len(pkt)
            })
    df = pd.DataFrame(records)
    df.to_csv(csv_path, index=False)
    return df
