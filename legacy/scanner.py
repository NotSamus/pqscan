from scapy.all import rdpcap, TCP, IP, Raw
import argparse
import math

parser = argparse.ArgumentParser(
        description="Analyze PCAP files for cryptographic algorithm detection."
    )
parser.add_argument(
"-f", "--file",
required=True,
help="PCAP or Path to the PCAP file to analyze"
)
args = parser.parse_args()


PQC_KEY_MAP = {
    800: "Kyber-512",
    1184: "Kyber-768",
    1568: "Kyber-1024",
}

def shannon_entropy(data):
    if not data:
        return 0
    freqs = [data.count(b) / len(data) for b in set(data)]
    return -sum(f * math.log2(f) for f in freqs)

def detect_pqc_streams(pcap_path):
    packets = rdpcap(pcap_path)
    streams = {}

    for pkt in packets:
        if IP in pkt and TCP in pkt and Raw in pkt:
            flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            seq = pkt[TCP].seq
            payload = bytes(pkt[Raw].load)
            streams.setdefault(flow, []).append((seq, payload))

    reassembled = {}
    for flow, segs in streams.items():
        segs.sort(key=lambda x: x[0])
        stream_bytes = b"".join(payload for _, payload in segs)
        reassembled[flow] = stream_bytes

    results = []
    for flow, data in reassembled.items():
        for size, name in PQC_KEY_MAP.items():
            # look for contiguous blocks near expected size
            for i in range(0, len(data) - size + 1):
                window = data[i:i+size]
                if abs(len(window) - size) <= 10:
                    ent = shannon_entropy(window)
                    if ent > 6.5:  # high-entropy data
                        results.append({
                            "flow": flow,
                            "detected": name,
                            "size": len(window),
                            "entropy": round(ent, 10),
                            "offset": i
                        })
                        break
    return results

if __name__ == "__main__":
    res = detect_pqc_streams(args.file)
    if not res:
        print("No PQC segments found.")
    else:
        res.sort(key=lambda x: x["entropy"], reverse=True)

        # print(f"Top {len(res)} detected segments (sorted by entropy):\n")
        # for r in res:
        #     s_ip, s_port, d_ip, d_port = r["flow"]
        #     print(f"{s_ip}:{s_port} → {d_ip}:{d_port} | "
        #           f"{r['detected']} ({r['size']} B, entropy={r['entropy']}) "
        #           f"at offset {r['offset']}")
       
       
        top = res[0]
        s_ip, s_port, d_ip, d_port = top["flow"]
        print(f"Highest entropy block: {top['detected']} "
            f"({top['size']} B, entropy={top['entropy']}) "
            f"from {s_ip}:{s_port} → {d_ip}:{d_port}")

