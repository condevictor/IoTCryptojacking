"""
Combina Benign-1 + CJ-Sniffer em CSV packet-level, AGRUPANDO POR DISPOSITIVO
antes de formar os bursts (como o artigo faz com MAC address).

Saida: [device_id, Timestamp, Packet Length, Label, burst_id]
O burst_id e unico por (dispositivo, sequencia de 10 pacotes).
"""
import os
import glob
import pandas as pd
from scapy.all import rdpcap

BENIGN_DIR = "/home/CIN/vddc/cryptojacking/data/benign-1"
CJ_DIR = "/home/CIN/vddc/cryptojacking/data/cj-sniffer/CJ-Sniffer-Dataset/Cryptomining_Traffic"
OUT = "/home/CIN/vddc/cryptojacking/data/combined/combined.csv"
BURST_SIZE = 10

def load_benign():
    """Le CSVs benignos, agrupa por Hw_src (MAC) e forma bursts por dispositivo."""
    rows = []
    files = sorted(glob.glob(os.path.join(BENIGN_DIR, "*.csv")))
    print(f"Benign: {len(files)} CSVs")
    for f in files:
        try:
            df = pd.read_csv(f)
            # aceita 'Time' ou 'Timestamp'
            tcol = 'Time' if 'Time' in df.columns else ('Timestamp' if 'Timestamp' in df.columns else None)
            if tcol is None:
                continue
            df = df[[tcol, 'Length', 'Hw_src']].dropna()
            df.columns = ['time', 'length', 'device']
            df['time'] = pd.to_numeric(df['time'], errors='coerce')
            df['length'] = pd.to_numeric(df['length'], errors='coerce')
            df = df.dropna()
            # agrupa por MAC e forma bursts
            for mac, g in df.groupby('device'):
                g = g.sort_values('time').reset_index(drop=True)
                for i in range(0, len(g) - BURST_SIZE + 1, BURST_SIZE):
                    burst = g.iloc[i:i+BURST_SIZE]
                    burst_id = f"benign_{mac}_{i//BURST_SIZE}"
                    for _, r in burst.iterrows():
                        rows.append((burst_id, r['time'], r['length'], 'Benign'))
        except Exception as e:
            print(f"  erro em {os.path.basename(f)}: {e}")
    print(f"  {len(rows)} pacotes benignos ({len(set(r[0] for r in rows))} bursts)")
    return rows

def load_cryptojacking():
    """Cada pcap = 1 dispositivo. Forma bursts de 10 pacotes consecutivos."""
    rows = []
    files = sorted(glob.glob(os.path.join(CJ_DIR, "*.pcap")))
    print(f"CJ-Sniffer: {len(files)} pcaps")
    for f in files:
        try:
            packets = rdpcap(f)
            dev = os.path.basename(f).replace('.pcap', '')
            buf = []
            burst_idx = 0
            for pkt in packets:
                if not (pkt.haslayer('IP') or pkt.haslayer('IPv6')):
                    continue
                buf.append((float(pkt.time), len(pkt)))
                if len(buf) == BURST_SIZE:
                    bid = f"cj_{dev}_{burst_idx}"
                    for ts, ln in buf:
                        rows.append((bid, ts, ln, 'Cryptojacking'))
                    buf = []
                    burst_idx += 1
        except Exception as e:
            print(f"  erro em {os.path.basename(f)}: {e}")
    print(f"  {len(rows)} pacotes cryptojacking ({len(set(r[0] for r in rows))} bursts)")
    return rows

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    benign = load_benign()
    cj = load_cryptojacking()
    df = pd.DataFrame(benign + cj, columns=['id', 'Timestamp', 'Packet Length', 'Label'])
    df = df.sort_values(['id', 'Timestamp']).reset_index(drop=True)
    df.to_csv(OUT, index=False)
    print(f"\nOK: {len(df)} pacotes, {df['id'].nunique()} bursts -> {OUT}")
    print(f"Classes: {df['Label'].value_counts().to_dict()}")
    print(f"Bursts por classe: {df.groupby('Label')['id'].nunique().to_dict()}")

if __name__ == '__main__':
    main()
