import os, glob, re
import pandas as pd
import numpy as np

BENIGN_DIR = "/home/CIN/vddc/cryptojacking/data/benign-1"
MALICIOUS_DIR = "/home/CIN/vddc/cryptojacking/data/malicious"
OUT = "/home/CIN/vddc/cryptojacking/data/article/article_combined.csv"
BURST = 10

TIME_CANDIDATES = ['Time','time','timestamp','Timestamp','ts','TS','frame.time_epoch']
LEN_CANDIDATES = ['Length','length','data_len','packet_length','size','Size','bytes','frame.len']

def detect_cols(df):
    tcol = next((c for c in TIME_CANDIDATES if c in df.columns), None)
    lcol = next((c for c in LEN_CANDIDATES if c in df.columns), None)
    if tcol is None or lcol is None:
        num = df.select_dtypes(include=[np.number]).columns.tolist()
        if tcol is None and num: tcol = num[0]
        if lcol is None and len(num) >= 2: lcol = num[-1]
    return tcol, lcol

def classify_attack(fname):
    f = fname.lower()
    if 'webminepool' in f: return 'inbrowser_webminepool'
    if 'webmine' in f: return 'inbrowser_webmine'
    if ('binary' in f or 'minergate' in f) and ('webos' in f or 'antmining' in f):
        return 'host_antmining'
    if 'binary' in f or 'minergate' in f:
        return 'host_minergate'
    if 'antmining' in f: return 'host_antmining'
    return 'unknown'

def classify_device(fname):
    f = fname.lower()
    if 'rasp' in f: return 'Raspberry'
    if 'desktop' in f or 'laptop' in f: return 'Laptop'
    if 'server' in f: return 'Server'
    if 'webos' in f: return 'WebOS'
    return 'Unknown'

def classify_throttle(fname):
    f = fname.lower()
    if 'aggressive' in f: return 'aggressive'
    if 'robust' in f: return 'robust'
    if 'stealthy' in f: return 'stealthy'
    return 'n/a'

def burst_features(chunk, tcol, lcol):
    lengths = pd.to_numeric(chunk[lcol], errors='coerce').dropna().values.astype(float)
    times = pd.to_numeric(chunk[tcol], errors='coerce').dropna().values.astype(float)
    if len(lengths) == 0 or len(times) == 0: return None
    iat = np.diff(np.sort(times)) if len(times) > 1 else np.array([0.0])
    if len(iat) == 0: iat = np.array([0.0])
    dur = float(np.max(times) - np.min(times)) if len(times) > 1 else 0.0
    return {
        'len_mean': float(np.mean(lengths)), 'len_std': float(np.std(lengths)),
        'len_min': float(np.min(lengths)),   'len_max': float(np.max(lengths)),
        'len_median': float(np.median(lengths)), 'len_sum': float(np.sum(lengths)),
        'len_range': float(np.max(lengths) - np.min(lengths)),
        'len_cv': float(np.std(lengths) / (np.mean(lengths) + 1e-9)),
        'iat_mean': float(np.mean(iat)), 'iat_std': float(np.std(iat)),
        'iat_min': float(np.min(iat)),   'iat_max': float(np.max(iat)),
        'iat_median': float(np.median(iat)), 'iat_sum': float(np.sum(iat)),
        'iat_range': float(np.max(iat) - np.min(iat)),
        'burst_duration': dur,
        'pps_burst': float(len(lengths) / (dur + 1e-9)) if dur > 0 else 0.0,
    }

def process_file(path, label):
    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"[SKIP] {os.path.basename(path)}: read error {e}"); return None
    tcol, lcol = detect_cols(df)
    if tcol is None or lcol is None:
        print(f"[SKIP] {os.path.basename(path)}: cols={list(df.columns)}"); return None
    df = df[[tcol, lcol]].copy()
    df[tcol] = pd.to_numeric(df[tcol], errors='coerce')
    df[lcol] = pd.to_numeric(df[lcol], errors='coerce')
    df = df.dropna().reset_index(drop=True)
    if len(df) < BURST:
        print(f"[SKIP] {os.path.basename(path)}: <{BURST} pacotes ({len(df)})"); return None
    fname = os.path.basename(path)
    fam = classify_attack(fname)
    dev = classify_device(fname) if label == 1 else 'Unknown'
    thr = classify_throttle(fname) if label == 1 else 'n/a'
    rows = []
    for i in range(0, len(df) - BURST + 1, BURST):
        f = burst_features(df.iloc[i:i+BURST], tcol, lcol)
        if f is None: continue
        f['Label'] = label
        f['attack_family'] = fam
        f['device'] = dev
        f['throttle'] = thr
        f['source_file'] = fname
        rows.append(f)
    return pd.DataFrame(rows) if rows else None

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    print(f"BENIGN_DIR    : {BENIGN_DIR} ({os.path.isdir(BENIGN_DIR)})")
    print(f"MALICIOUS_DIR : {MALICIOUS_DIR} ({os.path.isdir(MALICIOUS_DIR)})")
    all_dfs = []
    for label, d in [(0, BENIGN_DIR), (1, MALICIOUS_DIR)]:
        files = sorted(glob.glob(os.path.join(d, "*.csv")))
        print(f"\n--- {'BENIGN' if label==0 else 'MALICIOUS'}: {len(files)} CSVs")
        for p in files:
            r = process_file(p, label)
            if r is not None:
                all_dfs.append(r)
                print(f"  {os.path.basename(p):45s} {len(r):7d} bursts | fam={r['attack_family'].iloc[0]:25s} dev={r['device'].iloc[0]:10s} thr={r['throttle'].iloc[0]}")
    if not all_dfs:
        print("\n[FATAL] nenhum arquivo processado"); return
    out = pd.concat(all_dfs, ignore_index=True)
    out.to_csv(OUT, index=False)
    print(f"\nSalvo: {OUT}")
    print(f"Total bursts: {len(out)}")
    print(f"Label:         {out['Label'].value_counts().to_dict()}")
    print(f"attack_family: {out['attack_family'].value_counts().to_dict()}")
    print(f"device:        {out['device'].value_counts().to_dict()}")
    print(f"throttle:      {out['throttle'].value_counts().to_dict()}")
    print("\nCrosstab attack_family x device:")
    print(pd.crosstab(out['attack_family'], out['device']))

if __name__ == '__main__':
    main()
