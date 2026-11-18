import os, json, time, argparse, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

RNG = 90210
MAX_PER_CLASS = 500_000
N_ESTIMATORS = 200
TEST_SIZE = 0.20

FEATURES = ['len_mean','len_std','len_min','len_max','len_median','len_sum',
    'len_range','len_cv','iat_mean','iat_std','iat_min','iat_max','iat_median',
    'iat_sum','iat_range','burst_duration','pps_burst']

def load_pool(paths):
    dfs = [pd.read_csv(p, low_memory=False) for p in paths]
    df = pd.concat(dfs, ignore_index=True)
    df['attack_family'] = df['attack_family'].fillna('unknown').astype(str)
    df['device']        = df['device'].fillna('Unknown').astype(str)
    df['throttle']      = df['throttle'].fillna('none').astype(str)
    df['Label']         = df['Label'].astype(int)
    return df

def subsample_balanced(df, max_per_class=None, seed=RNG):
    if max_per_class is None:
        max_per_class = MAX_PER_CLASS
    pos = df[df['Label']==1]; neg = df[df['Label']==0]
    pos_s = pos.sample(n=min(max_per_class, len(pos)), random_state=seed)
    neg_s = neg.sample(n=min(max_per_class, len(neg)), random_state=seed)
    out = pd.concat([pos_s, neg_s], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def train_eval(train_df, test_df, tag):
    if train_df['Label'].nunique() < 2:
        print(f"[{tag}] train com 1 classe, pulando"); return None
    if test_df['Label'].nunique() < 2:
        print(f"[{tag}] test com 1 classe, pulando"); return None
    Xtr = train_df[FEATURES].values; ytr = train_df['Label'].values
    Xte = test_df[FEATURES].values;  yte = test_df['Label'].values
    clf = RandomForestClassifier(n_estimators=N_ESTIMATORS, n_jobs=-1,
                                 random_state=RNG, class_weight='balanced_subsample')
    t0 = time.time(); clf.fit(Xtr, ytr); train_t = time.time() - t0
    t0 = time.time(); yp = clf.predict(Xte); yprob = clf.predict_proba(Xte)[:,1]
    infer_t = time.time() - t0
    benign_mask = (yte==0); mal_mask = (yte==1)
    return {
        'tag': tag, 'n_train': len(train_df), 'n_test': len(test_df),
        'n_pos_train': int((ytr==1).sum()), 'n_neg_train': int((ytr==0).sum()),
        'n_pos_test':  int((yte==1).sum()), 'n_neg_test':  int((yte==0).sum()),
        'acc':         float(accuracy_score(yte, yp)),
        'prec':        float(precision_score(yte, yp, zero_division=0)),
        'recall':      float(recall_score(yte, yp, zero_division=0)),
        'f1':          float(f1_score(yte, yp, zero_division=0)),
        'roc_auc':     float(roc_auc_score(yte, yprob)),
        'acc_on_benign_test':    float(accuracy_score(yte[benign_mask], yp[benign_mask])),
        'acc_on_malicious_test': float(accuracy_score(yte[mal_mask],    yp[mal_mask])),
        'train_time_s': float(train_t), 'infer_time_s': float(infer_t),
        'confusion': confusion_matrix(yte, yp).tolist(),
    }

def run_baseline(df):
    tr_idx, te_idx = train_test_split(df.index, test_size=TEST_SIZE,
                                       random_state=RNG, stratify=df['Label'])
    tr = subsample_balanced(df.loc[tr_idx])
    te = df.loc[te_idx]
    return train_eval(tr, te, 'baseline_random_split')

def run_zeroday(df, tag, heldout_query):
    held_idx = df.query(heldout_query).index
    if len(held_idx) == 0:
        print(f"[{tag}] held-out vazio, pulando"); return None
    held = df.loc[held_idx]
    if held['Label'].sum() == 0:
        print(f"[{tag}] held-out so tem benigno, pulando"); return None
    benign = df[df['Label']==0]
    benign_train, benign_test = train_test_split(benign, test_size=TEST_SIZE,
                                                 random_state=RNG)
    mal_train = df[(df['Label']==1) & (~df.index.isin(held_idx))]
    if len(mal_train) == 0:
        print(f"[{tag}] sem malicious no treino, pulando"); return None
    tr = subsample_balanced(pd.concat([benign_train, mal_train], ignore_index=True))
    n = min(len(benign_test), len(held))
    if n < 50:
        print(f"[{tag}] test muito pequeno (n={n}), pulando"); return None
    te = pd.concat([
        benign_test.sample(n=n, random_state=RNG),
        held.sample(n=n, random_state=RNG),
    ], ignore_index=True)
    return train_eval(tr, te, tag)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--out', default='results/rf_zeroday')
    ap.add_argument('--max-per-class', type=int, default=500_000)
    ap.add_argument('--discover', action='store_true')
    args = ap.parse_args()
    global MAX_PER_CLASS
    MAX_PER_CLASS = args.max_per_class
    os.makedirs(args.out, exist_ok=True)
    df = load_pool(args.csv)
    print(f"loaded {len(df)} bursts | pos={int((df['Label']==1).sum())} neg={int((df['Label']==0).sum())}")
    print(f"attack_family: {df['attack_family'].value_counts().to_dict()}")
    print(f"device:        {df['device'].value_counts().to_dict()}")
    print(f"throttle:      {df['throttle'].value_counts().to_dict()}")
    missing = [c for c in FEATURES + ['Label','attack_family','device','throttle'] if c not in df.columns]
    if missing:
        print(f"[FATAL] colunas faltando: {missing}"); return
    if args.discover:
        print("[DISCOVER] schema OK, encerrando"); return
    results = [run_baseline(df)]
    pairs = [
        ("zeroday_family_webmine_heldout",     "attack_family=='inbrowser_webmine'"),
        ("zeroday_family_webminepool_heldout", "attack_family=='inbrowser_webminepool'"),
        ("zeroday_family_minergate_heldout",   "attack_family=='host_minergate'"),
        ("zeroday_family_antmining_heldout",   "attack_family=='host_antmining'"),
        ("zeroday_device_Server_heldout",      "device=='Server'"),
        ("zeroday_device_Laptop_heldout",      "device=='Laptop'"),
        ("zeroday_device_Raspberry_heldout",   "device=='Raspberry'"),
        ("zeroday_device_WebOS_heldout",       "device=='WebOS'"),
        ("zeroday_throttle_stealthy_heldout",  "throttle=='stealthy'"),
        ("zeroday_throttle_aggressive_heldout","throttle=='aggressive'"),
    ]
    for tag, q in pairs:
        r = run_zeroday(df, tag, q)
        if r: results.append(r)
    out = pd.DataFrame(results)
    out['delta_acc_vs_baseline']     = out['acc'] - out['acc'].iloc[0]
    out['delta_acc_mal_vs_baseline'] = out['acc_on_malicious_test'] - out['acc_on_malicious_test'].iloc[0]
    out['delta_f1_vs_baseline']      = out['f1']  - out['f1'].iloc[0]
    out.to_csv(os.path.join(args.out, 'rf_zeroday_results.csv'), index=False)
    with open(os.path.join(args.out, 'rf_zeroday_results.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print("\n=== SUMMARY ===")
    cols = ['tag','n_train','n_test','acc','f1','roc_auc',
            'acc_on_malicious_test','delta_acc_vs_baseline','train_time_s']
    print(out[cols].to_string(index=False))

if __name__ == '__main__':
    main()
