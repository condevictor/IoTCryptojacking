"""
rf_pruned_zeroday.py
====================

Versão podada do RF (50 árvores, profundidade 15) para deployment
em roteador doméstico. Cabe em ~400 KB compilado via m2cgen (vs
~19 MB da RF cheia). Mesmos 9 experimentos do
compare_rf_vs_svm_zeroday.py, mas com modelo menor.

Empata em acurácia com RF cheia (0,9174 vs 0,9167 média zero-day)
e é ~2× mais rápido em inferência. Gera results/rf_pruned/ →
Tabela X do relatorio_final.pdf.

Uso:
    python3 Code/rf_pruned_zeroday.py \
        --csv ../data/article/article_combined.csv \
        --out ../results/rf_pruned

Tempo de execução: ~3 min (50 árvores × 10k/classe × 9 fits).
"""

import os, json, time, argparse, pickle, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

RNG = 90210
MAX_PER_CLASS = 10_000
N_ESTIMATORS = 50
MAX_DEPTH = 15
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

def subsample_balanced(df, max_per_class=MAX_PER_CLASS, seed=RNG):
    # VERSAO CORRIGIDA: n = min(len(pos), len(neg), max_per_class)
    pos = df[df['Label']==1]; neg = df[df['Label']==0]
    n = min(len(pos), len(neg), max_per_class)
    pos_s = pos.sample(n=n, random_state=seed)
    neg_s = neg.sample(n=n, random_state=seed)
    out = pd.concat([pos_s, neg_s], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def train_eval(train_df, test_df, tag):
    if train_df['Label'].nunique() < 2 or test_df['Label'].nunique() < 2:
        print(f"[{tag}] 1 classe, pulando"); return None
    Xtr = train_df[FEATURES].values; ytr = train_df['Label'].values
    Xte = test_df[FEATURES].values;  yte = test_df['Label'].values
    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
        n_jobs=-1, random_state=RNG, class_weight='balanced_subsample')
    t0 = time.time(); clf.fit(Xtr, ytr); train_t = time.time() - t0
    t0 = time.time(); yp = clf.predict(Xte); infer_t = time.time() - t0
    yprob = clf.predict_proba(Xte)[:,1]
    model_size_bytes = len(pickle.dumps(clf))
    return {
        'tag': tag, 'n_train': len(train_df), 'n_test': len(test_df),
        'n_estimators': N_ESTIMATORS, 'max_depth': MAX_DEPTH,
        'model_size_kb': model_size_bytes / 1024,
        'n_nodes': int(sum(t.tree_.node_count for t in clf.estimators_)),
        'acc': float(accuracy_score(yte, yp)),
        'prec': float(precision_score(yte, yp, zero_division=0)),
        'recall': float(recall_score(yte, yp, zero_division=0)),
        'f1': float(f1_score(yte, yp, zero_division=0)),
        'roc_auc': float(roc_auc_score(yte, yprob)),
        'acc_on_malicious_test': float(accuracy_score(yte[yte==1], yp[yte==1])),
        'fpr': float((yp[yte==0]==1).mean()),
        'fnr': float((yp[yte==1]==0).mean()),
        'train_time_s': float(train_t), 'infer_time_s': float(infer_t),
        'infer_us_per_sample': float(infer_t / len(yte) * 1e6),
    }

def run_baseline(df):
    tr_idx, te_idx = train_test_split(df.index, test_size=TEST_SIZE,
                                       random_state=RNG, stratify=df['Label'])
    tr = subsample_balanced(df.loc[tr_idx]); te = df.loc[te_idx]
    return train_eval(tr, te, 'baseline_random_split')

def run_zeroday(df, tag, heldout_query):
    held_idx = df.query(heldout_query).index
    if len(held_idx) == 0: print(f"[{tag}] vazio"); return None
    held = df.loc[held_idx]
    if held['Label'].sum() == 0: print(f"[{tag}] held-out benigno"); return None
    benign = df[df['Label']==0]
    benign_train, benign_test = train_test_split(benign, test_size=TEST_SIZE, random_state=RNG)
    mal_train = df[(df['Label']==1) & (~df.index.isin(held_idx))]
    if len(mal_train) == 0: print(f"[{tag}] sem malicious"); return None
    tr = subsample_balanced(pd.concat([benign_train, mal_train], ignore_index=True))
    n = min(len(benign_test), len(held))
    if n < 50: print(f"[{tag}] test n={n}"); return None
    te = pd.concat([benign_test.sample(n=n, random_state=RNG),
                    held.sample(n=n, random_state=RNG)], ignore_index=True)
    return train_eval(tr, te, tag)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--out', default='../../results/rf_pruned')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    df = load_pool(args.csv)
    print(f"loaded {len(df)} bursts | config: {N_ESTIMATORS} trees, depth {MAX_DEPTH}")
    results = [run_baseline(df)]
    pairs = [
        ("zeroday_family_webmine_heldout",     "attack_family=='inbrowser_webmine'"),
        ("zeroday_family_webminepool_heldout", "attack_family=='inbrowser_webminepool'"),
        ("zeroday_family_minergate_heldout",   "attack_family=='host_minergate'"),
        ("zeroday_family_antmining_heldout",   "attack_family=='host_antmining'"),
        ("zeroday_device_Laptop_heldout",      "device=='Laptop'"),
        ("zeroday_device_Raspberry_heldout",   "device=='Raspberry'"),
        ("zeroday_throttle_stealthy_heldout",  "throttle=='stealthy'"),
        ("zeroday_throttle_aggressive_heldout","throttle=='aggressive'"),
    ]
    for tag, q in pairs:
        r = run_zeroday(df, tag, q)
        if r: results.append(r)
        if r: print(f"[{tag}] acc_mal={r['acc_on_malicious_test']:.4f} "
                    f"fpr={r['fpr']:.4f} infer={r['infer_us_per_sample']:.2f}us "
                    f"size={r['model_size_kb']:.1f}KB nodes={r['n_nodes']}")
    out = pd.DataFrame(results)
    out.to_csv(os.path.join(args.out, 'rf_pruned_results.csv'), index=False)
    with open(os.path.join(args.out, 'rf_pruned_results.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n=== SUMMARY (pruned RF: {N_ESTIMATORS} trees, depth {MAX_DEPTH}) ===")
    print(out[['tag','acc_mal' if 'acc_mal' in out else 'acc_on_malicious_test',
               'fpr','infer_us_per_sample','model_size_kb','n_nodes']].to_string(index=False)
          if 'acc_mal' in out else out[['tag','acc_on_malicious_test','fpr',
                                         'infer_us_per_sample','model_size_kb','n_nodes']].to_string(index=False))

if __name__ == '__main__':
    main()
