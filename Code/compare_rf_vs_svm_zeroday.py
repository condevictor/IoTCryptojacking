"""
compare_rf_vs_svm_zeroday.py
============================

Compara Random Forest cheia (200 árvores, prof. 30) e SVM RBF
(885-1805 SVs) sob protocolo zero-day, com as mesmas 17 features
NumPy e mesmo split. Gera results/rf_vs_svm/rf_vs_svm_zeroday.{csv,json}
→ Tabela XI do relatorio_final.pdf.

Uso:
    python3 Code/compare_rf_vs_svm_zeroday.py \
        --csv ../data/article/article_combined.csv \
        --out ../results/rf_vs_svm

Tempo de execução: ~45 min em 16 cores (SVM RBF é O(n²); usamos
10k amostras/classe para caber no orçamento).
"""

import os, json, time, argparse, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

RNG = 90210
MAX_PER_CLASS = 10_000      # SVM O(n^2); RF roda com o mesmo para comparação justa
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

def subsample_balanced(df, max_per_class=MAX_PER_CLASS, seed=RNG):
    pos = df[df['Label']==1]; neg = df[df['Label']==0]
    pos_s = pos.sample(n=min(max_per_class, len(pos)), random_state=seed)
    neg_s = neg.sample(n=min(max_per_class, len(neg)), random_state=seed)
    out = pd.concat([pos_s, neg_s], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def build_rf():
    return RandomForestClassifier(n_estimators=N_ESTIMATORS, n_jobs=-1,
                                   random_state=RNG, class_weight='balanced_subsample')

def build_svm():
    return Pipeline([
        ('scaler', StandardScaler()),
        ('svm', SVC(kernel='rbf', C=1.0, gamma='scale',
                    class_weight='balanced', random_state=RNG, cache_size=2000)),
    ])

def train_eval(model_name, train_df, test_df, tag):
    if train_df['Label'].nunique() < 2 or test_df['Label'].nunique() < 2:
        print(f"[{model_name}:{tag}] 1 classe, pulando"); return None
    Xtr = train_df[FEATURES].values; ytr = train_df['Label'].values
    Xte = test_df[FEATURES].values;  yte = test_df['Label'].values
    clf = build_rf() if model_name == 'rf' else build_svm()
    t0 = time.time(); clf.fit(Xtr, ytr); train_t = time.time() - t0
    t0 = time.time(); yp = clf.predict(Xte); infer_t = time.time() - t0
    n_test = len(yte)
    # número de SVs (só SVM tem)
    n_sv = 0
    if model_name == 'svm':
        n_sv = int(len(clf.named_steps['svm'].support_))
    return {
        'model': model_name, 'tag': tag,
        'n_train': len(train_df), 'n_test': n_test, 'n_sv': n_sv,
        'acc': float(accuracy_score(yte, yp)),
        'prec': float(precision_score(yte, yp, zero_division=0)),
        'recall': float(recall_score(yte, yp, zero_division=0)),
        'f1': float(f1_score(yte, yp, zero_division=0)),
        'roc_auc': float(roc_auc_score(yte, (clf.predict_proba(Xte)[:,1] if hasattr(clf,'predict_proba') else clf.decision_function(Xte)))),
        'acc_on_malicious_test': float(accuracy_score(yte[yte==1], yp[yte==1])),
        'train_time_s': float(train_t),
        'infer_time_s': float(infer_t),
        'infer_us_per_sample': float(infer_t / n_test * 1e6),
        'confusion': confusion_matrix(yte, yp).tolist(),
    }

def run_baseline(df, model_name):
    tr_idx, te_idx = train_test_split(df.index, test_size=TEST_SIZE,
                                       random_state=RNG, stratify=df['Label'])
    tr = subsample_balanced(df.loc[tr_idx])
    te = df.loc[te_idx]
    return train_eval(model_name, tr, te, 'baseline_random_split')

def run_zeroday(df, model_name, tag, heldout_query):
    held_idx = df.query(heldout_query).index
    if len(held_idx) == 0: return None
    held = df.loc[held_idx]
    if held['Label'].sum() == 0: return None
    benign = df[df['Label']==0]
    benign_train, benign_test = train_test_split(benign, test_size=TEST_SIZE, random_state=RNG)
    mal_train = df[(df['Label']==1) & (~df.index.isin(held_idx))]
    if len(mal_train) == 0: return None
    tr = subsample_balanced(pd.concat([benign_train, mal_train], ignore_index=True))
    n = min(len(benign_test), len(held))
    if n < 50: return None
    te = pd.concat([benign_test.sample(n=n, random_state=RNG),
                    held.sample(n=n, random_state=RNG)], ignore_index=True)
    return train_eval(model_name, tr, te, tag)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--out', default='results/rf_vs_svm')
    ap.add_argument('--models', nargs='+', default=['rf','svm'])
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    df = load_pool(args.csv)
    print(f"loaded {len(df)} bursts | pos={int((df['Label']==1).sum())} neg={int((df['Label']==0).sum())}")
    print(f"throttle: {df['throttle'].value_counts().to_dict()}")

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

    results = []
    for model_name in args.models:
        print(f"\n===== MODELO: {model_name.upper()} =====")
        r = run_baseline(df, model_name)
        if r: results.append(r); print(f"[{model_name}:baseline] acc={r['acc']:.4f} "
                                       f"acc_mal={r['acc_on_malicious_test']:.4f} "
                                       f"train={r['train_time_s']:.1f}s "
                                       f"infer={r['infer_us_per_sample']:.2f}µs/sample")
        for tag, q in pairs:
            r = run_zeroday(df, model_name, tag, q)
            if r:
                results.append(r)
                print(f"[{model_name}:{tag}] acc={r['acc']:.4f} "
                      f"acc_mal={r['acc_on_malicious_test']:.4f} "
                      f"train={r['train_time_s']:.1f}s "
                      f"infer={r['infer_us_per_sample']:.2f}µs/sample "
                      f"n_sv={r['n_sv']}")

    out = pd.DataFrame(results)
    out.to_csv(os.path.join(args.out, 'rf_vs_svm_zeroday.csv'), index=False)
    with open(os.path.join(args.out, 'rf_vs_svm_zeroday.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)

    # Tabela comparativa: pivot model x tag
    pivot_acc = out.pivot(index='tag', columns='model', values='acc_on_malicious_test')
    pivot_inf = out.pivot(index='tag', columns='model', values='infer_us_per_sample')
    print("\n=== ACC_MAL (0-day detection rate) ===")
    print(pivot_acc.to_string())
    print("\n=== INFER µs/sample ===")
    print(pivot_inf.to_string())

if __name__ == '__main__':
    main()
