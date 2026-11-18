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

BASE_FEATURES = [
    'len_mean','len_std','len_min','len_max','len_median','len_sum',
    'len_range','len_cv',
    'iat_mean','iat_std','iat_min','iat_max','iat_median','iat_sum','iat_range',
    'burst_duration','pps_burst',
]

RATIO_FEATURES = [
    'iat_cv',            # iat_std / iat_mean
    'len_std_norm',      # len_std / len_sum
    'iat_std_norm',      # iat_std / iat_sum
    'len_range_norm',    # len_range / len_mean
    'iat_range_norm',    # iat_range / iat_mean
    'len_min_max_ratio', # len_min / len_max
    'iat_min_max_ratio', # iat_min / iat_max
    'pps_per_byte',      # pps_burst / len_mean
    'pps_x_iat',         # pps_burst * iat_mean
    'len_per_iat',       # len_mean / iat_mean
    'dur_per_pkt',       # burst_duration / 10
]

def load_pool(paths):
    dfs = [pd.read_csv(p, low_memory=False) for p in paths]
    df = pd.concat(dfs, ignore_index=True)
    df['attack_family'] = df['attack_family'].fillna('unknown').astype(str)
    df['device']        = df['device'].fillna('Unknown').astype(str)
    df['throttle']      = df['throttle'].fillna('none').astype(str)
    df['Label']         = df['Label'].astype(int)
    return df

def add_ratio_features(df):
    eps = 1e-9
    df = df.copy()
    df['iat_cv']            = df['iat_std'] / (df['iat_mean'].abs() + eps)
    df['len_std_norm']      = df['len_std'] / (df['len_sum'].abs() + eps)
    df['iat_std_norm']      = df['iat_std'] / (df['iat_sum'].abs() + eps)
    df['len_range_norm']    = df['len_range'] / (df['len_mean'].abs() + eps)
    df['iat_range_norm']    = df['iat_range'] / (df['iat_mean'].abs() + eps)
    df['len_min_max_ratio'] = df['len_min'] / (df['len_max'].abs() + eps)
    df['iat_min_max_ratio'] = df['iat_min'] / (df['iat_max'].abs() + eps)
    df['pps_per_byte']      = df['pps_burst'] / (df['len_mean'].abs() + eps)
    df['pps_x_iat']         = df['pps_burst'] * df['iat_mean']
    df['len_per_iat']       = df['len_mean'] / (df['iat_mean'].abs() + eps)
    df['dur_per_pkt']       = df['burst_duration'] / 10.0
    for c in RATIO_FEATURES:
        df[c] = df[c].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df

def build_feature_matrix(df, augmentation):
    if augmentation == 'none':
        return df[BASE_FEATURES].values, list(BASE_FEATURES)
    df2 = add_ratio_features(df)
    if augmentation == 'ratios':
        cols = BASE_FEATURES + RATIO_FEATURES
        return df2[cols].values, list(cols)
    if augmentation.startswith('ratios_dup'):
        dup = int(augmentation.replace('ratios_dup', ''))
        cols = []; names = []
        for c in BASE_FEATURES:
            cols.append(df2[c].values); names.append(c)
        for c in RATIO_FEATURES:
            for k in range(dup):
                cols.append(df2[c].values); names.append(f'{c}__dup{k}')
        return np.column_stack(cols), names
    raise ValueError(f"unknown augmentation: {augmentation}")

def aggregate_importances(names, importances):
    """Soma importâncias de duplicatas; retorna dict ordenado."""
    agg = {}
    for n, imp in zip(names, importances):
        base = n.split('__dup')[0] if '__dup' in n else n
        agg[base] = agg.get(base, 0.0) + float(imp)
    return dict(sorted(agg.items(), key=lambda kv: -kv[1]))

def subsample_balanced(df, max_per_class=MAX_PER_CLASS, seed=RNG):
    pos = df[df['Label']==1]; neg = df[df['Label']==0]
    pos_s = pos.sample(n=min(max_per_class, len(pos)), random_state=seed)
    neg_s = neg.sample(n=min(max_per_class, len(neg)), random_state=seed)
    out = pd.concat([pos_s, neg_s], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def train_eval(train_df, test_df, tag, augmentation, max_features, n_estimators):
    if train_df['Label'].nunique() < 2:
        print(f"[{tag}] train com 1 classe, pulando"); return None
    if test_df['Label'].nunique() < 2:
        print(f"[{tag}] test com 1 classe, pulando"); return None
    Xtr, names = build_feature_matrix(train_df, augmentation)
    ytr = train_df['Label'].values
    Xte, _ = build_feature_matrix(test_df, augmentation)
    yte = test_df['Label'].values
    clf = RandomForestClassifier(n_estimators=n_estimators, n_jobs=-1,
                                 random_state=RNG,
                                 class_weight='balanced_subsample',
                                 max_features=max_features)
    t0 = time.time(); clf.fit(Xtr, ytr); train_t = time.time() - t0
    t0 = time.time(); yp = clf.predict(Xte); yprob = clf.predict_proba(Xte)[:,1]
    infer_t = time.time() - t0
    benign_mask = (yte==0); mal_mask = (yte==1)
    top10 = list(aggregate_importances(names, clf.feature_importances_).items())[:10]
    return {
        'tag': tag, 'augmentation': augmentation,
        'n_features_used': len(names),
        'n_train': len(train_df), 'n_test': len(test_df),
        'n_pos_train': int((ytr==1).sum()), 'n_neg_train': int((ytr==0).sum()),
        'n_pos_test':  int((yte==1).sum()), 'n_neg_test':  int((yte==0).sum()),
        'acc':         float(accuracy_score(yte, yp)),
        'prec':        float(precision_score(yte, yp, zero_division=0)),
        'recall':      float(recall_score(yte, yp, zero_division=0)),
        'f1':          float(f1_score(yte, yp, zero_division=0)),
        'roc_auc':     float(roc_auc_score(yte, yprob)) if len(np.unique(yte))>1 else float('nan'),
        'acc_on_benign_test':    float(accuracy_score(yte[benign_mask], yp[benign_mask])),
        'acc_on_malicious_test': float(accuracy_score(yte[mal_mask],    yp[mal_mask])),
        'train_time_s': float(train_t), 'infer_time_s': float(infer_t),
        'top10_importances': top10,
        'confusion': confusion_matrix(yte, yp).tolist(),
    }

def run_baseline(df, augmentation, max_per_class, max_features, n_estimators):
    tr_idx, te_idx = train_test_split(df.index, test_size=TEST_SIZE,
                                       random_state=RNG, stratify=df['Label'])
    tr = subsample_balanced(df.loc[tr_idx], max_per_class)
    te = df.loc[te_idx]
    return train_eval(tr, te, 'baseline_random_split', augmentation, max_features, n_estimators)

def run_zeroday(df, tag, heldout_query, augmentation, max_per_class, max_features, n_estimators):
    held_idx = df.query(heldout_query).index
    if len(held_idx) == 0:
        print(f"[{tag}] held-out vazio, pulando"); return None
    held = df.loc[held_idx]
    if held['Label'].sum() == 0:
        print(f"[{tag}] held-out so tem benigno, pulando"); return None
    benign = df[df['Label']==0]
    benign_train, benign_test = train_test_split(benign, test_size=TEST_SIZE, random_state=RNG)
    mal_train = df[(df['Label']==1) & (~df.index.isin(held_idx))]
    if len(mal_train) == 0:
        print(f"[{tag}] sem malicious no treino, pulando"); return None
    tr = subsample_balanced(pd.concat([benign_train, mal_train], ignore_index=True), max_per_class)
    n = min(len(benign_test), len(held))
    if n < 50:
        print(f"[{tag}] test muito pequeno (n={n}), pulando"); return None
    te = pd.concat([benign_test.sample(n=n, random_state=RNG),
                    held.sample(n=n, random_state=RNG)], ignore_index=True)
    return train_eval(tr, te, tag, augmentation, max_features, n_estimators)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--out', default='results/rf_zeroday')
    ap.add_argument('--augmentation', default='none',
                    choices=['none','ratios','ratios_dup2','ratios_dup3','ratios_dup5'])
    ap.add_argument('--max-per-class', type=int, default=MAX_PER_CLASS)
    ap.add_argument('--max-features', default='sqrt', help="'sqrt','log2', ou int")
    ap.add_argument('--n-estimators', type=int, default=N_ESTIMATORS)
    ap.add_argument('--suffix', default='')
    ap.add_argument('--quick', action='store_true', help='só baseline + 3 holdouts críticos')
    ap.add_argument('--discover', action='store_true')
    args = ap.parse_args()

    # max_features: converte para int se for dígito
    mf = args.max_features
    if isinstance(mf, str) and mf.isdigit():
        mf = int(mf)

    os.makedirs(args.out, exist_ok=True)
    df = load_pool(args.csv)
    print(f"loaded {len(df)} bursts | pos={int((df['Label']==1).sum())} neg={int((df['Label']==0).sum())}")
    print(f"attack_family: {df['attack_family'].value_counts().to_dict()}")
    print(f"device:        {df['device'].value_counts().to_dict()}")
    print(f"throttle:      {df['throttle'].value_counts().to_dict()}")
    missing = [c for c in BASE_FEATURES + ['Label','attack_family','device','throttle'] if c not in df.columns]
    if missing:
        print(f"[FATAL] colunas faltando: {missing}"); return
    if args.discover:
        # mostra quantas features cada config gera
        _, n1 = build_feature_matrix(df.head(10), 'none')
        _, n2 = build_feature_matrix(df.head(10), 'ratios')
        _, n3 = build_feature_matrix(df.head(10), 'ratios_dup3')
        print(f"[DISCOVER] features: none={len(n1)}, ratios={len(n2)}, ratios_dup3={len(n3)}")
        print("[DISCOVER] schema OK, encerrando"); return

    print(f"[CONFIG] augmentation={args.augmentation} max_features={mf} "
          f"n_estimators={args.n_estimators} max_per_class={args.max_per_class}")

    results = [run_baseline(df, args.augmentation, args.max_per_class, mf, args.n_estimators)]

    if args.quick:
        pairs = [
            ("zeroday_family_minergate_heldout", "attack_family=='host_minergate'"),
            ("zeroday_device_Server_heldout",    "device=='Server'"),
            ("zeroday_device_WebOS_heldout",     "device=='WebOS'"),
        ]
    else:
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
        r = run_zeroday(df, tag, q, args.augmentation, args.max_per_class, mf, args.n_estimators)
        if r: results.append(r)

    out = pd.DataFrame(results)
    out['delta_acc_vs_baseline']     = out['acc'] - out['acc'].iloc[0]
    out['delta_acc_mal_vs_baseline'] = out['acc_on_malicious_test'] - out['acc_on_malicious_test'].iloc[0]
    out['delta_f1_vs_baseline']      = out['f1']  - out['f1'].iloc[0]
    fname = f"rf_v2_results{args.suffix}.csv"
    out.to_csv(os.path.join(args.out, fname), index=False)
    with open(os.path.join(args.out, f"rf_v2_results{args.suffix}.json"), 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print("\n=== SUMMARY ===")
    cols = ['tag','augmentation','n_features_used','n_train','n_test',
            'acc','f1','roc_auc','acc_on_malicious_test',
            'delta_acc_mal_vs_baseline','train_time_s']
    print(out[cols].to_string(index=False))
    print("\nTop-5 features (baseline):")
    for n, imp in results[0]['top10_importances'][:5]:
        print(f"  {n:30s} {imp:.4f}")

if __name__ == '__main__':
    main()
