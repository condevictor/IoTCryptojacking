import os, json, time, argparse, warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
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

def subsample_balanced(df, max_per_class=MAX_PER_CLASS, seed=RNG):
    pos = df[df['Label']==1]; neg = df[df['Label']==0]
    pos_s = pos.sample(n=min(max_per_class, len(pos)), random_state=seed)
    neg_s = neg.sample(n=min(max_per_class, len(neg)), random_state=seed)
    out = pd.concat([pos_s, neg_s], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)

def fit_rf(train_df):
    Xtr = train_df[FEATURES].values; ytr = train_df['Label'].values
    clf = RandomForestClassifier(n_estimators=N_ESTIMATORS, n_jobs=-1,
                                 random_state=RNG, class_weight='balanced_subsample')
    clf.fit(Xtr, ytr)
    return clf

def calibrate_threshold(clf, X_benign_train, target_fpr=0.05):
    """Threshold such that ~target_fpr of benign TRAIN samples would be rejected."""
    proba = clf.predict_proba(X_benign_train)
    max_proba = proba.max(axis=1)
    return float(np.percentile(max_proba, target_fpr * 100))

def eval_osr(clf, Xte, yte, threshold):
    proba = clf.predict_proba(Xte)
    max_proba = proba.max(axis=1)
    yp = clf.predict(Xte)
    rejected = max_proba < threshold
    flagged_malicious = (yp != 0) | rejected
    yte_bin = (yte == 1)

    def safe_mean(arr, mask):
        return float(arr[mask].mean()) if mask.sum() > 0 else float('nan')

    return {
        'acc_standard': float(accuracy_score(yte, yp)),
        'acc_osr': float((flagged_malicious == yte_bin).mean()),
        'acc_benign_std': safe_mean((yp == 0), yte == 0),
        'acc_benign_osr': safe_mean((~flagged_malicious), yte == 0),
        'acc_mal_std': safe_mean((yp == 1), yte == 1),
        'acc_mal_osr': safe_mean(flagged_malicious, yte == 1),
        'rejection_rate_benign': safe_mean(rejected, yte == 0),
        'rejection_rate_mal':    safe_mean(rejected, yte == 1),
        'mean_confidence_benign': safe_mean(max_proba, yte == 0),
        'mean_confidence_mal':    safe_mean(max_proba, yte == 1),
    }

def run_experiment(df, tag, heldout_query=None, target_fpr=0.05):
    if heldout_query is None:
        tr_idx, te_idx = train_test_split(df.index, test_size=TEST_SIZE,
                                           random_state=RNG, stratify=df['Label'])
        tr = subsample_balanced(df.loc[tr_idx]); te = df.loc[te_idx]
    else:
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

    t0 = time.time(); clf = fit_rf(tr); train_t = time.time() - t0
    X_benign_train = tr[tr['Label']==0][FEATURES].values
    threshold = calibrate_threshold(clf, X_benign_train, target_fpr)

    Xte = te[FEATURES].values; yte = te['Label'].values
    t0 = time.time(); m = eval_osr(clf, Xte, yte, threshold); infer_t = time.time() - t0

    r = {'tag': tag, 'n_train': len(tr), 'n_test': len(te), 'threshold': threshold,
         'target_fpr': target_fpr, 'train_time_s': float(train_t),
         'infer_time_s': float(infer_t), 'infer_us_per_sample': float(infer_t/len(yte)*1e6),
         **m}
    print(f"[{tag}] std_mal={m['acc_mal_std']:.4f} osr_mal={m['acc_mal_osr']:.4f} "
          f"rej_benign={m['rejection_rate_benign']:.4f} "
          f"conf_benign={m['mean_confidence_benign']:.3f} conf_mal={m['mean_confidence_mal']:.3f} "
          f"infer={r['infer_us_per_sample']:.1f}us")
    return r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--out', default='results/rf_osr')
    ap.add_argument('--target-fpr', type=float, default=0.05)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    df = load_pool(args.csv)
    print(f"loaded {len(df)} bursts")
    print(f"attack_family: {df['attack_family'].value_counts().to_dict()}")

    results = [run_experiment(df, 'baseline_random_split', None, args.target_fpr)]
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
        r = run_experiment(df, tag, q, args.target_fpr)
        if r: results.append(r)

    out = pd.DataFrame(results)
    out['delta_mal_pct_points'] = (out['acc_mal_osr'] - out['acc_mal_std']) * 100
    out.to_csv(os.path.join(args.out, 'rf_osr_results.csv'), index=False)
    with open(os.path.join(args.out, 'rf_osr_results.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print("\n=== SUMMARY: OSR improvement on held-out malicious detection ===")
    print(out[['tag','acc_mal_std','acc_mal_osr','delta_mal_pct_points',
               'rejection_rate_benign','mean_confidence_mal']].to_string(index=False))

if __name__ == '__main__':
    main()
