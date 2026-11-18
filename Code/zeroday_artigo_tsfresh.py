import os, json, time, argparse, warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from tsfresh import extract_features
from tsfresh.feature_extraction import MinimalFCParameters, EfficientFCParameters
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.pipeline import Pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

RNG = 90210
TEST_SIZE = 0.20

def load_series(path):
    df = pd.read_csv(path)
    df['Label'] = df['Label'].astype(int)
    return df

def expand_to_long(df, max_rows):
    """Expande cada burst em 19 linhas (10 len + 9 iat) para tsfresh."""
    if max_rows and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=RNG).reset_index(drop=True)
    rows = []
    for idx, r in df.iterrows():
        lens = json.loads(r['len_series'])
        iats = json.loads(r['iat_series'])
        for v in lens:
            rows.append({'id': idx, 'kind': 'len', 'value': float(v)})
        for v in iats:
            rows.append({'id': idx, 'kind': 'iat', 'value': float(v)})
    return pd.DataFrame(rows), df

def extract_tsfresh(df_long, mode):
    fc = MinimalFCParameters() if mode == 'minimal' else EfficientFCParameters()
    print(f"[TSFRESH] modo={mode} series={df_long['id'].nunique()} pontos={len(df_long)}")
    t0 = time.time()
    feats = extract_features(
        df_long, column_id='id', column_kind='kind', column_value='value',
        default_fc_parameters=fc, n_jobs=8, disable_progressbar=True,
        show_warnings=False,
    )
    feats = feats.reindex(df_long['id'].unique())
    print(f"[TSFRESH] {feats.shape[1]} features em {time.time()-t0:.1f}s")
    return feats

def get_scores(clf, X):
    if hasattr(clf, 'decision_function'):
        return clf.decision_function(X)
    return clf.predict(X).astype(float)

def train_eval(Xtr, ytr, Xte, yte, tag):
    if len(np.unique(ytr)) < 2: return None
    if len(np.unique(yte)) < 2: return None
    clf = Pipeline([
        ('scale', StandardScaler()),
        ('select', SelectKBest(f_classif, k=min(50, Xtr.shape[1]))),
        ('svm', SVC(kernel='rbf', C=1.0, gamma='scale', random_state=RNG,
                    class_weight='balanced', cache_size=2000)),
    ])
    t0 = time.time(); clf.fit(Xtr, ytr); train_t = time.time() - t0
    t0 = time.time(); yp = clf.predict(Xte); score = get_scores(clf, Xte)
    infer_t = time.time() - t0
    benign_mask = (yte==0); mal_mask = (yte==1)
    try: auc = float(roc_auc_score(yte, score))
    except Exception: auc = float('nan')
    return {
        'tag': tag, 'n_train': len(Xtr), 'n_test': len(Xte),
        'n_pos_train': int((ytr==1).sum()), 'n_neg_train': int((ytr==0).sum()),
        'n_pos_test':  int((yte==1).sum()), 'n_neg_test':  int((yte==0).sum()),
        'acc':         float(accuracy_score(yte, yp)),
        'prec':        float(precision_score(yte, yp, zero_division=0)),
        'recall':      float(recall_score(yte, yp, zero_division=0)),
        'f1':          float(f1_score(yte, yp, zero_division=0)),
        'roc_auc':     auc,
        'acc_on_benign_test':    float(accuracy_score(yte[benign_mask], yp[benign_mask])),
        'acc_on_malicious_test': float(accuracy_score(yte[mal_mask],    yp[mal_mask])),
        'train_time_s': float(train_t), 'infer_time_s': float(infer_t),
        'confusion': confusion_matrix(yte, yp).tolist(),
    }

def run_baseline(X, y, tag='baseline_random_split'):
    idx = np.arange(len(y))
    tr_idx, te_idx = train_test_split(idx, test_size=TEST_SIZE, random_state=RNG, stratify=y)
    return train_eval(X[tr_idx], y[tr_idx], X[te_idx], y[te_idx], tag)

def run_zeroday(X, y, meta, tag, heldout_query):
    held_mask = meta.query(heldout_query).index.values
    if len(held_mask) == 0: return None
    held_set = set(held_mask.tolist())
    benign_idx = meta.index[meta['Label']==0].tolist()
    mal_idx = meta.index[meta['Label']==1].tolist()
    ben_tr, ben_te = train_test_split(benign_idx, test_size=TEST_SIZE, random_state=RNG)
    mal_tr = [i for i in mal_idx if i not in held_set]
    mal_te = list(held_set)
    if not mal_tr or not mal_te: return None
    n = min(len(ben_te), len(mal_te))
    if n < 50: return None
    te_idx = np.random.RandomState(RNG).choice(ben_te, n, replace=False).tolist() + \
             np.random.RandomState(RNG).choice(mal_te, n, replace=False).tolist()
    tr_idx = ben_tr + mal_tr
    return train_eval(X[tr_idx], y[tr_idx], X[te_idx], y[te_idx], tag)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--series', default='data/article/article_series.csv')
    ap.add_argument('--out', default='results/rf_zeroday')
    ap.add_argument('--tsfresh-mode', choices=['minimal','efficient'], default='efficient')
    ap.add_argument('--max-bursts', type=int, default=27000,
                    help='cap total de bursts (27k fiel ao artigo; 5k rapido)')
    ap.add_argument('--suffix', default='')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    df = load_series(args.series)
    print(f"loaded {len(df)} bursts | pos={int((df['Label']==1).sum())} neg={int((df['Label']==0).sum())}")
    print(f"attack_family: {df['attack_family'].value_counts().to_dict()}")

    df_long, meta = expand_to_long(df, args.max_bursts)
    feats = extract_tsfresh(df_long, args.tsfresh_mode)

    # manter só features não-NaN
    feats = feats.fillna(0)
    X = feats.values.astype(np.float32)
    y = meta['Label'].values
    print(f"[READY] X={X.shape} y={y.shape}")

    results = [run_baseline(X, y)]

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
        r = run_zeroday(X, y, meta, tag, q)
        if r: results.append(r)

    out = pd.DataFrame(results)
    out['delta_acc_vs_baseline']     = out['acc'] - out['acc'].iloc[0]
    out['delta_acc_mal_vs_baseline'] = out['acc_on_malicious_test'] - out['acc_on_malicious_test'].iloc[0]
    out.to_csv(os.path.join(args.out, f'artigo_tsfresh_results{args.suffix}.csv'), index=False)
    with open(os.path.join(args.out, f'artigo_tsfresh_results{args.suffix}.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print("\n=== SUMMARY ===")
    cols = ['tag','n_train','n_test','acc','f1','roc_auc',
            'acc_on_malicious_test','delta_acc_vs_baseline','train_time_s']
    print(out[cols].to_string(index=False))

if __name__ == '__main__':
    main()
