"""
Treina o pipeline no CSV combinado (Benign + Cryptojacking).
- CV: StratifiedGroupKFold (respeita grupos e balanceia classes)
- Holdout: GroupShuffleSplit (sem leakage)
"""
import sys
import pandas as pd
import numpy as np
from tsfresh import extract_features
from tsfresh.utilities.dataframe_functions import impute
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import cross_validate, StratifiedGroupKFold, GroupShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

MAX_BURSTS = 20000

def main(csv_path):
    df = pd.read_csv(csv_path)
    print(f"CSV: {csv_path} ({len(df)} pacotes, {df['id'].nunique()} bursts)")
    print(f"Classes: {df['Label'].value_counts().to_dict()}")

    # device (para grupos)
    df['device'] = df['id'].str.rsplit('_', n=1).str[0]
    labels_per_burst = df.groupby('id')['Label'].agg(lambda x: x.value_counts().index[0])
    print(f"Bursts por classe: {labels_per_burst.value_counts().to_dict()}")

    # subamostra balanceado
    n_per_class = MAX_BURSTS // 2
    benign = labels_per_burst[labels_per_burst == 'Benign'].index
    cj = labels_per_burst[labels_per_burst == 'Cryptojacking'].index
    rng = np.random.RandomState(90210)
    sampled = np.concatenate([
        rng.choice(benign, min(n_per_class, len(benign)), replace=False),
        rng.choice(cj, min(n_per_class, len(cj)), replace=False),
    ])
    df = df[df['id'].isin(sampled)].copy()
    print(f"Subamostrado: {len(sampled)} bursts")

    # features
    df = df.rename(columns={'Timestamp': 'time', 'Packet Length': 'value'})
    print("Extraindo features com tsfresh...")
    X = extract_features(df[['id', 'time', 'value']], column_id='id', column_sort='time',
                         impute_function=impute, disable_progressbar=False)
    print(f"Features: {X.shape}")

    y = labels_per_burst.loc[X.index].map({'Cryptojacking': 1, 'Benign': 0}).values
    groups = df.groupby('id')['device'].first().loc[X.index].values
    print(f"Distribuicao y: {pd.Series(y).value_counts().to_dict()}")
    print(f"Grupos (devices): {len(set(groups))}")

    # CV: StratifiedGroupKFold
    print("\nValidacao cruzada (StratifiedGroupKFold, cv=5)...")
    clf = make_pipeline(StandardScaler(), SVC(class_weight='balanced', random_state=90210))
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=90210)
    cv_results = cross_validate(clf, X.values, y, cv=sgkf, groups=groups,
        scoring=['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc'],
        return_train_score=False, n_jobs=-1)
    for m in ['test_accuracy', 'test_precision_weighted', 'test_recall_weighted', 'test_f1_weighted', 'test_roc_auc']:
        print(f"{m}: {cv_results[m].mean():.4f} (+/- {cv_results[m].std():.4f})")

    # Holdout: split manual estratificado por grupo (garante as duas classes)
    unique_groups = np.array(sorted(set(groups)))
    benign_groups = [g for g in unique_groups if g.startswith('benign_')]
    cj_groups = [g for g in unique_groups if g.startswith('cj_')]
    rng2 = np.random.RandomState(90210)
    test_benign = set(rng2.choice(benign_groups, min(2, len(benign_groups)), replace=False))
    test_cj = set(rng2.choice(cj_groups, min(15, len(cj_groups)), replace=False))
    test_groups = test_benign | test_cj
    test_mask = np.array([g in test_groups for g in groups])
    X_train, X_test = X.values[~test_mask], X.values[test_mask]
    y_train, y_test = y[~test_mask], y[test_mask]
    print(f"Split manual: {len(test_benign)} devices benignos + {len(test_cj)} pcaps CJ no teste")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(f"\nHoldout (20%) - Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Cryptojacking'], zero_division=0))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

if __name__ == '__main__':
    main(sys.argv[1])
