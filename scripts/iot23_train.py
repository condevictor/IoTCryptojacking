"""
Treina o pipeline do artigo (tsfresh + SVM) no CSV adaptado do IoT-23.
- Reproduz o artigo: quebra a sequencia de fluxos em BURSTS DE 10
- Cada burst = 1 amostra (id = burst index)
- Label = maioria dos fluxos no burst (Benign/Malicious)
- Validacao: StratifiedKFold cv=5 (em vez de KFold, por causa do desbalanceamento)
Uso: python iot23_train.py <csv_adaptado>
"""
import sys
import pandas as pd
import numpy as np
from tsfresh import extract_features
from tsfresh.utilities.dataframe_functions import impute
from sklearn.svm import SVC
from sklearn.model_selection import cross_validate, StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

BURST_SIZE = 10  # igual ao artigo

def main(csv_path):
    df = pd.read_csv(csv_path)
    print(f"CSV: {csv_path} ({len(df)} linhas)")
    print(f"Classes: {df['Label'].value_counts().to_dict()}")

    # ordena por timestamp (a sequencia de fluxos do dispositivo)
    df = df.sort_values('Timestamp').reset_index(drop=True)

    # cria bursts de 10 fluxos consecutivos
    df['burst_id'] = df.index // BURST_SIZE
    print(f"Bursts de {BURST_SIZE} fluxos: {df['burst_id'].nunique()}")

    # label por burst (majoritario)
    labels_per_burst = df.groupby('burst_id')['Label'].agg(
        lambda x: x.value_counts().index[0]
    )
    print(f"Labels por burst: {labels_per_burst.value_counts().to_dict()}")

    # tsfresh espera: id, time, value
    df = df.rename(columns={'Timestamp': 'time', 'Packet Length': 'value'})
    df['id'] = df['burst_id']

    print("\nExtraindo features com tsfresh...")
    X = extract_features(
        df[['id', 'time', 'value']],
        column_id='id', column_sort='time',
        impute_function=impute,
        disable_progressbar=False
    )
    print(f"Features: {X.shape} (amostras x features)")

    # alinha labels com as linhas de X
    y = labels_per_burst.loc[X.index].map({'Malicious': 1, 'Benign': 0}).values
    print(f"Distribuicao y: {pd.Series(y).value_counts().to_dict()}")

    if len(X) < 10:
        print("\nAVISO: menos de 10 amostras.")
        return

    # validacao cruzada estratificada (cv=5)
    print("\nValidacao cruzada (StratifiedKFold, cv=5)...")
    clf = SVC(class_weight='balanced', random_state=90210)
    n_splits = min(5, len(X) // 2)
    skfold = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=90210)
    cv_results = cross_validate(
        clf, X.values, y, cv=skfold,
        scoring=['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc'],
        return_train_score=False
    )
    for metric in ['test_accuracy', 'test_precision_weighted', 'test_recall_weighted',
                   'test_f1_weighted', 'test_roc_auc']:
        print(f"{metric}: {cv_results[metric].mean():.4f} (+/- {cv_results[metric].std():.4f})")

    # holdout 80/20 (estratificado)
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=0.2, random_state=90210, stratify=y
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(f"\nHoldout (20%) - Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'], zero_division=0))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

if __name__ == '__main__':
    main(sys.argv[1])
