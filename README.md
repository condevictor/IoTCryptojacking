# Detecção Leve de Cryptojacking em Redes IoT

**Reprodução do detector de Tekiner et al. (NDSS 2022) e uma versão
ainda mais leve para rodar no roteador doméstico.**

Autores: Victor Conde, Leonardo Brahim, João Victor Nobre, João Pedro Marinho
Disciplina: CIN0114 — Técnicas de Ataque e Detecção de Intrusão (UFPE, 2026)
Relatório completo: [`relatorio_final.pdf`](./relatorio_final.pdf)

---

## O que este repositório faz

O artigo de referência (Tekiner et al., NDSS 2022) propõe um detector
de cryptojacking baseado apenas em tráfego de rede, com 788 features
extraídas via `tsfresh` e classificador SVM. O pipeline atinge 99% de
acurácia, mas custa ~7h30 de processamento por dataset e exige uma
máquina dedicada ao lado do roteador.

Este trabalho:

1. **Reproduz** o artigo rodando o código original e refaz as tabelas
   com nossos próprios números (Tabelas II–VII do relatório).
2. **Avalia** o detector original em um conjunto novo (Benign-1 +
   CJ-Sniffer), com validação agrupada por dispositivo para evitar
   vazamento (Tabela IX).
3. **Propõe** uma versão enxuta: 17 features NumPy no lugar das 788
   do tsfresh, e Random Forest podada (50 árvores, prof. 15) exportável
   para C via `m2cgen`, que **cabe no firmware de um roteador comum**
   (Archer C7 v5: MIPS 750 MHz, 128 MB RAM, 16 MB flash).
4. **Compara honestamente** RF vs SVM sob um protocolo *zero-day* com
   8 experimentos (deixando de fora uma família, um dispositivo ou
   um throttle por vez — Tabela XI do relatório).
5. **Documenta** um bug de balanceamento na primeira versão do
   experimento (`results/rf_zeroday/ERRATUM.txt`), que inflava a queda
   da RF em ~40 p.p., e o corrige.

---

## Resultado principal

| Modelo | Acc baseline | Acc zero-day (média) | FPR | Inferência | Tamanho (deploy) |
|---|---|---|---|---|---|
| SVM RBF (17 car.) | 99,4% | **96,2%** | 3,06% | 48–113 µs | ~60–120 KB |
| RF cheia (200 árv.) | 99,4% | 91,7% | 1,13% | 1,41–1,55 µs | ~19 MB |
| **RF podada (50 árv.)** | **99,4%** | 91,7% | **1,18%** | **0,80–1,25 µs** | **~400 KB (C)** |

**Interpretação:** o SVM com as mesmas 17 características é 4,1–4,5 p.p. mais robusto no
zero-day; a RF podada tem **2,6× menos falsos positivos** e é
**40–140× mais rápida**, além de caber em firmware (~400 KB contra
~19 MB da RF cheia). O trade-off é acurácia por viabilidade de
deployment.

---

## Estrutura do repositório
```
.
├── Code/
│ ├── compare_rf_vs_svm_zeroday.py # Job 32143: RF cheia vs SVM, 8 holdouts
│ ├── rf_pruned_zeroday.py # Job 32143: RF podada, 8 holdouts
│ ├── zeroday_rf.py # Job 32091: RF original (com bug de balanceamento)
│ ├── rf_osr_zeroday.py # Protótipo OSR (não rodado em produção)
│ ├── zeroday_artigo_tsfresh.py # Protótipo tsfresh (referência)
│ ├── build_article_dataset.py # Extrator de features NumPy
│ └── *.py / *.ipynb # Reprodução fiel do artigo (Benign-1, Benign-2, S10)
├── Data/ # Placeholder para dataset (não versionado, ~200 MB)
├── results/
│ ├── rf_vs_svm/ # RF cheia vs SVM — CSVs e logs do job 32143
│ ├── rf_pruned/ # RF podada — CSVs do job 32143
│ ├── rf_zeroday/ # RF original (job 32091) + ERRATUM do bug
│ └── _archive/ # Experimentos inválidos (ver README interno)
├── docs/
│ ├── ANALISE_DEPLOYMENT_ROTEADOR.md # Cenário A (router) vs Cenário B (acoplado)
│ ├── PROXIMOS_PASSOS.md # Prioridades para o próximo ciclo
│ └── limitacoes-iot23.md # Limitações da adaptação ao IoT-23
├── scripts/ # Utilitários auxiliares
├── slurm/ # SLURM scripts para o cluster Apuana
├── relatorio_final.pdf # Relatório final (TADI CIN0114)
├── README.md # Este arquivo
└── LICENSE
```
---

## Como reproduzir

### Pré-requisitos

- Python 3.10+
- `pip install pandas scikit-learn numpy m2cgen`
- Dataset: baixar de [cslfiu/IoTCryptojacking](https://github.com/cslfiu/IoTCryptojacking)
  e colocar em `../data/article/article_combined.csv` (~200 MB, não versionado)

### Rodar a comparação RF vs SVM (job 32143)

```bash
python3 Code/compare_rf_vs_svm_zeroday.py \
    --csv ../data/article/article_combined.csv \
    --out ../results/rf_vs_svm
```

Tempo: ~45 min em 16 cores (SVM RBF é O(n²); usamos 10k amostras/classe).

### Rodar a RF podada (job 32143)

```bash
python3 Code/rf_pruned_zeroday.py \
    --csv ../data/article/article_combined.csv \
    --out ../results/rf_pruned
```

Tempo: ~3 min (50 árvores × 10k/classe × 9 fits).

### Exportar o modelo para C (deployment em roteador)

```python
from sklearn.ensemble import RandomForestClassifier
import m2cgen as m2c

clf = RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1,
                             random_state=90210, class_weight='balanced_subsample')
clf.fit(X_train, y_train)
open('rf_pruned_model.c', 'w').write(m2c.export_to_c(clf))
# C source: ~1,9 MB | compilado MIPS: ~400 KB
# Cabe em flash de 16 MB (Archer C7 v5) ocupando ~2,5%
```

---

## Ameaças à validade (resumo)

Documentadas em detalhe no relatório (Seção VIII) e no
`results/rf_zeroday/ERRATUM.txt`:

1. **Bug de balanceamento (corrigido):** `subsample_balanced` não
   garantia 1:1 quando a classe maliciosa tinha menos amostras que
   `MAX_PER_CLASS`. O gap de 44 p.p. do RF no MinerGate era artefato
   disso; corrigido, o gap real é de ~4,1 p.p. no zero-day.

2. **Nystroem inválido (arquivado):** a aproximação Nystroem do SVM
   RBF colapsou para uma classe em 7/9 holdouts. Arquivado em
   `results/_archive/INVALID_*`.

3. **AntMining ≡ WebOS e MinerGate ≈ Server:** os dois pares usam os
   mesmos dados de origem (respectivamente WebOS_binary.csv e Server
   como 99,96% do MinerGate), então não são experimentos independentes.
   Efetivamente são 8 holdouts únicos.

4. **Benigno sem atribuição de device:** o Benign-1 é público e não
   tem dispositivo por burst. O "zero-day por device" testa detecção
   de dispositivo desconhecido, não ataque em dispositivo conhecido.

---

## Citação

```bibtex
@inproceedings{tekiner2022lightweight,
  title={A Lightweight IoT Cryptojacking Detection Mechanism in
         Heterogeneous Smart Home Networks},
  author={Tekiner, Ege and Acar, Abbas and Uluagac, A. Selcuk},
  booktitle={Network and Distributed Systems Security (NDSS) Symposium},
  year={2022}
}
```
