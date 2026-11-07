# Limitações da adaptação ao IoT-23

## Contexto

O pipeline do artigo (Tekiner et al., NDSS 2022) foi reproduzido com sucesso nos
datasets originais (Benign-1, Benign-2, Imbalanced, Transferability). Para o novo
dataset (IoT-23), foi necessário adaptar o pipeline devido à diferença de
granularidade dos dados disponíveis.

## Diferenças entre o artigo e a adaptação

| Etapa | Artigo | Adaptação (IoT-23 small) |
| :--- | :--- | :--- |
| Unidade de dados | Pacote individual (`packet length`) | Fluxo agregado (`orig_ip_bytes / orig_pkts`) |
| Filtro por dispositivo | MAC address | Não filtra (Capture 34-1 tem 1 dispositivo) |
| Janela (burst) | 10 pacotes consecutivos | 10 fluxos consecutivos |
| Extração de features | `tsfresh` (160 FCs → ~783 features) | `tsfresh` (mesmo conjunto) |
| Classificador | `SVC()` default | `SVC(class_weight='balanced')` |
| Validação | `KFold` cv=5 | `StratifiedKFold` cv=5 |
| Label | Por burst | Maioria dos fluxos no burst |

## Por que não é 100% fiel

1. **Pacotes vs. fluxos.** A versão `small` do IoT-23 fornece apenas fluxos
   agregados (`conn.log.labeled`), não pacotes individuais. Os `.pcap` brutos
   (com pacotes) estão na versão `full` (21 GB), não utilizada.
2. **Burst de 10 pacotes vs. 10 fluxos.** Como não há pacotes individuais, o
   burst de 10 pacotes do artigo foi adaptado para um burst de 10 fluxos.
3. **Desbalanceamento extremo.** O IoT-23 tem ~8% benign e ~92% malicious.
   Adicionamos `class_weight='balanced'` ao SVM (o artigo usa default).
4. **`StratifiedKFold` em vez de `KFold`.** O artigo usa `KFold` não
   estratificado. Com 8% benign, um fold pode ter poucas ou zero amostras
   benignas. `StratifiedKFold` garante a proporção em cada fold (não altera a
   lógica de 5-fold).

## O que é preservado

- `tsfresh` com o mesmo conjunto de feature calculators (160 FCs → ~783 features)
- SVM com kernel RBF
- Validação cruzada 5-fold
- Split holdout 80/20
- Métricas: accuracy, precision, recall, F1, ROC-AUC

## Interpretação dos resultados

Os resultados no IoT-23 devem ser interpretados como uma avaliação de
**generalização** do detector para outros malwares IoT (Mirai, Trojan, Gafgyt),
e **não** como uma replicação exata do artigo. A adaptação preserva a ideia
geral (bursts → tsfresh → SVM → CV 5-fold), mas as diferenças acima devem ser
consideradas na comparação com os resultados originais.
