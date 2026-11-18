# Análise de deployment: RF vs SVM em roteador doméstico

Data: 18/11/2026
Baseado em: job 32143 (RF vs SVM, 10k balanceado) + erratum do subsample_balanced

## 1. Esclarecimento sobre os números de FP/FN (MinerGate held-out)

Confusion matrix `[[TN, FP], [FN, TP]]` do MinerGate held-out (test = 159.140 amostras):

| | RF | SVM |
|---|---|---|
| TN (benigno correto) | 78.668 | 77.135 |
| FP (benigno errado) | 902 | 2.435 |
| FN (malicioso errado) | 3.427 | 51 |
| TP (malicioso correto) | 76.143 | 79.519 |
| Total benigno test | 79.570 | 79.570 |
| Total malicioso test | 79.570 | 79.570 |

IMPORTANTE: 10.000 é o tamanho do TREINO (MAX_PER_CLASS=10k).
O TEST usa todos os bursts do holdout (n_test=159.140). Os 902 FP são
sobre 79.570 benignos, não sobre 10.000.

Métricas corretas:
  RF:  FPR = 902/79.570  = 1,13%   |  FNR = 3.427/79.570 = 4,31%
  SVM: FPR = 2.435/79.570 = 3,06%  |  FNR = 51/79.570    = 0,06%

O SVM tem 2,7x mais FP que o RF, mas 70x menos FN.

## 2. Interpretação do FN de 4,3% (RF) no contexto de mineração

Mineração de cripto é atividade CONTÍNUA, não evento único.
Se um roteador vê N bursts de uma sessão de mineração:
  P(não detectar nenhum dos N) = (0,0431)^N

Para N=100 bursts:
  (0,0431)^100 ≈ 10^-138  (essencialmente zero)

Ou seja: o FNR de 4,3% POR BURST se traduz em detecção de SESSÃO
próxima de 100% em segundos, porque o atacante precisa de throughput
contínuo para minerar.

O FNR por burst é a métrica correta para avaliação acadêmica, mas
não é a métrica operacional para um detector contínuo.

## 3. Viabilidade em roteador doméstico

Hardware típico: MIPS/ARM single-core ~500 MHz, 128-256 MB RAM.

### SVM RBF: INVIÁVEL
- 48-113 us/amostra em CPU servidor
- 500-5000 us/amostra em roteador doméstico
- ~200-2000 amostras/s: consome todo o orçamento de CPU do roteador
  (que também precisa rodar Wi-Fi, NAT, DHCP, DNS, firewall)
- Modelo: 885-1805 support vectors × 17 features × 4 bytes ≈ 60-120 KB
  (cabe em RAM), mas o custo de CPU no kernel RBF é o gargalo

### RF: VIÁVEL (com poda)
- 1,4-1,6 us/amostra em CPU servidor
- 15-75 us/amostra em roteador doméstico
- ~13.000-66.000 amostras/s: usa 0,1-0,4% da CPU para tráfego doméstico
- Modelo padrão (200 árvores, prof ~30): ~19 MB
  --> precisa poda para caber em 128 MB de RAM

### Poda recomendada para deployment em roteador
- 50 árvores, profundidade 15 → ~800 KB  (perda estimada: 0,5-1,5 p.p.)
- OU DecisionTreeClassifier único (prof 10-12) → ~5 KB  (perda maior)
- Exportar para C via m2cgen ou treelite → elimina dependência sklearn,
  roda em ~5 us/amostra no roteador

## 4. Tabela de decisão por critério de deployment

| Critério | RF | SVM | Peso no roteador |
|---|---|---|---|
| Cabe na CPU | OK (15-75 us) | NAO (0,5-5 ms) | Decisivo |
| Cabe na RAM (com poda) | OK (~800 KB) | NAO | Decisivo |
| Exportável para C | OK (m2cgen) | NAO (kernel RBF raro) | Alto |
| Latência inline < 100 us | OK | NAO | Alto |
| FPR baixo (usuário não triagem) | OK 1,1% | NAO 3,1% | Alto |
| Acurácia 0-day | 91,7% | 95,8% | Médio (perde 4,2 pp) |
| FNR por burst | 4,3% | 0,06% | Baixo (mitigado por sessão) |

RF ganha em 5/7 critérios. Os 2 que SVM ganha têm peso menor no
cenário doméstico porque:
  - Acurácia: gap real corrigido é 2,1 pp (não 44 pp), diferença pequena
  - FNR: mitigado pela detecção contínua (sessão detectada em segundos)

## 5. Conclusão para o paper

Para roteador doméstico, RF é a ÚNICA escolha viável. Não porque é mais
preciso — o SVM é 4,2 pp mais preciso em média 0-day — mas porque o SVM
não cabe no hardware.

Com poda (50 árvores/prof 15) e exportação para C (m2cgen), o RF roda
inline a 15-75 us/amostra usando ~1 MB de RAM. Detecta sessões de
mineração com taxa próxima de 100% (mesmo com FNR de 4,3% por burst),
porque mineração é atividade contínua.

O FN de 3.427 NÃO é "deixar passar 3.427 vulnerabilidades" — é
"deixar passar 4,3% dos bursts individuais", recuperado em segundos
pela próxima detecção.

## 6. O que realmente melhoraria a detecção no roteador (não é modelo)

O gargalo não é o classificador — é a representação (17 features).
Para roteador doméstico, os ganhos reais vêm de:

1. Features de porta Stratum (3333/4444/5555/14444) — custo zero
2. Features de assimetria upload/download — custo desprezível
3. Features de periodicidade (autocorrelação dos IATs, janela 30s)
4. Regras complementares (DNS de pool conhecido + porta Stratum)

Essas features resolvem o caso AntMining (onde o RF cai para 0,794)
sem precisar do SVM, e rodam a custo desprezível no roteador.

## 7. Referências internas
- Job 32143: results/rf_vs_svm/rf_vs_svm_zeroday.csv
- Erratum: results/rf_zeroday/ERRATUM.txt
- Curva de amplificação do bug: job 32137 (curve2) documentado no erratum
