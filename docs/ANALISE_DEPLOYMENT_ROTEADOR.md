# Análise de deployment: RF vs SVM — Cenário A vs Cenário B

Data: 18/11/2026 (corrigido)
Baseado em: job 32143 (RF vs SVM, 10k balanceado) + job 32137 (curva do bug)

## ⚠️ Correção importante (vs versão anterior deste documento)

A versão anterior afirmava "SVM é inviável em roteador doméstico" sem
distinguir DOIS cenários de deployment radicalmente diferentes. O paper
de referência (Tekiner et al., NDSS 2022) usa o **Cenário B** (máquina
acoplada ao router), NÃO o Cenário A (modelo no firmware do router).

Releitura do paper:
- Page 2: "network traffic-based features can be collected in a unified
  interface on the router" → observação do tráfego, não inferência
- Page 5, Topology: "There is also another computer in the network
  dedicated to collecting all the Internet traffic with port mirroring
  and ARP rerouting/poisoning techniques"
- Page 5, Table I: o router é um TP-Link Archer C7 v5 (Atheros QCA9563,
  OpenWRT), usado só para rotear — a coleta e classificação acontecem
  em uma máquina dedicada

Portanto: o setup do paper é **máquina acoplada**, não **modelo no router**.

## Cenário A — Modelo no firmware do router (Atheros QCA9563, 128 MB)

| Dimensão | Realidade |
|---|---|
| Hardware | MIPS 750 MHz, 128 MB RAM, OpenWRT |
| Runtime Python/sklearn | Inviável — precisa exportar para C |
| RF podado (50 árvores, prof 15) | Viável (~300-400 KB compilado, 0,8-13 us/amostra) |
| SVM RBF (885-1805 SVs) | Inviável (kernel RBF em C é raro; 0,5-5 ms/amostra) |
| FPR baixo importa | Sim — usuário doméstico não faz triagem |
| **Modelo recomendado** | **RF com poda + m2cgen para C** |

## Cenário B — Modelo em máquina acoplada (setup do paper)

| Dimensão | Realidade |
|---|---|
| Hardware | Raspberry Pi 4, mini-PC, NUC (Linux) |
| Runtime Python/sklearn | Viável — sklearn roda nativo |
| RF cheio (200 árvores) | Viável (~20 us/amostra em Pi 4) |
| SVM RBF (885-1805 SVs) | Viável (~400-1000 us/amostra em Pi 4) |
| Throughput necessário (rede doméstica) | 5-50 bursts/s — ambos atendem |
| FPR baixo importa | Sim, mitigado por agregação por device |
| **Modelo recomendado** | **RF** (menor FPR, mais rápido, sem perda significativa) |

## Comparação honesta: em que cada modelo ganha

| Dimensão | RF (proposto) | SVM (artigo) | Vencedor | Por quê importa |
|---|---|---|---|---|
| Acurácia 0-day (média) | 91,7% | **95,8%** | SVM (+4,2 pp) | Detecção pura |
| Acurácia 0-day (pior caso) | 79,4% (AntMining) | **86,8% (Webmine)** | SVM | Webmine é o caso mais difícil |
| Baseline in-distribution | **99,37%** | 99,37% | Empate | Reprodutibilidade do 99% |
| FPR (MinerGate held-out) | **1,13%** | 3,06% | **RF (3x menor)** | Menos falsos alarmes |
| FNR por burst (MinerGate) | 4,31% | **0,06%** | SVM | Detecção por burst |
| FNR por sessão de mineração | ~100% | ~100% | Empate | Mineração é contínua |
| Inferência (µs/amostra) | **1,4-1,6** | 48-113 | **RF (30-80x)** | Throughput de produção |
| Modelo (tamanho) | **~19 MB (cheio) / ~25 KB (podado)** | ~60-120 KB | **RF podado** | Cabe no router |
| Treino em 10k | 1,9 s | 0,8 s | SVM (marginal) | Irrelevante |
| Treino em 100k+ | **~30-60 s** | 1-2 h | **RF (escala)** | Viabilidade |
| Deployável em router (Cenário A) | **Sim (com poda)** | Não | **RF** | Único viável |
| Deployável em Pi 4 (Cenário B) | **Sim** | Sim | Empate | Ambos cabem |

## Conclusão para o paper

**Cenário B (setup do paper):** RF e SVM são viáveis em máquina acoplada
(Raspberry Pi 4 ou superior). O SVM é 4,2 pp mais preciso em 0-day, mas
o RF tem **3x menos falsos positivos** (1,13% vs 3,06%) e é **30-80x
mais rápido** em inferência. Para deploy em escala com orçamento de
hardware restrito, o RF é preferível; para análise forense ou threat
hunting, o SVM é preferível.

**Cenário A (modelo no router):** apenas RF com poda é viável. O SVM
não é deployável em firmware de router doméstico (kernel RBF sem
implementação C eficiente). Nesse cenário, a pergunta "RF ou SVM?" não
existe — a escolha é "RF podado ou nada".

**Narrativa honesta:** o RF proposto **não é mais preciso** que o SVM.
Ele é **mais eficiente operacionalmente** (FPR, throughput, tamanho do
modelo) e **deployável em cenários onde o SVM não cabe**. Para detecção
pura de 0-day, o SVM do artigo está mais bem posicionado — e a escolha
do artigo é defensável.

## Referências internas
- Job 32143: ../../results/rf_vs_svm/rf_vs_svm_zeroday.csv
- Job 32137 (curva do bug): ../../results/rf_zeroday/ERRATUM.txt
- RF podado (se rodado): ../../results/rf_pruned/rf_pruned_results.csv

## ⚠️ Correção: tamanho real do modelo exportado (m2cgen)

Medição feita em 18/11/2026:
  Pickle (sklearn):  1.235,6 KB
  C source (m2cgen): 1.952,6 KB
  C compilado MIPS:  ~280-440 KB (estimativa baseada em ~20 bytes/nó)

O modelo NÃO cabe em "~25 KB" como afirmado em versões anteriores.
Cabe em ~300-400 KB compilado, o que ainda é VIÁVEL no Archer C7 v5
(16 MB flash, ~4-8 MB livres após OpenWRT), mas ocupa ~5% do flash
disponível — não é "tiny".

Para deployment ainda menor, reduzir para 25 árvores / prof 10
(estimativa: ~140 KB compilado, perda de acurácia a medir) ou
15 árvores / prof 8 (~60 KB, perda maior).
