# CIN0114 - Técnicas de ataque e detecção de intrusão

Reprodução do artigo: Tekiner et al., "A Lightweight IoT Cryptojacking Detection Mechanism
in Heterogeneous Smart Home Networks" (NDSS 2022).

## Estrutura

- `Code/` — scripts Python (convertidos dos notebooks oficiais)
- `slurm/` — scripts SLURM para submissão no cluster Apuana
- `results/` — resultados numéricos (acurácias, mapeamento)

## Reprodução x Melhoria

### Reprodução fiel (Benign-1)
- `Malicious_vs_Benign_1 (All Scenarios).py`: código original do artigo, sem `n_jobs`.
- Executado no job `18973` (long-complex, 48 CPUs).
- Resultado: `results/s0_full.out` (13 cenários × 4 modelos).

### Melhoria de eficiência (Benign-2 em diante)
- `Malicious_vs_Benign_2 (All Scenarios).py`: adicionamos `n_jobs=-1` no `cross_validate`.
- **Acurácia idêntica** (paralelização dos folds, não mudança de cálculo).
- Tempo: ~7h → ~1h por cenário.
- Backup original: `*.pre_njobs.py` (ignorado pelo Git).

## Documentação adicional

- [`docs/limitacoes-iot23.md`](docs/limitacoes-iot23.md) — limitações da adaptação ao IoT-23
