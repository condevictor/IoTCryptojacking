#!/bin/bash
#SBATCH --job-name=rf_zd_v2
#SBATCH --partition=short-simple
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=logs/rf_zd_v2_%j.out
#SBATCH --error=logs/rf_zd_v2_%j.err

set -e
cd /home/CIN/vddc/cryptojacking
source ~/venv-cryptojacking/bin/activate
python3 -c "import pandas, sklearn, numpy; print('libs OK')"
mkdir -p logs results/rf_zeroday

CSV=data/article/article_combined.csv

echo "============================================================"
echo "[1/4] RF v1 (17 features originais, 500k) — reproduz job 32091"
echo "============================================================"
python3 code/artigo/Code/zeroday_rf_v2.py \
  --csv $CSV --out results/rf_zeroday \
  --augmentation none --suffix _v1_repro

echo ""
echo "============================================================"
echo "[2/4] RF v2a (28 features: 17 + 11 ratios, 500k)"
echo "============================================================"
python3 code/artigo/Code/zeroday_rf_v2.py \
  --csv $CSV --out results/rf_zeroday \
  --augmentation ratios --suffix _v2a

echo ""
echo "============================================================"
echo "[3/4] RF v2b (50 features: 16 base + 11 ratios x3, 500k)"
echo "============================================================"
python3 code/artigo/Code/zeroday_rf_v2.py \
  --csv $CSV --out results/rf_zeroday \
  --augmentation ratios_dup3 --suffix _v2b

echo ""
echo "============================================================"
echo "[4/4] RF v2b (50 features, 5k) — confirma smoke com 10 holdouts"
echo "============================================================"
python3 code/artigo/Code/zeroday_rf_v2.py \
  --csv $CSV --out results/rf_zeroday \
  --augmentation ratios_dup3 --max-per-class 5000 --suffix _v2b_5k

echo "=== DONE ==="
