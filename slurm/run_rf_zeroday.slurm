#!/bin/bash
#SBATCH --job-name=rf_zeroday
#SBATCH --partition=short-simple
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=04:00:00
#SBATCH --output=logs/rf_zeroday_%j.out
#SBATCH --error=logs/rf_zeroday_%j.err

set -e
cd /home/CIN/vddc/cryptojacking
source ~/venv-cryptojacking/bin/activate
python3 -c "import pandas, sklearn, numpy; print('libs OK')"
mkdir -p logs results/rf_zeroday
python3 code/artigo/Code/zeroday_rf.py \
  --csv data/article/article_combined.csv \
  --out results/rf_zeroday
echo "=== DONE ==="
