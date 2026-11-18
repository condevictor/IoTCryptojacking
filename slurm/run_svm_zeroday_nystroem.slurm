#!/bin/bash
#SBATCH --job-name=svm_zd_nys
#SBATCH --partition=short-simple
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=logs/svm_zd_nys_%j.out
#SBATCH --error=logs/svm_zd_nys_%j.err

set -e
cd /home/CIN/vddc/cryptojacking
source ~/venv-cryptojacking/bin/activate
mkdir -p logs results/rf_zeroday
python3 code/artigo/Code/zeroday_svm.py \
  --csv data/article/article_combined.csv \
  --out results/rf_zeroday \
  --mode rbf_nystroem --C 1.0 --max-per-class 500000 --max-iter 5000 \
  --n-components 300 --suffix _rbf_nys_500k
echo "=== DONE ==="
