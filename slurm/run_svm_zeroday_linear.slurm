#!/bin/bash
#SBATCH --job-name=svm_zd_lin
#SBATCH --partition=short-simple
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32G
#SBATCH --time=08:00:00
#SBATCH --output=logs/svm_zd_lin_%j.out
#SBATCH --error=logs/svm_zd_lin_%j.err

set -e
cd /home/CIN/vddc/cryptojacking
source ~/venv-cryptojacking/bin/activate
mkdir -p logs results/rf_zeroday
python3 code/artigo/Code/zeroday_svm.py \
  --csv data/article/article_combined.csv \
  --out results/rf_zeroday \
  --mode linear --C 1.0 --max-per-class 500000 --max-iter 5000 \
  --suffix _linear_500k
echo "=== DONE ==="
