#!/bin/bash
#SBATCH --job-name=build_ds
#SBATCH --partition=short-simple
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=32G
#SBATCH --time=01:00:00
#SBATCH --output=logs/build_ds_%j.out
#SBATCH --error=logs/build_ds_%j.err

set -e
cd /home/CIN/vddc/cryptojacking
source ~/venv-cryptojacking/bin/activate
mkdir -p logs data/article
python3 build_article_dataset.py
echo "=== BUILD DONE ==="
