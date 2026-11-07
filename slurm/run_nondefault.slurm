#!/bin/bash
#SBATCH --job-name=crypto_nondefault
#SBATCH --partition=long-complex
#SBATCH --cpus-per-task=48
#SBATCH --mem=64G
#SBATCH --time=7-00:00:00
#SBATCH --output=/home/CIN/vddc/cryptojacking/logs/nondefault_%j.out
#SBATCH --error=/home/CIN/vddc/cryptojacking/logs/nondefault_%j.err

set -e
export USER=vddc LOGNAME=vddc HOME=/home/CIN/vddc
source /etc/profile.d/z00_lmod.sh
module load Python/3.9.6-GCCcore-12.2.0
source $HOME/venv-cryptojacking/bin/activate

cd $HOME/cryptojacking/code/artigo/Code
python -u "Non-default parameters.py"
