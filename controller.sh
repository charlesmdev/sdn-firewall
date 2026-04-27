#!/bin/bash
set -euxo pipefail

exec > /tmp/controller-setup.log 2>&1

echo "Updating package list..."
sudo apt-get update

echo "Installing dependencies..."
sudo apt-get install -y \
    gcc \
    git \
    python3-pip \
    python3-venv \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev

echo "Move to /local..."
cd /local

echo "Cloning Ryu repository..."
if [ ! -d "ryu" ]; then
    git clone https://github.com/osrg/ryu.git
else
    echo "Ryu repo already exists, skipping clone."
fi

echo "Creating Python virtual environment..."
python3 -m venv /local/ryu-venv
source /local/ryu-venv/bin/activate

echo "Upgrading pip..."
python -m pip install --upgrade pip setuptools wheel

echo "Installing Ryu..."
cd /local/ryu
python -m pip install .

echo "Verifying installation..."
python -c "import ryu; print(ryu.__file__)"
which ryu-manager || true

echo "Ryu installation complete!"
