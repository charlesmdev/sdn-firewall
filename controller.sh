#!/bin/sh

# Exit immediately if a command fails
set -eux

# Log output
exec > /tmp/controller-setup.log 2>&1

echo "Updating package list..."
sudo apt update
sudo apt upgrade -y

echo "Installing dependencies..."
sudo apt install -y \
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

echo "Moving to /local..."
cd /local

echo "Cloning Ryu repository..."
if [ ! -d "/local/ryu" ]; then
    sudo git clone https://github.com/osrg/ryu.git
else
    echo "Ryu repository already exists, skipping clone."
fi

echo "Creating Python virtual environment..."
if [ ! -d "/local/ryu-venv" ]; then
    python3 -m venv /local/ryu-venv
fi

# Activate venv
. /local/ryu-venv/bin/activate

echo "Upgrading pip tools..."
python -m pip install --upgrade pip setuptools wheel

echo "Installing Ryu..."
cd /local/ryu
python -m pip install .

echo "Verifying Ryu installation..."
python -c "import ryu; print(ryu.__file__)"

if command -v ryu-manager >/dev/null 2>&1; then
    echo "ryu-manager installed successfully:"
    which ryu-manager
else
    echo "WARNING: ryu-manager not found in PATH"
fi

echo "Ryu installation complete!"
