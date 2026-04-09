#!/bin/bash

# Exit on error
set -e

echo "Updating package list..."
sudo apt-get update

echo "Installing dependencies..."
sudo apt-get install -y gcc python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
sudo apt-get install -y python3-pip git

echo "Cloning Ryu repository..."
if [ ! -d "ryu" ]; then
    git clone https://github.com/osrg/ryu.git
else
    echo "Ryu repo already exists, skipping clone."
fi

echo "Installing Ryu..."
cd ryu
pip3 install -r tools/pip-requires
python3 setup.py install

echo "Ryu installation complete!"
