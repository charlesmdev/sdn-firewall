#!/bin/bash
set -euxo pipefail

exec > /tmp/controller-setup.log 2>&1

echo "Updating package list..."
sudo apt-get update

echo "Installing system dependencies..."
sudo apt-get install -y \
    gcc \
    git \
    curl \
    python3-pip \
    python3-venv \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev

echo "Creating Python virtual environment..."
if [ ! -d /local/ryu-venv ]; then
    python3 -m venv /local/ryu-venv
fi

source /local/ryu-venv/bin/activate

echo "Installing Python build tools compatible with Ryu..."
python -m ensurepip --upgrade
python -m pip install --upgrade "pip<24" "setuptools<58" "wheel<0.38"

echo "Installing Ryu..."
python -m pip install --no-build-isolation ryu==4.34

echo "Fixing Ryu/Eventlet compatibility for Python 3.10..."
python -m pip install "eventlet==0.33.3" "dnspython>=2.2,<2.3"

echo "Patching Ryu WSGI ALREADY_HANDLED issue..."
RYU_WSGI=$(python -c "import ryu, os; print(os.path.join(os.path.dirname(ryu.__file__), 'app', 'wsgi.py'))")
sed -i "s/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = object()/g" "$RYU_WSGI"

echo "Verifying Ryu installation..."
ryu-manager --version || true

echo "Controller setup complete!"
echo "To start the Ryu firewall controller:"
echo "source /local/ryu-venv/bin/activate"
echo "cd /local/repository/firewall"
echo "ryu-manager firewall_rest_api.py"