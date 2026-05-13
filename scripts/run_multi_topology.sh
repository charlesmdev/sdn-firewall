#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo -n systemctl start openvswitch-switch
cd "$ROOT_DIR/firewall"
sudo -n python3 "$ROOT_DIR/firewall/topology_multi.py"
