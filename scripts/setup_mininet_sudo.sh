#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUDOERS_FILE="/etc/sudoers.d/sdn-firewall-mininet"

if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required for Mininet/Open vSwitch setup." >&2
    exit 1
fi

sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch iproute2 iputils-ping curl
sudo systemctl enable --now openvswitch-switch

TMP_FILE="$(mktemp)"
cat > "$TMP_FILE" <<EOF
# Allow the SDN firewall testbench to run Mininet/Open vSwitch commands without
# an interactive password prompt. This is intentionally scoped to local SDN lab
# commands and can be removed with:
#   sudo trash $SUDOERS_FILE
kartik ALL=(root) NOPASSWD: /usr/bin/mn, /usr/bin/mn *, /usr/bin/python3 $ROOT_DIR/firewall/topology.py, /usr/bin/python3 $ROOT_DIR/firewall/topology.py *, /usr/bin/python3 $ROOT_DIR/firewall/topology_multi.py, /usr/bin/python3 $ROOT_DIR/firewall/topology_multi.py *, /usr/bin/ovs-vsctl, /usr/bin/ovs-vsctl *, /usr/bin/systemctl start openvswitch-switch, /usr/bin/systemctl status openvswitch-switch, /usr/bin/systemctl is-active openvswitch-switch
EOF

sudo install -o root -g root -m 0440 "$TMP_FILE" "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE"
trash "$TMP_FILE"

sudo -n mn --version
sudo -n ovs-vsctl --version | sed -n '1,2p'
echo "Mininet/Open vSwitch setup complete. Non-interactive sudo is configured for project test commands."
