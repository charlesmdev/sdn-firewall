#!/bin/bash
set -euxo pipefail

# Usage: bash host.sh <HOST_NUMBER> <SWITCH_IP>
# Example (on host1): bash host.sh 1 10.10.1.2
# Example (on host2): bash host.sh 2 10.10.2.2
# Virtual IPs: host1=192.168.100.2, host2=.3, host3=.4, host4=.5

HOST_NUM="${1:-}"
SWITCH_IP="${2:-}"

if [ -z "$HOST_NUM" ] || [ -z "$SWITCH_IP" ]; then
    echo "Usage: bash host.sh <HOST_NUMBER> <SWITCH_IP>"
    echo "Example: bash host.sh 1 172.17.245.6"
    exit 1
fi

VIRTUAL_IP="192.168.100.$((HOST_NUM + 1))"

exec > /tmp/host${HOST_NUM}-setup.log 2>&1

echo "Setting up host$HOST_NUM with virtual IP $VIRTUAL_IP..."
echo "Tunnel pointing to switch at $SWITCH_IP"

sudo apt-get update
sudo apt-get install -y openvswitch-switch
sudo systemctl start openvswitch-switch

echo "Setting up OVS bridge..."
sudo ovs-vsctl --if-exists del-br br0
sudo ovs-vsctl add-br br0

echo "Adding GRE tunnel to switch at $SWITCH_IP..."
sudo ovs-vsctl add-port br0 gre-switch \
    -- set interface gre-switch type=gre options:remote_ip=$SWITCH_IP

echo "Assigning virtual IP $VIRTUAL_IP..."
sudo ip addr del $VIRTUAL_IP/24 dev br0 2>/dev/null || true
sudo ip addr add $VIRTUAL_IP/24 dev br0
sudo ip link set br0 up

echo ""
echo "=============================="
sudo ovs-vsctl show
echo ""
ip addr show br0
echo "=============================="
echo "Host$HOST_NUM setup complete! Virtual IP: $VIRTUAL_IP"