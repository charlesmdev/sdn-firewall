#!/bin/bash
set -euxo pipefail

# Usage: bash switch.sh <CONTROLLER_IP> <HOST1_IP> <HOST2_IP> <HOST3_IP> <HOST4_IP>
# Example: bash switch.sh 172.17.245.1 172.17.245.2 172.17.245.3 172.17.245.4 172.17.245.5

CONTROLLER_IP="${1:-}"
HOST1_IP="${2:-}"
HOST2_IP="${3:-}"
HOST3_IP="${4:-}"
HOST4_IP="${5:-}"

if [ -z "$CONTROLLER_IP" ]; then
    echo "ERROR: Pass the controller IP as the first argument."
    echo "Usage: bash switch.sh <CONTROLLER_IP> <HOST1_IP> <HOST2_IP> <HOST3_IP> <HOST4_IP>"
    exit 1
fi

exec > /tmp/switch-setup.log 2>&1

echo "Installing Open vSwitch..."
sudo apt-get update
sudo apt-get install -y openvswitch-switch
sudo systemctl start openvswitch-switch
sudo systemctl enable openvswitch-switch

echo "Setting up OVS bridge..."
sudo ovs-vsctl --if-exists del-br br0
sudo ovs-vsctl add-br br0
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13

echo "Connecting to Ryu controller at $CONTROLLER_IP:6633..."
sudo ovs-vsctl set-controller br0 tcp:$CONTROLLER_IP:6633

echo "Adding GRE tunnels to hosts..."
for i in 1 2 3 4; do
    varname="HOST${i}_IP"
    HOST_IP="${!varname}"
    if [ -n "$HOST_IP" ]; then
        echo "Adding tunnel to host$i at $HOST_IP..."
        sudo ovs-vsctl --if-exists del-port br0 gre-host$i
        sudo ovs-vsctl add-port br0 gre-host$i \
            -- set interface gre-host$i type=gre options:remote_ip=$HOST_IP
    else
        echo "Skipping host$i (no IP provided)"
    fi
done

echo ""
echo "=============================="
sudo ovs-vsctl show
echo "=============================="
echo "Switch setup complete!"
echo "Check above for 'is_connected: true' to confirm Ryu connection."