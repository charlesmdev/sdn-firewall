"""
topology.py — Mininet Topology (Improved)

Improvements:
  - Multi-switch support: builds a linear chain of switches (configurable).
  - Auto graph generation: dumps a topology graph as topology.png using
    matplotlib + networkx after the network starts.
  - CLI still available for interactive testing.

Usage:
    sudo python3 topology.py            # default: 2 switches, 4 hosts
    sudo python3 topology.py --switches 3 --hosts 6
"""

import argparse
import json
import os

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


# ---------------------------------------------------------------------------
# Improvement: auto graph generation
# ---------------------------------------------------------------------------

def generate_topology_graph(switches, hosts, links, output_path="topology.png"):
    """
    Render a simple topology diagram using networkx + matplotlib.
    Falls back gracefully if the libraries are not installed.
    """
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        G = nx.Graph()

        switch_names = [s.name for s in switches]
        host_names   = [h.name for h in hosts]

        G.add_nodes_from(switch_names, node_type="switch")
        G.add_nodes_from(host_names,   node_type="host")

        for src, dst in links:
            G.add_edge(src, dst)

        pos = nx.spring_layout(G, seed=42, k=2.5)

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.set_facecolor("#0f172a")
        fig.patch.set_facecolor("#0f172a")

        nx.draw_networkx_nodes(G, pos, nodelist=switch_names,
                               node_color="#4f46e5", node_size=900, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=host_names,
                               node_color="#0891b2", node_size=500, ax=ax)
        nx.draw_networkx_labels(G, pos, font_color="white",
                                font_size=9, font_weight="bold", ax=ax)
        nx.draw_networkx_edges(G, pos, edge_color="#64748b", width=2, ax=ax)

        ax.set_title("SDN Topology", color="white", fontsize=14, pad=12)
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(output_path, dpi=120, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close()
        info(f"[GRAPH] Topology saved to {output_path}\n")

    except ImportError as e:
        info(f"[GRAPH] Skipping graph generation (missing library: {e})\n")
        info("[GRAPH] Install with: pip install networkx matplotlib\n")


def export_topology_json(switches, hosts, links, output_path="topology.json"):
    """Save topology metadata to JSON for external tooling."""
    data = {
        "switches": [s.name for s in switches],
        "hosts":    [{"name": h.name, "ip": h.IP(), "mac": h.MAC()} for h in hosts],
        "links":    [list(l) for l in links],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    info(f"[GRAPH] Topology JSON saved to {output_path}\n")


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------

def build_topology(num_switches=2, num_hosts=4):
    """
    Build a linear chain of `num_switches` OpenFlow 1.3 switches.
    Hosts are distributed across switches as evenly as possible.

    Improvement (multi-switch): all switches connect to the same remote
    Ryu controller, which now handles each dpid independently.
    """
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    # Create switches
    switches = []
    for i in range(1, num_switches + 1):
        s = net.addSwitch(f"s{i}", protocols="OpenFlow13")
        switches.append(s)

    # Link switches in a chain: s1 -- s2 -- s3 ...
    switch_links = []
    for i in range(len(switches) - 1):
        net.addLink(switches[i], switches[i + 1])
        switch_links.append((switches[i].name, switches[i + 1].name))

    # Distribute hosts evenly across switches
    hosts = []
    host_links = []
    for i in range(1, num_hosts + 1):
        sw = switches[(i - 1) % num_switches]
        h = net.addHost(
            f"h{i}",
            ip=f"10.0.0.{i}/24",
            mac=f"00:00:00:00:00:{i:02x}",
        )
        net.addLink(h, sw)
        hosts.append(h)
        host_links.append((h.name, sw.name))

    net.start()

    info(f"[*] Network started: {num_switches} switch(es), {num_hosts} host(s)\n")
    info("[*] Controller expected at 127.0.0.1:6653\n")
    info("[*] Dashboard: http://127.0.0.1:8080/\n")

    # Auto graph generation (Improvement 5 support)
    all_links = switch_links + host_links
    generate_topology_graph(switches, hosts, all_links)
    export_topology_json(switches, hosts, all_links)

    CLI(net)
    net.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Firewall Mininet topology")
    parser.add_argument("--switches", type=int, default=2,
                        help="Number of switches (default: 2)")
    parser.add_argument("--hosts",   type=int, default=4,
                        help="Number of hosts   (default: 4)")
    args = parser.parse_args()

    setLogLevel("info")
    build_topology(num_switches=args.switches, num_hosts=args.hosts)
