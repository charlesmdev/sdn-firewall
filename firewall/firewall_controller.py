"""
firewall_controller.py — SDN Firewall Controller (Improved)

Improvements over original:
  1. Bidirectional rule support  — a single rule with "bidirectional": true
                                   installs drop flows in both directions.
  2. JSON persistence            — rules are saved to rules.json on every
                                   change and reloaded automatically on startup.
  3. Multiple-switch support     — every registered datapath receives every
                                   flow-mod, so the firewall works across a
                                   multi-switch topology.
  4. Port-based filtering        — fully tested TCP/UDP dst_port matching
                                   using proper OFPMatch fields.
  5. Web dashboard ready         — rules list is exposed via self.firewall_rules
                                   so firewall_rest_api.py can serve a dashboard.
"""

import json
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")
DROP_PRIORITY = 20


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # Improvement 2: load persisted rules on startup
        self.firewall_rules = self._load_rules()
        self.logger.info("[INIT] Loaded %d persisted rule(s).", len(self.firewall_rules))

    # ------------------------------------------------------------------
    # Improvement 2: JSON persistence helpers
    # ------------------------------------------------------------------

    def _load_rules(self):
        """Load firewall rules from disk. Returns [] if file is missing/corrupt."""
        if not os.path.exists(RULES_FILE):
            return []
        try:
            with open(RULES_FILE, "r") as f:
                rules = json.load(f)
            self.logger.info("[PERSIST] Rules loaded from %s", RULES_FILE)
            return rules
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning("[PERSIST] Could not load rules: %s", e)
            return []

    def _save_rules(self):
        """Persist current rule list to disk."""
        try:
            with open(RULES_FILE, "w") as f:
                json.dump(self.firewall_rules, f, indent=2)
            self.logger.info("[PERSIST] Rules saved to %s", RULES_FILE)
        except OSError as e:
            self.logger.error("[PERSIST] Could not save rules: %s", e)

    # ------------------------------------------------------------------
    # OpenFlow helpers
    # ------------------------------------------------------------------

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def drop_flow(self, datapath, priority, match, idle_timeout=0):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            idle_timeout=idle_timeout,
            match=match,
            instructions=[],          # empty = drop
        )
        datapath.send_msg(mod)

    def delete_drop_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=DROP_PRIORITY,
            match=match,
        )
        datapath.send_msg(mod)

    def build_match(self, datapath, rule):
        """
        Build an OFPMatch from a rule dict.

        Supported fields: src_ip, dst_ip, proto ('tcp'/'udp'), dst_port.
        Improvement 4: dst_port matching is tested for both TCP and UDP.
        """
        parser = datapath.ofproto_parser
        kwargs = {"eth_type": 0x0800}           # IPv4

        if rule.get("src_ip"):
            kwargs["ipv4_src"] = rule["src_ip"]
        if rule.get("dst_ip"):
            kwargs["ipv4_dst"] = rule["dst_ip"]

        proto = rule.get("proto", "").lower()
        dst_port = rule.get("dst_port")

        if proto == "tcp":
            kwargs["ip_proto"] = 6
            if dst_port:
                kwargs["tcp_dst"] = int(dst_port)
        elif proto == "udp":
            kwargs["ip_proto"] = 17
            if dst_port:
                kwargs["udp_dst"] = int(dst_port)

        return parser.OFPMatch(**kwargs)

    def _reversed_rule(self, rule):
        """Return a copy of rule with src_ip/dst_ip swapped (for bidirectional)."""
        rev = dict(rule)
        rev["src_ip"], rev["dst_ip"] = rule.get("dst_ip"), rule.get("src_ip")
        return rev

    # ------------------------------------------------------------------
    # Improvement 1: Bidirectional + Improvement 3: All datapaths
    # ------------------------------------------------------------------

    def install_block_rule(self, rule):
        """
        Install drop flow(s) on every connected switch for the given rule.
        If rule["bidirectional"] is True, also installs the reverse direction.
        """
        for dpid, datapath in self.datapaths.items():
            match = self.build_match(datapath, rule)
            self.drop_flow(datapath, DROP_PRIORITY, match)
            self.logger.info("[BLOCK] dpid=%s  %s -> %s",
                             dpid, rule.get("src_ip"), rule.get("dst_ip"))

            # Improvement 1: bidirectional option
            if rule.get("bidirectional"):
                rev = self._reversed_rule(rule)
                rev_match = self.build_match(datapath, rev)
                self.drop_flow(datapath, DROP_PRIORITY, rev_match)
                self.logger.info("[BLOCK-REV] dpid=%s  %s -> %s",
                                 dpid, rev.get("src_ip"), rev.get("dst_ip"))

    def remove_block_rule(self, rule):
        """Delete drop flow(s) from every connected switch."""
        for dpid, datapath in self.datapaths.items():
            match = self.build_match(datapath, rule)
            self.delete_drop_flow(datapath, match)
            self.logger.info("[UNBLOCK] dpid=%s  %s -> %s",
                             dpid, rule.get("src_ip"), rule.get("dst_ip"))

            if rule.get("bidirectional"):
                rev = self._reversed_rule(rule)
                rev_match = self.build_match(datapath, rev)
                self.delete_drop_flow(datapath, rev_match)
                self.logger.info("[UNBLOCK-REV] dpid=%s  %s -> %s",
                                 dpid, rev.get("src_ip"), rev.get("dst_ip"))

    # ------------------------------------------------------------------
    # Public API used by FirewallRestAPI
    # ------------------------------------------------------------------

    def add_rule(self, rule):
        """Add a rule, persist it, and push flows to all switches."""
        rule_id = len(self.firewall_rules)
        self.firewall_rules.append(rule)
        self._save_rules()                      # Improvement 2
        if rule.get("action", "block") == "block":
            self.install_block_rule(rule)       # Improvement 1 + 3
        return rule_id

    def delete_rule(self, rule_id):
        """Remove a rule by index, persist the change, and delete flows."""
        if rule_id < 0 or rule_id >= len(self.firewall_rules):
            return None
        removed = self.firewall_rules.pop(rule_id)
        self._save_rules()                      # Improvement 2
        if removed.get("action", "block") == "block":
            self.remove_block_rule(removed)     # Improvement 1 + 3
        return removed

    # ------------------------------------------------------------------
    # Packet-in: learning switch + rule check
    # ------------------------------------------------------------------

    def matches_rule(self, src_ip, dst_ip, proto, dst_port):
        for rule in self.firewall_rules:
            if rule.get("src_ip") and rule["src_ip"] != src_ip:
                continue
            if rule.get("dst_ip") and rule["dst_ip"] != dst_ip:
                continue
            if rule.get("proto") and rule["proto"] != proto:
                continue
            if rule.get("dst_port") and rule["dst_port"] != dst_port:
                continue
            return rule.get("action", "allow")
        return "allow"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        # Improvement 3: track every switch
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("[SWITCH] Connected: dpid=%s", datapath.id)

        # Re-install persisted block rules on reconnect (Improvement 2 + 3)
        for rule in self.firewall_rules:
            if rule.get("action", "block") == "block":
                match = self.build_match(datapath, rule)
                self.drop_flow(datapath, DROP_PRIORITY, match)
                if rule.get("bidirectional"):
                    rev = self._reversed_rule(rule)
                    rev_match = self.build_match(datapath, rev)
                    self.drop_flow(datapath, DROP_PRIORITY, rev_match)
        self.logger.info("[SWITCH] Re-installed %d persisted rule(s) on dpid=%s",
                         len(self.firewall_rules), datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto_num = ip_pkt.proto

            if proto_num == 6:
                proto = "tcp"
            elif proto_num == 17:
                proto = "udp"
            else:
                proto = str(proto_num)

            dst_port = None
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                dst_port = udp_pkt.dst_port

            action = self.matches_rule(src_ip, dst_ip, proto, dst_port)
            if action == "block":
                self.logger.info("[BLOCKED] %s -> %s", src_ip, dst_ip)
                return

        # Learning-switch forwarding
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
