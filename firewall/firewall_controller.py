"""
firewall_controller.py — SDN Firewall Controller

Improvements:
  1. Bidirectional rule support
  2. JSON persistence
  3. Multiple-switch support
  4. Port-based filtering
  5. Web dashboard
  6. Hit counters — polls OpenFlow flow stats every 3 s and stores
                    packet/byte counts per rule index in self.rule_stats.
                    The REST API exposes these so the dashboard can show
                    a live blocked-packets graph.
"""

import json
import os
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

RULES_FILE     = os.path.join(os.path.dirname(__file__), "rules.json")
DROP_PRIORITY  = 20
STATS_INTERVAL = 3   # seconds between flow-stats polls


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        self.firewall_rules = self._load_rules()

        # Hit counters: rule_index -> {"packets": int, "bytes": int}
        self.rule_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # History for the live graph (last 60 samples, ~3 min at default rate)
        self.stats_history = []

        # Background greenlet that polls flow stats
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info("[INIT] Loaded %d persisted rule(s).", len(self.firewall_rules))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_rules(self):
        if not os.path.exists(RULES_FILE):
            return []
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning("[PERSIST] Could not load rules: %s", e)
            return []

    def _save_rules(self):
        try:
            with open(RULES_FILE, "w") as f:
                json.dump(self.firewall_rules, f, indent=2)
        except OSError as e:
            self.logger.error("[PERSIST] Could not save rules: %s", e)

    # ------------------------------------------------------------------
    # Hit counter polling (Improvement 6)
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        """Greenlet: request flow stats from every switch every STATS_INTERVAL s."""
        while True:
            hub.sleep(STATS_INTERVAL)
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)

    def _request_flow_stats(self, datapath):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        req = parser.OFPFlowStatsRequest(
            datapath,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Match each returned drop flow back to a firewall rule by comparing
        priority and IP match fields, then accumulate packet/byte counts.
        """
        body      = ev.msg.body
        new_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

        for stat in body:
            if stat.priority != DROP_PRIORITY:
                continue   # only care about our drop flows

            m        = stat.match
            src_ip   = m.get("ipv4_src")
            dst_ip   = m.get("ipv4_dst")
            ip_proto = m.get("ip_proto")
            tcp_dst  = m.get("tcp_dst")
            udp_dst  = m.get("udp_dst")

            for idx, rule in enumerate(self.firewall_rules):
                if rule.get("action", "block") != "block":
                    continue

                r_src  = rule.get("src_ip")
                r_dst  = rule.get("dst_ip")
                r_proto = rule.get("proto", "").lower()
                r_port  = rule.get("dst_port")

                # Match forward direction
                forward = (
                    (r_src is None or str(src_ip) == r_src) and
                    (r_dst is None or str(dst_ip) == r_dst)
                )
                # Match reverse direction (bidirectional rule)
                reverse = rule.get("bidirectional") and (
                    (r_dst is None or str(src_ip) == r_dst) and
                    (r_src is None or str(dst_ip) == r_src)
                )

                if not (forward or reverse):
                    continue

                # Protocol check
                if r_proto == "tcp" and ip_proto != 6:
                    continue
                if r_proto == "udp" and ip_proto != 17:
                    continue

                # Port check
                if r_port:
                    flow_port = tcp_dst if ip_proto == 6 else udp_dst
                    if int(r_port) != flow_port:
                        continue

                new_stats[idx]["packets"] += stat.packet_count
                new_stats[idx]["bytes"]   += stat.byte_count
                break   # matched — no need to check further rules

        self.rule_stats = new_stats

        # Append a total-blocked snapshot for the graph
        total = sum(s["packets"] for s in new_stats.values())
        self.stats_history.append({
            "t":       int(time.time() * 1000),   # ms epoch (for JS Date)
            "packets": total,
        })
        if len(self.stats_history) > 60:
            self.stats_history = self.stats_history[-60:]

    # ------------------------------------------------------------------
    # OpenFlow helpers
    # ------------------------------------------------------------------

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle_timeout, match=match, instructions=inst,
        ))

    def drop_flow(self, datapath, priority, match, idle_timeout=0):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle_timeout, match=match, instructions=[],
        ))

    def delete_drop_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=DROP_PRIORITY,
            match=match,
        ))

    def build_match(self, datapath, rule):
        parser = datapath.ofproto_parser
        kwargs = {"eth_type": 0x0800}

        if rule.get("src_ip"):
            kwargs["ipv4_src"] = rule["src_ip"]
        if rule.get("dst_ip"):
            kwargs["ipv4_dst"] = rule["dst_ip"]

        proto    = rule.get("proto", "").lower()
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
        rev = dict(rule)
        rev["src_ip"], rev["dst_ip"] = rule.get("dst_ip"), rule.get("src_ip")
        return rev

    # ------------------------------------------------------------------
    # Rule install / remove
    # ------------------------------------------------------------------

    def install_block_rule(self, rule):
        for datapath in self.datapaths.values():
            self.drop_flow(datapath, DROP_PRIORITY, self.build_match(datapath, rule))
            if rule.get("bidirectional"):
                self.drop_flow(datapath, DROP_PRIORITY,
                               self.build_match(datapath, self._reversed_rule(rule)))

    def remove_block_rule(self, rule):
        for datapath in self.datapaths.values():
            self.delete_drop_flow(datapath, self.build_match(datapath, rule))
            if rule.get("bidirectional"):
                self.delete_drop_flow(datapath,
                                      self.build_match(datapath, self._reversed_rule(rule)))

    def add_rule(self, rule):
        rule_id = len(self.firewall_rules)
        self.firewall_rules.append(rule)
        self._save_rules()
        if rule.get("action", "block") == "block":
            self.install_block_rule(rule)
        return rule_id

    def delete_rule(self, rule_id):
        if rule_id < 0 or rule_id >= len(self.firewall_rules):
            return None
        removed = self.firewall_rules.pop(rule_id)

        # Shift stats keys down so indices stay aligned
        new_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for idx, val in self.rule_stats.items():
            if idx < rule_id:
                new_stats[idx] = val
            elif idx > rule_id:
                new_stats[idx - 1] = val
        self.rule_stats = new_stats

        self._save_rules()
        if removed.get("action", "block") == "block":
            self.remove_block_rule(removed)
        return removed

    # ------------------------------------------------------------------
    # Switch / packet events
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
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # Table-miss: send unmatched packets to controller
        self.add_flow(datapath, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)])

        # Re-install persisted rules
        for rule in self.firewall_rules:
            if rule.get("action", "block") == "block":
                self.drop_flow(datapath, DROP_PRIORITY, self.build_match(datapath, rule))
                if rule.get("bidirectional"):
                    self.drop_flow(datapath, DROP_PRIORITY,
                                   self.build_match(datapath, self._reversed_rule(rule)))

        self.logger.info("[SWITCH] Connected dpid=%s, re-installed %d rule(s)",
                         datapath.id, len(self.firewall_rules))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt    = packet.Packet(msg.data)
        eth    = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        if ip_pkt:
            proto_num = ip_pkt.proto
            proto = "tcp" if proto_num == 6 else ("udp" if proto_num == 17 else str(proto_num))

            dst_port = None
            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                dst_port = udp_pkt.dst_port

            if self.matches_rule(ip_pkt.src, ip_pkt.dst, proto, dst_port) == "block":
                self.logger.info("[BLOCKED] %s -> %s", ip_pkt.src, ip_pkt.dst)
                return

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, 1,
                          parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                          actions, idle_timeout=30)

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data,
        ))
