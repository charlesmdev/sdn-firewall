from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3

from policy import RuleStore, expanded_rule_matches, rule_cookie, utc_now


EXPECTED_TOPOLOGY = {
    'switches': [1, 2, 3],
    'links': [
        {'src_dpid': 1, 'dst_dpid': 2},
        {'src_dpid': 2, 'dst_dpid': 3}
    ]
}


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.rule_store = RuleStore()
        self.firewall_rules = self.rule_store.rules
        self.datapaths = {}
        self.switches = {}
        self.event_log = deque(maxlen=250)
        self.stats_cache = {}
        self.topology_anomalies = deque(maxlen=100)
        self.stats_thread = hub.spawn(self._stats_loop)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            idle_timeout=idle_timeout,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    def drop_flow(self, datapath, priority, match, idle_timeout=0, cookie=0):
        parser = datapath.ofproto_parser

        # Empty instruction list means drop the packet.
        inst = []

        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            idle_timeout=idle_timeout,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    def delete_rule_flows(self, datapath, rule_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            cookie=rule_cookie(rule_id),
            cookie_mask=0xffffffffffffffff,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )

        datapath.send_msg(mod)

    def _record_event(self, event_type, **fields):
        event = {'type': event_type, 'timestamp': utc_now()}
        event.update(fields)
        self.event_log.appendleft(event)

    def _proto_name(self, proto_num):
        if proto_num == 1:
            return 'icmp'
        if proto_num == 6:
            return 'tcp'
        if proto_num == 17:
            return 'udp'
        return str(proto_num)

    def _rule_matches_packet(self, rule, src_ip, dst_ip, proto, src_port, dst_port, icmp_type):
        if not rule.get('enabled', True):
            return False

        for match in expanded_rule_matches(rule):
            if match.get('src_ip') and match['src_ip'] != src_ip:
                continue
            if match.get('dst_ip') and match['dst_ip'] != dst_ip:
                continue
            if match.get('proto') and match['proto'] != proto:
                continue
            if match.get('src_port') and match['src_port'] != src_port:
                continue
            if match.get('dst_port') and match['dst_port'] != dst_port:
                continue
            if match.get('icmp_type') is not None and match['icmp_type'] != icmp_type:
                continue
            return True

        return False

    def matches_rule(self, src_ip, dst_ip, proto, src_port=None, dst_port=None, icmp_type=None):
        for rule in self.rule_store.list():
            if self._rule_matches_packet(rule, src_ip, dst_ip, proto, src_port, dst_port, icmp_type):
                return rule
        return None

    def build_match(self, datapath, match_spec):
        parser = datapath.ofproto_parser
        kwargs = {'eth_type': 0x0800}

        if match_spec.get('src_ip'):
            kwargs['ipv4_src'] = match_spec['src_ip']
        if match_spec.get('dst_ip'):
            kwargs['ipv4_dst'] = match_spec['dst_ip']

        proto = match_spec.get('proto')
        if proto == 'icmp':
            kwargs['ip_proto'] = 1
            if match_spec.get('icmp_type') is not None:
                kwargs['icmpv4_type'] = int(match_spec['icmp_type'])
        elif proto == 'tcp':
            kwargs['ip_proto'] = 6
            if match_spec.get('src_port'):
                kwargs['tcp_src'] = int(match_spec['src_port'])
            if match_spec.get('dst_port'):
                kwargs['tcp_dst'] = int(match_spec['dst_port'])
        elif proto == 'udp':
            kwargs['ip_proto'] = 17
            if match_spec.get('src_port'):
                kwargs['udp_src'] = int(match_spec['src_port'])
            if match_spec.get('dst_port'):
                kwargs['udp_dst'] = int(match_spec['dst_port'])

        return parser.OFPMatch(**kwargs)

    def install_rule_on_datapath(self, datapath, rule):
        if not rule.get('enabled', True) or rule.get('action') != 'block':
            return 0

        installed = 0
        for match_spec in expanded_rule_matches(rule):
            match = self.build_match(datapath, match_spec)
            self.drop_flow(
                datapath,
                priority=rule['priority'],
                match=match,
                cookie=rule_cookie(rule['id'])
            )
            installed += 1

        switch = self.switches.setdefault(datapath.id, {})
        switch['installed_rule_count'] = switch.get('installed_rule_count', 0) + installed
        return installed

    def install_rule(self, rule):
        installs = []
        for dpid, datapath in self.datapaths.items():
            count = self.install_rule_on_datapath(datapath, rule)
            installs.append({'dpid': dpid, 'flows': count, 'cookie': rule_cookie(rule['id'])})
        return installs

    def remove_rule_flows(self, rule_id):
        removed = []
        for dpid, datapath in self.datapaths.items():
            self.delete_rule_flows(datapath, rule_id)
            removed.append({'dpid': dpid, 'cookie': rule_cookie(rule_id)})
        return removed

    def replay_rules(self, datapath):
        installed = 0
        for rule in self.rule_store.list():
            installed += self.install_rule_on_datapath(datapath, rule)
        self.switches.setdefault(datapath.id, {})['installed_rule_count'] = installed
        return installed

    def create_rule(self, payload):
        rule = self.rule_store.create(payload)
        self.firewall_rules = self.rule_store.rules
        installs = self.install_rule(rule)
        self._record_event('rule_created', rule_id=rule['id'])
        return rule, installs

    def update_rule(self, rule_id, payload):
        old = self.rule_store.get(rule_id)
        if old is None:
            return None, []
        rule = self.rule_store.update(rule_id, payload)
        self.remove_rule_flows(rule_id)
        self.firewall_rules = self.rule_store.rules
        installs = self.install_rule(rule)
        self._record_event('rule_updated', rule_id=rule['id'])
        return rule, installs

    def delete_rule(self, rule_id):
        removed = self.rule_store.delete(rule_id)
        if removed is None:
            return None, []
        flow_removals = self.remove_rule_flows(rule_id)
        self.firewall_rules = self.rule_store.rules
        self._record_event('rule_deleted', rule_id=rule_id)
        return removed, flow_removals

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        reconnect = datapath.id in self.datapaths
        self.datapaths[datapath.id] = datapath
        self.switches[datapath.id] = {
            'dpid': datapath.id,
            'connected': True,
            'address': str(getattr(datapath, 'address', 'unknown')),
            'installed_rule_count': 0
        }

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: send unmatched packets to the controller.
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)
        installed = self.replay_rules(datapath)

        if reconnect:
            self._record_event('switch_reconnected', dpid=datapath.id)
        self.logger.info("Switch connected: dpid=%s rules=%s", datapath.id, installed)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

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
            proto = self._proto_name(ip_pkt.proto)
            src_port = None
            dst_port = None
            icmp_type = None

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port
            elif icmp_pkt:
                icmp_type = icmp_pkt.type

            matched_rule = self.matches_rule(src_ip, dst_ip, proto, src_port, dst_port, icmp_type)

            if matched_rule and matched_rule.get('action') == 'block':
                self._record_event(
                    'packet_blocked',
                    rule_id=matched_rule['id'],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    proto=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    icmp_type=icmp_type
                )
                self.logger.info("[BLOCKED] rule=%s %s -> %s", matched_rule['id'], src_ip, dst_ip)
                return

        # Learning-switch behavior for allowed traffic.
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac
            )

            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)

    def _stats_loop(self):
        while True:
            hub.sleep(5)
            for datapath in list(self.datapaths.values()):
                self.request_stats(datapath)

    def request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(
            datapath=datapath,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0,
            cookie_mask=0
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            cookie = getattr(stat, 'cookie', 0)
            if cookie & 0xffff0000 != 0xF1000000:
                continue
            rule_id = cookie & 0x0000ffff
            entry = self.stats_cache.setdefault(rule_id, {
                'rule_id': rule_id,
                'packet_count': 0,
                'byte_count': 0,
                'per_switch': {}
            })
            entry['per_switch'][str(dpid)] = {
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count
            }
            entry['packet_count'] = sum(item['packet_count'] for item in entry['per_switch'].values())
            entry['byte_count'] = sum(item['byte_count'] for item in entry['per_switch'].values())

    def get_switches(self):
        return [self.switches[dpid] for dpid in sorted(self.switches)]

    def get_topology(self):
        switches = [self.switches.get(dpid, {'dpid': dpid}) for dpid in sorted(self.datapaths)]
        connected_dpids = set(self.datapaths)
        links = []
        for link in EXPECTED_TOPOLOGY['links']:
            if link['src_dpid'] in connected_dpids and link['dst_dpid'] in connected_dpids:
                links.append({
                    'src_dpid': link['src_dpid'],
                    'src_port': link.get('src_port'),
                    'dst_dpid': link['dst_dpid'],
                    'dst_port': link.get('dst_port'),
                    'source': 'expected_topology'
                })

        return {
            'switches': switches,
            'links': links,
            'expected': EXPECTED_TOPOLOGY,
            'source': 'controller_cache'
        }

    def get_topology_anomalies(self):
        topology = self.get_topology()
        anomalies = []
        found_switches = {item['dpid'] for item in topology['switches']}
        expected_switches = set(EXPECTED_TOPOLOGY['switches'])

        for dpid in sorted(expected_switches - found_switches):
            anomalies.append({'type': 'missing_switch', 'severity': 'warning', 'dpid': dpid, 'timestamp': utc_now()})
        for dpid in sorted(found_switches - expected_switches):
            anomalies.append({'type': 'unknown_switch', 'severity': 'warning', 'dpid': dpid, 'timestamp': utc_now()})

        expected_links = {tuple(sorted((item['src_dpid'], item['dst_dpid']))) for item in EXPECTED_TOPOLOGY['links']}
        found_links = {tuple(sorted((item['src_dpid'], item['dst_dpid']))) for item in topology['links']}
        for src_dpid, dst_dpid in sorted(expected_links - found_links):
            anomalies.append({'type': 'missing_link', 'severity': 'warning', 'src_dpid': src_dpid, 'dst_dpid': dst_dpid, 'timestamp': utc_now()})
        for src_dpid, dst_dpid in sorted(found_links - expected_links):
            anomalies.append({'type': 'unknown_link', 'severity': 'warning', 'src_dpid': src_dpid, 'dst_dpid': dst_dpid, 'timestamp': utc_now()})

        return list(self.topology_anomalies) + anomalies

    def get_stats(self):
        return [self.stats_cache[key] for key in sorted(self.stats_cache)]
