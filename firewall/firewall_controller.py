from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.firewall_rules = []
        self.datapaths = {}  # <-- stores connected switches

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def drop_flow(self, datapath, priority, match, idle_timeout=0):
        parser = datapath.ofproto_parser
        inst = []  # no actions = drop
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath  # <-- save the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Table-miss: send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def matches_rule(self, src_ip, dst_ip, proto, dst_port):
        for rule in self.firewall_rules:
            if rule.get('src_ip') and rule['src_ip'] != src_ip:
                continue
            if rule.get('dst_ip') and rule['dst_ip'] != dst_ip:
                continue
            if rule.get('proto') and rule['proto'] != proto:
                continue
            if rule.get('dst_port') and rule['dst_port'] != dst_port:
                continue
            return rule['action']
        return 'allow'

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

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto
            dst_port = None

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                dst_port = udp_pkt.dst_port

            action = self.matches_rule(src_ip, dst_ip, proto, dst_port)
            if action == 'block':
                self.logger.info(f"[BLOCKED] {src_ip} -> {dst_ip}")
                return  # drop, don't forward

        # Learning switch — forward normally
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)