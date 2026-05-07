from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from webob import Response
from firewall_controller import SDNFirewall
import json


firewall_instance_name = 'firewall_app'


class FirewallRestAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'firewall_app': SDNFirewall
    }

    def __init__(self, *args, **kwargs):
        super(FirewallRestAPI, self).__init__(*args, **kwargs)

        self.firewall_app = kwargs['firewall_app']

        wsgi = kwargs['wsgi']
        wsgi.register(
            FirewallController,
            {firewall_instance_name: self.firewall_app}
        )


class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[firewall_instance_name]

    def json_response(self, data):
        body = (json.dumps(data) + '\n').encode('utf-8')
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=body
        )

    def build_match(self, datapath, rule):
        parser = datapath.ofproto_parser

        match_kwargs = {'eth_type': 0x0800}

        src_ip = rule.get('src_ip')
        dst_ip = rule.get('dst_ip')
        proto  = rule.get('proto')
        dst_port = rule.get('dst_port')

        if src_ip:
            match_kwargs['ipv4_src'] = src_ip
        if dst_ip:
            match_kwargs['ipv4_dst'] = dst_ip

        if proto == 'tcp':
            match_kwargs['ip_proto'] = 6
            if dst_port:
                match_kwargs['tcp_dst'] = int(dst_port)
        elif proto == 'udp':
            match_kwargs['ip_proto'] = 17
            if dst_port:
                match_kwargs['udp_dst'] = int(dst_port)

        return parser.OFPMatch(**match_kwargs)

    @route('firewall', '/firewall/rules', methods=['GET'])
    def list_rules(self, req, **kwargs):
        return self.json_response(self.app.firewall_rules)

    @route('firewall', '/firewall/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):
        body = json.loads(req.body.decode('utf-8'))

        self.app.firewall_rules.append(body)

        action = body.get('action', 'block')

        if action == 'block':
            for dpid, datapath in self.app.datapaths.items():
                match = self.build_match(datapath, body)
                self.app.drop_flow(datapath, priority=20, match=match)

        return self.json_response({
            'status': 'rule installed',
            'rule_id': len(self.app.firewall_rules) - 1,
            'rule': body
        })

    @route('firewall', '/firewall/rules/{rule_id}', methods=['DELETE'])
    def delete_rule(self, req, rule_id, **kwargs):
        rule_id = int(rule_id)

        if rule_id < 0 or rule_id >= len(self.app.firewall_rules):
            return self.json_response({
                'status': 'error',
                'msg': 'Rule not found'
            })

        removed = self.app.firewall_rules.pop(rule_id)

        for dpid, datapath in self.app.datapaths.items():
            match = self.build_match(datapath, removed)
            self.app.delete_drop_flow(datapath, match)

        return self.json_response({
            'status': 'deleted and flow removed',
            'rule': removed
        })
