from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from firewall_controller import SDNFirewall  # <-- import the controller
import json

firewall_instance_name = 'firewall_app'

class FirewallRestAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'firewall_app': SDNFirewall  # <-- Ryu injects SDNFirewall instance
    }

    def __init__(self, *args, **kwargs):
        super(FirewallRestAPI, self).__init__(*args, **kwargs)
        self.firewall_app = kwargs['firewall_app']  # <-- grab the SDNFirewall instance
        wsgi = kwargs['wsgi']
        wsgi.register(FirewallController,
                       {firewall_instance_name: self.firewall_app})  # <-- pass it to HTTP handler

class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[firewall_instance_name]  # <-- self.app IS SDNFirewall

    @route('firewall', '/firewall/rules', methods=['GET'])
    def list_rules(self, req, **kwargs):
        return json.dumps(self.app.firewall_rules)

    @route('firewall', '/firewall/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):
        body = json.loads(req.body)
        self.app.firewall_rules.append(body)

        src_ip = body.get('src_ip')
        dst_ip = body.get('dst_ip')
        action = body.get('action', 'block')

        if action == 'block':
            for dpid, datapath in self.app.datapaths.items():
                parser = datapath.ofproto_parser
                match_kwargs = {'eth_type': 0x0800}
                if src_ip:
                    match_kwargs['ipv4_src'] = src_ip
                if dst_ip:
                    match_kwargs['ipv4_dst'] = dst_ip
                match = parser.OFPMatch(**match_kwargs)
                self.app.drop_flow(datapath, priority=20, match=match)  # <-- actually pushes to OVS

        return json.dumps({'status': 'rule installed', 'rule': body})
    
    @route('firewall', '/firewall/rules/{rule_id}', methods=['DELETE'])
    def delete_rule(self, req, rule_id, **kwargs):
        rule_id = int(rule_id)
        if rule_id < len(self.app.firewall_rules):
            removed = self.app.firewall_rules.pop(rule_id)

            # Remove the drop flow from OVS
            src_ip = removed.get('src_ip')
            dst_ip = removed.get('dst_ip')

            for dpid, datapath in self.app.datapaths.items():
                parser = datapath.ofproto_parser
                match_kwargs = {'eth_type': 0x0800}
                if src_ip:
                    match_kwargs['ipv4_src'] = src_ip
                if dst_ip:
                    match_kwargs['ipv4_dst'] = dst_ip
                match = parser.OFPMatch(**match_kwargs)
                self.app.remove_flow(datapath, match)  # <-- actually removes from OVS

            return json.dumps({'status': 'deleted', 'rule': removed})
        return json.dumps({'status': 'error', 'msg': 'Rule not found'})