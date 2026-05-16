from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from webob import Response
from firewall_controller import SDNFirewall
from policy import RuleValidationError
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
        return self._json_response(data)

    def _json_response(self, data, status=200):
        body = (json.dumps(data) + '\n').encode('utf-8')
        return Response(
            status=status,
            content_type='application/json',
            charset='utf-8',
            body=body
        )

    def error_response(self, code, message, field=None, status=400):
        return self._json_response({
            'status': 'error',
            'error': {
                'code': code,
                'message': message,
                'field': field
            }
        }, status=status)

    def parse_json(self, req):
        try:
            body = req.body.decode('utf-8') if req.body else '{}'
            return json.loads(body)
        except (TypeError, ValueError):
            raise RuleValidationError('request body must be valid JSON', code='invalid_json')

    def handle_validation_error(self, exc):
        status = 501 if exc.code == 'not_implemented' else 400
        return self.error_response(exc.code, exc.message, exc.field, status=status)

    @route('firewall', '/firewall/health', methods=['GET'])
    def health(self, req, **kwargs):
        return self._json_response({
            'status': 'ok',
            'rules': len(self.app.rule_store.list()),
            'switches': len(self.app.datapaths)
        })

    @route('firewall', '/firewall/rules', methods=['GET'])
    def list_rules(self, req, **kwargs):
        return self._json_response(self.app.rule_store.list())

    @route('firewall', '/firewall/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):
        try:
            rule, installs = self.app.create_rule(self.parse_json(req))
        except RuleValidationError as exc:
            return self.handle_validation_error(exc)

        return self._json_response({
            'status': 'created',
            'rule': rule,
            'flows_installed': installs
        }, status=201)

    @route('firewall', '/firewall/rules/{rule_id}', methods=['GET'])
    def get_rule(self, req, rule_id, **kwargs):
        rule = self.app.rule_store.get(rule_id)
        if rule is None:
            return self.error_response('not_found', 'Rule not found', 'rule_id', status=404)
        return self._json_response(rule)

    @route('firewall', '/firewall/rules/{rule_id}', methods=['PATCH'])
    def update_rule(self, req, rule_id, **kwargs):
        try:
            rule, installs = self.app.update_rule(rule_id, self.parse_json(req))
        except RuleValidationError as exc:
            return self.handle_validation_error(exc)
        if rule is None:
            return self.error_response('not_found', 'Rule not found', 'rule_id', status=404)
        return self._json_response({
            'status': 'updated',
            'rule': rule,
            'flows_installed': installs
        })

    @route('firewall', '/firewall/rules/{rule_id}', methods=['DELETE'])
    def delete_rule(self, req, rule_id, **kwargs):
        removed, flow_removals = self.app.delete_rule(rule_id)
        if removed is None:
            return self.error_response('not_found', 'Rule not found', 'rule_id', status=404)
        return self._json_response({
            'status': 'deleted',
            'rule': removed,
            'flows_removed': flow_removals
        })

    @route('firewall', '/firewall/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        return self._json_response(self.app.get_switches())

    @route('firewall', '/firewall/topology', methods=['GET'])
    def topology(self, req, **kwargs):
        return self._json_response(self.app.get_topology())

    @route('firewall', '/firewall/topology/anomalies', methods=['GET'])
    def topology_anomalies(self, req, **kwargs):
        return self._json_response(self.app.get_topology_anomalies())

    @route('firewall', '/firewall/stats', methods=['GET'])
    def stats(self, req, **kwargs):
        return self._json_response(self.app.get_stats())

    @route('firewall', '/firewall/rules/{rule_id}/stats', methods=['GET'])
    def rule_stats(self, req, rule_id, **kwargs):
        rule = self.app.rule_store.get(rule_id)
        if rule is None:
            return self.error_response('not_found', 'Rule not found', 'rule_id', status=404)
        numeric_id = rule['id']
        stats = self.app.stats_cache.get(numeric_id, {
            'rule_id': numeric_id,
            'packet_count': 0,
            'byte_count': 0,
            'per_switch': {}
        })
        return self._json_response(stats)

    @route('firewall', '/firewall/events', methods=['GET'])
    def events(self, req, **kwargs):
        return self._json_response(list(self.app.event_log))
