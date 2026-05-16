import ipaddress
import json
import os
from copy import deepcopy
from datetime import datetime, timezone


class RuleValidationError(ValueError):
    def __init__(self, message, field=None, code='invalid_rule'):
        super().__init__(message)
        self.message = message
        self.field = field
        self.code = code


COOKIE_BASE = 0xF1000000
SUPPORTED_ACTIONS = {'block'}
SUPPORTED_DIRECTIONS = {'one-way', 'bidirectional'}
SUPPORTED_PROTOCOLS = {'tcp', 'udp', 'icmp'}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def rule_cookie(rule_id):
    return COOKIE_BASE | int(rule_id)


def default_rule_store_path():
    return os.environ.get(
        'SDN_FIREWALL_RULES_FILE',
        os.path.join(os.path.dirname(__file__), 'rules.json')
    )


def _validate_ip(value, field):
    if value is None:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise RuleValidationError('invalid IP address', field)
    return value


def _validate_port(value, field):
    if value in (None, ''):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise RuleValidationError('port must be an integer', field)
    if port < 1 or port > 65535:
        raise RuleValidationError('port must be between 1 and 65535', field)
    return port


def _validate_icmp_type(value):
    if value in (None, ''):
        return None
    try:
        icmp_type = int(value)
    except (TypeError, ValueError):
        raise RuleValidationError('icmp_type must be an integer', 'match.icmp_type')
    if icmp_type < 0 or icmp_type > 255:
        raise RuleValidationError('icmp_type must be between 0 and 255', 'match.icmp_type')
    return icmp_type


def _legacy_match(payload):
    match = dict(payload.get('match') or {})
    for key in ('src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'icmp_type'):
        if key in payload and key not in match:
            match[key] = payload[key]
    return match


def normalize_rule(payload, rule_id=None, existing=None):
    if not isinstance(payload, dict):
        raise RuleValidationError('rule payload must be a JSON object')

    existing = deepcopy(existing) if existing else {}
    now = utc_now()
    match = _legacy_match(payload)

    if existing:
        base = existing
        if 'match' in payload:
            base['match'].update(payload['match'] or {})
        for key in ('src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'icmp_type'):
            if key in payload:
                base['match'][key] = payload[key]
        for key, value in payload.items():
            if key not in ('match', 'src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'icmp_type', 'id', 'created_at'):
                base[key] = value
        base['updated_at'] = now
        payload = base
        match = payload.get('match') or {}

    action = payload.get('action', 'block')
    if action not in SUPPORTED_ACTIONS:
        raise RuleValidationError('only block rules are supported in v1', 'action')

    direction = payload.get('direction', 'one-way')
    if direction not in SUPPORTED_DIRECTIONS:
        raise RuleValidationError('direction must be one-way or bidirectional', 'direction')

    stateful = payload.get('stateful', False)
    if stateful is not False:
        raise RuleValidationError('stateful/reflexive rules are reserved for a later phase', 'stateful', 'not_implemented')

    src_ip = _validate_ip(match.get('src_ip'), 'match.src_ip')
    dst_ip = _validate_ip(match.get('dst_ip'), 'match.dst_ip')
    if not src_ip and not dst_ip:
        raise RuleValidationError('at least one of src_ip or dst_ip is required', 'match')

    proto = match.get('proto')
    if proto is not None:
        proto = str(proto).lower()
        if proto not in SUPPORTED_PROTOCOLS:
            raise RuleValidationError('proto must be tcp, udp, or icmp', 'match.proto')

    src_port = _validate_port(match.get('src_port'), 'match.src_port')
    dst_port = _validate_port(match.get('dst_port'), 'match.dst_port')
    icmp_type = _validate_icmp_type(match.get('icmp_type'))

    if (src_port or dst_port) and proto not in ('tcp', 'udp'):
        raise RuleValidationError('ports require proto to be tcp or udp', 'match.dst_port')
    if icmp_type is not None and proto != 'icmp':
        raise RuleValidationError('icmp_type requires proto to be icmp', 'match.icmp_type')

    try:
        priority = int(payload.get('priority', 100))
    except (TypeError, ValueError):
        raise RuleValidationError('priority must be an integer', 'priority')
    if priority < 1 or priority > 65535:
        raise RuleValidationError('priority must be between 1 and 65535', 'priority')

    scope = payload.get('scope') or {'switches': 'all'}
    if scope.get('switches', 'all') != 'all':
        raise RuleValidationError('only scope.switches=all is supported in v1', 'scope.switches', 'not_implemented')

    logging_cfg = payload.get('logging') or {'enabled': True, 'sample_rate': 1.0}
    stats_cfg = payload.get('stats') or {'enabled': True}

    created_at = payload.get('created_at') or now
    normalized = {
        'id': int(rule_id if rule_id is not None else payload.get('id', 0)),
        'name': str(payload.get('name') or 'Unnamed rule'),
        'description': str(payload.get('description') or ''),
        'enabled': bool(payload.get('enabled', True)),
        'priority': priority,
        'action': action,
        'direction': direction,
        'stateful': False,
        'match': {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': proto,
            'src_port': src_port,
            'dst_port': dst_port,
            'icmp_type': icmp_type
        },
        'scope': {'switches': 'all'},
        'logging': {
            'enabled': bool(logging_cfg.get('enabled', True)),
            'sample_rate': float(logging_cfg.get('sample_rate', 1.0))
        },
        'stats': {
            'enabled': bool(stats_cfg.get('enabled', True))
        },
        'created_at': created_at,
        'updated_at': payload.get('updated_at') or now
    }

    if normalized['logging']['sample_rate'] < 0 or normalized['logging']['sample_rate'] > 1:
        raise RuleValidationError('sample_rate must be between 0 and 1', 'logging.sample_rate')

    return normalized


def expanded_rule_matches(rule):
    matches = [deepcopy(rule['match'])]
    if rule.get('direction') == 'bidirectional':
        reverse = deepcopy(rule['match'])
        reverse['src_ip'], reverse['dst_ip'] = reverse.get('dst_ip'), reverse.get('src_ip')
        matches.append(reverse)
    return matches


class RuleStore:
    def __init__(self, path=None):
        self.path = path or default_rule_store_path()
        self.rules = []
        self.next_id = 1
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.rules = []
            self.next_id = 1
            return
        with open(self.path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        if isinstance(data, list):
            raw_rules = data
        else:
            raw_rules = data.get('rules', [])
        self.rules = [normalize_rule(rule, rule.get('id')) for rule in raw_rules]
        self.next_id = max([rule['id'] for rule in self.rules] or [0]) + 1

    def save(self):
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        data = {
            'version': 1,
            'next_id': self.next_id,
            'rules': self.rules
        }
        tmp_path = self.path + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write('\n')
        os.replace(tmp_path, self.path)

    def list(self):
        return deepcopy(self.rules)

    def get(self, rule_id):
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            return None
        for rule in self.rules:
            if rule['id'] == rule_id:
                return deepcopy(rule)
        return None

    def create(self, payload):
        rule = normalize_rule(payload, self.next_id)
        self.next_id += 1
        self.rules.append(rule)
        self.save()
        return deepcopy(rule)

    def update(self, rule_id, payload):
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            return None
        for index, current in enumerate(self.rules):
            if current['id'] == rule_id:
                updated = normalize_rule(payload, rule_id, current)
                self.rules[index] = updated
                self.save()
                return deepcopy(updated)
        return None

    def delete(self, rule_id):
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            return None
        for index, current in enumerate(self.rules):
            if current['id'] == rule_id:
                removed = self.rules.pop(index)
                self.save()
                return deepcopy(removed)
        return None
