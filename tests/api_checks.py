#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.error
import urllib.request


def request(base_url, method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(
        base_url.rstrip('/') + path,
        data=data,
        headers=headers,
        method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = resp.read().decode('utf-8')
            return resp.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode('utf-8')
        return exc.code, json.loads(payload) if payload else None
    except (urllib.error.URLError, TimeoutError):
        return 0, None


def check(condition, message):
    if condition:
        print('[PASS] ' + message)
        return True
    print('[FAIL] ' + message)
    return False


def load_json(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def get_rule(body):
    if isinstance(body, dict) and isinstance(body.get('rule'), dict):
        return body['rule']
    if isinstance(body, dict):
        return body
    return {}


def event_types_for_rule(events, rule_id):
    found = set()
    for event in events if isinstance(events, list) else []:
        candidates = {
            event.get('rule_id'),
            event.get('id'),
        }
        details = event.get('details') if isinstance(event.get('details'), dict) else {}
        candidates.add(details.get('rule_id'))
        candidates.add(details.get('id'))
        normalized = {str(item) for item in candidates if item is not None}
        if str(rule_id) in normalized and event.get('type'):
            found.add(event['type'])
    return found


def check_basic(base_url, fixtures_dir):
    ok = True

    status, body = request(base_url, 'GET', '/firewall/health')
    ok &= check(status == 200, 'health endpoint responds')
    ok &= check(body and body.get('status') == 'ok', 'health payload reports ok')

    status, body = request(base_url, 'GET', '/firewall/rules')
    ok &= check(status == 200, 'rules endpoint lists rules')
    ok &= check(isinstance(body, list), 'rules response is a list')

    invalid = load_json(fixtures_dir + '/invalid-port-without-proto.json')
    status, body = request(base_url, 'POST', '/firewall/rules', invalid)
    ok &= check(status == 400, 'invalid port rule returns 400')
    ok &= check(body and body.get('status') == 'error', 'invalid rule returns structured error')

    valid = load_json(fixtures_dir + '/block-h1-h2-icmp.json')
    status, body = request(base_url, 'POST', '/firewall/rules', valid)
    ok &= check(status == 201, 'valid ICMP rule returns 201')
    rule = get_rule(body)
    rule_id = rule.get('id')
    ok &= check(isinstance(rule_id, int), 'created rule has stable integer id')
    ok &= check(rule.get('match', {}).get('src_ip') == '10.0.0.1', 'created rule echoes source match')

    if rule_id is not None:
        status, body = request(base_url, 'GET', '/firewall/rules/{}'.format(rule_id))
        ok &= check(status == 200, 'created rule can be fetched by id')
        status, body = request(base_url, 'PATCH', '/firewall/rules/{}'.format(rule_id), {'enabled': False})
        ok &= check(status == 200 and get_rule(body).get('enabled') is False, 'rule can be disabled')
        status, body = request(base_url, 'DELETE', '/firewall/rules/{}'.format(rule_id))
        ok &= check(status == 200, 'rule can be deleted')

    return ok


def check_events(base_url, fixtures_dir):
    ok = True
    valid = load_json(fixtures_dir + '/block-h1-h2-icmp.json')
    status, body = request(base_url, 'POST', '/firewall/rules', valid)
    ok &= check(status == 201, 'event scenario creates rule')
    rule_id = get_rule(body).get('id')
    ok &= check(isinstance(rule_id, int), 'event scenario rule has id')
    if not isinstance(rule_id, int):
        return False

    status, body = request(base_url, 'PATCH', '/firewall/rules/{}'.format(rule_id), {'enabled': False})
    ok &= check(status == 200, 'event scenario updates rule')
    status, body = request(base_url, 'DELETE', '/firewall/rules/{}'.format(rule_id))
    ok &= check(status == 200, 'event scenario deletes rule')

    status, events = request(base_url, 'GET', '/firewall/events')
    ok &= check(status == 200, 'events endpoint responds')
    ok &= check(isinstance(events, list), 'events endpoint returns a list')

    expected = {'rule_created', 'rule_updated', 'rule_deleted'}
    found = event_types_for_rule(events, rule_id)
    ok &= check(expected.issubset(found), 'events include rule_created/rule_updated/rule_deleted for rule id')
    return ok


def check_topology_contract(base_url):
    ok = True

    status, switches = request(base_url, 'GET', '/firewall/switches')
    ok &= check(status == 200, 'switches endpoint responds')
    ok &= check(isinstance(switches, list), 'switches endpoint returns a list')
    for switch in switches if isinstance(switches, list) else []:
        ok &= check('dpid' in switch, 'switch entry includes dpid')

    status, topology = request(base_url, 'GET', '/firewall/topology')
    ok &= check(status == 200, 'topology endpoint responds')
    ok &= check(isinstance(topology, dict), 'topology endpoint returns an object')
    ok &= check('switches' in topology and 'links' in topology, 'topology has switches and links keys')
    ok &= check(isinstance(topology.get('switches'), list), 'topology switches is a list')
    ok &= check(isinstance(topology.get('links'), list), 'topology links is a list')

    status, anomalies = request(base_url, 'GET', '/firewall/topology/anomalies')
    ok &= check(status == 200, 'topology anomalies endpoint responds')
    ok &= check(isinstance(anomalies, list), 'topology anomalies returns a list')
    known_types = {
        'missing_switch',
        'unknown_switch',
        'missing_link',
        'unknown_link',
        'switch_reconnected',
    }
    for anomaly in anomalies if isinstance(anomalies, list) else []:
        ok &= check(isinstance(anomaly, dict), 'anomaly entry is an object')
        ok &= check('type' in anomaly and 'severity' in anomaly, 'anomaly includes type and severity')
        ok &= check(anomaly.get('type') in known_types, 'anomaly type is known')
    return ok


def check_rule_stats_shape(base_url, fixtures_dir):
    ok = True
    valid = load_json(fixtures_dir + '/block-h1-h2-icmp.json')
    status, body = request(base_url, 'POST', '/firewall/rules', valid)
    ok &= check(status == 201, 'stats scenario creates rule')
    rule_id = get_rule(body).get('id')
    if isinstance(rule_id, int):
        status, body = request(base_url, 'GET', '/firewall/rules/{}/stats'.format(rule_id))
        ok &= check(status == 200, 'rule stats endpoint responds')
        ok &= check(isinstance(body, dict), 'rule stats endpoint returns object')
        request(base_url, 'DELETE', '/firewall/rules/{}'.format(rule_id))
    return ok


def run(base_url, fixtures_dir, scenario):
    ok = True
    if scenario in ('basic', 'all'):
        ok &= check_basic(base_url, fixtures_dir)
    if scenario in ('events', 'all'):
        ok &= check_events(base_url, fixtures_dir)
    if scenario == 'topology':
        ok &= check_topology_contract(base_url)
    if scenario in ('stats', 'all'):
        ok &= check_rule_stats_shape(base_url, fixtures_dir)
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='http://127.0.0.1:8080')
    parser.add_argument('--fixtures-dir', default='tests/fixtures/rules')
    parser.add_argument('--scenario', choices=('basic', 'events', 'topology', 'stats', 'all'), default='all')
    args = parser.parse_args()
    sys.exit(run(args.base_url, args.fixtures_dir, args.scenario))


if __name__ == '__main__':
    main()
