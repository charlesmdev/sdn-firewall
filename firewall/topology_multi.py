import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController


BASE_URL = 'http://127.0.0.1:8080'
SCENARIO_FILE = Path('/tmp/sdn-firewall-topology-scenario')
SCENARIOS = ('dataplane', 'one-way', 'bidirectional', 'topology', 'tcp', 'replay', 'all')


def default_scenario():
    if SCENARIO_FILE.exists():
        scenario = SCENARIO_FILE.read_text(encoding='utf-8').strip()
        if scenario:
            return scenario
    return 'one-way'


def api_request(method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = resp.read().decode('utf-8')
        return json.loads(payload) if payload else None


def wait_for_switches(expected=3, timeout=15):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            switches = api_request('GET', '/firewall/switches')
            last = switches
            if isinstance(switches, list) and len(switches) >= expected:
                return switches
        except (urllib.error.URLError, TimeoutError, ValueError):
            pass
        time.sleep(0.5)
    raise RuntimeError('controller did not report {} switches; last={!r}'.format(expected, last))


def clear_rules():
    rules = api_request('GET', '/firewall/rules')
    for rule in list(rules):
        api_request('DELETE', '/firewall/rules/{}'.format(rule['id']))


def assert_ping(host, target_ip, should_succeed):
    output = host.cmd('ping -c 2 -W 1 {}'.format(target_ip))
    success = '0% packet loss' in output
    blocked = '100% packet loss' in output
    if should_succeed and not success:
        raise RuntimeError('expected ping to {} to succeed:\n{}'.format(target_ip, output))
    if not should_succeed and not blocked:
        raise RuntimeError('expected ping to {} to be blocked:\n{}'.format(target_ip, output))
    print('[PASS] {} ping {} {}'.format(host.name, target_ip, 'succeeded' if should_succeed else 'blocked'))


def host_cmd(host, command, timeout=8):
    wrapped = "timeout {} bash -lc '{}'".format(timeout, command.replace("'", "'\\''"))
    output = host.cmd(wrapped)
    print('[HOST {}] {}\n{}'.format(host.name, command, output.strip()))
    return output


def wait_for_rule_stats(rule_id, minimum_packets=1, timeout=12):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        stats = api_request('GET', '/firewall/rules/{}/stats'.format(rule_id))
        last = stats
        if stats.get('packet_count', 0) >= minimum_packets:
            return stats
        time.sleep(1)
    raise RuntimeError('expected rule stats to increment, got {}'.format(last))


def create_rule(rule):
    created = api_request('POST', '/firewall/rules', rule)
    if not isinstance(created, dict) or not isinstance(created.get('rule'), dict):
        raise RuntimeError('rule creation did not return rule object: {}'.format(created))
    if not isinstance(created['rule'].get('id'), int):
        raise RuntimeError('created rule did not include integer id: {}'.format(created))
    return created['rule'], created


def delete_rule(rule_id):
    api_request('DELETE', '/firewall/rules/{}'.format(rule_id))


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(s1, s2)
    net.addLink(h3, s2)
    net.addLink(s2, s3)
    net.addLink(h4, s3)

    return net


def assert_baseline_paths(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    assert_ping(h1, '10.0.0.2', should_succeed=True)
    assert_ping(h1, '10.0.0.3', should_succeed=True)
    assert_ping(h1, '10.0.0.4', should_succeed=True)
    assert_ping(h2, '10.0.0.4', should_succeed=True)


def scenario_dataplane(net):
    loss_pct = net.pingAll()
    if loss_pct != 0:
        raise RuntimeError('baseline pingall had {}% packet loss'.format(loss_pct))
    print('[PASS] baseline pingall reached all hosts')
    assert_baseline_paths(net)


def scenario_one_way(net):
    scenario_dataplane(net)
    h1 = net.get('h1')
    rule, created = create_rule({
        'name': 'Smoke block h1 to h2 ICMP',
        'description': 'Non-interactive dataplane smoke test rule',
        'action': 'block',
        'direction': 'one-way',
        'match': {'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'proto': 'icmp'}
    })
    installed = created.get('flows_installed', [])
    if len(installed) < 3:
        raise RuntimeError('expected rule to install on 3 switches, got {}'.format(installed))
    print('[PASS] block rule installed on all switches')

    assert_ping(h1, '10.0.0.2', should_succeed=False)
    wait_for_rule_stats(rule['id'])
    print('[PASS] OpenFlow stats counted blocked packets')

    delete_rule(rule['id'])
    assert_ping(h1, '10.0.0.2', should_succeed=True)
    print('[PASS] deleting rule restored connectivity')


def scenario_bidirectional(net):
    h1 = net.get('h1')
    h3 = net.get('h3')
    assert_ping(h1, '10.0.0.3', should_succeed=True)
    assert_ping(h3, '10.0.0.1', should_succeed=True)
    rule, created = create_rule({
        'name': 'Test bidirectional ICMP h1 h3',
        'description': 'Contract test for two-way ICMP block',
        'action': 'block',
        'direction': 'bidirectional',
        'match': {'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.3', 'proto': 'icmp'},
    })
    installed = created.get('flows_installed', [])
    flow_counts = [item.get('flows') for item in installed if isinstance(item, dict)]
    if len(flow_counts) < 3 or not all(isinstance(count, int) and count >= 2 for count in flow_counts):
        raise RuntimeError('expected bidirectional rule to install two flows per switch, got {}'.format(installed))
    print('[PASS] bidirectional rule installed on all switches')

    assert_ping(h1, '10.0.0.3', should_succeed=False)
    assert_ping(h3, '10.0.0.1', should_succeed=False)
    delete_rule(rule['id'])
    assert_ping(h1, '10.0.0.3', should_succeed=True)
    assert_ping(h3, '10.0.0.1', should_succeed=True)
    print('[PASS] bidirectional delete restored both directions')


def scenario_topology(net):
    switches = wait_for_switches()
    dpids = {int(item.get('dpid')) for item in switches if str(item.get('dpid')).isdigit()}
    if dpids != {1, 2, 3}:
        raise RuntimeError('expected switch DPIDs {1,2,3}, got {}'.format(sorted(dpids)))
    print('[PASS] switch endpoint reports DPID set {1,2,3}')

    topology = api_request('GET', '/firewall/topology')
    if not isinstance(topology, dict):
        raise RuntimeError('topology endpoint did not return object: {}'.format(topology))
    if not isinstance(topology.get('switches'), list) or not isinstance(topology.get('links'), list):
        raise RuntimeError('topology endpoint lacks switches/links lists: {}'.format(topology))
    topology_text = json.dumps(topology, sort_keys=True)
    if not all(str(dpid) in topology_text for dpid in (1, 2, 3)):
        raise RuntimeError('topology response did not include switch metadata: {}'.format(topology))
    print('[PASS] topology endpoint is structured and includes expected switches')

    anomalies = api_request('GET', '/firewall/topology/anomalies')
    if not isinstance(anomalies, list):
        raise RuntimeError('topology anomalies endpoint did not return list: {}'.format(anomalies))
    known_types = {'missing_switch', 'unknown_switch', 'missing_link', 'unknown_link', 'switch_reconnected'}
    for anomaly in anomalies:
        if not isinstance(anomaly, dict) or 'type' not in anomaly or 'severity' not in anomaly:
            raise RuntimeError('malformed anomaly entry: {}'.format(anomaly))
        if anomaly.get('type') not in known_types:
            raise RuntimeError('unknown anomaly type: {}'.format(anomaly))
        if anomaly.get('type') == 'unknown_switch' and str(anomaly.get('dpid')) in {'1', '2', '3'}:
            raise RuntimeError('expected switch reported as unknown: {}'.format(anomaly))
    print('[PASS] topology anomaly endpoint has valid shape')


def tcp_connect_ok(h3):
    command = (
        "python3 -c \"import socket,sys; "
        "s=socket.create_connection(('10.0.0.4',80),2); "
        "s.sendall(b'GET / HTTP/1.0\\\\r\\\\n\\\\r\\\\n'); "
        "data=s.recv(16); s.close(); sys.exit(0 if data else 2)\"; echo RC:$?"
    )
    return 'RC:0' in host_cmd(h3, command, timeout=5)


def scenario_tcp(net):
    h3 = net.get('h3')
    h4 = net.get('h4')
    server_pid = host_cmd(h4, 'python3 -m http.server 80 >/tmp/sdn-h4-http.log 2>&1 & echo $!', timeout=3).strip()
    try:
        time.sleep(1)
        if not tcp_connect_ok(h3):
            raise RuntimeError('baseline h3 could not reach h4 TCP port 80')
        print('[PASS] baseline h3 can reach h4 TCP port 80')
        rule, _created = create_rule({
            'name': 'Block h3 to h4 HTTP',
            'description': 'TCP destination-port filtering example',
            'enabled': True,
            'priority': 110,
            'action': 'block',
            'direction': 'one-way',
            'stateful': False,
            'match': {'src_ip': '10.0.0.3', 'dst_ip': '10.0.0.4', 'proto': 'tcp', 'dst_port': 80},
        })
        time.sleep(1)
        if tcp_connect_ok(h3):
            raise RuntimeError('h3 reached h4 TCP port 80 after block rule')
        print('[PASS] h3 cannot reach h4 TCP port 80 after block rule')
        delete_rule(rule['id'])
        if not tcp_connect_ok(h3):
            raise RuntimeError('h3 could not reach h4 TCP port 80 after delete')
        print('[PASS] h3 can reach h4 TCP port 80 after delete')
    finally:
        if server_pid:
            host_cmd(h4, 'kill {}'.format(server_pid), timeout=3)


def scenario_replay(net):
    h1 = net.get('h1')
    wait_for_switches()
    assert_ping(h1, '10.0.0.2', should_succeed=False)
    rules = api_request('GET', '/firewall/rules')
    rule_id = rules[0]['id'] if rules else None
    if rule_id is None:
        raise RuntimeError('expected persisted rule to be loaded')
    wait_for_rule_stats(rule_id)
    print('[PASS] replayed rule blocked traffic and stats incremented')
    delete_rule(rule_id)
    assert_ping(h1, '10.0.0.2', should_succeed=True)
    print('[PASS] deleting replayed rule restored connectivity')


def run_cli():
    net = build_topology()
    net.start()
    print("[*] Multi-switch network started. Controller expected at 127.0.0.1:6653")
    print("[*] Topology: h1/h2-s1-s2-s3-h4 with h3 on s2")
    CLI(net)
    net.stop()


def run_smoke():
    net = build_topology()
    try:
        net.start()
        print("[*] Multi-switch network started. Controller expected at 127.0.0.1:6653")
        print("[*] Topology: h1/h2-s1-s2-s3-h4 with h3 on s2")

        wait_for_switches()
        clear_rules()
        scenario_one_way(net)
    finally:
        net.stop()


def run_scenario(scenario):
    net = build_topology()
    try:
        net.start()
        print("[*] Multi-switch network started. Controller expected at 127.0.0.1:6653")
        print("[*] Topology: h1/h2-s1-s2-s3-h4 with h3 on s2")
        wait_for_switches()
        if scenario != 'replay':
            clear_rules()
        if scenario == 'dataplane':
            scenario_dataplane(net)
        elif scenario == 'one-way':
            scenario_one_way(net)
        elif scenario == 'bidirectional':
            scenario_bidirectional(net)
        elif scenario == 'topology':
            scenario_topology(net)
        elif scenario == 'tcp':
            scenario_tcp(net)
        elif scenario == 'replay':
            scenario_replay(net)
        elif scenario == 'all':
            scenario_one_way(net)
            clear_rules()
            scenario_bidirectional(net)
            clear_rules()
            scenario_topology(net)
            clear_rules()
            scenario_tcp(net)
        else:
            raise RuntimeError('unknown scenario {}'.format(scenario))
    finally:
        net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', action='store_true', help='open the interactive Mininet CLI')
    parser.add_argument(
        '--scenario',
        choices=SCENARIOS,
        default=default_scenario()
    )
    args = parser.parse_args()

    setLogLevel('info')
    if args.cli:
        run_cli()
    else:
        try:
            run_scenario(args.scenario)
        except Exception as exc:
            print('[FAIL] {}'.format(exc), file=sys.stderr)
            sys.exit(1)
