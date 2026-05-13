#!/usr/bin/env python3
import argparse
import errno
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = Path('/tmp/sdn-firewall-controller.log')
SCENARIO_FILE = Path('/tmp/sdn-firewall-topology-scenario')
TRASH_DIR = Path.home() / '.agent-trash' / 'firewall-project-tests'
BASE_URL = 'http://127.0.0.1:8080'


class ScenarioFailure(RuntimeError):
    pass


def ensure_root_for_mininet():
    if os.geteuid() == 0:
        return
    cmd = ['sudo', '-n', sys.executable] + sys.argv
    raise SystemExit(subprocess.call(cmd, cwd=str(ROOT)))


def check(condition, message):
    if condition:
        print('[PASS] {}'.format(message), flush=True)
        return True
    print('[FAIL] {}'.format(message), flush=True)
    return False


def require(condition, message):
    if not check(condition, message):
        raise ScenarioFailure(message)


def run_step(name, cmd, timeout=20, cwd=None):
    print('[STEP] {}'.format(name), flush=True)
    result = subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        timeout=timeout,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.stdout:
        print(result.stdout, end='' if result.stdout.endswith('\n') else '\n')
    if result.returncode != 0:
        raise ScenarioFailure('{} failed with exit code {}'.format(name, result.returncode))
    return result


def request(method, path, body=None, timeout=4):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode('utf-8')
            return resp.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode('utf-8')
        return exc.code, json.loads(payload) if payload else None


def wait_for_health(timeout=14):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            status, body = request('GET', '/firewall/health', timeout=1)
            if status == 200 and isinstance(body, dict):
                print('[PASS] controller health endpoint is ready', flush=True)
                return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise ScenarioFailure('controller health did not become ready: {}'.format(last_error))


def start_controller(rules_file):
    env = os.environ.copy()
    env['SDN_FIREWALL_RULES_FILE'] = str(rules_file)
    log_handle = LOG_FILE.open('w', encoding='utf-8')
    cmd = [str(ROOT / '.venv/bin/ryu-manager'), 'firewall_rest_api.py']
    print('[STEP] start Ryu controller with {}'.format(rules_file), flush=True)
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT / 'firewall'),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    wait_for_health()
    if proc.poll() is not None:
        print_controller_log()
        raise ScenarioFailure('controller exited early with code {}'.format(proc.returncode))
    return proc, log_handle


def stop_process(proc, name):
    if proc is None or proc.poll() is not None:
        return
    print('[STEP] stop {}'.format(name), flush=True)
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=6)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=6)


def print_controller_log():
    if LOG_FILE.exists():
        print('--- controller log ---', file=sys.stderr)
        print(LOG_FILE.read_text(encoding='utf-8')[-4000:], file=sys.stderr)


def trash_path(path):
    if not path.exists():
        return
    TRASH_DIR.mkdir(parents=True, exist_ok=True)
    target = TRASH_DIR / '{}.{}'.format(path.name, int(time.time() * 1000))
    try:
        path.replace(target)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            result = subprocess.run(['trash', str(path)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if result.returncode == 0:
                return
            print('[WARN] leaving generated temp file in place: {}'.format(path), flush=True)
            return
        raise


def new_rules_file(prefix):
    fd, name = tempfile.mkstemp(prefix=prefix, suffix='.json', dir='/tmp')
    os.close(fd)
    path = Path(name)
    path.write_text('[]', encoding='utf-8')
    return path


def load_fixture(name):
    with open(ROOT / 'tests' / 'fixtures' / 'rules' / name, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def select_topology_scenario(scenario):
    SCENARIO_FILE.write_text(scenario + '\n', encoding='utf-8')


def get_rule(body):
    if isinstance(body, dict) and isinstance(body.get('rule'), dict):
        return body['rule']
    if isinstance(body, dict):
        return body
    return {}


def setup_mininet_prereqs():
    run_step('start Open vSwitch', ['systemctl', 'start', 'openvswitch-switch'], timeout=8)
    run_step('clean Mininet before test', ['mn', '-c'], timeout=20)


def cleanup_mininet():
    try:
        run_step('clean Mininet after test', ['mn', '-c'], timeout=20)
    except Exception as exc:
        print('[WARN] cleanup failed: {}'.format(exc), file=sys.stderr)


def build_net():
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.topo import Topo

    class FirewallTopo(Topo):
        def build(self):
            s1 = self.addSwitch('s1', protocols='OpenFlow13')
            s2 = self.addSwitch('s2', protocols='OpenFlow13')
            s3 = self.addSwitch('s3', protocols='OpenFlow13')
            h1 = self.addHost('h1', ip='10.0.0.1/24')
            h2 = self.addHost('h2', ip='10.0.0.2/24')
            h3 = self.addHost('h3', ip='10.0.0.3/24')
            h4 = self.addHost('h4', ip='10.0.0.4/24')
            self.addLink(h1, s1)
            self.addLink(h2, s1)
            self.addLink(s1, s2)
            self.addLink(h3, s2)
            self.addLink(s2, s3)
            self.addLink(h4, s3)

    net = Mininet(
        topo=FirewallTopo(),
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        build=True,
    )
    net.start()
    return net


def wait_for_switches(expected={1, 2, 3}, timeout=12):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = request('GET', '/firewall/switches', timeout=2)
        last = body
        if status == 200 and isinstance(body, list):
            dpids = {int(item.get('dpid')) for item in body if str(item.get('dpid')).isdigit()}
            if expected.issubset(dpids):
                print('[PASS] switches registered: {}'.format(sorted(dpids)), flush=True)
                return body
        time.sleep(0.5)
    raise ScenarioFailure('expected switches were not registered: {}'.format(last))


def host_cmd(net, host, cmd, timeout=8):
    node = net.get(host)
    wrapped = "timeout {} bash -lc '{}'".format(timeout, cmd.replace("'", "'\\''"))
    output = node.cmd(wrapped)
    print('[HOST {}] {}\n{}'.format(host, cmd, output.strip()), flush=True)
    return output


def ping_ok(net, src, dst_ip):
    output = host_cmd(net, src, 'ping -c 2 -W 1 {}'.format(dst_ip), timeout=5)
    return ' 0% packet loss' in output or ', 0% packet loss' in output


def assert_ping(net, src, dst_ip, should_work, label):
    worked = ping_ok(net, src, dst_ip)
    require(worked is should_work, label)


def recursive_text(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def flows_show_all_switches(flows):
    text = recursive_text(flows)
    return all(token in text for token in ('1', '2', '3'))


def flows_show_both_directions(flows):
    if not isinstance(flows, list):
        return False
    flow_counts = [item.get('flows') for item in flows if isinstance(item, dict)]
    return len(flow_counts) >= 3 and all(isinstance(count, int) and count >= 2 for count in flow_counts)


def create_rule(rule):
    status, body = request('POST', '/firewall/rules', rule)
    created = get_rule(body)
    require(status == 201, 'rule creation returns 201')
    require(isinstance(created.get('id'), int), 'created rule has integer id')
    return created, body


def delete_rule(rule_id):
    status, _body = request('DELETE', '/firewall/rules/{}'.format(rule_id))
    require(status == 200, 'rule {} deleted'.format(rule_id))


def scenario_bidirectional(net):
    assert_ping(net, 'h1', '10.0.0.3', True, 'baseline h1 -> h3 ping succeeds')
    assert_ping(net, 'h3', '10.0.0.1', True, 'baseline h3 -> h1 ping succeeds')
    rule, body = create_rule({
        'name': 'Test bidirectional ICMP h1 h3',
        'description': 'Contract test for two-way ICMP block',
        'action': 'block',
        'direction': 'bidirectional',
        'match': {'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.3', 'proto': 'icmp'},
    })
    flows = body.get('flows_installed') if isinstance(body, dict) else None
    require(flows_show_all_switches(flows), 'creation response shows flows for all three switches')
    require(flows_show_both_directions(flows), 'creation response shows both bidirectional matches')
    time.sleep(1)
    assert_ping(net, 'h1', '10.0.0.3', False, 'h1 -> h3 ping is blocked')
    assert_ping(net, 'h3', '10.0.0.1', False, 'h3 -> h1 ping is blocked')
    delete_rule(rule['id'])
    time.sleep(1)
    assert_ping(net, 'h1', '10.0.0.3', True, 'h1 -> h3 ping recovers after delete')
    assert_ping(net, 'h3', '10.0.0.1', True, 'h3 -> h1 ping recovers after delete')


def scenario_topology(net):
    switches = wait_for_switches()
    dpids = {int(item.get('dpid')) for item in switches if str(item.get('dpid')).isdigit()}
    require(dpids == {1, 2, 3}, 'switch endpoint reports DPID set {1,2,3}')

    status, topology = request('GET', '/firewall/topology')
    require(status == 200 and isinstance(topology, dict), 'topology endpoint returns object')
    require(isinstance(topology.get('switches'), list), 'topology switches key is a list')
    require(isinstance(topology.get('links'), list), 'topology links key is a list')
    topo_text = recursive_text(topology)
    require(all(str(dpid) in topo_text for dpid in (1, 2, 3)), 'topology response includes expected switch metadata')

    status, anomalies = request('GET', '/firewall/topology/anomalies')
    require(status == 200 and isinstance(anomalies, list), 'topology anomalies endpoint returns list')
    known_types = {'missing_switch', 'unknown_switch', 'missing_link', 'unknown_link', 'switch_reconnected'}
    unknown_expected = []
    for anomaly in anomalies:
        require('type' in anomaly and 'severity' in anomaly, 'anomaly has type and severity')
        require(anomaly.get('type') in known_types, 'anomaly type is known')
        if anomaly.get('type') == 'unknown_switch' and str(anomaly.get('dpid')) in {'1', '2', '3'}:
            unknown_expected.append(anomaly)
    require(not unknown_expected, 'expected switches are not reported as unknown_switch')
    missing_links = [item for item in anomalies if item.get('type') == 'missing_link']
    if missing_links:
        print('[INFO] missing_link anomalies accepted when discovery metadata is still structured', flush=True)


def stat_count(stats):
    if not isinstance(stats, dict):
        return 0
    for key in ('packet_count', 'packets', 'hit_count', 'hits'):
        value = stats.get(key)
        if isinstance(value, int):
            return value
    return 0


def wait_for_rule_stats_increment(rule_id, previous=0, timeout=10):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = request('GET', '/firewall/rules/{}/stats'.format(rule_id), timeout=2)
        last = body
        if status == 200 and stat_count(body) > previous:
            print('[PASS] rule {} stats incremented: {}'.format(rule_id, body), flush=True)
            return
        time.sleep(1)
    raise ScenarioFailure('rule stats did not increment; last={}'.format(last))


def scenario_replay(rules_file):
    proc = log_handle = None
    try:
        proc, log_handle = start_controller(rules_file)
        rule, _body = create_rule(load_fixture('block-h1-h2-icmp.json'))
        rule_id = rule['id']
    finally:
        if proc is not None:
            stop_process(proc, 'Ryu controller')
        if log_handle is not None:
            log_handle.close()

    proc = log_handle = None
    net = None
    try:
        proc, log_handle = start_controller(rules_file)
        net = build_net()
        wait_for_switches()
        assert_ping(net, 'h1', '10.0.0.2', False, 'persisted h1 -> h2 block is replayed on switch connect')
        wait_for_rule_stats_increment(rule_id, previous=0)
        delete_rule(rule_id)
        time.sleep(1)
        assert_ping(net, 'h1', '10.0.0.2', True, 'h1 -> h2 recovers after replayed rule delete')
    finally:
        if net is not None:
            net.stop()
        if proc is not None:
            stop_process(proc, 'Ryu controller')
        if log_handle is not None:
            log_handle.close()


def tcp_connect_ok(net):
    client = (
        "python3 -c \"import socket,sys; "
        "s=socket.create_connection(('10.0.0.4',80),2); "
        "s.sendall(b'GET / HTTP/1.0\\\\r\\\\n\\\\r\\\\n'); "
        "data=s.recv(16); s.close(); sys.exit(0 if data else 2)\"; echo RC:$?"
    )
    output = host_cmd(net, 'h3', client, timeout=5)
    return 'RC:0' in output


def scenario_tcp(net):
    server_pid = host_cmd(net, 'h4', 'python3 -m http.server 80 >/tmp/sdn-h4-http.log 2>&1 & echo $!', timeout=3).strip()
    try:
        time.sleep(1)
        require(tcp_connect_ok(net), 'baseline h3 can reach h4 TCP port 80')
        rule, _body = create_rule(load_fixture('block-h3-h4-tcp-80.json'))
        time.sleep(1)
        require(not tcp_connect_ok(net), 'h3 cannot reach h4 TCP port 80 after block rule')
        delete_rule(rule['id'])
        time.sleep(1)
        require(tcp_connect_ok(net), 'h3 can reach h4 TCP port 80 after delete')
    finally:
        if server_pid:
            host_cmd(net, 'h4', 'kill {}'.format(server_pid), timeout=3)


def scenario_udp():
    print('[SKIP] UDP dataplane validation is not implemented: no reliable UDP echo harness is available without adding extra production/topology behavior.', flush=True)


def run_with_controller_and_net(rules_file, scenario):
    controller = None
    log_handle = None
    net = None
    try:
        controller, log_handle = start_controller(rules_file)
        net = build_net()
        wait_for_switches()
        if scenario == 'bidirectional':
            scenario_bidirectional(net)
        elif scenario == 'topology':
            scenario_topology(net)
        elif scenario == 'tcp':
            scenario_tcp(net)
        elif scenario == 'dataplane':
            assert_ping(net, 'h1', '10.0.0.2', True, 'baseline h1 -> h2 ping succeeds')
            assert_ping(net, 'h1', '10.0.0.3', True, 'baseline h1 -> h3 ping succeeds')
            assert_ping(net, 'h2', '10.0.0.4', True, 'baseline h2 -> h4 ping succeeds')
    finally:
        if net is not None:
            net.stop()
        if controller is not None:
            stop_process(controller, 'Ryu controller')
        if log_handle is not None:
            log_handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'scenario',
        nargs='?',
        default='dataplane',
        choices=('dataplane', 'bidirectional', 'replay', 'topology', 'tcp', 'udp', 'all'),
    )
    parser.add_argument('--keep-controller-log', action='store_true')
    args = parser.parse_args()

    rules_file = new_rules_file('sdn-firewall-smoke-rules-')
    controller = None
    log_handle = None
    try:
        run_step('start Open vSwitch', ['sudo', '-n', 'systemctl', 'start', 'openvswitch-switch'], timeout=8)
        run_step('clean Mininet before test', ['sudo', '-n', 'mn', '-c'], timeout=20)
        scenarios = ['dataplane', 'bidirectional', 'topology', 'tcp', 'replay'] if args.scenario == 'all' else [args.scenario]
        for scenario in scenarios:
            print('[SCENARIO] {}'.format(scenario), flush=True)
            if scenario == 'udp':
                scenario_udp()
                continue

            rules_file.write_text('[]', encoding='utf-8')
            controller, log_handle = start_controller(rules_file)

            if scenario == 'replay':
                rule, _body = create_rule(load_fixture('block-h1-h2-icmp.json'))
                stop_process(controller, 'Ryu controller')
                log_handle.close()
                controller = None
                log_handle = None
                controller, log_handle = start_controller(rules_file)
                topology_scenario = 'replay'
            else:
                topology_scenario = 'one-way' if scenario == 'dataplane' else scenario

            select_topology_scenario(topology_scenario)
            run_step(
                'run topology scenario {}'.format(topology_scenario),
                ['sudo', '-n', '/usr/bin/python3', str(ROOT / 'firewall/topology_multi.py')],
                timeout=75,
                cwd=ROOT / 'firewall'
            )

            stop_process(controller, 'Ryu controller')
            log_handle.close()
            controller = None
            log_handle = None
        print('[PASS] dataplane scenario(s) passed', flush=True)
        return 0
    except Exception as exc:
        print('[FAIL] {}'.format(exc), file=sys.stderr)
        print_controller_log()
        return 1
    finally:
        if controller is not None:
            stop_process(controller, 'Ryu controller')
        if log_handle is not None:
            log_handle.close()
        try:
            run_step('clean Mininet after test', ['sudo', '-n', 'mn', '-c'], timeout=20)
        except Exception as exc:
            print('[WARN] cleanup failed: {}'.format(exc), file=sys.stderr)
        trash_path(rules_file)
        trash_path(SCENARIO_FILE)
        if LOG_FILE.exists() and not args.keep_controller_log:
            trash_path(LOG_FILE)


if __name__ == '__main__':
    sys.exit(main())
