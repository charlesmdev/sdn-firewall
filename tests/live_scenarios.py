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
BASE_URL = 'http://127.0.0.1:8080'
LOG_FILE = Path('/tmp/sdn-firewall-live-scenarios-controller.log')
TRASH_DIR = Path.home() / '.agent-trash' / 'firewall-project-tests'


def check(condition, message):
    if condition:
        print('[PASS] ' + message)
        return True
    print('[FAIL] ' + message)
    return False


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


def load_fixture(name):
    with open(ROOT / 'tests' / 'fixtures' / 'rules' / name, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def get_rule(body):
    if isinstance(body, dict) and isinstance(body.get('rule'), dict):
        return body['rule']
    if isinstance(body, dict):
        return body
    return {}


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
    return proc, log_handle


def stop_controller(proc, log_handle):
    if proc.poll() is None:
        print('[STEP] stop Ryu controller', flush=True)
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=6)
    log_handle.close()


def wait_for_health(timeout=12):
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
    raise RuntimeError('controller health did not become ready: {}'.format(last_error))


def run_cmd(name, cmd, timeout=8, env=None):
    print('[STEP] {}'.format(name), flush=True)
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        timeout=timeout,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )


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


def scenario_persistence():
    ok = True
    rules_fd, rules_name = tempfile.mkstemp(prefix='sdn-firewall-persistence-', suffix='.json', dir='/tmp')
    os.close(rules_fd)
    rules_file = Path(rules_name)
    rules_file.write_text('[]', encoding='utf-8')
    proc = log_handle = None
    rule_id = None
    try:
        proc, log_handle = start_controller(rules_file)
        fixture = load_fixture('block-h1-h2-icmp.json')
        status, body = request('POST', '/firewall/rules', fixture)
        rule = get_rule(body)
        rule_id = rule.get('id')
        ok &= check(status == 201, 'persistence scenario creates rule')
        ok &= check(isinstance(rule_id, int), 'persisted rule has integer id')
        ok &= check(rule.get('name') == fixture['name'], 'created rule name matches fixture')
        stop_controller(proc, log_handle)
        proc = log_handle = None

        proc, log_handle = start_controller(rules_file)
        status, body = request('GET', '/firewall/rules')
        rules = body if isinstance(body, list) else []
        matching = [item for item in rules if item.get('id') == rule_id]
        ok &= check(status == 200, 'rules list works after restart')
        ok &= check(len(matching) == 1, 'persisted rule is loaded after restart')
        if matching:
            loaded = matching[0]
            ok &= check(loaded.get('name') == fixture['name'], 'persisted rule keeps name')
            ok &= check(loaded.get('direction') == fixture['direction'], 'persisted rule keeps direction')
            ok &= check(loaded.get('match', {}).get('src_ip') == fixture['match']['src_ip'], 'persisted rule keeps match')

        if isinstance(rule_id, int):
            status, _body = request('DELETE', '/firewall/rules/{}'.format(rule_id))
            ok &= check(status == 200, 'persisted rule can be deleted')
        stop_controller(proc, log_handle)
        proc = log_handle = None

        proc, log_handle = start_controller(rules_file)
        status, body = request('GET', '/firewall/rules')
        rules = body if isinstance(body, list) else []
        ok &= check(status == 200, 'rules list works after delete restart')
        ok &= check(all(item.get('id') != rule_id for item in rules), 'deleted rule stays deleted after restart')
    finally:
        if proc is not None and log_handle is not None:
            stop_controller(proc, log_handle)
        trash_path(rules_file)
    return ok


def scenario_demo():
    ok = True
    rules_fd, rules_name = tempfile.mkstemp(prefix='sdn-firewall-demo-', suffix='.json', dir='/tmp')
    os.close(rules_fd)
    rules_file = Path(rules_name)
    rules_file.write_text('[]', encoding='utf-8')
    proc = log_handle = None
    try:
        proc, log_handle = start_controller(rules_file)
        env = os.environ.copy()
        env['SDN_FIREWALL_BASE_URL'] = BASE_URL
        scenarios = ('health', 'list-rules', 'stats', 'events')
        for scenario in scenarios:
            result = run_cmd(
                'demo scenario {}'.format(scenario),
                [str(ROOT / 'scripts' / 'demo.sh'), '--scenario', scenario],
                timeout=6,
                env=env,
            )
            output = result.stdout.strip()
            ok &= check(result.returncode == 0, 'demo {} exits 0'.format(scenario))
            ok &= check(output.startswith('{') or output.startswith('['), 'demo {} emits JSON-ish output'.format(scenario))
    finally:
        if proc is not None and log_handle is not None:
            stop_controller(proc, log_handle)
        trash_path(rules_file)
    return ok


def scenario_tui():
    result = run_cmd('TUI smoke with short timeout', ['timeout', '4', sys.executable, str(ROOT / 'scripts' / 'tui.py')], timeout=7)
    output = result.stdout or ''
    missing_rich = 'requires: python -m pip install rich' in output and result.returncode == 1
    timed_out_without_traceback = result.returncode == 124 and 'Traceback' not in output
    clean_exit = result.returncode == 0 and 'Traceback' not in output
    ok = missing_rich or timed_out_without_traceback or clean_exit
    check(ok, 'TUI handles missing rich or controller-down smoke without traceback')
    if output.strip():
        print(output[-1200:])
    return ok


def scenario_api_checks(api_scenario):
    rules_fd, rules_name = tempfile.mkstemp(prefix='sdn-firewall-api-', suffix='.json', dir='/tmp')
    os.close(rules_fd)
    rules_file = Path(rules_name)
    rules_file.write_text('[]', encoding='utf-8')
    proc = log_handle = None
    try:
        proc, log_handle = start_controller(rules_file)
        result = run_cmd(
            'API contract checks {}'.format(api_scenario),
            [
                sys.executable,
                str(ROOT / 'tests' / 'api_checks.py'),
                '--base-url',
                BASE_URL,
                '--fixtures-dir',
                str(ROOT / 'tests' / 'fixtures' / 'rules'),
                '--scenario',
                api_scenario,
            ],
            timeout=20,
        )
        if result.stdout:
            print(result.stdout, end='' if result.stdout.endswith('\n') else '\n')
        ok = result.returncode == 0
        check(ok, 'API contract checks {} exit 0'.format(api_scenario))
        return ok
    finally:
        if proc is not None and log_handle is not None:
            stop_controller(proc, log_handle)
        trash_path(rules_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('scenario', choices=('api', 'events', 'stats', 'persistence', 'demo', 'tui'))
    args = parser.parse_args()
    try:
        if args.scenario == 'api':
            ok = scenario_api_checks('all')
        elif args.scenario == 'events':
            ok = scenario_api_checks('events')
        elif args.scenario == 'stats':
            ok = scenario_api_checks('stats')
        elif args.scenario == 'persistence':
            ok = scenario_persistence()
        elif args.scenario == 'demo':
            ok = scenario_demo()
        else:
            ok = scenario_tui()
        return 0 if ok else 1
    except Exception as exc:
        print('[FAIL] {}'.format(exc), file=sys.stderr)
        if LOG_FILE.exists():
            print('--- controller log ---', file=sys.stderr)
            print(LOG_FILE.read_text(encoding='utf-8')[-4000:], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
