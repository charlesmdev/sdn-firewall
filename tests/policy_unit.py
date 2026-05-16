#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'firewall'))

from policy import RuleValidationError, expanded_rule_matches, normalize_rule


def check(condition, message):
    if condition:
        print('[PASS] ' + message)
        return True
    print('[FAIL] ' + message)
    return False


def load_fixture(name):
    with open(ROOT / 'tests' / 'fixtures' / 'rules' / name, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def main():
    ok = True
    rule = normalize_rule(load_fixture('block-h1-h2-icmp.json'), 1)
    ok &= check(rule['id'] == 1, 'normalization assigns requested id')
    ok &= check(rule['match']['proto'] == 'icmp', 'ICMP proto is accepted')

    bidir = normalize_rule(load_fixture('block-h1-h3-bidir.json'), 2)
    matches = expanded_rule_matches(bidir)
    ok &= check(len(matches) == 2, 'bidirectional rule expands to two matches')
    ok &= check(matches[1]['src_ip'] == '10.0.0.3', 'reverse match swaps source')

    try:
        normalize_rule(load_fixture('invalid-port-without-proto.json'), 3)
        ok &= check(False, 'invalid port rule is rejected')
    except RuleValidationError as exc:
        ok &= check(exc.field == 'match.dst_port', 'invalid port reports field')

    try:
        normalize_rule(load_fixture('invalid-stateful.json'), 4)
        ok &= check(False, 'stateful rule is rejected')
    except RuleValidationError as exc:
        ok &= check(exc.code == 'not_implemented', 'stateful rejection is explicit')

    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
