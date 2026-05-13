#!/usr/bin/env python3
import json
import sys
import time
import urllib.error
import urllib.request


BASE_URL = 'http://127.0.0.1:8080'


def fetch(path):
    try:
        with urllib.request.urlopen(BASE_URL + path, timeout=2) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {'error': str(exc)}


def main():
    try:
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table
        from rich.panel import Panel
        from rich.layout import Layout
    except ImportError:
        print('The Rich TUI requires: python -m pip install rich')
        return 1

    console = Console()

    def table_from_rules(rules):
        table = Table(title='Rules')
        for column in ('ID', 'Enabled', 'Action', 'Direction', 'Match', 'Hits'):
            table.add_column(column)
        stats_by_rule = {item.get('rule_id'): item for item in fetch('/firewall/stats') if isinstance(item, dict)}
        for rule in rules if isinstance(rules, list) else []:
            match = rule.get('match', {})
            match_text = '{} -> {} {}'.format(
                match.get('src_ip') or '*',
                match.get('dst_ip') or '*',
                match.get('proto') or 'ip'
            )
            if match.get('dst_port'):
                match_text += ':{}'.format(match['dst_port'])
            stats = stats_by_rule.get(rule.get('id'), {})
            table.add_row(
                str(rule.get('id')),
                str(rule.get('enabled')),
                rule.get('action', ''),
                rule.get('direction', ''),
                match_text,
                str(stats.get('packet_count', 0))
            )
        return table

    def table_from_switches(switches):
        table = Table(title='Switches')
        for column in ('DPID', 'Connected', 'Rules', 'Address'):
            table.add_column(column)
        for switch in switches if isinstance(switches, list) else []:
            table.add_row(
                str(switch.get('dpid')),
                str(switch.get('connected')),
                str(switch.get('installed_rule_count', 0)),
                str(switch.get('address', 'unknown'))
            )
        return table

    def render():
        layout = Layout()
        layout.split_column(
            Layout(name='top', size=5),
            Layout(name='middle'),
            Layout(name='bottom', size=10)
        )
        layout['middle'].split_row(Layout(name='rules'), Layout(name='switches'))

        health = fetch('/firewall/health')
        anomalies = fetch('/firewall/topology/anomalies')
        events = fetch('/firewall/events')
        rules = fetch('/firewall/rules')
        switches = fetch('/firewall/switches')

        layout['top'].update(Panel(json.dumps(health, indent=2), title='Health'))
        layout['rules'].update(table_from_rules(rules))
        layout['switches'].update(table_from_switches(switches))
        bottom_text = 'Anomalies:\n{}\n\nEvents:\n{}'.format(
            json.dumps(anomalies, indent=2),
            json.dumps(events[:5] if isinstance(events, list) else events, indent=2)
        )
        layout['bottom'].update(Panel(bottom_text, title='Security View'))
        return layout

    with Live(render(), console=console, refresh_per_second=0.5) as live:
        while True:
            time.sleep(2)
            live.update(render())


if __name__ == '__main__':
    sys.exit(main())
