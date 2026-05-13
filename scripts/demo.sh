#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SDN_FIREWALL_BASE_URL:-http://127.0.0.1:8080}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

post_rule() {
    local fixture="$1"
    curl -sS -X POST "$BASE_URL/firewall/rules" \
        -H "Content-Type: application/json" \
        --data-binary "@$ROOT_DIR/tests/fixtures/rules/$fixture"
    echo
}

show_menu() {
    cat <<MENU
SDN Firewall Demo

1. Health
2. List rules
3. Add one-way ICMP block h1 -> h2
4. Add bidirectional ICMP block h1 <-> h3
5. Add TCP dst_port 80 block h3 -> h4
6. Show switches
7. Show topology anomalies
8. Show stats
9. Show events
0. Exit
MENU
}

run_choice() {
    case "$1" in
        1|health) curl -sS "$BASE_URL/firewall/health"; echo ;;
        2|list-rules|rules) curl -sS "$BASE_URL/firewall/rules"; echo ;;
        3|add-h1-h2-icmp) post_rule "block-h1-h2-icmp.json" ;;
        4|add-h1-h3-bidirectional) post_rule "block-h1-h3-bidir.json" ;;
        5|add-h3-h4-tcp-80) post_rule "block-h3-h4-tcp-80.json" ;;
        6|switches) curl -sS "$BASE_URL/firewall/switches"; echo ;;
        7|anomalies) curl -sS "$BASE_URL/firewall/topology/anomalies"; echo ;;
        8|stats) curl -sS "$BASE_URL/firewall/stats"; echo ;;
        9|events) curl -sS "$BASE_URL/firewall/events"; echo ;;
        topology) curl -sS "$BASE_URL/firewall/topology"; echo ;;
        0|exit) exit 0 ;;
        *) echo "Unknown option: $1" ;;
    esac
}

if [ "${1:-}" = "--scenario" ]; then
    run_choice "${2:-1}"
    exit 0
fi

while true; do
    show_menu
    printf "> "
    read -r choice
    run_choice "$choice"
done
