#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-unit}"

run_unit() {
    python3 "$ROOT_DIR/tests/policy_unit.py"
}

run_api() {
    run_live api
}

run_api_scenario() {
    run_live "$1"
}

run_live() {
    python3 "$ROOT_DIR/tests/live_scenarios.py" "$1"
}

run_dataplane() {
    "$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/scripts/dataplane_smoke.py" "$1"
}

case "$MODE" in
    unit)
        run_unit
        ;;
    api)
        run_api
        ;;
    dataplane)
        run_dataplane dataplane
        ;;
    bidirectional)
        run_dataplane bidirectional
        ;;
    persistence)
        run_live persistence
        ;;
    replay)
        run_dataplane replay
        ;;
    topology)
        run_dataplane topology
        ;;
    tcp)
        run_dataplane tcp
        ;;
    tui)
        run_live tui
        ;;
    demo)
        run_live demo
        ;;
    events)
        run_api_scenario events
        ;;
    stats)
        run_api_scenario stats
        ;;
    all)
        run_unit
        run_api
        run_live persistence
        run_live tui
        run_live demo
        run_dataplane all
        ;;
    *)
        echo "Usage: $0 [unit|api|dataplane|bidirectional|persistence|replay|topology|tcp|tui|demo|events|stats|all]"
        exit 2
        ;;
esac
