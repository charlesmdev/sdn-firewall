#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_FILE="${SDN_FIREWALL_RULES_FILE:-$ROOT_DIR/firewall/rules.json}"

cd "$ROOT_DIR/firewall"
SDN_FIREWALL_RULES_FILE="$RULES_FILE" "$ROOT_DIR/.venv/bin/ryu-manager" firewall_rest_api.py
