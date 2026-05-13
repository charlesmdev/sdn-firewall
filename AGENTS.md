# Repo Instructions: SDN Firewall

## Environment

- Use the project-local Ryu environment at `.venv/`.
- Recreate it with `./scripts/setup_ryu_env.sh` if needed.
- Mininet/Open vSwitch require root privileges, but this repo is configured for narrow non-interactive sudo on the project test commands after `./scripts/setup_mininet_sudo.sh` has been run once by the user.

## Test Commands

- Unit/policy checks:
  ```bash
  ./scripts/testbench.sh unit
  ```
- Live REST API checks require the controller to be running:
  ```bash
  ./scripts/run_controller.sh
  ./scripts/testbench.sh api
  ```
- Preferred live dataplane smoke test. This script owns controller/topology
  lifecycle and uses short per-step deadlines, so do not wrap it in a long
  interactive Mininet workflow:
  ```bash
  ./scripts/run_dataplane_smoke.sh
  ```

## Mininet/Ryu Safety

- Prefer `./scripts/run_dataplane_smoke.sh` for automated dataplane testing.
- Do not use interactive Mininet CLI commands in automation unless explicitly requested.
- `firewall/topology_multi.py` runs a bounded smoke test by default; use `--cli` only for manual interactive debugging.
- `sudo -n mn -c` kills stale `ryu-manager` processes. For full tests, clean Mininet first, then start Ryu, then start Mininet/topology.
- Always use per-step timeouts around live SDN tests so a controller/switch wait cannot hang the session indefinitely. `scripts/dataplane_smoke.py` is the canonical example.
- After interrupted tests, check for leftovers:
  ```bash
  ps -eo pid,ppid,stat,cmd | rg 'ryu-manager|topology_multi|mn --|mnexec|firewall_rest_api' || true
  sudo -n mn -c
  ```

## Generated Files

- `.venv/`, `__pycache__/`, and `firewall/rules.json` are generated and ignored.
- Do not commit generated rule stores or Python cache directories.
