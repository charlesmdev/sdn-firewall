# SDN Firewall with CloudLab, Ryu, and Mininet

This project implements an SDN firewall using Ryu, OpenFlow 1.3, Open vSwitch, and Mininet. The controller behaves like a learning switch for allowed traffic and programs OpenFlow drop rules for blocked traffic through a REST API.

The active upgrade plan lives in `PROJECT_PLAN.md`.

## Project Files

- `firewall_controller.py`  
  Main Ryu SDN firewall controller. It handles switch connection, MAC learning, forwarding, packet inspection, drop-flow installation, and drop-flow deletion.

- `firewall_rest_api.py`  
  REST API for health, rule CRUD, switches, topology, topology anomalies, stats, and events.

- `topology.py`  
  Mininet topology with four hosts and one OpenFlow 1.3 switch.

- `topology_multi.py`
  Local multi-switch topology: `h1/h2-s1-s2-s3-h4` with `h3` on `s2`.

- `policy.py`
  Rule schema validation, stable rule IDs, bidirectional expansion, cookies, and JSON persistence.

- `scripts/testbench.sh`
  Testbench entrypoint for policy unit checks and API checks.

- `scripts/demo.sh` and `scripts/tui.py`
  Demo helper and Rich-based read-only TUI.

- `controller.sh`  
  CloudLab setup script that installs Mininet, Open vSwitch, Python dependencies, and Ryu.

- `profile.py` and `controller.xml`  
  CloudLab profile files.

## CloudLab Setup

After the CloudLab node is ready, run:

```bash
chmod +x controller.sh
./controller.sh
```

Activate the Ryu virtual environment:

```bash
source /local/ryu-venv/bin/activate
```

If the virtual environment was created manually in the home directory instead, use:

```bash
source ~/ryu-venv/bin/activate
```

## Local Environment Setup

Create the local Ryu environment:

```bash
./scripts/setup_ryu_env.sh
```

Start the controller:

```bash
./scripts/run_controller.sh
```

Run API tests while the controller is running:

```bash
./scripts/testbench.sh api
```

Mininet and Open vSwitch need root privileges because they create network namespaces, veth pairs, and OVS bridges. Run this once to install the OS packages and allow the project test commands to use non-interactive sudo:

```bash
./scripts/setup_mininet_sudo.sh
```

After that, the bounded non-interactive dataplane smoke can be run without a password prompt:

```bash
./scripts/run_dataplane_smoke.sh
```

For manual debugging, the multi-switch topology can be started interactively:

```bash
sudo -n python3 firewall/topology_multi.py --cli
```

## How to Run

Use three terminals.

### Terminal 1: Start Ryu

```bash
source /local/ryu-venv/bin/activate
cd firewall
ryu-manager firewall_rest_api.py
```

If using the home directory venv:

```bash
source ~/ryu-venv/bin/activate
cd firewall
ryu-manager firewall_rest_api.py
```

Keep this terminal running.

### Terminal 2: Start Mininet

```bash
sudo mn -c
sudo python3 topology.py
```

For the upgraded multi-switch topology:

```bash
sudo mn -c
sudo python3 topology_multi.py
```

Inside the Mininet prompt, test normal connectivity:

```bash
pingall
h1 ping h2
h1 ping h3
```

### Terminal 3: Add Firewall Rules

Block ICMP from h1 to h2:

```bash
curl -X POST http://127.0.0.1:8080/firewall/rules \
-H "Content-Type: application/json" \
-d '{"name":"Block h1 to h2 ICMP","action":"block","direction":"one-way","match":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","proto":"icmp"}}'
```

Block ICMP bidirectionally between h1 and h3:

```bash
curl -X POST http://127.0.0.1:8080/firewall/rules \
-H "Content-Type: application/json" \
-d '{"name":"Block h1 and h3 ICMP","action":"block","direction":"bidirectional","match":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.3","proto":"icmp"}}'
```

List firewall rules:

```bash
curl http://127.0.0.1:8080/firewall/rules
```

Delete the first rule and re-enable traffic:

```bash
curl -X DELETE http://127.0.0.1:8080/firewall/rules/1
```

View controller state:

```bash
curl http://127.0.0.1:8080/firewall/health
curl http://127.0.0.1:8080/firewall/switches
curl http://127.0.0.1:8080/firewall/topology
curl http://127.0.0.1:8080/firewall/topology/anomalies
curl http://127.0.0.1:8080/firewall/stats
curl http://127.0.0.1:8080/firewall/events
```

Run local checks that do not require Ryu/Mininet:

```bash
./scripts/testbench.sh unit
```

Run API checks while Ryu is running:

```bash
./scripts/testbench.sh api
```

Run the demo helper:

```bash
./scripts/demo.sh
```

## Expected Demo

Before adding the rule:

```text
h1 ping h2 = works
h1 ping h3 = works
```

After adding the rule:

```text
h1 ping h2 = blocked
h1 ping h3 = still works
```

After deleting the rule:

```text
h1 ping h2 = works again
```

## Notes

Run only this command for Ryu:

```bash
ryu-manager firewall_rest_api.py
```

Run it from the `firewall/` directory so sibling modules import cleanly.

Do not run:

```bash
ryu-manager firewall_controller.py firewall_rest_api.py
```

The REST API already loads the firewall controller through Ryu contexts, so running both files directly can cause duplicate app errors.

Firewall rules persist to `firewall/rules.json` by default. Override this path for tests with:

```bash
export SDN_FIREWALL_RULES_FILE=/tmp/sdn-firewall-rules.json
```
