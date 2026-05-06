# SDN Firewall with CloudLab, Ryu, and Mininet

This project implements a basic SDN firewall using Ryu, OpenFlow 1.3, Open vSwitch, and Mininet. The controller behaves like a learning switch for allowed traffic and blocks selected traffic using firewall rules added through a REST API.

## Project Files

- `firewall_controller.py`  
  Main Ryu SDN firewall controller. It handles switch connection, MAC learning, forwarding, packet inspection, drop-flow installation, and drop-flow deletion.

- `firewall_rest_api.py`  
  REST API for listing, adding, and deleting firewall rules.

- `topology.py`  
  Mininet topology with four hosts and one OpenFlow 1.3 switch.

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

## How to Run

Use three terminals.

### Terminal 1: Start Ryu

```bash
source /local/ryu-venv/bin/activate
ryu-manager firewall_rest_api.py
```

If using the home directory venv:

```bash
source ~/ryu-venv/bin/activate
ryu-manager firewall_rest_api.py
```

Keep this terminal running.

### Terminal 2: Start Mininet

```bash
sudo mn -c
sudo python3 topology.py
```

Inside the Mininet prompt, test normal connectivity:

```bash
pingall
h1 ping h2
h1 ping h3
```

### Terminal 3: Add Firewall Rules

Block traffic from h1 to h2:

```bash
curl -X POST http://127.0.0.1:8080/firewall/rules \
-H "Content-Type: application/json" \
-d '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","action":"block"}'
```

List firewall rules:

```bash
curl http://127.0.0.1:8080/firewall/rules
```

Delete the first rule and re-enable traffic:

```bash
curl -X DELETE http://127.0.0.1:8080/firewall/rules/0
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

Do not run:

```bash
ryu-manager firewall_controller.py firewall_rest_api.py
```

The REST API already loads the firewall controller through Ryu contexts, so running both files directly can cause duplicate app errors.
