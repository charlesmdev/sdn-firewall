# SDN Firewall Upgrade Plan

## Current Architecture

```text
curl / demo operator
        |
        v
Ryu WSGI REST API
        |
        v
SDN firewall controller
        |
        v
OpenFlow 1.3
        |
        v
Open vSwitch / Mininet hosts
```

The starting implementation is a Ryu learning switch with a small REST API. Rules are kept in memory and can install OpenFlow drop rules on connected switches.

## Target Architecture

```text
Testbench / demo / Rich TUI / curl
        |
        v
REST API / northbound interface
        |
        v
Policy manager
  - rule schema
  - validation
  - persistence
  - bidirectional expansion
        |
        v
SDN firewall controller
  - switch registry
  - preemptive rule replay
  - topology/anomaly reporting
  - OpenFlow stats cache
        |
        v
OpenFlow 1.3
        |
        v
OVS switches and Mininet hosts
```

## Development Loop

Each implementation phase follows the same cycle:

1. Plan the phase behavior in this document.
2. Add or update testbench checks first.
3. Implement only the production code needed for that phase.
4. Run verification.
5. Record remaining gaps before moving to the next phase.

## Rule Schema

Rules use a project-specific JSON schema that borrows from common ACL/firewall policy ideas without adopting a heavy external standard.

```json
{
  "id": 1,
  "name": "Block h1 to h2 ICMP",
  "description": "Demo rule showing bidirectional ping blocking",
  "enabled": true,
  "priority": 100,
  "action": "block",
  "direction": "bidirectional",
  "stateful": false,
  "match": {
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "proto": "icmp",
    "src_port": null,
    "dst_port": null,
    "icmp_type": null
  },
  "scope": {
    "switches": "all"
  },
  "logging": {
    "enabled": true,
    "sample_rate": 1.0
  },
  "stats": {
    "enabled": true
  },
  "created_at": "2026-05-09T00:00:00Z",
  "updated_at": "2026-05-09T00:00:00Z"
}
```

V1 supports `block`, `one-way`, `bidirectional`, `tcp`, `udp`, and `icmp`. `stateful` is reserved for reflexive firewall work and must be `false` in V1.

## REST API

Core endpoints:

- `GET /firewall/health`
- `GET /firewall/rules`
- `POST /firewall/rules`
- `GET /firewall/rules/{id}`
- `PATCH /firewall/rules/{id}`
- `DELETE /firewall/rules/{id}`
- `GET /firewall/switches`
- `GET /firewall/topology`
- `GET /firewall/topology/anomalies`
- `GET /firewall/stats`
- `GET /firewall/rules/{id}/stats`
- `GET /firewall/events`

Errors use structured JSON:

```json
{
  "status": "error",
  "error": {
    "code": "invalid_rule",
    "message": "dst_port requires proto to be tcp or udp",
    "field": "match.dst_port"
  }
}
```

## Local Topology

The upgraded local topology is loop-free but multi-hop:

```text
h1 --- s1 --- s2 --- s3 --- h4
       |      |
       h2     h3
```

Expected demo paths:

- same switch: `h1 <-> h2`
- one hop: `h1 <-> h3`
- multi-hop: `h1 <-> h4`
- multi-hop alternate: `h2 <-> h4`

## Topology Hardening

Topology hardening is detect-and-alert only in V1. It compares the discovered topology to the expected local topology and reports:

- unknown switch
- missing expected switch
- unknown link
- missing expected link
- switch reconnect event

This improves operator visibility but does not claim to prevent fake-controller injection. Rogue-controller defenses require control-channel controls such as controller IP restrictions, TLS, certificates, or network isolation.

## Phases

### Phase 0: Planning Framework

Create this document and make it the canonical roadmap.

### Phase 1: Testbench Skeleton

Add Bash orchestration, Python API checks, and JSON fixtures before controller changes.

### Phase 2: Health Endpoint And API Errors

Add health and structured response helpers.

### Phase 3: Rule Schema And Validation

Normalize rule input, add stable IDs, and reject invalid policies before OpenFlow installation.

### Phase 4: Rule CRUD

Implement list/create/get/patch/delete using stable IDs.

### Phase 5: ICMP And Bidirectional OpenFlow

Generate one or two OpenFlow matches per rule. Treat ICMP as a first-class protocol.

### Phase 6: Persistence And Preemptive Loading

Load rules at startup, persist changes, and replay enabled rules on switch connect.

### Phase 7: Multi-Switch Topology

Add the three-switch topology while preserving the original simple topology.

### Phase 8: Switch Registry And Topology Discovery

Expose connected switches and discovered topology through REST.

### Phase 9: Topology Hardening

Compare discovered state against the expected topology and expose anomalies.

### Phase 10: Stats And Events

Use OpenFlow cookies and cached stats polling for low-latency counters. Add bounded event history.

### Phase 11: Demo Runner

Add a menu-driven demo and non-interactive scenarios.

### Phase 12: Rich TUI

Add a read-only `rich` dashboard for controller health, switches, rules, stats, topology, anomalies, and events.

### Phase 13: CloudLab Follow-Up

Fix CloudLab scripts after local Mininet behavior is stable.

## Backlog

- Reflexive/stateful temporary reverse-flow rules.
- `inbound` and `outbound` directions after zones/interfaces are defined.
- Automatic topology quarantine.
- TLS/certificate hardening for controller-switch channels.

## Test Coverage Status

The black-box testbench now exposes explicit modes:

- `unit`: policy fixture checks already present in the repository.
- `api`: health, rule CRUD, structured errors, event log contract, and rule stats response shape against a harness-owned controller.
- `persistence`: starts the controller with a temp `/tmp` rule store, creates a rule, restarts, verifies the same rule is loaded, deletes it, restarts again, and verifies it remains deleted.
- `dataplane`: starts controller plus a harness-owned three-switch Mininet topology and verifies baseline connectivity.
- `bidirectional`: validates h1/h3 bidirectional ICMP block creation, flow-install response evidence for all three switches and both directions, dataplane blocking in both directions, and recovery after delete.
- `replay`: persists an h1->h2 ICMP block before switch connection, restarts the controller, starts topology, verifies preemptive blocking, checks switch registration and rule stats increment, deletes the rule, and verifies recovery.
- `topology`: validates `/firewall/switches`, `/firewall/topology`, and `/firewall/topology/anomalies` structure with the expected three-switch topology. `missing_link` anomalies remain acceptable when discovery metadata is otherwise structured.
- `tcp`: validates live TCP destination-port blocking for h3->h4 port 80 and recovery after delete.
- `tui`: smoke-tests the TUI for missing-Rich or controller-down behavior without visual assertions.
- `demo`: verifies named non-interactive demo scenarios for health, list-rules, stats, and events.

UDP live dataplane validation is intentionally skipped for now: the current test harness does not include a reliable UDP echo/check protocol, and this plan requires not faking UDP success. UDP remains covered only by rule/API validation until a bounded UDP echo fixture is added to the harness.

Current verification status: `./scripts/testbench.sh all` passed locally on May 12, 2026.
