# SDN Firewall Checkpoint

Branch: `k-firewall`

Latest implementation commit at the time of this checkpoint:
`a9b00f8 Implement SDN firewall upgrades and testbench`

This document records the current project state, what is submittable now, and what should be implemented next. Treat `PROJECT_PLAN.md` as the broader roadmap and this file as the practical handoff.

## Current Project Scope

This branch turns the original Ryu learning-switch firewall demo into a policy-driven SDN firewall project with:

- Structured firewall rules.
- REST API rule management.
- Persistent rule storage.
- One-way and bidirectional blocking.
- ICMP/TCP/UDP policy fields.
- Live TCP port blocking in Mininet.
- Multi-switch OpenFlow enforcement.
- Rule replay after controller restart or switch reconnect.
- OpenFlow stats polling.
- Event logging.
- Topology and topology-anomaly endpoints.
- A bounded automated testbench.
- A non-interactive demo runner.
- A Rich-based read-only TUI.

The intended submission framing is:

> A Ryu/OpenFlow SDN firewall controller with persistent JSON policy, bidirectional and protocol-aware blocking, multi-switch rule deployment, preemptive replay after reconnect, topology anomaly reporting, OpenFlow rule statistics, event logging, and an automated Mininet validation harness.

## Architecture Snapshot

```text
Operator / demo / Rich TUI / tests / curl
        |
        v
Ryu WSGI REST API
        |
        v
Policy layer
  - validation
  - stable IDs
  - JSON persistence
  - bidirectional expansion
  - OpenFlow cookie assignment
        |
        v
SDN firewall controller
  - switch registry
  - MAC learning for allowed traffic
  - drop-flow install/delete
  - rule replay on switch connect
  - stats polling
  - event log
  - topology/anomaly reporting
        |
        v
OpenFlow 1.3
        |
        v
Open vSwitch / Mininet topology
```

The primary local topology is:

```text
h1 --- s1 --- s2 --- s3 --- h4
       |      |
       h2     h3
```

This gives same-switch, one-hop, and multi-hop paths without making routing/topology logic unnecessarily complex for the class scope.

## What Has Been Accomplished

### Rule Model And Policy Layer

Implemented in `firewall/policy.py`.

Completed:

- Project-specific JSON rule schema.
- Stable integer rule IDs.
- Rule normalization for new and legacy-style payloads.
- Validation for IP addresses, ports, protocols, priority, direction, and unsupported stateful mode.
- Supported actions: `block`.
- Supported directions: `one-way`, `bidirectional`.
- Supported protocol fields: `icmp`, `tcp`, `udp`.
- ICMP type support in the schema and OpenFlow match generation.
- TCP/UDP source and destination port fields.
- Rule metadata fields:
  - `name`
  - `description`
  - `enabled`
  - `priority`
  - `scope`
  - `logging`
  - `stats`
  - `created_at`
  - `updated_at`
- Bidirectional rule expansion by generating a reverse match.
- OpenFlow cookie generation per rule.
- JSON persistence through `RuleStore`.

Important design choice:

- `stateful: true` is explicitly rejected for now with a structured `not_implemented` error. Reflexive/stateful rules should be added only after the stateless firewall is stable and well-tested.

### REST API

Implemented in `firewall/firewall_rest_api.py`.

Completed endpoints:

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

Completed API behavior:

- Structured success responses for create/update/delete.
- Structured error responses:

```json
{
  "status": "error",
  "error": {
    "code": "invalid_rule",
    "message": "example validation message",
    "field": "match.dst_port"
  }
}
```

- Rule CRUD through stable IDs rather than list indexes.
- Rule creation returns flow-install evidence for connected switches.
- Rule deletion returns flow-removal evidence.
- Rule stats endpoint returns a bounded object even before packets are counted.

### Controller And OpenFlow Behavior

Implemented in `firewall/firewall_controller.py`.

Completed:

- Learning-switch behavior for allowed traffic.
- OpenFlow 1.3 support.
- Switch registry keyed by DPID.
- Multi-switch rule installation.
- Rule replay on switch connection.
- Rule replay after controller restart when persisted rules already exist.
- Drop-flow installation for:
  - IP source/destination matches.
  - ICMP matches.
  - TCP port matches.
  - UDP port matches at the rule-generation level.
- Bidirectional blocking by installing forward and reverse drop flows.
- Flow deletion by rule cookie.
- OpenFlow stats polling in a background greenlet.
- Stats aggregation per rule and per switch.
- Event log entries for rule lifecycle and blocked packets.

Important correctness improvement:

- The topology endpoint originally attempted to call Ryu topology APIs synchronously. In this setup that can block the REST request. It was changed to return bounded controller-cache data plus expected topology metadata, so `/firewall/topology` cannot hang the API.

### Persistence And Replay

Completed:

- Rules persist to `firewall/rules.json` by default.
- Tests override the rule store with `SDN_FIREWALL_RULES_FILE`.
- Controller loads persisted rules at startup.
- When a switch connects, enabled rules are replayed onto that switch.
- Deleting a rule persists across restart.

### Multi-Switch Local Topology

Implemented in `firewall/topology_multi.py`.

Completed:

- Three-switch topology with four hosts.
- Non-interactive scenario execution for testbench automation.
- Manual `--cli` mode for debugging.
- Scenario selection through `/tmp/sdn-firewall-topology-scenario` for automated runs, avoiding sudo argument/prompt issues.
- Live scenario support for:
  - baseline dataplane
  - one-way ICMP block
  - bidirectional ICMP block
  - topology endpoint validation
  - TCP port blocking
  - replayed persisted rule validation

### Testbench And Verification

Implemented under `scripts/` and `tests/`.

Important commands:

```bash
./scripts/testbench.sh unit
./scripts/testbench.sh api
./scripts/testbench.sh persistence
./scripts/testbench.sh dataplane
./scripts/testbench.sh bidirectional
./scripts/testbench.sh replay
./scripts/testbench.sh topology
./scripts/testbench.sh tcp
./scripts/testbench.sh tui
./scripts/testbench.sh demo
./scripts/testbench.sh all
```

The most important full verification command is:

```bash
./scripts/testbench.sh all
```

This passed locally after the current implementation.

Current tested behaviors:

- Rule normalization.
- ICMP protocol acceptance.
- Bidirectional expansion.
- Invalid port rejection.
- Rejection of `stateful: true`.
- REST health.
- Rule list/create/get/update/delete.
- Structured validation errors.
- Event log create/update/delete events.
- Rule stats response shape.
- Persistence across controller restart.
- Deleted rules staying deleted after restart.
- Multi-switch baseline connectivity.
- One-way ICMP block and delete recovery.
- Bidirectional ICMP block and delete recovery.
- Preemptive rule replay after controller restart/switch reconnect.
- Topology endpoint response shape.
- Topology anomaly endpoint response shape.
- Live TCP destination port 80 block and delete recovery.
- Demo runner scenarios.
- Rich TUI smoke behavior.

### Demo And Operator Tooling

Completed:

- `scripts/demo.sh` supports named non-interactive scenarios.
- `scripts/tui.py` provides a Rich-based read-only dashboard.
- The TUI is useful for presentation, but currently only smoke-tested.
- `README.md` documents local setup, controller startup, test commands, demo flows, and API examples.
- `AGENTS.md` documents Ryu/Mininet safety rules to avoid stuck sessions.

### Environment And Automation

Completed:

- `requirements-ryu.txt` for the local Ryu environment.
- `scripts/setup_ryu_env.sh` for creating the local environment.
- `scripts/setup_mininet_sudo.sh` for scoped non-interactive sudo on Mininet/OVS commands.
- `scripts/dataplane_smoke.py` owns controller/topology lifecycle with bounded timeouts.
- Test artifacts are moved through `trash` when possible instead of destructive deletion.

## Current Submittable State

This branch is submittable as a backend-heavy SDN firewall project.

The strongest submittable claims are:

- The project implements a northbound REST-controlled SDN firewall.
- Rules are structured, validated, persisted, and managed through stable IDs.
- The controller programs OpenFlow drop rules onto multiple OVS switches.
- Bidirectional rules install both forward and reverse drop flows.
- Persisted rules are replayed when the controller restarts and switches reconnect.
- The system exposes switch, topology, anomaly, stats, and event information.
- The project includes repeatable local Mininet tests proving the important dataplane behaviors.

Avoid overstating these claims:

- This is not yet a stateful/reflexive firewall.
- This is not yet a production-secure controller-switch deployment.
- Topology hardening is detect-and-alert only.
- UDP is supported in the schema/OpenFlow generation path, but live UDP dataplane validation is not implemented yet.
- The Rich TUI is smoke-tested, not deeply interaction-tested.
- The web dashboard is not implemented on this branch.
- CloudLab deployment polish is still pending.

## Known Gaps To Fix Next

### 1. Add Live UDP Dataplane Validation

Priority: high.

Reason:

- The project currently says the schema supports UDP.
- The controller can generate UDP OpenFlow matches.
- But the live testbench does not yet prove UDP blocking in Mininet.

Recommended implementation:

1. Add a bounded UDP echo receiver on `h4`.
2. Add a UDP client check from `h3`.
3. Verify baseline `h3 -> h4` UDP works.
4. Add rule:

```json
{
  "name": "Block h3 to h4 UDP 9999",
  "action": "block",
  "direction": "one-way",
  "match": {
    "src_ip": "10.0.0.3",
    "dst_ip": "10.0.0.4",
    "proto": "udp",
    "dst_port": 9999
  }
}
```

5. Verify the UDP request times out or fails after the rule is installed.
6. Delete the rule.
7. Verify UDP connectivity recovers.

Files likely touched:

- `tests/fixtures/rules/block-h3-h4-udp-9999.json`
- `firewall/topology_multi.py`
- `scripts/dataplane_smoke.py`
- `scripts/testbench.sh`
- `PROJECT_PLAN.md`
- `CHECKPOINT.md`

Acceptance criteria:

- `./scripts/testbench.sh udp` passes.
- `./scripts/testbench.sh all` includes UDP and passes.
- The final README can accurately claim live TCP and UDP port blocking.

### 2. Add Stats History Endpoint

Priority: medium-high.

Reason:

- The current stats endpoint gives current counters.
- A dashboard or presentation graph needs time-series samples.
- `origin/post-pres-update` has a useful version of this idea, but its implementation should not be copied wholesale because our stats model is cookie/rule-ID based.

Recommended endpoint:

- `GET /firewall/stats/history`

Recommended response shape:

```json
[
  {
    "timestamp": "2026-05-13T00:00:00Z",
    "total_packets": 12,
    "total_bytes": 1008,
    "rules": {
      "1": {
        "packet_count": 12,
        "byte_count": 1008
      }
    }
  }
]
```

Implementation notes:

- Store a bounded deque, for example 60 or 120 samples.
- Sample from the existing stats cache after flow stats replies.
- Do not make packet handling wait on stats writes.
- Keep the endpoint read-only and cheap.

Acceptance criteria:

- New API test confirms endpoint shape.
- If live traffic creates drops, history eventually reflects nonzero counts.
- `./scripts/testbench.sh api` still passes.

### 3. Port A Minimal Web Dashboard

Priority: medium.

Reason:

- The current branch is technically stronger than `post-pres-update`, but a dashboard improves presentation.
- The dashboard should use our existing API and rule schema, not the simpler list-index rule model from `post-pres-update`.

Recommended scope:

- Read-only first.
- Show:
  - controller health
  - connected switches
  - active rules
  - stats
  - events
  - topology anomalies
- Optional second step:
  - simple add/delete rule form using the current schema.

Files likely touched:

- `firewall/firewall_rest_api.py`
- possibly `static/` or `web/` if we do not want a giant embedded HTML string.

Acceptance criteria:

- `GET /` returns a dashboard.
- Existing API tests still pass.
- Add one smoke test that `GET /` returns HTML and status 200.

### 4. Add Topology Graph Export

Priority: medium.

Reason:

- `origin/post-pres-update` includes useful graph generation ideas.
- A graph/image makes the project easier to present.

Recommended implementation:

- Keep graph generation outside the controller critical path.
- Prefer a script that calls `/firewall/topology` and writes:
  - `topology.json`
  - optionally `topology.png`
- Do not make REST requests depend on `networkx` or `matplotlib`.

Files likely added:

- `scripts/export_topology_graph.py`
- optional documentation in `README.md`.

Acceptance criteria:

- With controller and topology running, the script writes a graph artifact.
- Missing optional graph libraries produce a clear message, not a crash.

### 5. Improve Topology Hardening Semantics

Priority: medium.

Current state:

- The controller reports expected/missing/unknown switches and links based on the expected lab topology.
- It does not enforce any quarantine or trust decision.

Recommended next step:

- Add a configured expected-topology file instead of hardcoding `EXPECTED_TOPOLOGY`.
- Include severity and remediation hints in anomalies.
- Add an event when an anomaly first appears.
- Consider a read-only endpoint first:

```text
GET /firewall/topology/policy
```

Then, if time allows:

```text
PATCH /firewall/topology/policy
```

Future enforcement option:

- Block rule installation on unknown switches.
- Or install table-miss drop on unknown switches.

Do not claim controller-injection protection unless TLS/controller-channel controls are implemented.

### 6. Add Rule Scope By Switch

Priority: medium.

Current state:

- The schema has `scope`, but only `{"switches": "all"}` is supported.

Reason to add:

- It would make multi-switch behavior more interesting.
- It allows demonstrations like "block only at edge switch" versus "block everywhere."

Recommended schema extension:

```json
{
  "scope": {
    "switches": [1, 2]
  }
}
```

Acceptance criteria:

- A rule scoped to switch 1 installs only on switch 1.
- A rule scoped to all still installs on every connected switch.
- Replay respects scope.
- Tests cover all three cases:
  - all switches
  - one switch
  - invalid unknown switch ID.

### 7. Add Better Demo Scripts

Priority: medium.

Reason:

- The project is strongest when demonstrated live.
- A polished demo script avoids typing many commands during presentation.

Recommended demo modes:

- `baseline`: show connectivity.
- `icmp-one-way`: block h1 -> h2 only.
- `icmp-bidir`: block h1 <-> h3.
- `tcp-port`: block h3 -> h4 TCP 80.
- `replay`: create persistent rule, restart controller, show it still blocks.
- `topology`: print switches/topology/anomalies.

Acceptance criteria:

- Each scenario is non-interactive and bounded.
- Each prints clear PASS/FAIL output.
- Each leaves no Mininet/Ryu processes running.

### 8. CloudLab Follow-Up

Priority: medium-low until local behavior is finished.

Reason:

- Local Mininet is now stable.
- CloudLab support should use the same controller/test architecture rather than becoming a separate project.

Recommended work:

- Review `controller.sh`, `profile.py`, `controller.xml`, and existing CloudLab branches.
- Update dependencies for the current Ryu environment.
- Add a short CloudLab verification path:
  - install
  - start controller
  - start OVS/Mininet or remote switch profile
  - run API smoke
  - run dataplane smoke if supported

Acceptance criteria:

- Fresh CloudLab node setup works from documented commands.
- Differences between local and CloudLab are documented.

## Future Upgrades To Consider

### Reflexive / Stateful Rules

Potential value:

- Shows a more advanced firewall idea.
- Allows temporary reverse-path rules for established flows.

Risks:

- More complex than it sounds.
- Requires tracking flow initiation, timeouts, reverse tuple generation, and cleanup.
- Can undermine strict firewall semantics if not explained clearly.

Recommended approach:

- Keep it backlog until stateless TCP/UDP is fully validated.
- Implement only a small, explicit demo case first.
- Use short idle timeouts for temporary reverse flows.

### Inbound / Outbound Direction

Potential value:

- More familiar firewall terminology.

Current blocker:

- The project has no concept of zones, interfaces, or trusted/untrusted edges.

Recommended approach:

- Do not add `inbound`/`outbound` until zones are defined.
- If implemented, add a `zones` config mapping switch ports or hosts to zone names.

### Allow Rules And Rule Ordering

Potential value:

- More realistic ACL behavior.

Current state:

- V1 only supports `block`.

Recommended approach:

- Add explicit rule ordering and priority semantics first.
- Decide default policy:
  - allow by default, block by matching rule
  - or deny by default, allow by matching rule

For the current class project, allow-by-default with block rules is simpler and easier to explain.

### Topology Quarantine

Potential value:

- Turns topology hardening from visibility into enforcement.

Possible behavior:

- Unknown switch connects.
- Controller records anomaly.
- Controller installs table-miss drop or refuses rule replay on that switch.

Risk:

- Can break demos if expected topology is wrong.

Recommended approach:

- Add as an optional mode:

```json
{
  "topology_policy": {
    "unknown_switch_action": "observe"
  }
}
```

Valid values:

- `observe`
- `block`
- `quarantine`

### Controller Channel Security

Potential value:

- More serious answer to rogue-controller or fake-infrastructure concerns.

Reality:

- This is not solved by topology discovery alone.
- It requires network isolation, controller IP restrictions, TLS, certificates, or switch-side configuration.

Recommended presentation wording:

- Current topology hardening detects unexpected switch/link state.
- It does not cryptographically authenticate switches or controllers.
- Future work would use OpenFlow TLS and certificate-based trust.

### Dashboard And Presentation UX

Potential value:

- High presentation impact.

Recommended minimal dashboard:

- One page.
- No complex frontend framework.
- Poll existing endpoints.
- Show:
  - health
  - switches
  - active rules
  - stats
  - recent events
  - topology anomalies

Avoid:

- Replacing the tested backend with dashboard-specific logic.
- Duplicating rule schema in fragile JavaScript.

## Suggested Next Implementation Order

1. Add live UDP dataplane test and implementation fixes if needed.
2. Add stats history endpoint.
3. Add dashboard backed by current API.
4. Add topology graph export script.
5. Improve topology hardening configuration.
6. Add switch-scoped rules.
7. Add polished demo modes for the final presentation.
8. Revisit CloudLab setup.
9. Only then consider reflexive/stateful rules.

## Commands For The Next Developer

Start with:

```bash
git checkout k-firewall
git pull
./scripts/testbench.sh all
```

If Mininet sudo has not been configured on the machine:

```bash
./scripts/setup_mininet_sudo.sh
```

For controller-only work:

```bash
./scripts/testbench.sh unit
./scripts/testbench.sh api
./scripts/testbench.sh persistence
```

For dataplane work:

```bash
./scripts/testbench.sh dataplane
./scripts/testbench.sh bidirectional
./scripts/testbench.sh replay
./scripts/testbench.sh topology
./scripts/testbench.sh tcp
```

For manual controller use:

```bash
./scripts/run_controller.sh
```

For manual topology use:

```bash
sudo -n python3 firewall/topology_multi.py --cli
```

## Notes On `origin/post-pres-update`

That branch contains useful presentation-focused ideas:

- Web dashboard.
- Stats history.
- Topology graph generation.
- Configurable topology generation.

Do not merge it wholesale into `k-firewall`.

Reasons:

- It uses simpler index/list-based rule behavior.
- It lacks the structured policy layer added here.
- It does not use stable rule IDs in the same way.
- Its stats mapping is weaker than the cookie-based approach here.
- It does not include the current black-box Mininet testbench.

Best path:

- Port selected presentation ideas into this branch while preserving the current policy, controller, and test architecture.

## Definition Of Done For Final Submission

Minimum:

- `./scripts/testbench.sh all` passes.
- README explains setup and demo commands.
- Presentation clearly distinguishes implemented behavior from future work.
- Live demo shows at least:
  - baseline connectivity
  - ICMP one-way or bidirectional block
  - TCP port block
  - persistence/replay
  - topology/anomaly endpoint

Stronger:

- UDP live dataplane test passes.
- Dashboard shows rules/stats/events.
- Stats history graph works.
- Topology graph export works.

Ideal:

- CloudLab setup is documented and tested.
- Switch-scoped rules are implemented.
- Topology hardening has configurable expected topology.
