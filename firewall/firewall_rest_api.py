"""
firewall_rest_api.py — SDN Firewall REST API + Web Dashboard (Improved)

Improvement 5: Serves a real-time web dashboard at http://127.0.0.1:8080/
               that shows current rules and lets you add/delete them without curl.

All other improvements (1-4) flow through firewall_controller.py.
"""

import json
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from webob import Response
from firewall_controller import SDNFirewall

firewall_instance_name = "firewall_app"

# ---------------------------------------------------------------------------
# Minimal single-file HTML dashboard (Improvement 5)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SDN Firewall Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  header { background: linear-gradient(135deg, #1e40af, #7c3aed); padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 1.6rem; font-weight: 700; color: #fff; }
  header .badge { background: rgba(255,255,255,0.2); border-radius: 20px; padding: 4px 14px; font-size: 0.8rem; color: #fff; }
  .container { max-width: 1000px; margin: 32px auto; padding: 0 24px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
  .card h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 16px; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
  input, select { width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #475569; border-radius: 8px; color: #e2e8f0; font-size: 0.9rem; }
  input::placeholder { color: #64748b; }
  .row { display: flex; align-items: center; gap: 12px; margin-top: 12px; }
  label { font-size: 0.85rem; color: #94a3b8; display: flex; align-items: center; gap: 6px; cursor: pointer; }
  input[type=checkbox] { width: auto; accent-color: #6366f1; }
  button { padding: 10px 22px; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: opacity .15s; }
  button:hover { opacity: .85; }
  .btn-add { background: #4f46e5; color: #fff; }
  .btn-del { background: #dc2626; color: #fff; padding: 6px 14px; font-size: 0.8rem; border-radius: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { text-align: left; padding: 10px 14px; color: #64748b; font-weight: 600; border-bottom: 1px solid #334155; }
  td { padding: 10px 14px; border-bottom: 1px solid #1e293b; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #0f172a; }
  .tag { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.78rem; font-weight: 600; }
  .tag-block { background: #7f1d1d; color: #fca5a5; }
  .tag-allow { background: #14532d; color: #86efac; }
  .tag-bi  { background: #1e3a5f; color: #93c5fd; margin-left: 4px; }
  .empty { text-align: center; color: #475569; padding: 32px; }
  .status { padding: 10px 14px; border-radius: 8px; font-size: 0.85rem; margin-top: 12px; display: none; }
  .status.ok  { background: #14532d; color: #86efac; display: block; }
  .status.err { background: #7f1d1d; color: #fca5a5; display: block; }
</style>
</head>
<body>
<header>
  <div>
    <h1>&#x1F6E1;&#xFE0F; SDN Firewall Dashboard</h1>
  </div>
  <span class="badge" id="rule-count">Loading…</span>
</header>

<div class="container">

  <!-- Add Rule -->
  <div class="card">
    <h2>Add Rule</h2>
    <div class="form-grid">
      <div><input id="src_ip"   placeholder="Source IP (e.g. 10.0.0.1)"></div>
      <div><input id="dst_ip"   placeholder="Dest IP (e.g. 10.0.0.2)"></div>
      <div>
        <select id="proto">
          <option value="">Any Protocol</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
      </div>
      <div><input id="dst_port" placeholder="Dest Port (optional)" type="number"></div>
      <div>
        <select id="action">
          <option value="block">Block</option>
          <option value="allow">Allow</option>
        </select>
      </div>
    </div>
    <div class="row">
      <label><input type="checkbox" id="bidir"> Bidirectional</label>
      <button class="btn-add" onclick="addRule()">+ Add Rule</button>
    </div>
    <div class="status" id="add-status"></div>
  </div>

  <!-- Rule Table -->
  <div class="card">
    <h2>Active Rules</h2>
    <table>
      <thead>
        <tr>
          <th>#</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Dst Port</th><th>Action</th><th></th>
        </tr>
      </thead>
      <tbody id="rules-body">
        <tr><td colspan="7" class="empty">Loading…</td></tr>
      </tbody>
    </table>
  </div>

</div>

<script>
const API = '';

async function fetchRules() {
  const res = await fetch(API + '/firewall/rules');
  const rules = await res.json();
  const tbody = document.getElementById('rules-body');
  document.getElementById('rule-count').textContent = rules.length + ' rule' + (rules.length !== 1 ? 's' : '') + ' active';
  if (rules.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">No rules yet. Add one above.</td></tr>';
    return;
  }
  tbody.innerHTML = rules.map((r, i) => `
    <tr>
      <td><code>${i}</code></td>
      <td>${r.src_ip || '<span style="color:#475569">any</span>'}</td>
      <td>${r.dst_ip || '<span style="color:#475569">any</span>'}</td>
      <td>${r.proto  || '<span style="color:#475569">any</span>'}</td>
      <td>${r.dst_port || '<span style="color:#475569">—</span>'}</td>
      <td>
        <span class="tag ${r.action === 'block' ? 'tag-block' : 'tag-allow'}">${r.action || 'block'}</span>
        ${r.bidirectional ? '<span class="tag tag-bi">↔ bidir</span>' : ''}
      </td>
      <td><button class="btn-del" onclick="deleteRule(${i})">Delete</button></td>
    </tr>
  `).join('');
}

async function addRule() {
  const rule = {
    src_ip:        document.getElementById('src_ip').value.trim()   || undefined,
    dst_ip:        document.getElementById('dst_ip').value.trim()   || undefined,
    proto:         document.getElementById('proto').value           || undefined,
    dst_port:      document.getElementById('dst_port').value        ? parseInt(document.getElementById('dst_port').value) : undefined,
    action:        document.getElementById('action').value,
    bidirectional: document.getElementById('bidir').checked || undefined,
  };
  // Remove undefined keys
  Object.keys(rule).forEach(k => rule[k] === undefined && delete rule[k]);

  const status = document.getElementById('add-status');
  try {
    const res = await fetch(API + '/firewall/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule)
    });
    const data = await res.json();
    status.className = 'status ok';
    status.textContent = 'Rule #' + data.rule_id + ' installed successfully.';
    fetchRules();
    // clear inputs
    ['src_ip','dst_ip','dst_port'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('proto').value = '';
    document.getElementById('action').value = 'block';
    document.getElementById('bidir').checked = false;
  } catch(e) {
    status.className = 'status err';
    status.textContent = 'Error: ' + e.message;
  }
}

async function deleteRule(id) {
  await fetch(API + '/firewall/rules/' + id, { method: 'DELETE' });
  fetchRules();
}

fetchRules();
setInterval(fetchRules, 5000);   // auto-refresh every 5 s
</script>
</body>
</html>
"""


class FirewallRestAPI(app_manager.RyuApp):
    _CONTEXTS = {
        "wsgi": WSGIApplication,
        "firewall_app": SDNFirewall,
    }

    def __init__(self, *args, **kwargs):
        super(FirewallRestAPI, self).__init__(*args, **kwargs)
        self.firewall_app = kwargs["firewall_app"]
        wsgi = kwargs["wsgi"]
        wsgi.register(
            FirewallController,
            {firewall_instance_name: self.firewall_app},
        )


class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[firewall_instance_name]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def json_response(self, data, status=200):
        body = (json.dumps(data) + "\n").encode("utf-8")
        return Response(content_type="application/json",
                        charset="utf-8",
                        status=status,
                        body=body)

    # ------------------------------------------------------------------
    # Improvement 5: Web dashboard
    # ------------------------------------------------------------------

    @route("dashboard", "/", methods=["GET"])
    def dashboard(self, req, **kwargs):
        return Response(content_type="text/html",
                        charset="utf-8",
                        body=DASHBOARD_HTML.encode("utf-8"))

    # ------------------------------------------------------------------
    # REST endpoints
    # ------------------------------------------------------------------

    @route("firewall", "/firewall/rules", methods=["GET"])
    def list_rules(self, req, **kwargs):
        return self.json_response(self.app.firewall_rules)

    @route("firewall", "/firewall/rules", methods=["POST"])
    def add_rule(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.json_response({"status": "error", "msg": "Invalid JSON"}, 400)

        # Improvement 1: bidirectional flag honoured inside add_rule()
        rule_id = self.app.add_rule(body)

        return self.json_response({
            "status": "rule installed",
            "rule_id": rule_id,
            "rule": body,
        })

    @route("firewall", "/firewall/rules/{rule_id}", methods=["DELETE"])
    def delete_rule(self, req, rule_id, **kwargs):
        try:
            rule_id = int(rule_id)
        except ValueError:
            return self.json_response({"status": "error", "msg": "rule_id must be an integer"}, 400)

        removed = self.app.delete_rule(rule_id)

        if removed is None:
            return self.json_response({"status": "error", "msg": "Rule not found"}, 404)

        return self.json_response({
            "status": "deleted and flow removed",
            "rule": removed,
        })
