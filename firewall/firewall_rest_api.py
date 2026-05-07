"""
firewall_rest_api.py — SDN Firewall REST API + Web Dashboard

Endpoints:
  GET  /                        → web dashboard (HTML)
  GET  /firewall/rules          → list rules (with live hit counts)
  POST /firewall/rules          → add rule
  DEL  /firewall/rules/{id}     → delete rule
  GET  /firewall/stats          → per-rule packet/byte counts
  GET  /firewall/stats/history  → time-series data for the live graph
"""

import json
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from webob import Response
from firewall_controller import SDNFirewall

firewall_instance_name = "firewall_app"

# ---------------------------------------------------------------------------
# Dashboard HTML — dark theme with live graph + hit counter table
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

  header {
    background: linear-gradient(135deg, #1e40af, #7c3aed);
    padding: 20px 32px;
    display: flex; align-items: center; justify-content: space-between;
  }
  header h1 { font-size: 1.4rem; font-weight: 700; color: #fff; }
  .pill { background: rgba(255,255,255,0.18); border-radius: 20px; padding: 3px 14px; font-size: 0.78rem; color: #fff; }

  .container { max-width: 1060px; margin: 28px auto; padding: 0 20px; }

  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
  @media(max-width:700px){ .grid2 { grid-template-columns: 1fr; } }

  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
  .card h2 { font-size: 0.78rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: .07em; margin-bottom: 14px; }

  /* stat boxes */
  .stat-row { display: flex; gap: 12px; margin-bottom: 20px; }
  .stat { flex: 1; background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: 800; color: #a78bfa; }
  .stat .lbl { font-size: 0.75rem; color: #64748b; margin-top: 2px; }

  /* form */
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  input, select { width: 100%; padding: 9px 11px; background: #0f172a; border: 1px solid #475569; border-radius: 7px; color: #e2e8f0; font-size: 0.88rem; }
  input::placeholder { color: #475569; }
  .row { display: flex; align-items: center; gap: 12px; margin-top: 10px; flex-wrap: wrap; }
  label { font-size: 0.82rem; color: #94a3b8; display: flex; align-items: center; gap: 5px; cursor: pointer; }
  input[type=checkbox] { width: auto; accent-color: #6366f1; }
  button { padding: 9px 20px; border: none; border-radius: 7px; font-size: 0.88rem; font-weight: 600; cursor: pointer; transition: opacity .15s; }
  button:hover { opacity: .82; }
  .btn-add { background: #4f46e5; color: #fff; }
  .btn-del { background: #dc2626; color: #fff; padding: 5px 12px; font-size: 0.78rem; border-radius: 5px; }
  .status { padding: 9px 13px; border-radius: 7px; font-size: 0.82rem; margin-top: 10px; display: none; }
  .status.ok  { background: #14532d; color: #86efac; display: block; }
  .status.err { background: #7f1d1d; color: #fca5a5; display: block; }

  /* table */
  table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  th { text-align: left; padding: 9px 12px; color: #64748b; font-weight: 600; border-bottom: 1px solid #334155; }
  td { padding: 9px 12px; border-bottom: 1px solid #1e293b; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #0f172a44; }
  .tag { display: inline-block; padding: 2px 9px; border-radius: 11px; font-size: 0.74rem; font-weight: 600; }
  .tag-block { background: #7f1d1d; color: #fca5a5; }
  .tag-allow { background: #14532d; color: #86efac; }
  .tag-bi    { background: #1e3a5f; color: #93c5fd; margin-left: 3px; }
  .hit-badge { font-size: 0.8rem; font-weight: 700; color: #f59e0b; }
  .empty { text-align: center; color: #475569; padding: 28px; }

  /* canvas chart */
  canvas { width: 100% !important; }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1;&#xFE0F; SDN Firewall Dashboard</h1>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="pill" id="rule-count">0 rules</span>
    <span class="pill" id="total-blocked">0 blocked</span>
  </div>
</header>

<div class="container">

  <!-- Summary stats -->
  <div class="stat-row">
    <div class="stat"><div class="num" id="s-rules">0</div><div class="lbl">Active Rules</div></div>
    <div class="stat"><div class="num" id="s-blocked">0</div><div class="lbl">Total Blocked Pkts</div></div>
    <div class="stat"><div class="num" id="s-bytes">0</div><div class="lbl">Blocked Bytes</div></div>
    <div class="stat"><div class="num" id="s-switches">—</div><div class="lbl">Switches</div></div>
  </div>

  <!-- Live graph + Add rule -->
  <div class="grid2">

    <!-- Live blocked-packet graph -->
    <div class="card">
      <h2>Blocked Packets — Live</h2>
      <canvas id="graph" height="160"></canvas>
    </div>

    <!-- Add rule form -->
    <div class="card">
      <h2>Add Rule</h2>
      <div class="form-grid">
        <input id="src_ip"   placeholder="Source IP">
        <input id="dst_ip"   placeholder="Dest IP">
        <select id="proto">
          <option value="">Any Protocol</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <input id="dst_port" placeholder="Dest Port" type="number">
        <select id="action">
          <option value="block">Block</option>
          <option value="allow">Allow</option>
        </select>
      </div>
      <div class="row">
        <label><input type="checkbox" id="bidir"> Bidirectional</label>
        <button class="btn-add" onclick="addRule()">+ Add Rule</button>
      </div>
      <div class="status" id="add-status"></div>
    </div>
  </div>

  <!-- Rule table with hit counts -->
  <div class="card">
    <h2>Active Rules &amp; Hit Counts</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Port</th><th>Action</th><th>Pkts Blocked</th><th>Bytes</th><th></th></tr>
      </thead>
      <tbody id="rules-body">
        <tr><td colspan="9" class="empty">Loading…</td></tr>
      </tbody>
    </table>
  </div>

</div>

<script>
// ── Minimal canvas line chart ────────────────────────────────────────────────
const canvas = document.getElementById('graph');
const ctx    = canvas.getContext('2d');
let history  = [];

function drawGraph() {
  const W = canvas.offsetWidth, H = canvas.offsetHeight;
  canvas.width  = W * devicePixelRatio;
  canvas.height = H * devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio);

  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, W, H);

  if (history.length < 2) {
    ctx.fillStyle = '#475569';
    ctx.font = '12px Segoe UI';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for data…', W/2, H/2);
    return;
  }

  const pad   = { t: 10, r: 10, b: 28, l: 42 };
  const iW    = W - pad.l - pad.r;
  const iH    = H - pad.t - pad.b;
  const maxV  = Math.max(...history.map(d => d.packets), 1);
  const minT  = history[0].t;
  const maxT  = history[history.length-1].t;
  const rangeT = maxT - minT || 1;

  const xOf = d => pad.l + ((d.t - minT) / rangeT) * iW;
  const yOf = d => pad.t + iH - (d.packets / maxV) * iH;

  // Grid lines
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (iH / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iW, y); ctx.stroke();
    ctx.fillStyle = '#475569'; ctx.font = '10px Segoe UI'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxV - (maxV/4)*i), pad.l - 4, y + 3);
  }

  // Gradient fill
  const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + iH);
  grad.addColorStop(0, 'rgba(167,139,250,0.35)');
  grad.addColorStop(1, 'rgba(167,139,250,0.0)');

  ctx.beginPath();
  ctx.moveTo(xOf(history[0]), yOf(history[0]));
  history.forEach(d => ctx.lineTo(xOf(d), yOf(d)));
  ctx.lineTo(xOf(history[history.length-1]), pad.t + iH);
  ctx.lineTo(xOf(history[0]), pad.t + iH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.strokeStyle = '#a78bfa';
  ctx.lineWidth   = 2;
  ctx.lineJoin    = 'round';
  history.forEach((d, i) => i === 0 ? ctx.moveTo(xOf(d), yOf(d)) : ctx.lineTo(xOf(d), yOf(d)));
  ctx.stroke();

  // Latest value dot
  const last = history[history.length-1];
  ctx.beginPath();
  ctx.arc(xOf(last), yOf(last), 4, 0, Math.PI*2);
  ctx.fillStyle = '#a78bfa'; ctx.fill();

  // X-axis label
  ctx.fillStyle = '#475569'; ctx.font = '10px Segoe UI'; ctx.textAlign = 'center';
  ctx.fillText('← ' + history.length + ' samples, every 3s →', pad.l + iW/2, H - 6);
}

// ── Data fetching ────────────────────────────────────────────────────────────
let statsCache = {};

async function fetchStats() {
  try {
    const [rulesRes, histRes] = await Promise.all([
      fetch('/firewall/stats'),
      fetch('/firewall/stats/history'),
    ]);
    statsCache = await rulesRes.json();
    const hist = await histRes.json();
    if (hist.length) history = hist;
    drawGraph();
  } catch(e) { /* controller not ready yet */ }
}

async function fetchRules() {
  try {
    const res   = await fetch('/firewall/rules');
    const rules = await res.json();

    const totalPkts  = Object.values(statsCache).reduce((a,s) => a + (s.packets||0), 0);
    const totalBytes = Object.values(statsCache).reduce((a,s) => a + (s.bytes||0),   0);

    document.getElementById('rule-count').textContent    = rules.length + ' rule' + (rules.length !== 1 ? 's' : '');
    document.getElementById('total-blocked').textContent = totalPkts + ' blocked';
    document.getElementById('s-rules').textContent       = rules.length;
    document.getElementById('s-blocked').textContent     = totalPkts.toLocaleString();
    document.getElementById('s-bytes').textContent       = fmtBytes(totalBytes);

    const tbody = document.getElementById('rules-body');
    if (!rules.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty">No rules yet. Add one above.</td></tr>';
      return;
    }
    tbody.innerHTML = rules.map((r, i) => {
      const st = statsCache[i] || { packets: 0, bytes: 0 };
      return `<tr>
        <td><code>${i}</code></td>
        <td>${r.src_ip || dim('any')}</td>
        <td>${r.dst_ip || dim('any')}</td>
        <td>${r.proto  || dim('any')}</td>
        <td>${r.dst_port || dim('—')}</td>
        <td>
          <span class="tag ${r.action==='block'?'tag-block':'tag-allow'}">${r.action||'block'}</span>
          ${r.bidirectional ? '<span class="tag tag-bi">↔</span>' : ''}
        </td>
        <td><span class="hit-badge">${st.packets.toLocaleString()}</span></td>
        <td>${fmtBytes(st.bytes)}</td>
        <td><button class="btn-del" onclick="deleteRule(${i})">Delete</button></td>
      </tr>`;
    }).join('');
  } catch(e) { /* ignore */ }
}

function dim(t) { return `<span style="color:#475569">${t}</span>`; }
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

async function addRule() {
  const rule = {};
  const src = document.getElementById('src_ip').value.trim();
  const dst = document.getElementById('dst_ip').value.trim();
  const proto = document.getElementById('proto').value;
  const port  = document.getElementById('dst_port').value;
  const bidir = document.getElementById('bidir').checked;

  if (src)   rule.src_ip = src;
  if (dst)   rule.dst_ip = dst;
  if (proto) rule.proto  = proto;
  if (port)  rule.dst_port = parseInt(port);
  if (bidir) rule.bidirectional = true;
  rule.action = document.getElementById('action').value;

  const status = document.getElementById('add-status');
  try {
    const res  = await fetch('/firewall/rules', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(rule)
    });
    const data = await res.json();
    if (data.status === 'rule installed') {
      status.className = 'status ok';
      status.textContent = 'Rule #' + data.rule_id + ' installed.';
      ['src_ip','dst_ip','dst_port'].forEach(id => document.getElementById(id).value='');
      document.getElementById('proto').value  = '';
      document.getElementById('action').value = 'block';
      document.getElementById('bidir').checked = false;
      fetchRules(); fetchStats();
    } else {
      status.className = 'status err';
      status.textContent = data.msg || 'Error';
    }
  } catch(e) {
    status.className = 'status err';
    status.textContent = e.message;
  }
}

async function deleteRule(id) {
  await fetch('/firewall/rules/' + id, { method: 'DELETE' });
  fetchRules(); fetchStats();
}

// ── Boot ────────────────────────────────────────────────────────────────────
fetchStats();
fetchRules();
setInterval(fetchStats, 3000);
setInterval(fetchRules, 3000);
window.addEventListener('resize', drawGraph);
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
        wsgi.register(FirewallController, {firewall_instance_name: self.firewall_app})


class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[firewall_instance_name]

    def json_response(self, data, status=200):
        body = (json.dumps(data) + "\n").encode("utf-8")
        return Response(content_type="application/json", charset="utf-8",
                        status=status, body=body)

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    @route("dashboard", "/", methods=["GET"])
    def dashboard(self, req, **kwargs):
        return Response(content_type="text/html", charset="utf-8",
                        body=DASHBOARD_HTML.encode("utf-8"))

    # ------------------------------------------------------------------
    # Rules
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

        rule_id = self.app.add_rule(body)
        return self.json_response({"status": "rule installed", "rule_id": rule_id, "rule": body})

    @route("firewall", "/firewall/rules/{rule_id}", methods=["DELETE"])
    def delete_rule(self, req, rule_id, **kwargs):
        try:
            rule_id = int(rule_id)
        except ValueError:
            return self.json_response({"status": "error", "msg": "rule_id must be int"}, 400)

        removed = self.app.delete_rule(rule_id)
        if removed is None:
            return self.json_response({"status": "error", "msg": "Rule not found"}, 404)
        return self.json_response({"status": "deleted and flow removed", "rule": removed})

    # ------------------------------------------------------------------
    # Hit counter endpoints (Improvement 6)
    # ------------------------------------------------------------------

    @route("stats", "/firewall/stats", methods=["GET"])
    def get_stats(self, req, **kwargs):
        """Per-rule packet/byte counts keyed by rule index (as string)."""
        data = {str(k): v for k, v in self.app.rule_stats.items()}
        return self.json_response(data)

    @route("stats_history", "/firewall/stats/history", methods=["GET"])
    def get_stats_history(self, req, **kwargs):
        """Time-series list of {t, packets} for the live graph."""
        return self.json_response(self.app.stats_history)
