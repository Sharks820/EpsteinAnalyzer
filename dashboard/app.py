"""
EpsteinAnalyzer - Dashboard Application
Flask web UI for investigative document analysis.
Runs locally at http://127.0.0.1:8080
"""

import html
import jinja2
import json
import logging
import os
import re
import sys
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    render_template_string,
    request,
    jsonify,
    redirect,
    url_for,
    abort,
    send_from_directory,
)
from flask_socketio import SocketIO, emit

# ---------------------------------------------------------------------------
# Resolve project root so imports work with `python -m dashboard.app`
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db import DatabaseManager  # noqa: E402

# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "EPSTEIN_SECRET_KEY", os.urandom(32).hex()
)
socketio = SocketIO(app, async_mode="threading")

# Lazy-initialized database manager (avoids import-time side effects)
_db: "DatabaseManager | None" = None
_db_lock = threading.Lock()
logger = logging.getLogger(__name__)


def _get_db() -> "DatabaseManager":
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                _db = DatabaseManager(str(PROJECT_ROOT / "config" / "settings.yaml"))
                _db.initialize()
    return _db

# ---------------------------------------------------------------------------
# Helper: get a fresh DB connection (with Row factory)
# ---------------------------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    return _get_db().get_connection()


def query_one(sql: str, params: tuple = ()):
    conn = get_conn()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def query_all(sql: str, params: tuple = ()):
    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_scalar(sql: str, params: tuple = ()):
    conn = get_conn()
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()):
    conn = get_conn()
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def escape_like(s: str) -> str:
    """Escape LIKE wildcard characters so user input is treated literally."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def sanitize_fts(q: str) -> str:
    """Strip non-word characters and wrap in double quotes to disable FTS5 operators."""
    cleaned = re.sub(r'[^\w\s]', '', q).strip()
    if not cleaned:
        return None  # Caller must handle: skip FTS query
    return '"' + cleaned.replace('"', '""') + '"'


def safe_json(val, default=None):
    """Parse a JSON column safely, returning *default* on failure."""
    if val is None:
        return default if default is not None else []
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


# ============================================================================
#  JINJA2 BASE TEMPLATE  (dark intelligence-analyst theme)
# ============================================================================

BASE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}EpsteinAnalyzer{% endblock %}</title>
<style>
/* ---- reset & base ---- */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#1c2333; --bg4:#21283b;
  --fg:#e6edf3; --fg2:#8b949e; --accent:#58a6ff; --accent2:#1f6feb;
  --green:#3fb950; --red:#f85149; --orange:#d29922; --purple:#bc8cff;
  --yellow:#e3b341; --cyan:#39d353; --pink:#f778ba;
  --border:#30363d; --shadow:rgba(0,0,0,.4);
  --font-mono:'Cascadia Code','Fira Code','Consolas',monospace;
  --font-sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
}
html{font-size:14px;scroll-behavior:smooth}
body{background:var(--bg);color:var(--fg);font-family:var(--font-sans);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
img{max-width:100%}
/* ---- layout ---- */
.app-shell{display:flex;min-height:100vh}
.sidebar{width:240px;background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:100;
  overflow-y:auto}
.sidebar .logo{padding:20px 16px 12px;font-size:1.15rem;font-weight:700;color:var(--accent);
  border-bottom:1px solid var(--border);letter-spacing:.5px;display:flex;align-items:center;gap:8px}
.sidebar .logo .dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.sidebar nav{flex:1;padding:8px 0}
.sidebar nav a{display:flex;align-items:center;gap:10px;padding:9px 16px;color:var(--fg2);
  font-size:.88rem;border-left:3px solid transparent;transition:.15s}
.sidebar nav a:hover,.sidebar nav a.active{background:var(--bg3);color:var(--fg);
  border-left-color:var(--accent);text-decoration:none}
.sidebar nav a .badge{margin-left:auto;background:var(--red);color:#fff;
  font-size:.7rem;padding:1px 6px;border-radius:10px;font-weight:600}
.sidebar .sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:.75rem;color:var(--fg2)}
.main{margin-left:240px;flex:1;padding:24px 32px 40px;min-width:0}
/* ---- typography ---- */
h1{font-size:1.6rem;font-weight:700;margin-bottom:4px}
h2{font-size:1.25rem;font-weight:600;margin-bottom:8px;color:var(--fg)}
h3{font-size:1.05rem;font-weight:600;margin-bottom:6px}
.subtitle{color:var(--fg2);font-size:.88rem;margin-bottom:20px}
/* ---- cards & panels ---- */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.card-header h3{margin:0}
.grid{display:grid;gap:16px}
.grid-2{grid-template-columns:repeat(2,1fr)}
.grid-3{grid-template-columns:repeat(3,1fr)}
.grid-4{grid-template-columns:repeat(4,1fr)}
@media(max-width:1200px){.grid-4{grid-template-columns:repeat(2,1fr)}}
@media(max-width:900px){.grid-3,.grid-2{grid-template-columns:1fr}.sidebar{display:none}.main{margin-left:0}}
/* ---- stat cards ---- */
.stat{text-align:center;padding:16px}
.stat .value{font-size:2rem;font-weight:700;color:var(--accent);line-height:1.1}
.stat .label{font-size:.78rem;color:var(--fg2);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.stat.green .value{color:var(--green)}.stat.red .value{color:var(--red)}
.stat.orange .value{color:var(--orange)}.stat.purple .value{color:var(--purple)}
/* ---- buttons ---- */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:6px;
  font-size:.85rem;font-weight:500;border:1px solid var(--border);background:var(--bg3);
  color:var(--fg);cursor:pointer;transition:.15s;font-family:inherit}
.btn:hover{background:var(--bg4);text-decoration:none}
.btn-primary{background:var(--accent2);border-color:var(--accent2);color:#fff}
.btn-primary:hover{background:#388bfd}
.btn-danger{background:#da3633;border-color:#da3633;color:#fff}
.btn-danger:hover{background:#f85149}
.btn-success{background:#238636;border-color:#238636;color:#fff}
.btn-success:hover{background:#2ea043}
.btn-warning{background:#9e6a03;border-color:#9e6a03;color:#fff}
.btn-sm{padding:5px 10px;font-size:.78rem}
.btn-lg{padding:12px 24px;font-size:1rem}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
/* ---- tables ---- */
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border)}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.5px;color:var(--fg2);font-weight:600}
tr:hover{background:var(--bg3)}
/* ---- badges / tags ---- */
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:500}
.tag-blue{background:rgba(88,166,255,.15);color:var(--accent)}
.tag-green{background:rgba(63,185,80,.15);color:var(--green)}
.tag-red{background:rgba(248,81,73,.15);color:var(--red)}
.tag-orange{background:rgba(210,153,34,.15);color:var(--orange)}
.tag-purple{background:rgba(188,140,255,.15);color:var(--purple)}
.tag-yellow{background:rgba(227,179,65,.15);color:var(--yellow)}
/* ---- forms ---- */
input[type=text],input[type=search],input[type=number],select,textarea{
  background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  color:var(--fg);padding:8px 12px;font-size:.88rem;font-family:inherit;width:100%}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(88,166,255,.15)}
/* ---- progress bar ---- */
.progress{height:8px;background:var(--bg4);border-radius:4px;overflow:hidden}
.progress-bar{height:100%;border-radius:4px;transition:width .4s}
.progress-bar.green{background:var(--green)}.progress-bar.blue{background:var(--accent)}
.progress-bar.orange{background:var(--orange)}.progress-bar.red{background:var(--red)}
/* ---- dataset buttons ---- */
.ds-grid{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.ds-btn{width:56px;height:40px;border-radius:6px;display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.9rem;cursor:pointer;border:2px solid transparent;transition:.15s}
.ds-btn.completed{background:rgba(63,185,80,.2);color:var(--green);border-color:var(--green)}
.ds-btn.current{background:rgba(88,166,255,.2);color:var(--accent);border-color:var(--accent);animation:pulse 2s infinite}
.ds-btn.pending{background:var(--bg4);color:var(--fg2);border-color:var(--border)}
.ds-btn:hover{transform:scale(1.08)}
/* ---- alerts ---- */
.alert{padding:12px 16px;border-radius:6px;margin-bottom:16px;border:1px solid;font-size:.88rem;
  display:flex;align-items:center;gap:10px}
.alert-critical{background:rgba(248,81,73,.1);border-color:var(--red);color:var(--red)}
.alert-warning{background:rgba(210,153,34,.1);border-color:var(--orange);color:var(--orange)}
.alert-info{background:rgba(88,166,255,.1);border-color:var(--accent);color:var(--accent)}
/* ---- highlight classes for document viewer ---- */
.hl-person{background:rgba(88,166,255,.25);color:#79c0ff;padding:1px 3px;border-radius:2px;cursor:pointer}
.hl-org{background:rgba(63,185,80,.25);color:var(--green);padding:1px 3px;border-radius:2px;cursor:pointer}
.hl-location{background:rgba(227,179,65,.25);color:var(--yellow);padding:1px 3px;border-radius:2px;cursor:pointer}
.hl-financial{background:rgba(248,81,73,.25);color:var(--red);padding:1px 3px;border-radius:2px}
.hl-legal{background:rgba(188,140,255,.25);color:var(--purple);padding:1px 3px;border-radius:2px}
.hl-redaction{background:#000;color:#fff;padding:1px 4px;border-radius:2px;cursor:pointer;
  text-shadow:0 0 6px var(--red),0 0 12px var(--orange);letter-spacing:.5px}
.hl-flagged{background:rgba(210,153,34,.3);color:var(--orange);padding:1px 3px;border-radius:2px;
  border:1px solid var(--orange)}
/* ---- entity leaderboard ---- */
.leaderboard-row{display:flex;align-items:center;gap:12px;padding:10px 12px;border-bottom:1px solid var(--border)}
.leaderboard-row:hover{background:var(--bg3)}
.leaderboard-rank{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.85rem;background:var(--bg4);color:var(--fg2);flex-shrink:0}
.leaderboard-row:nth-child(1) .leaderboard-rank{background:rgba(227,179,65,.2);color:var(--yellow)}
.leaderboard-row:nth-child(2) .leaderboard-rank{background:rgba(139,148,158,.2);color:var(--fg2)}
.leaderboard-row:nth-child(3) .leaderboard-rank{background:rgba(210,153,34,.2);color:var(--orange)}
.leaderboard-name{flex:1;font-weight:600}
.leaderboard-score{font-family:var(--font-mono);font-weight:700;font-size:1.1rem}
/* ---- search ---- */
.search-box{position:relative;margin-bottom:16px}
.search-box input{padding-left:36px}
.search-box::before{content:"";position:absolute;left:12px;top:50%;transform:translateY(-50%);
  width:16px;height:16px;border:2px solid var(--fg2);border-radius:50%}
/* ---- image review ---- */
.image-review-container{display:flex;gap:24px;align-items:flex-start}
.image-preview{flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  min-height:400px;display:flex;align-items:center;justify-content:center;overflow:hidden}
.image-preview img{max-width:100%;max-height:600px;object-fit:contain}
.image-controls{width:320px;flex-shrink:0}
/* ---- two-panel doc viewer ---- */
.doc-viewer{display:grid;grid-template-columns:1fr 1fr;gap:16px;min-height:600px}
.doc-viewer .panel{background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.doc-viewer .panel-header{padding:10px 16px;background:var(--bg3);border-bottom:1px solid var(--border);
  font-weight:600;font-size:.85rem;text-transform:uppercase;letter-spacing:.5px;color:var(--fg2)}
.doc-viewer .panel-body{padding:16px;overflow-y:auto;max-height:calc(100vh - 200px)}
.doc-viewer iframe{width:100%;height:calc(100vh - 200px);border:none;background:#fff}
/* ---- sparkline annotations ---- */
.annotation{background:var(--bg3);border-left:3px solid var(--accent);padding:10px 14px;
  margin-bottom:8px;border-radius:0 6px 6px 0;font-size:.88rem}
.annotation .an-label{font-size:.72rem;text-transform:uppercase;color:var(--fg2);margin-bottom:2px;font-weight:600}
/* ---- timeline ---- */
.timeline{position:relative;padding-left:24px}
.timeline::before{content:"";position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}
.timeline-item{position:relative;margin-bottom:16px;padding-left:16px}
.timeline-item::before{content:"";position:absolute;left:-20px;top:6px;width:12px;height:12px;
  border-radius:50%;background:var(--accent);border:2px solid var(--bg2)}
.timeline-date{font-size:.75rem;color:var(--fg2);font-family:var(--font-mono)}
/* ---- scrollbar ---- */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--fg2)}
/* ---- misc ---- */
.mono{font-family:var(--font-mono)}
.text-muted{color:var(--fg2)}
.text-red{color:var(--red)}.text-green{color:var(--green)}.text-orange{color:var(--orange)}
.text-accent{color:var(--accent)}.text-purple{color:var(--purple)}.text-yellow{color:var(--yellow)}
.mb-0{margin-bottom:0}.mb-1{margin-bottom:8px}.mb-2{margin-bottom:16px}.mb-3{margin-bottom:24px}
.mt-2{margin-top:16px}.mt-3{margin-top:24px}
.flex{display:flex}.flex-between{justify-content:space-between}.items-center{align-items:center}
.gap-2{gap:16px}.gap-1{gap:8px}
.hidden{display:none}
.w-full{width:100%}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999}
.toast{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 20px;
  margin-top:8px;box-shadow:0 4px 12px var(--shadow);animation:slideIn .3s}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
</style>
{% block head %}{% endblock %}
</head>
<body>
<div class="app-shell">
  <!-- Sidebar Navigation -->
  <aside class="sidebar">
    <div class="logo"><span class="dot"></span> EpsteinAnalyzer</div>
    <nav>
      <a href="/" class="{% if active == 'dashboard' %}active{% endif %}">&#9635; Command Center</a>
      <a href="/entities" class="{% if active == 'entities' %}active{% endif %}">&#9734; Entity Explorer</a>
      <a href="/graph" class="{% if active == 'graph' %}active{% endif %}">&#9784; Spiderweb Graph</a>
      <a href="/chains" class="{% if active == 'chains' %}active{% endif %}">&#9993; Email Chains</a>
      <a href="/findings" class="{% if active == 'findings' %}active{% endif %}">&#9873; Findings Board</a>
      <a href="/images/review" class="{% if active == 'images' %}active{% endif %}">&#9638; Image Review
        {% if pending_images %}<span class="badge">{{ pending_images }}</span>{% endif %}</a>
      <a href="/deletions" class="{% if active == 'deletions' %}active{% endif %}">&#9746; Deletion Queue
        {% if pending_deletions %}<span class="badge">{{ pending_deletions }}</span>{% endif %}</a>
      <a href="/export" class="{% if active == 'export' %}active{% endif %}">&#9112; Export Tools</a>
      <a href="/audit" class="{% if active == 'audit' %}active{% endif %}">&#9783; Audit Log</a>
      <a href="/settings" class="{% if active == 'settings' %}active{% endif %}">&#9881; Settings</a>
    </nav>
    <div class="sidebar-footer">
      Disk: {{ disk_pct }}% of {{ disk_max_gb }} GB<br>
      <div class="progress mt-1" style="margin-top:6px">
        <div class="progress-bar {% if disk_pct > 90 %}red{% elif disk_pct > 78 %}orange{% else %}green{% endif %}"
             style="width:{{ disk_pct }}%"></div>
      </div>
    </div>
  </aside>

  <!-- Main Content -->
  <main class="main">
    {% block content %}{% endblock %}
  </main>
</div>

<div id="toast-container" class="toast-container"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.4/socket.io.min.js"></script>
<script>
const socket = io();
socket.on('progress', function(data){
  showToast(data.message, data.level || 'info');
});
socket.on('refresh', function(){ location.reload(); });
function showToast(msg, level){
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast';
  t.style.borderLeftColor = level==='error'?'var(--red)':level==='success'?'var(--green)':'var(--accent)';
  t.style.borderLeftWidth = '3px';
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(()=>{ t.style.opacity='0'; setTimeout(()=>t.remove(),300); }, 4000);
}
function apiPost(url, body){
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})})
    .then(r=>r.json());
}
function apiGet(url){
  return fetch(url).then(r=>r.json());
}
</script>
{% block scripts %}{% endblock %}
</body>
</html>"""


# ============================================================================
#  Context processor -- injects sidebar data into every template
# ============================================================================

@app.context_processor
def inject_sidebar_data():
    try:
        stats = _get_db().get_stats()
    except Exception as e:
        logger.warning("sidebar stats failed: %s", e)
        stats = {}
    return {
        "pending_images": stats.get("pending_image_reviews", 0),
        "pending_deletions": stats.get("pending_deletions", 0),
        "disk_pct": stats.get("disk_usage_percent", 0),
        "disk_max_gb": stats.get("disk_max_gb", 0),
    }


# ============================================================================
#  1.  COMMAND CENTER  (/)
# ============================================================================

DASHBOARD_TEMPLATE = (
    BASE_TEMPLATE.replace("{% block title %}EpsteinAnalyzer{% endblock %}", "{% block title %}Command Center - EpsteinAnalyzer{% endblock %}")
    # We won't do string replacement on the base -- instead we use Jinja extends below
)

# For real Jinja rendering we need to use render_template_string with {% extends %}
# but that requires registering the base.  Simpler: we compose full pages inline.

COMMAND_CENTER_HTML = r"""{% extends "base.html" %}
{% block title %}Command Center - EpsteinAnalyzer{% endblock %}
{% block content %}
<!-- Removed Files Alert -->
{% if removed_count > 0 %}
<div class="alert alert-critical">
  <strong>&#9888; CRITICAL:</strong> {{ removed_count }} file(s) detected as removed from official sources!
  <a href="/entities?filter=removed" class="btn btn-danger btn-sm" style="margin-left:auto">Investigate Now</a>
</div>
{% endif %}

{% if needs_compact %}
<div class="alert alert-warning">
  <strong>&#9888; DISK WARNING:</strong> Usage at {{ disk_usage_pct }}% - auto-compact recommended.
  <button class="btn btn-warning btn-sm" style="margin-left:auto" onclick="apiPost('/api/compact').then(d=>{showToast('Compact complete: freed '+d.freed_mb+'MB','success');setTimeout(()=>location.reload(),1500)})">Run Auto-Compact</button>
</div>
{% endif %}

<h1>Command Center</h1>
<p class="subtitle">Dataset loading, pipeline status, and analysis overview</p>

<!-- Dataset Status -->
<div class="card">
  <div class="card-header">
    <h3>Dataset Status</h3>
    <button class="btn btn-primary" onclick="loadNextDataset()">Load Next Dataset</button>
  </div>
  <div class="ds-grid">
    {% for ds in datasets %}
    <div class="ds-btn {{ ds.css_class }}" title="Dataset {{ ds.dataset_number }}: {{ ds.status }}"
         onclick="loadDataset({{ ds.dataset_number }})">
      {{ ds.dataset_number }}
    </div>
    {% endfor %}
    {% for n in range(datasets|length + 1, 13) %}
    <div class="ds-btn pending" title="Dataset {{ n }}: not started" onclick="loadDataset({{ n }})">{{ n }}</div>
    {% endfor %}
  </div>
  <div id="ds-progress" class="hidden">
    <p id="ds-progress-text" class="text-accent mb-1"></p>
    <div class="progress"><div id="ds-progress-bar" class="progress-bar blue" style="width:0%"></div></div>
  </div>
</div>

<!-- Stats Grid -->
<div class="grid grid-4 mb-3">
  <div class="card stat">
    <div class="value">{{ stats.total_documents }}</div>
    <div class="label">Documents</div>
  </div>
  <div class="card stat green">
    <div class="value">{{ stats.processed_documents }}</div>
    <div class="label">Analyzed</div>
  </div>
  <div class="card stat purple">
    <div class="value">{{ stats.total_entities }}</div>
    <div class="label">Entities</div>
  </div>
  <div class="card stat orange">
    <div class="value">{{ stats.total_relationships }}</div>
    <div class="label">Connections</div>
  </div>
</div>

<div class="grid grid-3 mb-3">
  <div class="card stat">
    <div class="value">{{ stats.total_redactions }}</div>
    <div class="label">Redactions Found</div>
  </div>
  <div class="card stat green">
    <div class="value">{{ stats.recovered_redactions }}</div>
    <div class="label">Redactions Recovered</div>
  </div>
  <div class="card stat red">
    <div class="value">{{ stats.removed_files_detected }}</div>
    <div class="label">Removed Files</div>
  </div>
</div>

<div class="grid grid-2">
  <!-- Pipeline Status -->
  <div class="card">
    <h3 class="mb-2">Pipeline Status</h3>
    <table>
      <tr><td>Downloaded</td><td class="mono text-accent">{{ pipeline.downloaded }}</td></tr>
      <tr><td>OCR Processed</td><td class="mono text-green">{{ pipeline.ocr_complete }}</td></tr>
      <tr><td>AI Analyzed</td><td class="mono text-purple">{{ pipeline.analyzed }}</td></tr>
      <tr><td>User Reviewed</td><td class="mono text-yellow">{{ pipeline.reviewed }}</td></tr>
      <tr><td>Email Chains</td><td class="mono">{{ stats.total_email_chains }}</td></tr>
      <tr><td>Findings Pinned</td><td class="mono">{{ stats.total_findings }}</td></tr>
    </table>
  </div>

  <!-- Top Priority Documents -->
  <div class="card">
    <h3 class="mb-2">Top Priority Documents</h3>
    {% if priority_docs %}
    <table>
      <thead><tr><th>Document</th><th>Score</th><th>Type</th></tr></thead>
      <tbody>
      {% for doc in priority_docs %}
      <tr>
        <td><a href="/document/{{ doc.id }}">{{ doc.original_filename|truncate(40) }}</a></td>
        <td class="mono text-orange">{{ doc.priority_score }}</td>
        <td><span class="tag tag-blue">{{ doc.doc_type or 'unknown' }}</span></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="text-muted">No documents processed yet.</p>
    {% endif %}
  </div>
</div>

<div class="grid grid-2 mt-2">
  <!-- Recent AI Findings -->
  <div class="card">
    <h3 class="mb-2">Recent AI Findings</h3>
    {% if recent_analyses %}
    {% for a in recent_analyses %}
    <div class="annotation">
      <div class="an-label">{{ a.model_name }} &middot; {{ a.created_at }}</div>
      {{ a.summary|default('Analysis pending...')|truncate(200) }}
      {% if a.document_id %}
      <a href="/document/{{ a.document_id }}" class="btn btn-sm mt-1" style="margin-top:6px;display:inline-block">View Document</a>
      {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <p class="text-muted">No AI analyses completed yet.</p>
    {% endif %}
  </div>

  <!-- Knowledge Graph Stats -->
  <div class="card">
    <h3 class="mb-2">Knowledge Graph</h3>
    <div class="grid grid-2">
      <div class="stat"><div class="value text-accent">{{ stats.total_entities }}</div><div class="label">Entities</div></div>
      <div class="stat"><div class="value text-purple">{{ stats.total_relationships }}</div><div class="label">Connections</div></div>
    </div>
    <div class="grid grid-2 mt-2">
      <div class="stat"><div class="value text-orange">{{ stats.total_redactions }}</div><div class="label">Redactions</div></div>
      <div class="stat"><div class="value text-green">{{ stats.recovered_redactions }}</div><div class="label">Recovered</div></div>
    </div>
    <div class="mt-2" style="text-align:center">
      <a href="/graph" class="btn btn-primary">Open Spiderweb View</a>
    </div>
  </div>
</div>
{% endblock %}

{% block scripts %}
<script>
socket.on('dataset_progress', function(data){
  const el = document.getElementById('ds-progress');
  const bar = document.getElementById('ds-progress-bar');
  const txt = document.getElementById('ds-progress-text');
  el.classList.remove('hidden');
  bar.style.width = data.percent + '%';
  txt.textContent = data.message;
  if(data.percent >= 100){ setTimeout(()=>location.reload(), 2000); }
});
function loadDataset(n){
  showToast('Starting dataset '+n+'...','info');
  apiPost('/api/dataset/'+n+'/load');
}
function loadNextDataset(){
  apiGet('/api/stats').then(data => {
    // Find the next unloaded dataset
    let next = 1;
    if(data.datasets){
      for(let d of data.datasets){
        if(d.status !== 'processed' && d.status !== 'processing'){
          next = d.dataset_number;
          break;
        }
        next = d.dataset_number + 1;
      }
    }
    if(next > 12) next = 12;
    loadDataset(next);
  });
}
</script>
{% endblock %}
"""


@app.route("/")
def command_center():
    stats = _get_db().get_stats()
    datasets_raw = _get_db().get_dataset_status()
    # Add CSS class for dataset buttons
    datasets = []
    for ds in datasets_raw:
        d = dict(ds)
        if d["status"] in ("processed",):
            d["css_class"] = "completed"
        elif d["status"] in ("downloading", "processing"):
            d["css_class"] = "current"
        else:
            d["css_class"] = "pending"
        datasets.append(d)

    # Pipeline counts
    pipeline = {
        "downloaded": query_scalar("SELECT COUNT(*) FROM documents WHERE status != 'pending'"),
        "ocr_complete": query_scalar("SELECT COUNT(*) FROM documents WHERE ocr_completed = 1"),
        "analyzed": query_scalar("SELECT COUNT(*) FROM documents WHERE analysis_completed = 1"),
        "reviewed": query_scalar("SELECT COUNT(*) FROM documents WHERE user_reviewed = 1"),
    }

    priority_docs = query_all(
        "SELECT id, original_filename, priority_score, doc_type FROM documents ORDER BY priority_score DESC LIMIT 10"
    )
    recent_analyses = query_all(
        "SELECT document_id, model_name, summary, created_at FROM ai_analyses ORDER BY created_at DESC LIMIT 5"
    )
    removed_count = stats.get("removed_files_detected", 0)

    return render_template_string(
        COMMAND_CENTER_HTML,
        active="dashboard",
        stats=stats,
        datasets=datasets,
        pipeline=pipeline,
        priority_docs=priority_docs,
        recent_analyses=recent_analyses,
        removed_count=removed_count,
        needs_compact=stats.get("needs_compact", False),
        disk_usage_pct=stats.get("disk_usage_percent", 0),
    )


# ============================================================================
#  2.  DOCUMENT VIEWER  (/document/<id>)
# ============================================================================

DOCUMENT_VIEWER_HTML = r"""{% extends "base.html" %}
{% block title %}Document {{ doc.id }} - EpsteinAnalyzer{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>{{ doc.original_filename }}</h1>
    <p class="subtitle">
      Dataset {{ doc.dataset_id or '?' }} &middot; {{ doc.page_count }} pages &middot;
      Priority: <span class="text-orange">{{ doc.priority_score }}</span> &middot;
      <span class="tag tag-{{ 'green' if doc.analysis_completed else 'orange' }}">
        {{ doc.status }}
      </span>
    </p>
  </div>
  <div class="btn-group">
    <button class="btn btn-sm {% if doc.user_flagged %}btn-warning{% endif %}"
            onclick="apiPost('/api/document/{{ doc.id }}/flag').then(()=>location.reload())">
      {% if doc.user_flagged %}Flagged{% else %}Flag{% endif %}
    </button>
    {% if prev_doc_id %}<a href="/document/{{ prev_doc_id }}" class="btn btn-sm">&larr; Prev</a>{% endif %}
    {% if next_doc_id %}<a href="/document/{{ next_doc_id }}" class="btn btn-sm">Next &rarr;</a>{% endif %}
  </div>
</div>

<div class="doc-viewer">
  <!-- Left Panel: PDF / Source View -->
  <div class="panel">
    <div class="panel-header">Original Document</div>
    {% if doc.file_path and doc.file_type == 'pdf' %}
    <iframe src="/serve_file/{{ doc.id }}" title="PDF Viewer"></iframe>
    {% else %}
    <div class="panel-body">
      <p class="text-muted">Preview not available for {{ doc.file_type }} files.</p>
      {% if pages %}
      <h3 class="mb-2 mt-2">Extracted Text</h3>
      {% for page in pages %}
      <div class="card">
        <div class="text-muted mb-1">Page {{ page.page_number }}</div>
        <pre style="white-space:pre-wrap;font-size:.85rem">{{ page.text_content }}</pre>
      </div>
      {% endfor %}
      {% endif %}
    </div>
    {% endif %}
  </div>

  <!-- Right Panel: AI Analysis -->
  <div class="panel">
    <div class="panel-header">AI Analysis</div>
    <div class="panel-body">
      <!-- Highlight Legend -->
      <div class="mb-2" style="display:flex;gap:8px;flex-wrap:wrap;font-size:.78rem">
        <span class="hl-person">Person</span>
        <span class="hl-org">Organization</span>
        <span class="hl-location">Location</span>
        <span class="hl-financial">Financial</span>
        <span class="hl-legal">Legal Case</span>
        <span class="hl-redaction">Redaction</span>
        <span class="hl-flagged">AI Flagged</span>
      </div>

      {% if consensus %}
      <div class="card">
        <h3 class="mb-1">Consensus Summary</h3>
        <p>{{ consensus.consensus_summary or 'No consensus generated yet.' }}</p>
        {% if consensus.agreement_level %}
        <span class="tag tag-{{ 'green' if consensus.agreement_level == 'full' else 'orange' }} mt-1">
          Agreement: {{ consensus.agreement_level }}
        </span>
        {% endif %}
      </div>
      {% endif %}

      <!-- Paragraph Annotations (Spark Notes) -->
      {% if annotations %}
      <h3 class="mb-2">Paragraph-by-Paragraph Analysis</h3>
      {% for ann in annotations %}
      <div class="annotation">
        <div class="an-label">Page {{ ann.page }} &middot; Para {{ ann.para }}</div>
        <div>{{ ann.html|safe }}</div>
      </div>
      {% endfor %}
      {% endif %}

      <!-- Entity Mentions -->
      {% if entity_links %}
      <h3 class="mb-2 mt-3">Entities in This Document</h3>
      <table>
        <thead><tr><th>Entity</th><th>Type</th><th>Score</th><th>Mention</th></tr></thead>
        <tbody>
        {% for el in entity_links %}
        <tr>
          <td>
            <a href="/entity/{{ el.entity_id }}">{{ el.entity_name }}</a>
            {% if el.entity_type == 'person' %}
              <a href="https://www.google.com/search?q={{ el.entity_name|urlencode }}" target="_blank"
                 class="btn btn-sm" style="margin-left:4px;padding:2px 6px;font-size:.7rem">G</a>
            {% elif el.entity_type == 'organization' %}
              <a href="https://www.google.com/search?q={{ el.entity_name|urlencode }}+public+records" target="_blank"
                 class="btn btn-sm" style="margin-left:4px;padding:2px 6px;font-size:.7rem">PR</a>
            {% elif el.entity_type == 'location' %}
              <a href="https://www.google.com/maps/search/{{ el.entity_name|urlencode }}" target="_blank"
                 class="btn btn-sm" style="margin-left:4px;padding:2px 6px;font-size:.7rem">Map</a>
            {% endif %}
          </td>
          <td><span class="tag tag-{{ {'person':'blue','organization':'green','location':'yellow','financial':'red','legal_case':'purple'}.get(el.entity_type,'blue') }}">{{ el.entity_type }}</span></td>
          <td class="mono text-orange">{{ el.damning_score }}</td>
          <td class="truncate" style="max-width:200px">{{ el.mention_type or '' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% endif %}

      <!-- Redactions on this document -->
      {% if redactions %}
      <h3 class="mb-2 mt-3">Redactions ({{ redactions|length }})</h3>
      {% for r in redactions %}
      <div class="card" style="border-left:3px solid {% if r.is_recovered %}var(--green){% else %}var(--red){% endif %}">
        <div class="flex flex-between items-center">
          <span>Page {{ r.page_number }} &middot; {{ r.redaction_type }}</span>
          {% if r.is_recovered %}
          <span class="tag tag-green">RECOVERED</span>
          {% else %}
          <span class="tag tag-red">UNRESOLVED</span>
          {% endif %}
        </div>
        {% if r.recovered_text %}
        <div class="mt-1"><strong>Recovered:</strong> <span class="hl-redaction">{{ r.recovered_text }}</span></div>
        {% endif %}
        {% if r.ai_candidates_parsed %}
        <div class="mt-1 text-muted" style="font-size:.82rem">
          <strong>AI Candidates:</strong>
          {% for c in r.ai_candidates_parsed %}
          {{ c.name }} ({{ (c.confidence * 100)|int }}%){% if not loop.last %}, {% endif %}
          {% endfor %}
        </div>
        {% endif %}
        {% if r.context_before %}
        <div class="mt-1 text-muted" style="font-size:.82rem">...{{ r.context_before[-80:] }} <span class="hl-redaction">[REDACTED]</span> {{ r.context_after[:80] if r.context_after }}...</div>
        {% endif %}
      </div>
      {% endfor %}
      {% endif %}

      <!-- Source Info -->
      <div class="card mt-3" style="background:var(--bg3)">
        <h3 class="mb-1" style="font-size:.85rem">Source Information</h3>
        <table style="font-size:.82rem">
          <tr><td class="text-muted">File</td><td>{{ doc.original_filename }}</td></tr>
          <tr><td class="text-muted">Hash</td><td class="mono" style="font-size:.75rem">{{ doc.file_hash[:24] }}...</td></tr>
          <tr><td class="text-muted">Source</td><td>{{ doc.source }}</td></tr>
          <tr><td class="text-muted">Type</td><td>{{ doc.doc_type or 'Unknown' }}</td></tr>
          <tr><td class="text-muted">Pages</td><td>{{ doc.page_count }}</td></tr>
          <tr><td class="text-muted">Size</td><td>{{ (doc.size_bytes / 1024)|round(1) }} KB</td></tr>
          {% if doc.is_removed_from_source %}<tr><td class="text-red">REMOVED</td><td class="text-red">This file has been removed from its original source!</td></tr>{% endif %}
        </table>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/document/<int:doc_id>")
def document_viewer(doc_id):
    doc = query_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
    if not doc:
        abort(404)

    pages = query_all(
        "SELECT page_number, text_content FROM document_pages WHERE document_id = ? ORDER BY page_number",
        (doc_id,),
    )

    # Consensus analysis
    consensus = query_one("SELECT * FROM ai_consensus WHERE document_id = ?", (doc_id,))

    # Entity links
    entity_links = query_all(
        """SELECT edl.*, e.name as entity_name, e.entity_type, e.implication_score
           FROM entity_document_links edl
           JOIN entities e ON e.id = edl.entity_id
           WHERE edl.document_id = ?
           ORDER BY edl.damning_score DESC""",
        (doc_id,),
    )

    # Redactions
    redactions_raw = query_all(
        "SELECT * FROM redactions WHERE document_id = ? ORDER BY page_number", (doc_id,)
    )
    redactions = []
    for r in redactions_raw:
        r["ai_candidates_parsed"] = safe_json(r.get("ai_candidates"), [])
        redactions.append(r)

    # Build paragraph annotations from pages + AI analyses
    annotations = []
    analyses = query_all(
        "SELECT * FROM ai_analyses WHERE document_id = ? ORDER BY created_at DESC LIMIT 1",
        (doc_id,),
    )
    for i, page in enumerate(pages):
        text = page.get("text_content", "") or ""
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        for j, para in enumerate(paragraphs[:5]):  # Limit to 5 per page for performance
            # Apply entity highlighting (escape para first to prevent XSS)
            # Sort entities longest-first so shorter names don't break longer ones
            highlighted = html.escape(para)
            for el in sorted(entity_links, key=lambda e: len(e.get("entity_name", "")), reverse=True):
                name = el.get("entity_name", "")
                if not name:
                    continue
                safe_name = html.escape(name)
                if safe_name in highlighted:
                    etype = el.get("entity_type", "person")
                    css_map = {
                        "person": "hl-person",
                        "organization": "hl-org",
                        "location": "hl-location",
                        "financial": "hl-financial",
                        "legal_case": "hl-legal",
                    }
                    css = css_map.get(etype, "hl-person")
                    link = f'<a href="/entity/{int(el["entity_id"])}" class="{css}">{safe_name}</a>'
                    highlighted = highlighted.replace(safe_name, link)
            annotations.append({
                "page": page["page_number"],
                "para": j + 1,
                "html": highlighted,
            })

    # Query actual prev/next document IDs (handles non-contiguous IDs)
    prev_row = query_one("SELECT id FROM documents WHERE id < ? ORDER BY id DESC LIMIT 1", (doc_id,))
    next_row = query_one("SELECT id FROM documents WHERE id > ? ORDER BY id ASC LIMIT 1", (doc_id,))

    return render_template_string(
        DOCUMENT_VIEWER_HTML,
        active="document",
        doc=doc,
        pages=pages,
        consensus=consensus,
        entity_links=entity_links,
        redactions=redactions,
        annotations=annotations[:50],  # Cap total annotations
        prev_doc_id=prev_row["id"] if prev_row else None,
        next_doc_id=next_row["id"] if next_row else None,
    )


@app.route("/serve_file/<int:doc_id>")
def serve_file(doc_id):
    doc = query_one("SELECT file_path FROM documents WHERE id = ?", (doc_id,))
    if not doc or not doc.get("file_path"):
        abort(404)
    fp = Path(doc["file_path"]).resolve()
    # Prevent path traversal: file must be inside the configured data directory
    data_dir = _get_db().data_dir.resolve()
    if not fp.is_relative_to(data_dir):
        abort(403)
    if not fp.exists():
        abort(404)
    return send_from_directory(str(fp.parent), fp.name)


# ============================================================================
#  3.  ENTITY EXPLORER  (/entities)
# ============================================================================

ENTITIES_HTML = r"""{% extends "base.html" %}
{% block title %}Entity Explorer - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Entity Explorer</h1>
<p class="subtitle">Searchable index of all identified entities with implication rankings</p>

<div class="grid grid-2 mb-3">
  <!-- Search & Filter -->
  <div class="card">
    <h3 class="mb-2">Search & Filter</h3>
    <form method="get" action="/entities">
      <div class="mb-1">
        <input type="search" name="q" value="{{ q }}" placeholder="Search entities by name, alias, or role...">
      </div>
      <div class="flex gap-1 mb-1">
        <select name="type" style="flex:1">
          <option value="">All Types</option>
          {% for t in entity_types %}<option value="{{ t }}" {% if t == filter_type %}selected{% endif %}>{{ t }}</option>{% endfor %}
        </select>
        <input type="number" name="min_score" value="{{ min_score }}" placeholder="Min score" style="flex:1">
        <input type="number" name="max_score" value="{{ max_score }}" placeholder="Max score" style="flex:1">
      </div>
      <div class="flex gap-1">
        <select name="dataset" style="flex:1">
          <option value="">All Datasets</option>
          {% for i in range(1,13) %}<option value="{{ i }}" {% if i == filter_dataset %}selected{% endif %}>Dataset {{ i }}</option>{% endfor %}
        </select>
        <button class="btn btn-primary" type="submit">Search</button>
      </div>
    </form>
  </div>

  <!-- Quick Stats -->
  <div class="card">
    <h3 class="mb-2">Global Implication Leaderboard</h3>
    {% for e in top_entities %}
    <div class="leaderboard-row">
      <div class="leaderboard-rank">{{ loop.index }}</div>
      <div class="leaderboard-name">
        <a href="/entity/{{ e.id }}">{{ e.canonical_name or e.name }}</a>
        <div class="text-muted" style="font-size:.75rem">{{ e.entity_type }} &middot; {{ e.evidence_count }} evidence</div>
      </div>
      <div class="leaderboard-score text-orange">{{ e.effective_score|round(1) }}</div>
    </div>
    {% endfor %}
    {% if not top_entities %}
    <p class="text-muted">No entities recorded yet.</p>
    {% endif %}
  </div>
</div>

<!-- Results Table -->
<div class="card">
  <div class="card-header">
    <h3>{{ entities|length }} Entities Found</h3>
  </div>
  <table>
    <thead>
      <tr><th>#</th><th>Name</th><th>Type</th><th>Role</th><th>Score</th><th>Evidence</th><th>Docs</th><th>Actions</th></tr>
    </thead>
    <tbody>
    {% for e in entities %}
    <tr>
      <td class="text-muted">{{ e.id }}</td>
      <td><a href="/entity/{{ e.id }}"><strong>{{ e.canonical_name or e.name }}</strong></a>
        {% if e.is_victim %}<span class="tag tag-red" style="font-size:.65rem">VICTIM</span>{% endif %}
        {% if e.is_redacted_placeholder %}<span class="tag tag-purple" style="font-size:.65rem">REDACTED</span>{% endif %}
      </td>
      <td><span class="tag tag-{{ {'person':'blue','organization':'green','location':'yellow','financial':'red','legal_case':'purple'}.get(e.entity_type,'blue') }}">{{ e.entity_type }}</span></td>
      <td class="truncate" style="max-width:180px">{{ e.role or '' }}</td>
      <td class="mono text-orange">{{ e.effective_score|round(1) }}</td>
      <td class="mono">{{ e.evidence_count }}</td>
      <td class="mono">{{ e.document_count }}</td>
      <td><a href="/entity/{{ e.id }}" class="btn btn-sm">View</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""


@app.route("/entities")
def entities_list():
    q = request.args.get("q", "").strip()
    filter_type = request.args.get("type", "")
    min_score = request.args.get("min_score", "")
    max_score = request.args.get("max_score", "")
    filter_dataset = request.args.get("dataset", "")

    # Build query
    conditions = []
    params = []
    if q:
        conditions.append(
            r"(e.name LIKE ? ESCAPE '\' OR e.canonical_name LIKE ? ESCAPE '\'"
            r" OR e.aliases LIKE ? ESCAPE '\' OR e.role LIKE ? ESCAPE '\')"
        )
        like = f"%{escape_like(q)}%"
        params.extend([like, like, like, like])
    if filter_type:
        conditions.append("e.entity_type = ?")
        params.append(filter_type)
    if min_score:
        try:
            conditions.append("COALESCE(e.user_score, e.implication_score) >= ?")
            params.append(float(min_score))
        except (ValueError, TypeError):
            pass
    if max_score:
        try:
            conditions.append("COALESCE(e.user_score, e.implication_score) <= ?")
            params.append(float(max_score))
        except (ValueError, TypeError):
            pass
    if filter_dataset:
        try:
            conditions.append("e.first_seen_dataset = ?")
            params.append(int(filter_dataset))
        except (ValueError, TypeError):
            pass

    where = " AND ".join(conditions) if conditions else "1=1"
    sql = f"""
        SELECT e.*,
               COALESCE(e.user_score, e.implication_score) as effective_score
        FROM entities e
        WHERE {where}
        ORDER BY effective_score DESC
        LIMIT 200
    """
    entities = query_all(sql, tuple(params))

    # Top leaderboard (always top 10 overall)
    top_entities = query_all("""
        SELECT id, name, canonical_name, entity_type, evidence_count,
               COALESCE(user_score, implication_score) as effective_score
        FROM entities
        WHERE is_victim = 0
        ORDER BY effective_score DESC
        LIMIT 10
    """)

    entity_types = [
        "person", "organization", "location", "aircraft",
        "financial", "legal_case", "contact_info", "event", "redacted_entity",
    ]

    return render_template_string(
        ENTITIES_HTML,
        active="entities",
        entities=entities,
        top_entities=top_entities,
        entity_types=entity_types,
        q=q,
        filter_type=filter_type,
        min_score=min_score,
        max_score=max_score,
        filter_dataset=int(filter_dataset) if filter_dataset and filter_dataset.isdigit() else None,
    )


# ============================================================================
#  4.  ENTITY EVIDENCE CARD  (/entity/<id>)
# ============================================================================

ENTITY_CARD_HTML = r"""{% extends "base.html" %}
{% block title %}{{ entity.canonical_name or entity.name }} - EpsteinAnalyzer{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>{{ entity.canonical_name or entity.name }}</h1>
    <p class="subtitle">
      <span class="tag tag-{{ {'person':'blue','organization':'green','location':'yellow','financial':'red','legal_case':'purple'}.get(entity.entity_type,'blue') }}">{{ entity.entity_type }}</span>
      {% if entity.role %}&middot; {{ entity.role }}{% endif %}
      {% if entity.organization %}&middot; {{ entity.organization }}{% endif %}
    </p>
  </div>
  <div class="btn-group">
    {% if entity.google_url %}
    <a href="{{ entity.google_url }}" target="_blank" class="btn btn-sm">Google</a>
    {% else %}
    <a href="https://www.google.com/search?q={{ (entity.canonical_name or entity.name)|urlencode }}" target="_blank" class="btn btn-sm">Google</a>
    {% endif %}
    {% if entity.wikipedia_url %}
    <a href="{{ entity.wikipedia_url }}" target="_blank" class="btn btn-sm">Wikipedia</a>
    {% else %}
    <a href="https://en.wikipedia.org/wiki/Special:Search?search={{ (entity.canonical_name or entity.name)|urlencode }}" target="_blank" class="btn btn-sm">Wikipedia</a>
    {% endif %}
  </div>
</div>

<!-- Score Card -->
<div class="grid grid-4 mb-3">
  <div class="card stat orange">
    <div class="value">{{ effective_score|round(1) }}</div>
    <div class="label">Implication Score</div>
  </div>
  <div class="card stat">
    <div class="value">{{ entity.evidence_count }}</div>
    <div class="label">Evidence Items</div>
  </div>
  <div class="card stat">
    <div class="value">{{ entity.document_count }}</div>
    <div class="label">Documents</div>
  </div>
  <div class="card stat purple">
    <div class="value">{{ redaction_exposure }}</div>
    <div class="label">Redaction Candidates</div>
  </div>
</div>

{% if entity.user_score_locked %}
<div class="alert alert-info mb-2">Score manually locked by user at {{ entity.user_score }}</div>
{% endif %}

<div class="grid grid-2 mb-3">
  <!-- Top 5 Most Damning Evidence -->
  <div class="card">
    <h3 class="mb-2">Top 5 Most Damning Evidence</h3>
    {% for ev in top_evidence %}
    <div class="card" style="border-left:3px solid var(--orange)">
      <div class="flex flex-between items-center">
        <span class="mono text-orange" style="font-size:1.1rem;font-weight:700">{{ ev.damning_score }}</span>
        <span class="tag tag-{{ {'email':'blue','flight_log':'green','financial':'red','testimony':'yellow','photo_video':'purple','court_filing':'purple'}.get(ev.evidence_type,'blue') }}">{{ ev.evidence_type or 'other' }}</span>
      </div>
      <p class="mt-1" style="font-size:.88rem">{{ ev.context_snippet|truncate(200) if ev.context_snippet else 'No snippet available' }}</p>
      {% if ev.score_reasoning %}<p class="text-muted mt-1" style="font-size:.78rem">{{ ev.score_reasoning }}</p>{% endif %}
      <a href="/document/{{ ev.document_id }}" class="btn btn-sm mt-1" style="margin-top:6px;display:inline-block">View Document</a>
    </div>
    {% endfor %}
    {% if not top_evidence %}
    <p class="text-muted">No evidence linked yet.</p>
    {% endif %}
  </div>

  <!-- Evidence Breakdown by Type -->
  <div class="card">
    <h3 class="mb-2">Evidence Breakdown by Type</h3>
    <table>
      <thead><tr><th>Type</th><th>Count</th><th>Avg Score</th></tr></thead>
      <tbody>
      {% for b in evidence_breakdown %}
      <tr>
        <td><span class="tag tag-{{ {'email':'blue','flight_log':'green','financial':'red','testimony':'yellow','photo_video':'purple','court_filing':'purple'}.get(b.evidence_type,'blue') }}">{{ b.evidence_type or 'other' }}</span></td>
        <td class="mono">{{ b.cnt }}</td>
        <td class="mono text-orange">{{ b.avg_score|round(1) }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>

    <h3 class="mb-2 mt-3">Connections ({{ connections|length }})</h3>
    {% for c in connections %}
    <div class="leaderboard-row">
      <div class="leaderboard-rank" style="font-size:.7rem;width:24px;height:24px">{{ c.shared }}</div>
      <div class="leaderboard-name">
        <a href="/entity/{{ c.id }}">{{ c.name }}</a>
        <div class="text-muted" style="font-size:.72rem">{{ c.relationship_type }}</div>
      </div>
    </div>
    {% endfor %}
    {% if not connections %}
    <p class="text-muted">No connections mapped yet.</p>
    {% endif %}
  </div>
</div>

<!-- All Evidence Documents Button -->
<div style="text-align:center" class="mt-3">
  <a href="/entities?q={{ (entity.canonical_name or entity.name)|urlencode }}" class="btn btn-primary btn-lg">
    VIEW ALL EVIDENCE DOCUMENTS
  </a>
</div>
{% endblock %}
"""


@app.route("/entity/<int:entity_id>")
def entity_card(entity_id):
    entity = query_one("SELECT * FROM entities WHERE id = ?", (entity_id,))
    if not entity:
        abort(404)

    effective_score = entity.get("user_score") if entity.get("user_score") is not None else entity.get("implication_score", 0)

    top_evidence = query_all(
        """SELECT edl.*, d.original_filename
           FROM entity_document_links edl
           JOIN documents d ON d.id = edl.document_id
           WHERE edl.entity_id = ?
           ORDER BY edl.damning_score DESC
           LIMIT 5""",
        (entity_id,),
    )

    evidence_breakdown = query_all(
        """SELECT evidence_type, COUNT(*) as cnt, AVG(damning_score) as avg_score
           FROM entity_document_links
           WHERE entity_id = ?
           GROUP BY evidence_type
           ORDER BY cnt DESC""",
        (entity_id,),
    )

    # Connections via relationships
    connections = query_all(
        """SELECT e.id, e.name, r.relationship_type, r.evidence_count as shared
           FROM relationships r
           JOIN entities e ON e.id = r.target_entity_id
           WHERE r.source_entity_id = ?
           UNION
           SELECT e.id, e.name, r.relationship_type, r.evidence_count as shared
           FROM relationships r
           JOIN entities e ON e.id = r.source_entity_id
           WHERE r.target_entity_id = ?
           ORDER BY shared DESC
           LIMIT 20""",
        (entity_id, entity_id),
    )

    # Redaction exposure -- how many redactions list this entity as a candidate
    redaction_exposure = query_scalar(
        r"SELECT COUNT(*) FROM redactions WHERE ai_candidates LIKE ? ESCAPE '\'",
        (f"%{escape_like(entity.get('name', ''))}%",),
    )

    return render_template_string(
        ENTITY_CARD_HTML,
        active="entities",
        entity=entity,
        effective_score=effective_score,
        top_evidence=top_evidence,
        evidence_breakdown=evidence_breakdown,
        connections=connections,
        redaction_exposure=redaction_exposure,
    )


# ============================================================================
#  5.  SPIDERWEB GRAPH  (/graph)
# ============================================================================

GRAPH_HTML = r"""{% extends "base.html" %}
{% block title %}Knowledge Graph - EpsteinAnalyzer{% endblock %}
{% block head %}
<script src="https://d3js.org/d3.v7.min.js"></script>
{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>Spiderweb View</h1>
    <p class="subtitle">Interactive knowledge graph &middot; {{ node_count }} entities &middot; {{ edge_count }} connections</p>
  </div>
  <div class="btn-group">
    <select id="graphFilter" onchange="filterGraph(this.value)">
      <option value="all">All Types</option>
      <option value="person">People</option>
      <option value="organization">Organizations</option>
      <option value="location">Locations</option>
      <option value="aircraft">Aircraft</option>
      <option value="financial">Financial</option>
      <option value="legal_case">Legal Cases</option>
      <option value="contact_info">Contact Info</option>
      <option value="event">Events</option>
      <option value="redacted_entity">Redacted</option>
    </select>
    <button class="btn btn-sm" onclick="resetZoom()">Reset View</button>
  </div>
</div>
<div class="card" style="padding:0;overflow:hidden;height:calc(100vh - 160px)">
  <svg id="graph" style="width:100%;height:100%"></svg>
</div>
{% endblock %}

{% block scripts %}
<script>
const graphData = {{ graph_data|tojson }};
const width = document.getElementById('graph').clientWidth || 1200;
const height = document.getElementById('graph').clientHeight || 700;
const svg = d3.select('#graph').attr('viewBox', [0, 0, width, height]);

const colorMap = {
  person: '#58a6ff', organization: '#3fb950', location: '#e3b341',
  aircraft: '#d29922', financial: '#f85149', legal_case: '#bc8cff',
  contact_info: '#8b949e', event: '#f778ba', redacted_entity: '#ff7b72'
};

const simulation = d3.forceSimulation(graphData.nodes)
  .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
  .force('charge', d3.forceManyBody().strength(-200))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide().radius(20));

const g = svg.append('g');

// Zoom
const zoom = d3.zoom().scaleExtent([0.1, 5]).on('zoom', e => g.attr('transform', e.transform));
svg.call(zoom);

const link = g.append('g')
  .selectAll('line')
  .data(graphData.links)
  .join('line')
  .attr('stroke', '#30363d')
  .attr('stroke-width', d => Math.min(d.weight || 1, 5))
  .attr('stroke-opacity', 0.6);

const node = g.append('g')
  .selectAll('circle')
  .data(graphData.nodes)
  .join('circle')
  .attr('r', d => 4 + Math.min(d.score || 0, 50) / 5)
  .attr('fill', d => colorMap[d.type] || '#8b949e')
  .attr('stroke', '#0d1117')
  .attr('stroke-width', 1.5)
  .style('cursor', 'pointer')
  .on('click', (e, d) => { window.location = '/entity/' + d.id; })
  .call(d3.drag()
    .on('start', (e, d) => { if(!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end', (e, d) => { if(!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
  );

node.append('title').text(d => d.name + ' (' + d.type + ') - Score: ' + (d.score||0).toFixed(1));

const label = g.append('g')
  .selectAll('text')
  .data(graphData.nodes)
  .join('text')
  .text(d => d.name)
  .attr('font-size', 9)
  .attr('fill', '#e6edf3')
  .attr('dx', 12)
  .attr('dy', 4)
  .style('pointer-events', 'none');

simulation.on('tick', () => {
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('cx', d => d.x).attr('cy', d => d.y);
  label.attr('x', d => d.x).attr('y', d => d.y);
});

function resetZoom(){ svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity); }
function filterGraph(type){
  if(type === 'all'){
    node.attr('opacity', 1); label.attr('opacity', 1); link.attr('opacity', 0.6);
  } else {
    node.attr('opacity', d => d.type === type ? 1 : 0.1);
    label.attr('opacity', d => d.type === type ? 1 : 0.05);
    link.attr('opacity', d => {
      const s = graphData.nodes.find(n => n.id === (typeof d.source === 'object' ? d.source.id : d.source));
      const t = graphData.nodes.find(n => n.id === (typeof d.target === 'object' ? d.target.id : d.target));
      return (s && s.type === type) || (t && t.type === type) ? 0.6 : 0.05;
    });
  }
}
</script>
{% endblock %}
"""


@app.route("/graph")
def graph_view():
    # Build graph data for D3
    entities = query_all(
        """SELECT id, name, canonical_name, entity_type, implication_score,
                  COALESCE(user_score, implication_score) as score
           FROM entities
           WHERE is_victim = 0
           ORDER BY score DESC
           LIMIT 300"""
    )
    relationships = query_all(
        """SELECT source_entity_id, target_entity_id, relationship_type, weight
           FROM relationships
           ORDER BY weight DESC
           LIMIT 1000"""
    )

    entity_ids = {e["id"] for e in entities}
    nodes = [
        {"id": e["id"], "name": e.get("canonical_name") or e["name"], "type": e["entity_type"], "score": e.get("score", 0)}
        for e in entities
    ]
    links = [
        {"source": r["source_entity_id"], "target": r["target_entity_id"],
         "type": r["relationship_type"], "weight": r.get("weight", 1)}
        for r in relationships
        if r["source_entity_id"] in entity_ids and r["target_entity_id"] in entity_ids
    ]

    graph_data = {"nodes": nodes, "links": links}

    return render_template_string(
        GRAPH_HTML,
        active="graph",
        graph_data=graph_data,
        node_count=len(nodes),
        edge_count=len(links),
    )


# ============================================================================
#  6.  EMAIL CHAIN RECONSTRUCTOR  (/chains)
# ============================================================================

CHAINS_HTML = r"""{% extends "base.html" %}
{% block title %}Email Chains - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Email Chain Reconstructor</h1>
<p class="subtitle">{{ chains|length }} reconstructed email threads</p>

<div class="card mb-2">
  <form method="get" action="/chains" class="flex gap-1">
    <input type="search" name="q" value="{{ q }}" placeholder="Search by subject or participants..." style="flex:1">
    <select name="gaps" style="width:160px">
      <option value="">All Chains</option>
      <option value="1" {% if filter_gaps %}selected{% endif %}>Has Gaps Only</option>
    </select>
    <button class="btn btn-primary" type="submit">Filter</button>
  </form>
</div>

<div class="card">
  <table>
    <thead><tr><th>Subject</th><th>Emails</th><th>Participants</th><th>Date Range</th><th>Gaps</th><th>Priority</th><th></th></tr></thead>
    <tbody>
    {% for c in chains %}
    <tr>
      <td><a href="/chain/{{ c.id }}"><strong>{{ c.normalized_subject or 'No Subject' }}</strong></a></td>
      <td class="mono">{{ c.email_count }}{% if c.expected_email_count and c.expected_email_count > c.email_count %}<span class="text-red">/{{ c.expected_email_count }}</span>{% endif %}</td>
      <td class="truncate" style="max-width:200px">{{ c.participants_display }}</td>
      <td class="mono text-muted" style="font-size:.78rem">{{ c.first_email_date or '?' }} &rarr; {{ c.last_email_date or '?' }}</td>
      <td>{% if c.has_gaps %}<span class="tag tag-red">GAPS</span>{% else %}<span class="tag tag-green">Complete</span>{% endif %}</td>
      <td class="mono text-orange">{{ c.priority_score }}</td>
      <td><a href="/chain/{{ c.id }}" class="btn btn-sm">View Thread</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if not chains %}
  <p class="text-muted" style="padding:20px;text-align:center">No email chains reconstructed yet.</p>
  {% endif %}
</div>
{% endblock %}
"""


@app.route("/chains")
def chains_list():
    q = request.args.get("q", "").strip()
    filter_gaps = request.args.get("gaps", "")
    conditions = []
    params = []
    if q:
        conditions.append(r"(normalized_subject LIKE ? ESCAPE '\' OR participants LIKE ? ESCAPE '\')")
        like = f"%{escape_like(q)}%"
        params.extend([like, like])
    if filter_gaps:
        conditions.append("has_gaps = 1")

    where = " AND ".join(conditions) if conditions else "1=1"
    chains_raw = query_all(
        f"SELECT * FROM email_chains WHERE {where} ORDER BY priority_score DESC LIMIT 200",
        tuple(params),
    )
    chains = []
    for c in chains_raw:
        c["participants_display"] = ", ".join(safe_json(c.get("participants"), [])[:4])
        chains.append(c)

    return render_template_string(
        CHAINS_HTML, active="chains", chains=chains, q=q, filter_gaps=filter_gaps
    )


# ============================================================================
#  7.  INDIVIDUAL CHAIN VIEW  (/chain/<id>)
# ============================================================================

CHAIN_DETAIL_HTML = r"""{% extends "base.html" %}
{% block title %}Chain: {{ chain.normalized_subject or 'Thread' }} - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>{{ chain.normalized_subject or 'Untitled Thread' }}</h1>
<p class="subtitle">
  {{ chain.email_count }} emails &middot; Priority {{ chain.priority_score }}
  {% if chain.has_gaps %}<span class="tag tag-red">GAPS DETECTED</span>{% endif %}
</p>

{% if chain.ai_summary %}
<div class="card" style="border-left:3px solid var(--accent)">
  <h3 class="mb-1">AI Summary</h3>
  <p>{{ chain.ai_summary }}</p>
</div>
{% endif %}

{% if chain.has_gaps and gap_details %}
<div class="alert alert-warning">
  <strong>Gap Alert:</strong> {{ gap_details|length }} missing email(s) detected in this thread.
  {% for gap in gap_details %}
  Between positions {{ gap.get('after', '?') }} and {{ gap.get('before', '?') }}.
  {% endfor %}
</div>
{% endif %}

<div class="timeline">
  {% for msg in messages %}
  {% if (msg.position_in_chain or loop.index) in gap_before_positions %}
  <div class="timeline-item" style="padding:8px 16px">
    <div style="border:2px dashed var(--orange);border-radius:8px;padding:12px 16px;background:rgba(210,153,34,.08);display:flex;align-items:center;gap:10px">
      <span style="font-size:1.2rem">&#9888;</span>
      <div>
        <strong class="text-orange" style="font-size:.85rem">Missing Email(s) Detected</strong>
        <div class="text-muted" style="font-size:.78rem">Gap in chain — one or more emails appear to be missing before position #{{ msg.position_in_chain or loop.index }}</div>
      </div>
    </div>
  </div>
  {% endif %}
  <div class="timeline-item">
    <div class="timeline-date">{{ msg.email_date or 'Unknown date' }} &middot; #{{ msg.position_in_chain or loop.index }}</div>
    <div class="card">
      <div class="flex flex-between items-center mb-1">
        <div>
          <strong>{{ msg.from_name or msg.from_address or 'Unknown' }}</strong>
          <span class="text-muted">&lt;{{ msg.from_address or '' }}&gt;</span>
        </div>
        <a href="/document/{{ msg.document_id }}" class="btn btn-sm">Source Doc</a>
      </div>
      {% if msg.to_list %}
      <div class="text-muted mb-1" style="font-size:.82rem">To: {{ msg.to_list }}</div>
      {% endif %}
      {% if msg.subject %}
      <div class="mb-1" style="font-size:.88rem"><strong>Subject:</strong> {{ msg.subject }}</div>
      {% endif %}
      <div style="white-space:pre-wrap;font-size:.88rem;background:var(--bg3);padding:12px;border-radius:6px;margin-top:8px">{{ msg.body_new_text or msg.body_text or 'No body text available.' }}</div>
    </div>
  </div>
  {% endfor %}
</div>

{% if not messages %}
<p class="text-muted" style="text-align:center;padding:40px">No emails found in this chain.</p>
{% endif %}
{% endblock %}
"""


@app.route("/chain/<int:chain_id>")
def chain_detail(chain_id):
    chain = query_one("SELECT * FROM email_chains WHERE id = ?", (chain_id,))
    if not chain:
        abort(404)
    messages_raw = query_all(
        "SELECT * FROM email_messages WHERE chain_id = ? ORDER BY COALESCE(position_in_chain, 0), email_date",
        (chain_id,),
    )
    messages = []
    for m in messages_raw:
        m["to_list"] = ", ".join(safe_json(m.get("to_addresses"), []))
        messages.append(m)

    gap_details = safe_json(chain.get("gap_details"), [])

    # Build set of positions that have a gap just before them
    gap_before_positions = set()
    for gap in gap_details:
        before_pos = gap.get("before")
        if before_pos is not None:
            gap_before_positions.add(before_pos)

    return render_template_string(
        CHAIN_DETAIL_HTML, active="chains", chain=chain, messages=messages,
        gap_details=gap_details, gap_before_positions=gap_before_positions,
    )


# ============================================================================
#  8.  FINDINGS BOARD  (/findings)
# ============================================================================

FINDINGS_HTML = r"""{% extends "base.html" %}
{% block title %}Findings Board - EpsteinAnalyzer{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>Findings Board</h1>
    <p class="subtitle">{{ findings|length }} pinned findings across {{ categories|length }} categories</p>
  </div>
  <button class="btn btn-primary" onclick="document.getElementById('newFinding').classList.toggle('hidden')">+ New Finding</button>
</div>

<!-- New Finding Form -->
<div id="newFinding" class="card hidden mb-2">
  <h3 class="mb-2">Create New Finding</h3>
  <form method="post" action="/findings/create">
    <div class="mb-1"><input type="text" name="title" placeholder="Finding title..." required></div>
    <div class="flex gap-1 mb-1">
      <select name="category" required style="flex:1">
        <option value="">Select Category</option>
        <option value="financial">Financial</option>
        <option value="trafficking">Trafficking</option>
        <option value="political">Political</option>
        <option value="cover_up">Cover-Up</option>
        <option value="fraud">Fraud</option>
        <option value="obstruction">Obstruction</option>
        <option value="other">Other</option>
      </select>
      <select name="confidence_level" style="flex:1">
        <option value="unverified">Unverified</option>
        <option value="likely">Likely</option>
        <option value="confirmed">Confirmed</option>
      </select>
    </div>
    <div class="mb-1"><textarea name="summary" rows="3" placeholder="Summary..."></textarea></div>
    <div class="mb-1"><textarea name="detailed_notes" rows="4" placeholder="Detailed notes..."></textarea></div>
    <button class="btn btn-primary" type="submit">Save Finding</button>
  </form>
</div>

{% for cat in categories %}
<div class="mb-3">
  <h2 class="mb-2" style="text-transform:capitalize">{{ cat.replace('_', ' ') }} ({{ cat_counts[cat] }})</h2>
  <div class="grid grid-2">
    {% for f in findings if f.category == cat %}
    <div class="card" style="border-left:3px solid {{ {'financial':'var(--red)','trafficking':'var(--orange)','political':'var(--purple)','cover_up':'var(--yellow)','fraud':'var(--red)','obstruction':'var(--orange)'}.get(f.category,'var(--accent)') }}">
      <div class="flex flex-between items-center">
        <h3 style="margin:0">{{ f.title }}</h3>
        <span class="tag tag-{{ {'unverified':'orange','likely':'blue','confirmed':'green','published':'purple'}.get(f.confidence_level,'blue') }}">{{ f.confidence_level }}</span>
      </div>
      {% if f.summary %}<p class="mt-1" style="font-size:.88rem">{{ f.summary }}</p>{% endif %}
      <div class="text-muted mt-1" style="font-size:.75rem">
        Created {{ f.created_at }}
        {% if f.linked_docs_count %}&middot; {{ f.linked_docs_count }} docs{% endif %}
        {% if f.linked_entities_count %}&middot; {{ f.linked_entities_count }} entities{% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>
{% endfor %}

{% if not findings %}
<div class="card" style="text-align:center;padding:40px">
  <p class="text-muted">No findings created yet. Click "+ New Finding" to start.</p>
</div>
{% endif %}
{% endblock %}
"""


@app.route("/findings")
def findings_board():
    findings_raw = query_all("SELECT * FROM findings ORDER BY category, created_at DESC")
    findings = []
    categories = []
    cat_counts = {}
    for f in findings_raw:
        f["linked_docs_count"] = len(safe_json(f.get("linked_document_ids"), []))
        f["linked_entities_count"] = len(safe_json(f.get("linked_entity_ids"), []))
        findings.append(f)
        cat = f["category"]
        if cat and cat not in categories:
            categories.append(cat)
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return render_template_string(
        FINDINGS_HTML, active="findings", findings=findings, categories=categories, cat_counts=cat_counts
    )


@app.route("/findings/create", methods=["POST"])
def findings_create():
    title = request.form.get("title", "").strip()
    if not title:
        return redirect(url_for("findings_board"))
    execute(
        """INSERT INTO findings (title, category, summary, detailed_notes, confidence_level)
           VALUES (?, ?, ?, ?, ?)""",
        (
            title,
            request.form.get("category", "other"),
            request.form.get("summary", ""),
            request.form.get("detailed_notes", ""),
            request.form.get("confidence_level", "unverified"),
        ),
    )
    _get_db().log_action("create_finding", f"Created finding: {title}")
    return redirect(url_for("findings_board"))


# ============================================================================
#  9.  IMAGE REVIEW GATE  (/images/review)
# ============================================================================

IMAGE_REVIEW_HTML = r"""{% extends "base.html" %}
{% block title %}Image Review Gate - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Image Review Gate</h1>
<p class="subtitle">{{ pending_count }} images awaiting review &middot; One at a time, never auto-saved</p>

{% if image %}
<div class="image-review-container">
  <div class="image-preview">
    {% if image.minor_detected %}
    <div style="text-align:center;padding:40px">
      <div class="text-red" style="font-size:2rem;font-weight:700">AUTO-QUARANTINED</div>
      <p class="text-muted mt-2">Potential minor detected. Image has been quarantined.</p>
      <p class="text-muted">Only discard options available.</p>
    </div>
    {% elif image.file_path %}
    <img src="/serve_image/{{ image.id }}" alt="Image for review">
    {% else %}
    <p class="text-muted">Image file not available for preview.</p>
    {% endif %}
  </div>

  <div class="image-controls">
    <div class="card">
      <h3 class="mb-2">Image #{{ image.id }}</h3>
      <table style="font-size:.85rem">
        <tr><td class="text-muted">Document</td><td><a href="/document/{{ image.document_id }}">{{ image.document_id }}</a></td></tr>
        <tr><td class="text-muted">Page</td><td>{{ image.page_number or 'N/A' }}</td></tr>
        <tr><td class="text-muted">Recovery</td><td>{{ image.recovery_method or 'N/A' }}</td></tr>
        <tr><td class="text-muted">Original Redacted</td><td>{{ 'Yes' if image.original_redacted else 'No' }}</td></tr>
        {% if image.estimated_date %}<tr><td class="text-muted">Est. Date</td><td>{{ image.estimated_date }}</td></tr>{% endif %}
        {% if image.location_clues %}<tr><td class="text-muted">Location</td><td>{{ image.location_clues }}</td></tr>{% endif %}
      </table>

      {% if image.ai_description %}
      <div class="mt-2">
        <h3 class="mb-1" style="font-size:.85rem">AI Assessment</h3>
        <p style="font-size:.85rem">{{ image.ai_description }}</p>
      </div>
      {% endif %}

      {% if image.minor_detected %}
      <div class="alert alert-critical mt-2">
        <strong>MINOR DETECTED</strong> - Auto-quarantined
      </div>
      <form method="post" action="/images/review/{{ image.id }}/decide" class="mt-2">
        <button name="decision" value="discard_victim" class="btn btn-danger w-full mb-1">Discard (Victim Material)</button>
      </form>
      {% else %}
      <form method="post" action="/images/review/{{ image.id }}/decide" class="mt-2">
        <div class="btn-group" style="flex-direction:column">
          <button name="decision" value="save" class="btn btn-success w-full">Save to Evidence</button>
          <button name="decision" value="save_redacted" class="btn btn-primary w-full">Save with Custom Redactions</button>
          <button name="decision" value="discard_victim" class="btn btn-danger w-full">Discard (Victim Material)</button>
          <button name="decision" value="discard_no_value" class="btn w-full">Discard (No Investigative Value)</button>
          <button name="decision" value="flagged" class="btn btn-warning w-full">Flag for Later Review</button>
        </div>
      </form>
      {% endif %}
    </div>
  </div>
</div>
{% else %}
<div class="card" style="text-align:center;padding:60px">
  <div style="font-size:2rem;margin-bottom:12px">&#10003;</div>
  <h2>All Images Reviewed</h2>
  <p class="text-muted">No pending images in the review queue.</p>
</div>
{% endif %}
{% endblock %}
"""


@app.route("/images/review")
def image_review():
    # Get next unreviewed image -- quarantined minors shown with restricted options
    image = query_one(
        """SELECT * FROM images
           WHERE user_reviewed = 0 AND recovery_successful = 1
           ORDER BY minor_detected DESC, id ASC
           LIMIT 1"""
    )
    pending_count = query_scalar(
        "SELECT COUNT(*) FROM images WHERE user_reviewed = 0 AND recovery_successful = 1"
    )
    return render_template_string(
        IMAGE_REVIEW_HTML, active="images", image=image, pending_count=pending_count
    )


@app.route("/images/review/<int:image_id>/decide", methods=["POST"])
def image_decide(image_id):
    decision = request.form.get("decision", "flagged")
    image = query_one("SELECT * FROM images WHERE id = ?", (image_id,))
    if not image:
        abort(404)

    # If minor detected, only allow discard
    if image.get("minor_detected") and decision not in ("discard_victim",):
        decision = "discard_victim"

    execute(
        "UPDATE images SET user_reviewed = 1, user_decision = ?, updated_at = ? WHERE id = ?",
        (decision, datetime.now(tz=timezone.utc).isoformat(), image_id),
    )
    _get_db().log_action("image_review", f"Image {image_id} decision: {decision}")
    return redirect(url_for("image_review"))


@app.route("/serve_image/<int:image_id>")
def serve_image(image_id):
    image = query_one(
        "SELECT file_path, quarantined, minor_detected FROM images WHERE id = ?",
        (image_id,),
    )
    if not image or not image.get("file_path"):
        abort(404)
    if image.get("quarantined") or image.get("minor_detected"):
        abort(403)
    fp = Path(image["file_path"]).resolve()
    data_dir = _get_db().data_dir.resolve()
    if not fp.is_relative_to(data_dir):
        abort(403)
    if not fp.exists():
        abort(404)
    return send_from_directory(str(fp.parent), fp.name)


# ============================================================================
#  10. DELETION QUEUE  (/deletions)
# ============================================================================

DELETIONS_HTML = r"""{% extends "base.html" %}
{% block title %}Deletion Queue - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Deletion Queue</h1>
<p class="subtitle">{{ items|length }} items pending your review</p>

{% for item in items %}
<div class="card" style="border-left:3px solid {% if item.user_decision == 'pending' %}var(--orange){% elif item.user_decision == 'keep' %}var(--green){% else %}var(--red){% endif %}">
  <div class="flex flex-between items-center mb-1">
    <div>
      <h3 style="margin:0">{{ item.original_filename or 'Document #' ~ item.document_id }}</h3>
      <span class="text-muted" style="font-size:.82rem">{{ item.doc_type or 'Unknown type' }} &middot; {{ (item.size_bytes / 1024)|round(1) }} KB</span>
    </div>
    <span class="tag tag-{{ {'pending':'orange','keep':'green','delete':'red'}.get(item.user_decision,'orange') }}">{{ item.user_decision }}</span>
  </div>

  <div class="mb-1">
    <strong class="text-muted" style="font-size:.82rem">Reason:</strong>
    <span style="font-size:.88rem">{{ item.reason }}</span>
  </div>

  {% if item.ai_assessment %}
  <div class="mb-1">
    <strong class="text-muted" style="font-size:.82rem">AI Assessment:</strong>
    <span style="font-size:.88rem">{{ item.ai_assessment }}</span>
  </div>
  {% endif %}

  {% if item.user_decision == 'pending' %}
  <div class="btn-group mt-2">
    <form method="post" action="/deletions/{{ item.id }}/decide" style="display:inline">
      <button name="decision" value="keep" class="btn btn-success btn-sm">Keep</button>
    </form>
    <form method="post" action="/deletions/{{ item.id }}/decide" style="display:inline">
      <button name="decision" value="delete" class="btn btn-danger btn-sm">Delete</button>
    </form>
    <a href="/document/{{ item.document_id }}" class="btn btn-sm">Preview Full Document</a>
  </div>
  {% endif %}
</div>
{% endfor %}

{% if not items %}
<div class="card" style="text-align:center;padding:40px">
  <p class="text-muted">Deletion queue is empty. Nothing to review.</p>
</div>
{% endif %}
{% endblock %}
"""


@app.route("/deletions")
def deletions_queue():
    items = query_all(
        """SELECT dq.*, d.original_filename, d.doc_type, d.size_bytes
           FROM deletion_queue dq
           JOIN documents d ON d.id = dq.document_id
           ORDER BY
             CASE dq.user_decision WHEN 'pending' THEN 0 ELSE 1 END,
             dq.created_at DESC
           LIMIT 100"""
    )
    return render_template_string(DELETIONS_HTML, active="deletions", items=items)


@app.route("/deletions/<int:item_id>/decide", methods=["POST"])
def deletion_decide(item_id):
    decision = request.form.get("decision", "keep")
    execute(
        "UPDATE deletion_queue SET user_decision = ?, decided_at = ? WHERE id = ?",
        (decision, datetime.now(tz=timezone.utc).isoformat(), item_id),
    )
    if decision == "delete":
        row = query_one("SELECT document_id FROM deletion_queue WHERE id = ?", (item_id,))
        if row:
            execute("UPDATE documents SET status = 'deleted' WHERE id = ?", (row["document_id"],))
    _get_db().log_action("deletion_decision", f"Item {item_id}: {decision}")
    return redirect(url_for("deletions_queue"))


# ============================================================================
#  11. EXPORT TOOLS  (/export)
# ============================================================================

EXPORT_HTML = r"""{% extends "base.html" %}
{% block title %}Export Tools - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Export Tools</h1>
<p class="subtitle">Format and publish findings for external platforms</p>

<div class="grid grid-3">
  <!-- Reddit Post Formatter -->
  <div class="card">
    <h3 class="mb-2">Reddit Post Formatter</h3>
    <p class="text-muted mb-2" style="font-size:.85rem">Generate a formatted Reddit post from selected findings. Victim names are automatically stripped.</p>
    <form method="post" action="/export/reddit">
      <div class="mb-1">
        <select name="finding_id">
          <option value="">Select a finding...</option>
          {% for f in findings %}
          <option value="{{ f.id }}">{{ f.title }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="mb-1">
        <select name="subreddit">
          <option value="Epstein">r/Epstein</option>
          <option value="EpsteinFiles">r/EpsteinFiles</option>
          <option value="conspiracy">r/conspiracy</option>
        </select>
      </div>
      <button class="btn btn-primary w-full" type="submit">Generate Post</button>
    </form>
  </div>

  <!-- Report Generator -->
  <div class="card">
    <h3 class="mb-2">Investigation Report</h3>
    <p class="text-muted mb-2" style="font-size:.85rem">Generate a comprehensive report of all confirmed findings with evidence citations.</p>
    <form method="post" action="/export/report">
      <div class="mb-1">
        <select name="confidence_filter">
          <option value="all">All Findings</option>
          <option value="confirmed">Confirmed Only</option>
          <option value="likely">Likely + Confirmed</option>
        </select>
      </div>
      <div class="mb-1">
        <select name="format">
          <option value="markdown">Markdown</option>
          <option value="html">HTML</option>
          <option value="txt">Plain Text</option>
        </select>
      </div>
      <button class="btn btn-primary w-full" type="submit">Generate Report</button>
    </form>
  </div>

  <!-- Public Viewer Publisher -->
  <div class="card">
    <h3 class="mb-2">Public Viewer</h3>
    <p class="text-muted mb-2" style="font-size:.85rem">Publish a static HTML viewer for public sharing. Only includes entities above the minimum score threshold.</p>
    <form method="post" action="/export/public">
      <div class="mb-1">
        <label class="text-muted" style="font-size:.78rem">Min Implication Score</label>
        <input type="number" name="min_score" value="50">
      </div>
      <div class="mb-1">
        <label class="text-muted" style="font-size:.78rem">
          <input type="checkbox" name="strip_raw" checked> Strip raw document text
        </label>
      </div>
      <button class="btn btn-primary w-full" type="submit">Publish Viewer</button>
    </form>
  </div>
</div>

{% if export_result %}
<div class="card mt-3">
  <h3 class="mb-2">Export Result</h3>
  <pre id="export-output" style="white-space:pre-wrap;background:var(--bg3);padding:16px;border-radius:6px;font-size:.85rem;max-height:400px;overflow-y:auto">{{ export_result }}</pre>
  <div class="btn-group mt-2">
    <button class="btn btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('export-output').textContent);showToast('Copied to clipboard','success')">Copy to Clipboard</button>
    <button class="btn btn-sm btn-primary" onclick="(function(){var t=document.getElementById('export-output').textContent;var ext=t.trim().startsWith('<!DOCTYPE')||t.trim().startsWith('<html')?'.html':t.trim().startsWith('#')?'.md':'.txt';var blob=new Blob([t],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='epstein_report_'+new Date().toISOString().slice(0,10)+ext;a.click();URL.revokeObjectURL(a.href);showToast('Download started','success')})()">Download as File</button>
  </div>
</div>
{% endif %}
{% endblock %}
"""


@app.route("/export")
def export_tools():
    findings = query_all("SELECT id, title FROM findings ORDER BY created_at DESC")
    return render_template_string(EXPORT_HTML, active="export", findings=findings, export_result=None)


@app.route("/export/reddit", methods=["POST"])
def export_reddit():
    finding_id = request.form.get("finding_id")
    subreddit = request.form.get("subreddit", "Epstein")
    if not finding_id:
        return redirect(url_for("export_tools"))

    try:
        fid = int(finding_id)
    except (ValueError, TypeError):
        return redirect(url_for("export_tools"))
    finding = query_one("SELECT * FROM findings WHERE id = ?", (fid,))
    if not finding:
        return redirect(url_for("export_tools"))

    # Build Reddit markdown
    lines = [
        f"# {finding['title']}",
        "",
        f"**Category:** {(finding['category'] or 'Other').replace('_', ' ').title()}",
        f"**Confidence:** {finding['confidence_level']}",
        "",
        "---",
        "",
        finding.get("summary", "") or "",
        "",
    ]
    if finding.get("detailed_notes"):
        lines.extend(["## Details", "", finding["detailed_notes"], ""])

    lines.extend([
        "---",
        "",
        f"*Generated by EpsteinAnalyzer | r/{subreddit}*",
    ])
    export_result = "\n".join(lines)

    findings = query_all("SELECT id, title FROM findings ORDER BY created_at DESC")
    return render_template_string(EXPORT_HTML, active="export", findings=findings, export_result=export_result)


@app.route("/export/report", methods=["POST"])
def export_report():
    confidence = request.form.get("confidence_filter", "all")
    fmt = request.form.get("format", "markdown")

    conditions = []
    if confidence == "confirmed":
        conditions.append("confidence_level = 'confirmed'")
    elif confidence == "likely":
        conditions.append("confidence_level IN ('likely', 'confirmed')")
    where = " AND ".join(conditions) if conditions else "1=1"

    report_findings = query_all(f"SELECT * FROM findings WHERE {where} ORDER BY category, created_at DESC")

    if fmt == "html":
        lines = [
            "<!DOCTYPE html><html><head><title>EpsteinAnalyzer Investigation Report</title>",
            "<style>body{font-family:sans-serif;max-width:900px;margin:40px auto;background:#111;color:#eee;padding:20px}",
            "h1{color:#58a6ff}h2{color:#3fb950;border-bottom:1px solid #333;padding-bottom:6px}h3{color:#e6edf3}",
            ".confidence{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.82rem;margin-bottom:8px}",
            ".confirmed{background:#238636;color:#fff}.likely{background:#9e6a03;color:#fff}.unverified{background:#30363d;color:#8b949e}",
            "p{line-height:1.6;color:#c9d1d9}</style></head><body>",
            f"<h1>EpsteinAnalyzer Investigation Report</h1>",
            f"<p style='color:#8b949e'>Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>",
        ]
        current_cat = None
        for f in report_findings:
            if f["category"] != current_cat:
                current_cat = f["category"]
                lines.append(f"<h2>{html.escape((current_cat or 'Other').replace('_', ' ').title())}</h2>")
            lines.append(f"<h3>{html.escape(f['title'])}</h3>")
            conf = f['confidence_level'] or 'unverified'
            lines.append(f"<span class='confidence {html.escape(conf)}'>{html.escape(conf)}</span>")
            if f.get("summary"):
                lines.append(f"<p>{html.escape(f['summary'])}</p>")
            if f.get("detailed_notes"):
                lines.append(f"<p>{html.escape(f['detailed_notes'])}</p>")
        lines.append("</body></html>")
        export_result = "\n".join(lines)
    elif fmt == "txt":
        lines = [
            "EPSTEIN ANALYZER INVESTIGATION REPORT",
            f"Generated: {datetime.now(tz=timezone.utc).isoformat()}",
            "=" * 60, "",
        ]
        current_cat = None
        for f in report_findings:
            if f["category"] != current_cat:
                current_cat = f["category"]
                cat_title = (current_cat or "Other").replace("_", " ").upper()
                lines.extend(["", "-" * 40, cat_title, "-" * 40, ""])
            lines.append(f['title'])
            lines.append(f"  Confidence: {f['confidence_level']}")
            if f.get("summary"):
                lines.append(f"  {f['summary']}")
            if f.get("detailed_notes"):
                lines.append(f"  {f['detailed_notes']}")
            lines.append("")
        export_result = "\n".join(lines)
    else:
        lines = ["# EpsteinAnalyzer Investigation Report", f"Generated: {datetime.now(tz=timezone.utc).isoformat()}", ""]
        current_cat = None
        for f in report_findings:
            if f["category"] != current_cat:
                current_cat = f["category"]
                lines.append(f"\n## {(current_cat or 'Other').replace('_', ' ').title()}\n")
            lines.append(f"### {f['title']}")
            lines.append(f"Confidence: {f['confidence_level']}")
            if f.get("summary"):
                lines.append(f"\n{f['summary']}")
            if f.get("detailed_notes"):
                lines.append(f"\n{f['detailed_notes']}")
            lines.append("")
        export_result = "\n".join(lines)
    findings = query_all("SELECT id, title FROM findings ORDER BY created_at DESC")
    return render_template_string(EXPORT_HTML, active="export", findings=findings, export_result=export_result)


@app.route("/export/public", methods=["POST"])
def export_public():
    try:
        min_score = int(request.form.get("min_score", 50))
    except (ValueError, TypeError):
        min_score = 50
    entities = query_all(
        "SELECT name, canonical_name, entity_type, implication_score, evidence_count FROM entities WHERE implication_score >= ? AND is_victim = 0 ORDER BY implication_score DESC",
        (min_score,),
    )
    lines = [
        "<!DOCTYPE html><html><head><title>EpsteinAnalyzer Public Report</title>",
        "<style>body{font-family:sans-serif;max-width:900px;margin:40px auto;background:#111;color:#eee;padding:20px}",
        "table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #333;text-align:left}",
        "th{color:#888;font-size:.85rem}h1{color:#58a6ff}</style></head><body>",
        "<h1>EpsteinAnalyzer - Public Entity Report</h1>",
        f"<p style='color:#888'>Entities with implication score >= {min_score} | Generated {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d')}</p>",
        "<table><thead><tr><th>Name</th><th>Type</th><th>Score</th><th>Evidence Count</th></tr></thead><tbody>",
    ]
    for e in entities:
        name = html.escape(e.get('canonical_name') or e['name'])
        etype = html.escape(e['entity_type'])
        lines.append(
            f"<tr><td>{name}</td><td>{etype}</td>"
            f"<td>{e['implication_score']:.1f}</td><td>{e['evidence_count']}</td></tr>"
        )
    lines.append("</tbody></table></body></html>")
    export_result = "\n".join(lines)

    findings = query_all("SELECT id, title FROM findings ORDER BY created_at DESC")
    return render_template_string(EXPORT_HTML, active="export", findings=findings, export_result=export_result)


# ============================================================================
#  12. SETTINGS  (/settings)
# ============================================================================

SETTINGS_HTML = r"""{% extends "base.html" %}
{% block title %}Settings - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Settings</h1>
<p class="subtitle">Configuration and system management</p>

<div class="grid grid-2">
  <div class="card">
    <h3 class="mb-2">System Status</h3>
    <table>
      <tr><td class="text-muted">Database Path</td><td class="mono" style="font-size:.82rem">{{ db_path }}</td></tr>
      <tr><td class="text-muted">Data Directory</td><td class="mono" style="font-size:.82rem">{{ data_dir }}</td></tr>
      <tr><td class="text-muted">Database Size</td><td>{{ db_size_mb }} MB</td></tr>
      <tr><td class="text-muted">Disk Usage</td><td>{{ disk.total_gb }} GB / {{ disk.max_gb }} GB ({{ disk.usage_percent }}%)</td></tr>
      <tr><td class="text-muted">Auto-Compact Threshold</td><td>{{ disk.compact_threshold_percent }}%</td></tr>
      <tr><td class="text-muted">Needs Compact</td><td>{% if disk.needs_compact %}<span class="text-red">YES</span>{% else %}<span class="text-green">No</span>{% endif %}</td></tr>
    </table>
    <div class="btn-group mt-2">
      <button class="btn btn-warning" onclick="apiPost('/api/compact').then(d=>{showToast('Freed '+d.freed_mb+' MB','success');setTimeout(()=>location.reload(),1500)})">Run Auto-Compact</button>
    </div>
  </div>

  <div class="card">
    <h3 class="mb-2">Pipeline Configuration</h3>
    <table>
      <tr><td class="text-muted">OCR Engine</td><td>{{ config.processor.ocr.engine }}</td></tr>
      <tr><td class="text-muted">OCR DPI</td><td>{{ config.processor.ocr.dpi }}</td></tr>
      <tr><td class="text-muted">AI Models</td><td>
        {% for m, v in config.ai_pipeline.models.items() %}
        <span class="tag tag-{{ 'green' if v.enabled else 'red' }}">{{ m }}</span>
        {% endfor %}
      </td></tr>
      <tr><td class="text-muted">Consensus Min</td><td>{{ config.ai_pipeline.consensus.min_models_for_consensus }} models</td></tr>
      <tr><td class="text-muted">Batch Size</td><td>{{ config.ai_pipeline.batch.max_batch_size }}</td></tr>
    </table>
  </div>

  <div class="card">
    <h3 class="mb-2">Security</h3>
    <table>
      <tr><td class="text-muted">Encryption</td><td>{{ config.security.encryption.algorithm }}</td></tr>
      <tr><td class="text-muted">Key Derivation</td><td>{{ config.security.encryption.key_derivation }}</td></tr>
      <tr><td class="text-muted">Honeypots</td><td>{{ 'Enabled' if config.security.honeypots.enabled else 'Disabled' }}</td></tr>
      <tr><td class="text-muted">Integrity Checks</td><td>{{ 'On Startup' if config.security.integrity.check_on_startup else 'Disabled' }}</td></tr>
    </table>
  </div>

  <div class="card">
    <h3 class="mb-2">Harvester Sources</h3>
    <table>
      {% for src in config.harvester.enabled_sources %}
      <tr><td><span class="tag tag-green">{{ src }}</span></td></tr>
      {% endfor %}
    </table>
  </div>
</div>

<div class="card mt-2">
  <h3 class="mb-2">Recent Audit Log</h3>
  <table>
    <thead><tr><th>Time</th><th>Action</th><th>Details</th><th>User</th></tr></thead>
    <tbody>
    {% for log in audit_logs %}
    <tr>
      <td class="mono text-muted" style="font-size:.78rem">{{ log.created_at }}</td>
      <td>{{ log.action }}</td>
      <td class="truncate" style="max-width:400px">{{ log.details or '' }}</td>
      <td>{% if log.user_initiated %}<span class="tag tag-blue">User</span>{% else %}<span class="tag tag-purple">System</span>{% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if not audit_logs %}
  <p class="text-muted" style="padding:12px">No audit log entries.</p>
  {% endif %}
</div>
{% endblock %}
"""


@app.route("/settings")
def settings_page():
    disk = _get_db().check_disk_usage()
    db_size = 0
    if _get_db().db_path.exists():
        db_size = round(_get_db().db_path.stat().st_size / (1024 ** 2), 2)

    audit_logs = query_all("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50")

    return render_template_string(
        SETTINGS_HTML,
        active="settings",
        disk=disk,
        db_path=str(_get_db().db_path),
        data_dir=str(_get_db().data_dir),
        db_size_mb=db_size,
        config=_get_db().config,
        audit_logs=audit_logs,
    )


# ============================================================================
#  13. AUDIT LOG  (/audit)
# ============================================================================

AUDIT_HTML = r"""{% extends "base.html" %}
{% block title %}Audit Log - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Audit Log</h1>
<p class="subtitle">{{ total_entries }} total entries</p>

<div class="card mb-2">
  <form method="get" action="/audit" class="flex gap-1">
    <select name="action" style="width:200px">
      <option value="">All Actions</option>
      {% for a in action_types %}
      <option value="{{ a }}" {% if a == filter_action %}selected{% endif %}>{{ a }}</option>
      {% endfor %}
    </select>
    <select name="source" style="width:140px">
      <option value="">All Sources</option>
      <option value="user" {% if filter_source == 'user' %}selected{% endif %}>User</option>
      <option value="system" {% if filter_source == 'system' %}selected{% endif %}>System</option>
    </select>
    <input type="search" name="q" value="{{ q }}" placeholder="Search details..." style="flex:1">
    <button class="btn btn-primary" type="submit">Filter</button>
  </form>
</div>

<div class="card">
  <table>
    <thead><tr><th>Time</th><th>Action</th><th>Details</th><th>Source</th></tr></thead>
    <tbody>
    {% for log in audit_logs %}
    <tr>
      <td class="mono text-muted" style="font-size:.78rem;white-space:nowrap">{{ log.created_at }}</td>
      <td><span class="tag tag-blue">{{ log.action }}</span></td>
      <td class="truncate" style="max-width:500px;font-size:.88rem" title="{{ log.details or '' }}">{{ log.details or '' }}</td>
      <td>{% if log.user_initiated %}<span class="tag tag-green">User</span>{% else %}<span class="tag tag-purple">System</span>{% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if not audit_logs %}
  <p class="text-muted" style="padding:20px;text-align:center">No audit log entries match your filters.</p>
  {% endif %}
</div>

{% if total_pages > 1 %}
<div class="flex gap-1 mt-2" style="justify-content:center;align-items:center">
  {% if page > 1 %}
  <a href="/audit?page={{ page - 1 }}&action={{ filter_action }}&source={{ filter_source }}&q={{ q }}" class="btn btn-sm">&larr; Prev</a>
  {% endif %}
  <span class="text-muted" style="font-size:.85rem">Page {{ page }} of {{ total_pages }}</span>
  {% if page < total_pages %}
  <a href="/audit?page={{ page + 1 }}&action={{ filter_action }}&source={{ filter_source }}&q={{ q }}" class="btn btn-sm">Next &rarr;</a>
  {% endif %}
</div>
{% endif %}
{% endblock %}
"""


@app.route("/audit")
def audit_page():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    per_page = 50
    filter_action = request.args.get("action", "").strip()
    filter_source = request.args.get("source", "").strip()
    q = request.args.get("q", "").strip()

    conditions = []
    params = []
    if filter_action:
        conditions.append("action = ?")
        params.append(filter_action)
    if filter_source == "user":
        conditions.append("user_initiated = 1")
    elif filter_source == "system":
        conditions.append("user_initiated = 0")
    if q:
        conditions.append(r"details LIKE ? ESCAPE '\'")
        params.append(f"%{escape_like(q)}%")

    where = " AND ".join(conditions) if conditions else "1=1"

    total_entries = query_scalar(
        f"SELECT COUNT(*) FROM audit_log WHERE {where}", tuple(params)
    )
    total_pages = max(1, (total_entries + per_page - 1) // per_page)
    page = min(page, total_pages)

    audit_logs = query_all(
        f"SELECT * FROM audit_log WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        tuple(params) + (per_page, (page - 1) * per_page),
    )

    action_types = [
        r["action"]
        for r in query_all("SELECT DISTINCT action FROM audit_log ORDER BY action")
    ]

    return render_template_string(
        AUDIT_HTML,
        active="audit",
        audit_logs=audit_logs,
        action_types=action_types,
        filter_action=filter_action,
        filter_source=filter_source,
        q=q,
        page=page,
        total_pages=total_pages,
        total_entries=total_entries,
    )


# ============================================================================
#  API ROUTES
# ============================================================================

@app.route("/api/stats")
def api_stats():
    stats = _get_db().get_stats()
    datasets = _get_db().get_dataset_status()
    stats["datasets"] = datasets
    return jsonify(stats)


@app.route("/api/dataset/<int:n>/load", methods=["POST"])
def api_dataset_load(n):
    """Trigger dataset download via the real HarvesterEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    # Upsert dataset record
    conn = get_conn()
    try:
        existing = conn.execute("SELECT id FROM datasets WHERE dataset_number = ?", (n,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE datasets SET status = 'downloading', updated_at = ? WHERE dataset_number = ?",
                (datetime.now(tz=timezone.utc).isoformat(), n),
            )
        else:
            conn.execute(
                "INSERT INTO datasets (dataset_number, source, status) VALUES (?, 'doj', 'downloading')",
                (n,),
            )
        conn.commit()
    finally:
        conn.close()

    _get_db().log_action("dataset_load", f"Started loading dataset {n}")
    socketio.emit("progress", {"message": f"Dataset {n} download started...", "level": "info"})
    socketio.emit("dataset_progress", {"dataset": n, "percent": 0, "message": f"Initializing dataset {n}..."})

    def _background_load():
        try:
            from harvester.harvester import HarvesterEngine

            def harvester_progress(event):
                msg = event.get("message", "")
                pct = event.get("percent")
                socketio.emit("dataset_progress", {
                    "dataset": n,
                    "percent": pct if pct is not None else 0,
                    "message": msg,
                })

            engine = HarvesterEngine(progress_cb=harvester_progress)
            paths = engine.download_dataset(n)

            conn2 = get_conn()
            try:
                conn2.execute(
                    "UPDATE datasets SET status = 'downloaded', downloaded_at = ?, updated_at = ? WHERE dataset_number = ?",
                    (datetime.now(tz=timezone.utc).isoformat(), datetime.now(tz=timezone.utc).isoformat(), n),
                )
                conn2.commit()
            finally:
                conn2.close()

            socketio.emit("dataset_progress", {"dataset": n, "percent": 100, "message": f"Dataset {n}: {len(paths)} files downloaded!"})
            socketio.emit("progress", {"message": f"Dataset {n} loaded! {len(paths)} files.", "level": "success"})
        except Exception as exc:
            logger.exception("Dataset %d load failed", n)
            conn2 = get_conn()
            try:
                conn2.execute(
                    "UPDATE datasets SET status = 'error', updated_at = ? WHERE dataset_number = ?",
                    (datetime.now(tz=timezone.utc).isoformat(), n),
                )
                conn2.commit()
            finally:
                conn2.close()
            socketio.emit("progress", {"message": f"Dataset {n} load FAILED: {exc}", "level": "error"})

    socketio.start_background_task(_background_load)
    return jsonify({"status": "started", "dataset": n})


@app.route("/api/dataset/<int:n>/process", methods=["POST"])
def api_dataset_process(n):
    """Trigger document processing via the real ProcessorEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    conn = get_conn()
    try:
        conn.execute(
            "UPDATE datasets SET status = 'processing', updated_at = ? WHERE dataset_number = ?",
            (datetime.now(tz=timezone.utc).isoformat(), n),
        )
        conn.commit()
    finally:
        conn.close()

    _get_db().log_action("dataset_process", f"Started processing dataset {n}")
    socketio.emit("progress", {"message": f"Processing dataset {n}...", "level": "info"})

    def _background_process():
        try:
            from processor.processor import ProcessorEngine

            def processor_progress(stage, current, total, message=""):
                pct = int(current / total * 100) if total > 0 else 0
                socketio.emit("dataset_progress", {
                    "dataset": n,
                    "percent": pct,
                    "message": f"{stage}: {current}/{total} {message}".strip(),
                })

            engine = ProcessorEngine(progress_cb=processor_progress)
            engine.db.initialize()
            result = engine.process_dataset(n)

            conn2 = get_conn()
            try:
                conn2.execute(
                    "UPDATE datasets SET status = 'processed', updated_at = ? WHERE dataset_number = ?",
                    (datetime.now(tz=timezone.utc).isoformat(), n),
                )
                conn2.commit()
            finally:
                conn2.close()

            total_docs = result.get("total", 0)
            errors = result.get("errors", 0)
            socketio.emit("dataset_progress", {"dataset": n, "percent": 100, "message": f"Processing complete! {total_docs} docs, {errors} errors"})
            socketio.emit("progress", {"message": f"Dataset {n} processed! {total_docs} documents.", "level": "success"})
        except Exception as exc:
            logger.exception("Dataset %d processing failed", n)
            conn2 = get_conn()
            try:
                conn2.execute(
                    "UPDATE datasets SET status = 'error', updated_at = ? WHERE dataset_number = ?",
                    (datetime.now(tz=timezone.utc).isoformat(), n),
                )
                conn2.commit()
            finally:
                conn2.close()
            socketio.emit("progress", {"message": f"Dataset {n} processing FAILED: {exc}", "level": "error"})

    socketio.start_background_task(_background_process)
    return jsonify({"status": "processing", "dataset": n})


@app.route("/api/dataset/<int:n>/analyze", methods=["POST"])
def api_dataset_analyze(n):
    """Trigger AI analysis via the real PipelineEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    _get_db().log_action("dataset_analyze", f"Started AI analysis on dataset {n}")
    socketio.emit("progress", {"message": f"AI analysis started for dataset {n}...", "level": "info"})

    def _background_analyze():
        try:
            from ai_pipeline.pipeline import PipelineEngine

            engine = PipelineEngine()

            def pipeline_progress(current, total, doc_id, status):
                pct = round(current / total * 100) if total else 0
                socketio.emit("dataset_progress", {
                    "dataset": n,
                    "percent": pct,
                    "message": f"[{current}/{total}] Document {doc_id}: {status}",
                })

            engine.progress_callback = pipeline_progress
            results = engine.analyze_dataset(n)

            if not results:
                socketio.emit("progress", {"message": f"Dataset {n}: no documents to analyze.", "level": "warning"})
                return

            successes = sum(1 for r in results if "error" not in r.get("result", {}))
            errors = len(results) - successes

            conn2 = get_conn()
            try:
                conn2.execute(
                    "UPDATE datasets SET status = 'analyzed', updated_at = ? WHERE dataset_number = ?",
                    (datetime.now(tz=timezone.utc).isoformat(), n),
                )
                conn2.commit()
            finally:
                conn2.close()

            socketio.emit("dataset_progress", {"dataset": n, "percent": 100, "message": f"Analysis complete! {successes} succeeded, {errors} failed"})
            socketio.emit("progress", {"message": f"Dataset {n} analyzed! {successes} succeeded, {errors} failed.", "level": "success"})
        except Exception as exc:
            logger.exception("Dataset %d analysis failed", n)
            socketio.emit("progress", {"message": f"Dataset {n} analysis FAILED: {exc}", "level": "error"})

    socketio.start_background_task(_background_analyze)
    return jsonify({"status": "analyzing", "dataset": n})


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"results": []})
    fts_query = sanitize_fts(q)
    if fts_query is None:
        # Query had no searchable characters; fall back to LIKE directly
        results = query_all(
            r"""SELECT document_id, page_number, substr(text_content, 1, 200) as snippet
               FROM document_pages
               WHERE text_content LIKE ? ESCAPE '\'
               LIMIT 50""",
            (f"%{escape_like(q)}%",),
        )
        return jsonify({"query": q, "results": results})
    try:
        results = query_all(
            """SELECT dp.document_id, dp.page_number,
                      snippet(document_text_fts, 2, '<mark>', '</mark>', '...', 64) as snippet
               FROM document_text_fts
               JOIN document_pages dp ON dp.id = document_text_fts.rowid
               WHERE document_text_fts MATCH ?
               LIMIT 50""",
            (fts_query,),
        )
    except Exception:
        # FTS might not be populated; fall back to LIKE
        results = query_all(
            r"""SELECT document_id, page_number, substr(text_content, 1, 200) as snippet
               FROM document_pages
               WHERE text_content LIKE ? ESCAPE '\'
               LIMIT 50""",
            (f"%{escape_like(q)}%",),
        )
    return jsonify({"query": q, "results": results})


@app.route("/api/entity/<int:entity_id>/evidence")
def api_entity_evidence(entity_id):
    evidence = query_all(
        """SELECT edl.*, d.original_filename, d.doc_type
           FROM entity_document_links edl
           JOIN documents d ON d.id = edl.document_id
           WHERE edl.entity_id = ?
           ORDER BY edl.damning_score DESC""",
        (entity_id,),
    )
    return jsonify({"entity_id": entity_id, "evidence": evidence})


@app.route("/api/compact", methods=["POST"])
def api_compact():
    result = _get_db().auto_compact()
    _get_db().log_action("auto_compact", json.dumps(result))
    socketio.emit("progress", {"message": f"Compact complete: freed {result['freed_mb']} MB", "level": "success"})
    return jsonify(result)


@app.route("/api/document/<int:doc_id>/flag", methods=["POST"])
def api_document_flag(doc_id):
    doc = query_one("SELECT user_flagged FROM documents WHERE id = ?", (doc_id,))
    if not doc:
        return jsonify({"error": "Not found"}), 404
    new_flag = 0 if doc["user_flagged"] else 1
    execute("UPDATE documents SET user_flagged = ?, updated_at = ? WHERE id = ?",
            (new_flag, datetime.now(tz=timezone.utc).isoformat(), doc_id))
    _get_db().log_action("document_flag", f"Document {doc_id} flagged={new_flag}")
    return jsonify({"flagged": bool(new_flag)})


# ============================================================================
#  SocketIO events
# ============================================================================

@socketio.on("connect")
def handle_connect():
    emit("progress", {"message": "Connected to EpsteinAnalyzer", "level": "info"})


# ============================================================================
#  Template registration (so {% extends "base.html" %} works)
# ============================================================================

class _OverlayLoader(jinja2.BaseLoader):
    """A Jinja2 loader that serves our inline base template and delegates the rest."""

    def __init__(self, inner):
        self._inner = inner

    def get_source(self, environment, template):
        if template == "base.html":
            return (BASE_TEMPLATE, "base.html", lambda: True)
        if self._inner:
            return self._inner.get_source(environment, template)
        raise jinja2.TemplateNotFound(template)

    def list_templates(self):
        templates = ["base.html"]
        if self._inner and hasattr(self._inner, "list_templates"):
            templates.extend(self._inner.list_templates())
        return templates


# Register overlay loader once at import time (not per-request)
app.jinja_env.loader = _OverlayLoader(app.jinja_env.loader)


# ============================================================================
#  ENTRY POINT
# ============================================================================

def main():
    import yaml
    config_path = PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    host = config.get("dashboard", {}).get("host", "127.0.0.1")
    port = config.get("dashboard", {}).get("port", 8080)
    debug = config.get("dashboard", {}).get("debug", False)
    secret = config.get("dashboard", {}).get("secret_key", "")
    if secret and secret not in ("CHANGE_THIS_ON_FIRST_RUN", "local-dev-key"):
        app.config["SECRET_KEY"] = secret
    # else: keep the random key generated at import time

    print(f"\n{'='*60}")
    print(f"  EpsteinAnalyzer Dashboard")
    print(f"  http://{host}:{port}")
    print(f"{'='*60}\n")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
