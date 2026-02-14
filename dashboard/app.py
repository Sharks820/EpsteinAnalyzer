"""
EpsteinAnalyzer - Dashboard Application
Flask web UI for investigative document analysis.
Runs locally at http://127.0.0.1:8080
"""

import hmac
import html
import io
import jinja2
import json
import logging
import math
import os
import re
import secrets
import sys
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    render_template_string,
    request,
    jsonify,
    redirect,
    url_for,
    abort,
    send_file,
    send_from_directory,
    session,
)
from flask_socketio import SocketIO, emit

# ---------------------------------------------------------------------------
# Resolve project root so imports work with `python -m dashboard.app`
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db import DatabaseManager  # noqa: E402

# Prevent .pyc files from being written
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "EPSTEIN_SECRET_KEY", os.urandom(32).hex()
)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # localhost, no HTTPS
socketio = SocketIO(app, async_mode="threading")

# Vault integration (initialized at startup if vault exists)
_vault_auth = None       # DashboardAuth instance
_vault_key_mgr = None    # KeyManager instance
_vault_file_mgr = None   # VaultFileManager instance
_vault_mode = None        # "master" or "decoy"

# Lazy-initialized database manager (avoids import-time side effects)
_db: "DatabaseManager | None" = None
_real_db: "DatabaseManager | None" = None  # preserved reference for restoring after decoy
_db_lock = threading.Lock()
logger = logging.getLogger(__name__)
_activity_lock = threading.Lock()
_activity_state = {
    "active": False,
    "dataset": None,
    "percent": 0,
    "message": "Idle",
    "level": "info",
    "updated_at": 0.0,
}
_live_emit_lock = threading.Lock()
_live_emit_last = 0.0
_live_cc_emit_last = 0.0


def _get_activity_snapshot() -> dict:
    with _activity_lock:
        snap = dict(_activity_state)
    if snap.get("active") and (time.time() - snap.get("updated_at", 0.0) > 240):
        # Safety timeout to avoid stale "running" badges on abandoned sessions.
        snap["active"] = False
    return snap


def _set_activity(
    *,
    active: Optional[bool] = None,
    dataset: Optional[int] = None,
    percent: Optional[int] = None,
    message: Optional[str] = None,
    level: Optional[str] = None,
) -> dict:
    with _activity_lock:
        if active is not None:
            _activity_state["active"] = bool(active)
        if dataset is not None:
            _activity_state["dataset"] = dataset
        if percent is not None:
            try:
                _activity_state["percent"] = max(0, min(100, int(percent)))
            except (TypeError, ValueError):
                pass
        if message is not None:
            _activity_state["message"] = str(message)
        if level is not None:
            _activity_state["level"] = str(level)
        _activity_state["updated_at"] = time.time()
        return dict(_activity_state)


def _emit_progress(message: str, level: str = "info", *, active: Optional[bool] = None, percent: Optional[int] = None, dataset: Optional[int] = None):
    state = _set_activity(active=active, percent=percent, message=message, level=level, dataset=dataset)
    socketio.emit("progress", {"message": message, "level": level})
    socketio.emit("activity", {
        "active": state["active"],
        "dataset": state["dataset"],
        "percent": state["percent"],
        "message": state["message"],
        "level": state["level"],
    })
    force = (not state["active"]) or int(state.get("percent") or 0) >= 100 or level in {"success", "error", "warning"}
    _emit_live_updates(force=force)


def _emit_dataset_progress(dataset: int, percent: int, message: str):
    state = _set_activity(active=True, dataset=dataset, percent=percent, message=message, level="info")
    socketio.emit("dataset_progress", {
        "dataset": dataset,
        "percent": percent,
        "message": message,
    })
    socketio.emit("activity", {
        "active": state["active"],
        "dataset": state["dataset"],
        "percent": state["percent"],
        "message": state["message"],
        "level": state["level"],
    })
    _emit_live_updates(force=int(percent or 0) >= 100)


def _emit_live_updates(*, force: bool = False):
    """Broadcast fresh stats/state to all pages with lightweight throttling."""
    global _live_emit_last, _live_cc_emit_last
    now = time.time()
    with _live_emit_lock:
        if not force and (now - _live_emit_last) < 1.5:
            return
        _live_emit_last = now
        emit_cc = force or (now - _live_cc_emit_last) >= 5.0
        if emit_cc:
            _live_cc_emit_last = now

    try:
        stats = _get_db().get_stats()
        socketio.emit("stats_update", stats)
        socketio.emit("documents_hint", {"updated_at": now})
        if emit_cc:
            socketio.emit("command_center_update", _command_center_live_payload())
    except Exception as exc:
        logger.debug("live update emit failed: %s", exc)


def _build_analysis_progress_callback(dataset_number: int):
    """Create analysis progress callback + heartbeat emitter for long-running docs."""
    state_lock = threading.Lock()
    state = {
        "current": 0,
        "total": 0,
        "doc_id": None,
        "status": "starting",
        "updated_at": time.time(),
    }
    stop_event = threading.Event()

    def _emit_from_state(*, stale: bool = False):
        with state_lock:
            current = int(state["current"])
            total = int(state["total"])
            doc_id = state["doc_id"]
            status = str(state["status"] or "running")
            updated_at = float(state["updated_at"])

        if total > 0:
            pct = max(1, min(99, round(current / total * 100)))
            doc_label = f"Doc {doc_id}" if doc_id else "Current doc"
            suffix = status
            if stale and (time.time() - updated_at) >= 5:
                suffix = f"{status} (still running)"
            _emit_dataset_progress(
                dataset_number,
                pct,
                f"AI Analysis [{current}/{total}] {doc_label}: {suffix}",
            )
        else:
            _emit_progress(
                f"AI analysis warming up for dataset {dataset_number}...",
                "info",
                active=True,
                percent=1,
                dataset=dataset_number,
            )

    def callback(current, total, doc_id, status):
        with state_lock:
            state["current"] = int(current or 0)
            state["total"] = int(total or 0)
            state["doc_id"] = doc_id
            state["status"] = status or "running"
            state["updated_at"] = time.time()
        _emit_from_state(stale=False)

    def _heartbeat():
        while not stop_event.wait(4):
            _emit_from_state(stale=True)

    threading.Thread(target=_heartbeat, daemon=True).start()
    return callback, stop_event


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
<meta name="csrf-token" content="{{ csrf_token_value }}">
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
.ds-btn.processed{background:rgba(163,113,247,.2);color:var(--purple);border-color:var(--purple)}
.ds-btn.downloaded{background:rgba(210,153,34,.2);color:var(--orange);border-color:var(--orange)}
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
<body data-page="{{ active or '' }}">
<div class="app-shell">
  <!-- Sidebar Navigation -->
  <aside class="sidebar">
    <div class="logo"><span class="dot"></span> EpsteinAnalyzer</div>
    <nav>
      <a href="/" class="{% if active == 'dashboard' %}active{% endif %}">&#9635; Command Center</a>
      <a href="/documents" class="{% if active == 'documents' %}active{% endif %}">&#9776; All Documents</a>
      <a href="/entities" class="{% if active == 'entities' %}active{% endif %}">&#9734; Entity Explorer</a>
      <a href="/graph" class="{% if active == 'graph' %}active{% endif %}">&#9784; Spiderweb Graph</a>
      <a href="/chains" class="{% if active == 'chains' %}active{% endif %}">&#9993; Email Chains</a>
      <a href="/findings" class="{% if active == 'findings' %}active{% endif %}">&#9873; Findings Board</a>
      <a href="/images/review" class="{% if active == 'images' %}active{% endif %}">&#9638; Image Review
        <span id="nav-badge-images" class="badge" style="{% if not pending_images %}display:none{% endif %}">{{ pending_images }}</span></a>
      <a href="/deletions" class="{% if active == 'deletions' %}active{% endif %}">&#9746; Deletion Queue
        <span id="nav-badge-deletions" class="badge" style="{% if not pending_deletions %}display:none{% endif %}">{{ pending_deletions }}</span></a>
      <a href="/export" class="{% if active == 'export' %}active{% endif %}">&#9112; Export Tools</a>
      <a href="/audit" class="{% if active == 'audit' %}active{% endif %}">&#9783; Audit Log</a>
      <a href="/settings" class="{% if active == 'settings' %}active{% endif %}">&#9881; Settings</a>
      <a href="/logout" style="margin-top:auto;border-top:1px solid var(--border)">&#10140; Logout &amp; Lock</a>
    </nav>
    <div class="sidebar-footer">
      Disk: {{ disk_gb }} GB / {{ disk_max_gb }} GB ({{ disk_pct }}%)<br>
      <div class="progress mt-1" style="margin-top:6px">
        <div class="progress-bar {% if disk_pct > 90 %}red{% elif disk_pct > 78 %}orange{% else %}green{% endif %}"
             style="width:{{ [disk_pct, 1]|max if disk_gb > 0 else 0 }}%"></div>
      </div>
      <div style="margin-top:10px">
        <div class="text-muted" style="font-size:.75rem">
          Activity:
          <span id="global-activity-text">{{ activity_state.message }}</span>
        </div>
        <div class="progress mt-1" style="margin-top:5px">
          <div id="global-activity-bar"
               class="progress-bar {% if activity_state.active %}blue{% else %}green{% endif %}"
               style="width:{{ activity_state.percent if activity_state.active else 0 }}%"></div>
        </div>
      </div>
    </div>
  </aside>

  <!-- Main Content -->
  <main class="main">
    {% block content %}{% endblock %}
  </main>
</div>

<div id="toast-container" class="toast-container"></div>

<script src="/static/socket.io.min.js"></script>
<script>
const socket = io();
const __activityStorageKey = 'ea.activity.state.v1';

function applyGlobalActivityVisual(pct){
  const bar = document.getElementById('global-activity-bar');
  if(!bar) return;
  bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
}

function saveGlobalActivityState(data){
  try{
    sessionStorage.setItem(__activityStorageKey, JSON.stringify({
      active: !!data.active,
      dataset: data.dataset ?? null,
      percent: Number.parseInt(data.percent ?? 0, 10) || 0,
      message: data.message || 'Idle',
      level: data.level || 'info',
      updatedAt: Date.now(),
    }));
  } catch(e){}
}

function loadGlobalActivityState(){
  try{
    const raw = sessionStorage.getItem(__activityStorageKey);
    if(!raw) return null;
    const data = JSON.parse(raw);
    if(!data || (Date.now() - Number(data.updatedAt || 0)) > 15 * 60 * 1000){
      return null;
    }
    return data;
  } catch(e){
    return null;
  }
}

function updateSidebarBadge(id, count){
  const el = document.getElementById(id);
  if(!el) return;
  const n = Math.max(0, Number.parseInt(count ?? 0, 10) || 0);
  el.textContent = String(n);
  el.style.display = n > 0 ? '' : 'none';
}

function applyGlobalStats(stats){
  if(!stats) return;
  updateSidebarBadge('nav-badge-images', stats.pending_image_reviews);
  updateSidebarBadge('nav-badge-deletions', stats.pending_deletions);
  window.dispatchEvent(new CustomEvent('ea:stats', { detail: stats }));
}

function setGlobalActivity(data){
  const bar = document.getElementById('global-activity-bar');
  const txt = document.getElementById('global-activity-text');
  if(!bar || !txt || !data) return;
  const active = !!data.active;
  const pct = Math.max(0, Math.min(100, parseInt(data.percent || 0, 10)));
  const msg = data.message || (active ? 'Processing...' : 'Idle');
  const visualPct = active ? pct : 0;
  txt.textContent = msg;
  applyGlobalActivityVisual(visualPct);
  bar.classList.remove('blue','green','orange','red');
  if(!active){
    bar.classList.add('green');
  } else if (pct < 85){
    bar.classList.add('blue');
  } else {
    bar.classList.add('orange');
  }
  saveGlobalActivityState({
    active: active,
    dataset: data.dataset ?? null,
    percent: pct,
    message: msg,
    level: data.level || 'info',
  });
}

socket.on('activity', function(data){
  setGlobalActivity(data);
});
socket.on('progress', function(data){
  showToast(data.message, data.level || 'info');
  apiGet('/api/activity').then(setGlobalActivity).catch(()=>{});
});
socket.on('refresh', function(){ location.reload(); });
socket.on('dataset_progress', function(){ apiGet('/api/activity').then(setGlobalActivity).catch(()=>{}); });
socket.on('stats_update', function(data){
  applyGlobalStats(data || {});
});
socket.on('command_center_update', function(data){
  window.dispatchEvent(new CustomEvent('ea:command-center-live', { detail: data || {} }));
});
socket.on('documents_hint', function(){
  window.dispatchEvent(new Event('ea:documents-hint'));
});
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
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken},body:JSON.stringify(body||{})})
    .then(async r=>{
      let data = {};
      try { data = await r.json(); } catch(e){ data = {}; }
      if(!r.ok){
        const err = new Error(data.error || data.message || ('Request failed: '+r.status));
        err.status = r.status;
        err.data = data;
        throw err;
      }
      return data;
    });
}
function apiGet(url){
  return fetch(url).then(r=>r.json());
}

// Keep global activity and sidebar counters truthful and synced on every page.
const __savedActivity = loadGlobalActivityState();
if(__savedActivity){ setGlobalActivity(__savedActivity); }
apiGet('/api/activity').then(setGlobalActivity).catch(()=>{});
apiGet('/api/stats').then(applyGlobalStats).catch(()=>{});
setInterval(function(){
  apiGet('/api/activity').then(setGlobalActivity).catch(()=>{});
  apiGet('/api/stats').then(applyGlobalStats).catch(()=>{});
}, 4000);
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

    # Ensure CSRF token exists in session
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    disk_pct = stats.get("disk_usage_percent") or 0
    disk_gb = stats.get("disk_usage_gb") or 0
    disk_max = stats.get("disk_max_gb") or 0

    return {
        "pending_images": stats.get("pending_image_reviews", 0),
        "pending_deletions": stats.get("pending_deletions", 0),
        "disk_pct": disk_pct,
        "disk_gb": disk_gb,
        "disk_max_gb": disk_max,
        "activity_state": _get_activity_snapshot(),
        "csrf_token_value": session.get("_csrf_token", ""),
    }


@app.before_request
def csrf_protect():
    """Validate CSRF token on all POST/PUT/DELETE requests."""
    if request.method in ("POST", "PUT", "DELETE"):
        # Check header first (AJAX), then form field
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        expected = session.get("_csrf_token", "")
        if not token or not hmac.compare_digest(token, expected):
            abort(403)


# ============================================================================
#  LOGIN PAGE
# ============================================================================

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login - EpsteinAnalyzer</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#1c2333;
  --fg:#e6edf3; --fg2:#8b949e; --accent:#58a6ff; --accent2:#1f6feb;
  --red:#f85149; --border:#30363d; --green:#3fb950;
  --font-sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
}
html{font-size:14px}
body{background:var(--bg);color:var(--fg);font-family:var(--font-sans);
  display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:40px;width:400px;max-width:90vw}
.login-box h1{font-size:1.4rem;margin-bottom:8px;text-align:center}
.login-box .subtitle{color:var(--fg2);font-size:.85rem;text-align:center;margin-bottom:24px}
.login-box .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);
  animation:pulse 2s infinite;margin-right:6px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:.85rem;color:var(--fg2)}
.form-group input{background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  color:var(--fg);padding:10px 14px;font-size:.92rem;width:100%;font-family:inherit}
.form-group input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.15)}
.btn-login{width:100%;padding:12px;background:var(--accent2);border:none;border-radius:6px;
  color:#fff;font-size:.95rem;font-weight:600;cursor:pointer;transition:.15s;font-family:inherit}
.btn-login:hover{background:#388bfd}
.error{color:var(--red);font-size:.85rem;margin-bottom:12px;text-align:center}
.attempts{color:var(--fg2);font-size:.78rem;text-align:center;margin-top:12px}
</style>
</head>
<body>
<div class="login-box">
  <h1><span class="dot"></span> EpsteinAnalyzer</h1>
  <p class="subtitle">Secure Document Analysis Platform</p>
  {% if error %}
  <div class="error">{{ error }}</div>
  {% endif %}
  <form method="post" action="/login">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autofocus
             autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn-login">Unlock</button>
  </form>
  {% if attempts_info %}
  <p class="attempts">{{ attempts_info }}</p>
  {% endif %}
</div>
</body>
</html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page — first gate for vault authentication."""
    global _vault_mode

    error = None
    attempts_info = None

    if request.method == "POST":
        password = request.form.get("password", "")
        # CSRF is validated by the global csrf_protect() before_request handler
        if _vault_auth:
            success, mode, message = _vault_auth.attempt_login(password)
            if success:
                _vault_mode = mode
                global _db, _real_db
                if mode == "decoy":
                    # Save real DB reference before swapping to decoy
                    from security.vault import NullDatabaseProxy
                    if _real_db is None:
                        _real_db = _db
                    schema_path = str(PROJECT_ROOT / "database" / "schema.sql")
                    _db = NullDatabaseProxy(schema_path)
                elif _real_db is not None:
                    # Restore real DB after a previous decoy session
                    _db = _real_db
                    _real_db = None
                return redirect(url_for("command_center"))
            else:
                error = message
        else:
            # No vault configured — fail closed, do NOT auto-authenticate
            error = "Vault not configured. Run 'python setup.py init' to set up security."

    # Generate CSRF token
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return render_template_string(
        LOGIN_HTML,
        error=error,
        attempts_info=attempts_info,
        csrf_token=session["_csrf_token"],
    )


@app.route("/logout")
def logout():
    """Logout and lock vault."""
    global _vault_mode
    if _vault_auth:
        _vault_auth.logout()
    _vault_mode = None
    session.clear()
    return redirect(url_for("login"))


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
  <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
    <button class="btn btn-primary" onclick="processAllDatasets()">Process All Downloaded</button>
    <button class="btn btn-primary" style="background:var(--purple)" onclick="analyzeAllDatasets()">Analyze All Processed</button>
  </div>
  <div id="ds-progress" class="hidden">
    <p id="ds-progress-text" class="text-accent mb-1"></p>
    <div class="progress"><div id="ds-progress-bar" class="progress-bar blue" style="width:0%"></div></div>
  </div>
</div>

<!-- Stats Grid -->
<div class="grid grid-4 mb-3">
  <a href="/documents" class="card stat" style="text-decoration:none;cursor:pointer">
    <div id="cc-stat-total-docs" class="value">{{ stats.total_documents }}</div>
    <div class="label">Documents</div>
  </a>
  <a href="/documents?status=analyzed" class="card stat green" style="text-decoration:none;cursor:pointer">
    <div id="cc-stat-analyzed-docs" class="value">{{ stats.processed_documents }}</div>
    <div class="label">Analyzed</div>
  </a>
  <a href="/entities" class="card stat purple" style="text-decoration:none;cursor:pointer">
    <div id="cc-stat-entities" class="value">{{ stats.total_entities }}</div>
    <div class="label">Entities</div>
  </a>
  <a href="/graph" class="card stat orange" style="text-decoration:none;cursor:pointer">
    <div id="cc-stat-connections" class="value">{{ stats.total_relationships }}</div>
    <div class="label">Connections</div>
  </a>
</div>

<div class="grid grid-3 mb-3">
  <div class="card stat">
    <div id="cc-stat-redactions" class="value">{{ stats.total_redactions }}</div>
    <div class="label">Redactions Found</div>
  </div>
  <div class="card stat green">
    <div id="cc-stat-redactions-recovered" class="value">{{ stats.recovered_redactions }}</div>
    <div class="label">Redactions Recovered</div>
  </div>
  <div class="card stat red">
    <div id="cc-stat-removed" class="value">{{ stats.removed_files_detected }}</div>
    <div class="label">Removed Files</div>
  </div>
</div>

<div class="grid grid-2">
  <!-- Pipeline Status -->
  <div class="card">
    <h3 class="mb-2">Pipeline Status</h3>
    <table>
      <tr><td>Downloaded</td><td id="cc-pipeline-downloaded" class="mono text-accent">{{ pipeline.downloaded }}</td></tr>
      <tr><td>OCR Processed</td><td id="cc-pipeline-ocr" class="mono text-green">{{ pipeline.ocr_complete }}</td></tr>
      <tr><td>AI Analyzed</td><td id="cc-pipeline-analyzed" class="mono text-purple">{{ pipeline.analyzed }}</td></tr>
      <tr><td>User Reviewed</td><td id="cc-pipeline-reviewed" class="mono text-yellow">{{ pipeline.reviewed }}</td></tr>
      <tr><td>Email Chains</td><td id="cc-stat-email-chains" class="mono">{{ stats.total_email_chains }}</td></tr>
      <tr><td>Findings Pinned</td><td id="cc-stat-findings" class="mono">{{ stats.total_findings }}</td></tr>
    </table>
  </div>

  <!-- Top Priority Documents -->
  <div class="card">
    <div class="flex flex-between items-center mb-2">
      <h3>Top Priority Documents</h3>
      <a href="/documents?sort=priority" class="btn btn-sm">View All &rarr;</a>
    </div>
    {% if priority_docs %}
    <table>
      <thead><tr><th>Document</th><th>Score</th><th>Type</th></tr></thead>
      <tbody id="cc-priority-tbody">
      {% for doc in priority_docs %}
      <tr>
        <td><a href="/document/{{ doc.id }}">{{ (doc.original_filename or 'Untitled')|truncate(40) }}</a></td>
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
    <div id="cc-recent-analyses">
    {% if recent_analyses %}
    {% for a in recent_analyses %}
    <div class="annotation">
      <div class="an-label">{{ a.model_name }} &middot; {{ a.created_at }}</div>
      {{ (a.summary or 'Analysis pending...')|truncate(200) }}
      {% if a.document_id %}
      <a href="/document/{{ a.document_id }}" class="btn btn-sm mt-1" style="margin-top:6px;display:inline-block">View Document</a>
      {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <p class="text-muted">No AI analyses completed yet.</p>
    {% endif %}
    </div>
  </div>

  <!-- Knowledge Graph Stats -->
  <div class="card">
    <h3 class="mb-2">Knowledge Graph</h3>
    <div class="grid grid-2">
      <div class="stat"><div id="cc-kg-entities" class="value text-accent">{{ stats.total_entities }}</div><div class="label">Entities</div></div>
      <div class="stat"><div id="cc-kg-connections" class="value text-purple">{{ stats.total_relationships }}</div><div class="label">Connections</div></div>
    </div>
    <div class="grid grid-2 mt-2">
      <div class="stat"><div id="cc-kg-redactions" class="value text-orange">{{ stats.total_redactions }}</div><div class="label">Redactions</div></div>
      <div class="stat"><div id="cc-kg-recovered" class="value text-green">{{ stats.recovered_redactions }}</div><div class="label">Recovered</div></div>
    </div>
    <div class="mt-2" style="text-align:center">
      <a href="/graph" class="btn btn-primary">Open Spiderweb View</a>
    </div>
  </div>
</div>
{% endblock %}

{% block scripts %}
<script>
let __datasetCompleteTimer = null;
let __datasetLastUpdate = 0;
let __datasetLastPoll = 0;

function setDatasetProgress(data){
  const el = document.getElementById('ds-progress');
  const bar = document.getElementById('ds-progress-bar');
  const txt = document.getElementById('ds-progress-text');
  if(!el || !bar || !txt || !data) return;
  const pctRaw = Number.parseInt(data.percent ?? 0, 10);
  const pct = Number.isFinite(pctRaw) ? Math.max(0, Math.min(100, pctRaw)) : 0;
  const msg = data.message || 'Working...';
  const isError = /(fail|error)/i.test(msg);
  const isDone = /(complete|completed|done|idle)/i.test(msg);
  const active = (typeof data.active === 'boolean') ? data.active : (!isDone && !isError && pct < 100);
  el.classList.remove('hidden');
  bar.style.width = pct + '%';
  txt.textContent = msg;
  __datasetLastUpdate = Date.now();
  try{
    sessionStorage.setItem('ea.dataset.progress.v1', JSON.stringify({
      dataset: data.dataset ?? null,
      percent: pct,
      message: msg,
      active: !!active,
      updatedAt: Date.now(),
    }));
  } catch(e){}
  if(pct >= 100 && !isError){
    if(!__datasetCompleteTimer){
      __datasetCompleteTimer = setTimeout(()=>location.reload(), 2000);
    }
  } else if (__datasetCompleteTimer){
    clearTimeout(__datasetCompleteTimer);
    __datasetCompleteTimer = null;
  }
}

function syncDatasetProgressFromActivity(data){
  if(!data) return;
  const datasetNum = Number.parseInt(data.dataset ?? 0, 10);
  const hasDataset = Number.isFinite(datasetNum) && datasetNum > 0;
  const msg = data.message || '';
  if(hasDataset && (data.active || Number.parseInt(data.percent ?? 0, 10) > 0 || /dataset/i.test(msg))){
    setDatasetProgress({
      dataset: datasetNum,
      percent: data.percent,
      message: msg || ('Dataset ' + datasetNum + ' running...'),
      active: !!data.active,
    });
  } else if(!data.active && __datasetLastUpdate > 0 && /(complete|completed|failed|error|idle|done)/i.test(msg)){
    setDatasetProgress({
      percent: 100,
      message: msg,
      active: false,
    });
  }
}

socket.on('dataset_progress', function(data){
  setDatasetProgress(data);
});
socket.on('activity', function(data){
  syncDatasetProgressFromActivity(data);
});

apiGet('/api/activity').then(syncDatasetProgressFromActivity).catch(()=>{});
try{
  const cached = JSON.parse(sessionStorage.getItem('ea.dataset.progress.v1') || '{}');
  if(cached && cached.message && (Date.now() - Number(cached.updatedAt || 0)) < 15 * 60 * 1000){
    setDatasetProgress(cached);
  }
} catch(e){}

function escapeHtml(s){
  return String(s ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[ch]));
}

function setText(id, value){
  const el = document.getElementById(id);
  if(el) el.textContent = String(value ?? 0);
}

function renderPriorityDocs(items){
  const body = document.getElementById('cc-priority-tbody');
  if(!body) return;
  const docs = Array.isArray(items) ? items : [];
  body.innerHTML = docs.map(d => (
    '<tr>' +
      '<td><a href=\"/document/' + Number(d.id || 0) + '\">' + escapeHtml(d.original_filename || 'Untitled') + '</a></td>' +
      '<td class=\"mono text-orange\">' + escapeHtml(d.priority_score ?? 0) + '</td>' +
      '<td><span class=\"tag tag-blue\">' + escapeHtml(d.doc_type || 'unknown') + '</span></td>' +
    '</tr>'
  )).join('');
}

function renderRecentAnalyses(items){
  const wrap = document.getElementById('cc-recent-analyses');
  if(!wrap) return;
  const analyses = Array.isArray(items) ? items : [];
  if(!analyses.length){
    wrap.innerHTML = '<p class=\"text-muted\">No AI analyses completed yet.</p>';
    return;
  }
  wrap.innerHTML = analyses.map(a => (
    '<div class=\"annotation\">' +
      '<div class=\"an-label\">' + escapeHtml(a.model_name || 'model') + ' &middot; ' + escapeHtml(a.created_at || '') + '</div>' +
      escapeHtml(a.summary || 'Analysis pending...') +
      (a.document_id ? ('<a href=\"/document/' + Number(a.document_id) + '\" class=\"btn btn-sm mt-1\" style=\"margin-top:6px;display:inline-block\">View Document</a>') : '') +
    '</div>'
  )).join('');
}

function applyCommandCenterStats(stats){
  if(!stats) return;
  setText('cc-stat-total-docs', stats.total_documents);
  setText('cc-stat-analyzed-docs', stats.processed_documents);
  setText('cc-stat-entities', stats.total_entities);
  setText('cc-stat-connections', stats.total_relationships);
  setText('cc-stat-redactions', stats.total_redactions);
  setText('cc-stat-redactions-recovered', stats.recovered_redactions);
  setText('cc-stat-removed', stats.removed_files_detected);
  setText('cc-stat-email-chains', stats.total_email_chains);
  setText('cc-stat-findings', stats.total_findings);
  setText('cc-kg-entities', stats.total_entities);
  setText('cc-kg-connections', stats.total_relationships);
  setText('cc-kg-redactions', stats.total_redactions);
  setText('cc-kg-recovered', stats.recovered_redactions);
}

function applyCommandCenterLive(data){
  if(!data) return;
  if(data.stats){ applyCommandCenterStats(data.stats); }
  if(data.pipeline){
    setText('cc-pipeline-downloaded', data.pipeline.downloaded);
    setText('cc-pipeline-ocr', data.pipeline.ocr_complete);
    setText('cc-pipeline-analyzed', data.pipeline.analyzed);
    setText('cc-pipeline-reviewed', data.pipeline.reviewed);
  }
  if(data.priority_docs){ renderPriorityDocs(data.priority_docs); }
  if(data.recent_analyses){ renderRecentAnalyses(data.recent_analyses); }
}

window.addEventListener('ea:stats', function(evt){
  applyCommandCenterStats(evt.detail || {});
});
window.addEventListener('ea:command-center-live', function(evt){
  applyCommandCenterLive(evt.detail || {});
});

function refreshCommandCenterLive(){
  apiGet('/api/command_center/live').then(applyCommandCenterLive).catch(()=>{});
}

refreshCommandCenterLive();
setInterval(function(){
  const now = Date.now();
  if(now - __datasetLastUpdate > 2500 && now - __datasetLastPoll > 2500){
    __datasetLastPoll = now;
    apiGet('/api/activity').then(syncDatasetProgressFromActivity).catch(()=>{});
  }
}, 2500);
setInterval(refreshCommandCenterLive, 5000);

function loadDataset(n){
  showToast('Starting dataset '+n+'...','info');
  setDatasetProgress({
    dataset: n,
    percent: 1,
    message: 'Initializing dataset ' + n + '...',
  });
  apiPost('/api/dataset/'+n+'/load').catch(err=>{
    setDatasetProgress({ dataset: n, percent: 0, message: err.message || ('Dataset ' + n + ' load request failed'), active: false });
    showToast(err.message || ('Dataset '+n+' load request failed'), 'error');
  });
}
function processDataset(n){
  showToast('Processing dataset '+n+'...','info');
  setDatasetProgress({
    dataset: n,
    percent: 1,
    message: 'Processing dataset ' + n + '...',
  });
  apiPost('/api/dataset/'+n+'/process').catch(err=>{
    setDatasetProgress({ dataset: n, percent: 0, message: err.message || ('Dataset ' + n + ' process request failed'), active: false });
    showToast(err.message || ('Dataset '+n+' process request failed'), 'error');
  });
}
function analyzeDataset(n){
  showToast('Analyzing dataset '+n+'...','info');
  setDatasetProgress({
    dataset: n,
    percent: 1,
    message: 'Analyzing dataset ' + n + '...',
  });
  apiPost('/api/dataset/'+n+'/analyze').catch(err=>{
    setDatasetProgress({ dataset: n, percent: 0, message: err.message || ('Dataset ' + n + ' analyze request failed'), active: false });
    showToast(err.message || ('Dataset '+n+' analyze request failed'), 'error');
  });
}
function processAllDatasets(){
  showToast('Processing all downloaded datasets...','info');
  apiGet('/api/stats').then(data => {
    if(data.datasets){
      for(let d of data.datasets){
        if(d.status === 'downloaded' || d.status === 'ocr_complete'){ processDataset(d.dataset_number); }
      }
    }
  });
}
function analyzeAllDatasets(){
  showToast('Analyzing all processed datasets...','info');
  apiGet('/api/stats').then(data => {
    if(data.datasets){
      let queued = 0;
      for(let d of data.datasets){
        const processedFiles = Number.parseInt(d.processed_files || 0, 10) || 0;
        if(d.status === 'processed' && processedFiles > 0){
          analyzeDataset(d.dataset_number);
          queued += 1;
        }
      }
      if(queued === 0){
        showToast('No processed datasets with documents are ready for AI analysis.', 'warning');
      }
    }
  });
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
    live = _command_center_live_payload()
    stats = live["stats"]
    datasets_raw = _get_db().get_dataset_status()
    # Add CSS class for dataset buttons
    datasets = []
    for ds in datasets_raw:
        d = dict(ds)
        if d["status"] in ("analyzed",):
            d["css_class"] = "completed"
        elif d["status"] in ("processed",):
            d["css_class"] = "processed"
        elif d["status"] in ("downloading", "processing", "analyzing"):
            d["css_class"] = "current"
        elif d["status"] in ("downloaded",):
            d["css_class"] = "downloaded"
        else:
            d["css_class"] = "pending"
        datasets.append(d)

    pipeline = live["pipeline"]
    priority_docs = live["priority_docs"]
    recent_analyses = live["recent_analyses"]
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
    {% endif %}
    <div class="panel-body">
      {% if not (doc.file_path and doc.file_type == 'pdf') %}
      <p class="text-muted mb-2">Preview not available for {{ doc.file_type }} files.</p>
      {% endif %}

      {% if pages %}
      <h3 class="mb-1">Full Extracted Document Text</h3>
      <p class="text-muted mb-2" style="font-size:.78rem">
        {{ pages|length }} pages &middot; {{ full_text_chars }} characters
      </p>
      <input id="docTextFilter" type="search" placeholder="Filter extracted text..." class="mb-2">
      <div id="docTextPages">
        {% for page in pages %}
        <details class="card doc-text-page" {% if loop.index <= 2 %}open{% endif %} data-page-text="{{ (page.text_content or '')|lower }}">
          <summary style="cursor:pointer;font-weight:600">Page {{ page.page_number }}</summary>
          <pre style="white-space:pre-wrap;font-size:.85rem;margin-top:10px">{{ page.text_content }}</pre>
        </details>
        {% endfor %}
      </div>
      {% else %}
      <p class="text-muted">No extracted text available yet.</p>
      {% endif %}
    </div>
  </div>

  <!-- Right Panel: AI Analysis -->
  <div class="panel">
    <div class="panel-header">AI Analysis</div>
    <div class="panel-body">
      <!-- Highlight Legend (only shows types present in this document) -->
      <div class="mb-2" style="display:flex;gap:8px;flex-wrap:wrap;font-size:.78rem">
        {% if entity_type_counts.get('person') %}<span class="hl-person">Person ({{ entity_type_counts.person }})</span>{% endif %}
        {% if entity_type_counts.get('organization') %}<span class="hl-org">Organization ({{ entity_type_counts.organization }})</span>{% endif %}
        {% if entity_type_counts.get('location') %}<span class="hl-location">Location ({{ entity_type_counts.location }})</span>{% endif %}
        {% if entity_type_counts.get('financial') %}<span class="hl-financial">Financial ({{ entity_type_counts.financial }})</span>{% endif %}
        {% if entity_type_counts.get('legal_case') %}<span class="hl-legal">Legal Case ({{ entity_type_counts.legal_case }})</span>{% endif %}
        {% if redactions %}<span class="hl-redaction">Redaction ({{ redactions|length }})</span>{% endif %}
        {% if flag_count %}<span class="hl-flagged">AI Flagged ({{ flag_count }})</span>{% endif %}
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

      {% if career_roles %}
      <h3 class="mb-2 mt-3">Association Role Classification</h3>
      <table>
        <thead><tr><th>Name</th><th>Role</th><th>Organization</th><th>Employment Link</th><th>Crime Link</th></tr></thead>
        <tbody>
        {% for cr in career_roles %}
        <tr>
          <td>{{ cr.name or 'Unknown' }}</td>
          <td>{{ cr.role or 'Unknown' }}</td>
          <td>{{ cr.organization or 'Unknown' }}</td>
          <td>{{ cr.employment_link or 'unknown' }}</td>
          <td>{{ cr.crime_link or 'unknown' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
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
          <tr><td class="text-muted">Hash</td><td class="mono" style="font-size:.75rem">{{ (doc.file_hash or 'N/A')[:24] }}{% if doc.file_hash %}...{% endif %}</td></tr>
          <tr><td class="text-muted">Source</td><td>{{ doc.source }}</td></tr>
          <tr><td class="text-muted">Type</td><td>{{ doc.doc_type or 'Unknown' }}</td></tr>
          <tr><td class="text-muted">Pages</td><td>{{ doc.page_count }}</td></tr>
          <tr><td class="text-muted">Size</td><td>{{ ((doc.size_bytes or 0) / 1024)|round(1) }} KB</td></tr>
          {% if doc.is_removed_from_source %}<tr><td class="text-red">REMOVED</td><td class="text-red">This file has been removed from its original source!</td></tr>{% endif %}
        </table>
      </div>
    </div>
  </div>
</div>
<script>
(function(){
  const input = document.getElementById('docTextFilter');
  if (!input) return;
  input.addEventListener('input', function(){
    const q = (input.value || '').toLowerCase().trim();
    document.querySelectorAll('.doc-text-page').forEach(function(el){
      const hay = el.getAttribute('data-page-text') || '';
      el.style.display = (!q || hay.includes(q)) ? '' : 'none';
    });
  });
})();
</script>
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
    latest_analysis = analyses[0] if analyses else {}
    career_roles = safe_json(latest_analysis.get("career_roles"), []) if latest_analysis else []
    full_text_chars = sum(len((p.get("text_content") or "")) for p in pages)
    annotation_per_page_limit = 12
    annotation_total_cap = 220

    # Count entity types present in this document for the legend badges
    entity_type_counts: dict[str, int] = {}
    for el in entity_links:
        etype = el.get("entity_type", "")
        if etype:
            entity_type_counts[etype] = entity_type_counts.get(etype, 0) + 1

    # Count flags from consensus
    flag_count = 0
    if consensus:
        try:
            # Also check AI flags from raw analyses
            for a in analyses:
                raw_flags = safe_json(a.get("flags"), [])
                flag_count += len(raw_flags) if isinstance(raw_flags, list) else 0
        except Exception:
            pass

    # Pre-build entity lookup for paragraph highlighting
    css_map = {
        "person": "hl-person",
        "organization": "hl-org",
        "location": "hl-location",
        "financial": "hl-financial",
        "legal_case": "hl-legal",
    }
    # Build entity name -> (entity_id, entity_type, css_class) mapping
    entity_info_map: dict[str, tuple] = {}
    for el in entity_links:
        name = el.get("entity_name", "")
        if not name:
            continue
        safe_name = html.escape(name)
        if safe_name not in entity_info_map:
            etype = el.get("entity_type", "person")
            css = css_map.get(etype, "hl-person")
            entity_info_map[safe_name] = (int(el["entity_id"]), etype, css)

    # Sort longest-first once for all paragraphs
    sorted_entity_names = sorted(entity_info_map.keys(), key=len, reverse=True)
    entity_pattern = "|".join(re.escape(n) for n in sorted_entity_names) if sorted_entity_names else None

    for i, page in enumerate(pages):
        text = page.get("text_content", "") or ""
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        for j, para in enumerate(paragraphs[:annotation_per_page_limit]):
            highlighted = html.escape(para)

            # Track which entity types appear in THIS paragraph
            para_types: set[str] = set()
            has_redaction = "[REDACTED]" in para.upper() or "[REDACTION]" in para.upper() or "\u2588" in para

            def _replace_entity(m):
                info = entity_info_map.get(m.group(0))
                if info:
                    eid, etype, css = info
                    para_types.add(etype)
                    return f'<a href="/entity/{eid}" class="{css}">{m.group(0)}</a>'
                return m.group(0)

            if entity_pattern:
                highlighted = re.sub(entity_pattern, _replace_entity, highlighted)

            if has_redaction:
                para_types.add("redaction")

            # Build per-paragraph badge HTML
            badge_map = {
                "person": ("hl-person", "Person"),
                "organization": ("hl-org", "Org"),
                "location": ("hl-location", "Location"),
                "financial": ("hl-financial", "Financial"),
                "legal_case": ("hl-legal", "Legal"),
                "redaction": ("hl-redaction", "Redaction"),
            }
            badges_html = ""
            if para_types:
                badge_parts = []
                for pt in ["person", "organization", "location", "financial", "legal_case", "redaction"]:
                    if pt in para_types:
                        css_cls, label = badge_map[pt]
                        badge_parts.append(f'<span class="{css_cls}" style="font-size:.68rem;padding:1px 5px">{label}</span>')
                badges_html = '<div style="display:flex;gap:4px;margin-bottom:4px;flex-wrap:wrap">' + "".join(badge_parts) + '</div>'

            annotations.append({
                "page": page["page_number"],
                "para": j + 1,
                "html": badges_html + highlighted,
            })

    # Query actual prev/next document IDs (handles non-contiguous IDs)
    prev_row = query_one("SELECT id FROM documents WHERE id < ? ORDER BY id DESC LIMIT 1", (doc_id,))
    next_row = query_one("SELECT id FROM documents WHERE id > ? ORDER BY id ASC LIMIT 1", (doc_id,))

    return render_template_string(
        DOCUMENT_VIEWER_HTML,
        active="document",
        doc=doc,
        pages=pages,
        full_text_chars=full_text_chars,
        consensus=consensus,
        entity_links=entity_links,
        redactions=redactions,
        annotations=annotations[:annotation_total_cap],
        career_roles=career_roles,
        entity_type_counts=entity_type_counts,
        flag_count=flag_count,
        prev_doc_id=prev_row["id"] if prev_row else None,
        next_doc_id=next_row["id"] if next_row else None,
    )


@app.route("/serve_file/<int:doc_id>")
def serve_file(doc_id):
    doc = query_one("SELECT file_path FROM documents WHERE id = ?", (doc_id,))
    if not doc or not doc.get("file_path"):
        abort(404)

    # Try vault decryption first
    if _vault_file_mgr:
        vault_uuid = _vault_file_mgr.get_vault_uuid_for_path(doc["file_path"])
        if vault_uuid:
            try:
                buf = _vault_file_mgr.decrypt_to_memory(vault_uuid)
                # Determine mimetype from original filename
                ext = Path(doc["file_path"]).suffix.lower()
                mimetypes = {
                    ".pdf": "application/pdf", ".png": "image/png",
                    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                    ".txt": "text/plain", ".csv": "text/csv",
                }
                mimetype = mimetypes.get(ext, "application/octet-stream")
                return send_file(
                    buf, mimetype=mimetype,
                    download_name=Path(doc["file_path"]).name,
                )
            except Exception as e:
                logger.warning("Vault decrypt failed for doc %d: %s", doc_id, e)

    # Fallback: serve from disk
    fp = Path(doc["file_path"]).resolve()
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


# ============================================================================
#  ALL DOCUMENTS  (/documents)
# ============================================================================

ALL_DOCUMENTS_HTML = r"""{% extends "base.html" %}
{% block title %}All Documents - EpsteinAnalyzer{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <h1>All Documents</h1>
  <div class="btn-group" style="display:flex;gap:8px;align-items:center">
    <form method="get" style="display:flex;gap:8px;align-items:center">
      <input type="text" name="q" placeholder="Search filename..." value="{{ q }}"
             style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--fg);font-size:.85rem;width:200px">
      <select name="sort" onchange="this.form.submit()"
              style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--fg);font-size:.85rem">
        <option value="priority" {% if sort == 'priority' %}selected{% endif %}>Sort: Priority</option>
        <option value="name" {% if sort == 'name' %}selected{% endif %}>Sort: Name</option>
        <option value="newest" {% if sort == 'newest' %}selected{% endif %}>Sort: Newest</option>
        <option value="oldest" {% if sort == 'oldest' %}selected{% endif %}>Sort: Oldest</option>
        <option value="size" {% if sort == 'size' %}selected{% endif %}>Sort: Size</option>
      </select>
      <select name="status" onchange="this.form.submit()"
              style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--fg);font-size:.85rem">
        <option value="" {% if not status_filter %}selected{% endif %}>All Status</option>
        <option value="analyzed" {% if status_filter == 'analyzed' %}selected{% endif %}>Analyzed</option>
        <option value="downloaded" {% if status_filter == 'downloaded' %}selected{% endif %}>Downloaded</option>
        <option value="pending" {% if status_filter == 'pending' %}selected{% endif %}>Pending</option>
        <option value="flagged" {% if status_filter == 'flagged' %}selected{% endif %}>Flagged</option>
      </select>
      <button type="submit" class="btn btn-sm">Filter</button>
    </form>
  </div>
</div>

<p class="text-muted mb-2"><span id="all-docs-total">{{ total_docs }}</span> documents total &middot; Page {{ page }} of {{ total_pages }}</p>

<table>
  <thead>
    <tr>
      <th style="width:40px">#</th>
      <th>Filename</th>
      <th>Dataset</th>
      <th>Type</th>
      <th>Pages</th>
      <th>Size</th>
      <th>Priority</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody id="all-docs-tbody">
  {% for doc in docs %}
  <tr id="doc-row-{{ doc.id }}" data-doc-id="{{ doc.id }}" style="cursor:pointer" onclick="location.href='/document/{{ doc.id }}'">
    <td class="mono text-muted">{{ doc.id }}</td>
    <td><a href="/document/{{ doc.id }}">{{ (doc.original_filename or 'Untitled')|truncate(50) }}</a></td>
    <td class="mono">{{ doc.dataset_id or '-' }}</td>
    <td id="doc-type-{{ doc.id }}"><span class="tag tag-blue">{{ doc.doc_type or '?' }}</span></td>
    <td class="mono">{{ doc.page_count or 0 }}</td>
    <td class="mono">{{ '%.1f'|format((doc.size_bytes or 0) / 1024) }} KB</td>
    <td id="doc-priority-{{ doc.id }}" class="mono text-orange">{{ doc.priority_score or 0 }}</td>
    <td id="doc-status-{{ doc.id }}">
      {% if doc.user_flagged %}<span class="tag tag-red">Flagged</span>
      {% elif doc.analysis_completed %}<span class="tag tag-green">Analyzed</span>
      {% elif doc.ocr_completed %}<span class="tag tag-yellow">OCR Done</span>
      {% else %}<span class="tag tag-blue">{{ doc.status or 'downloaded' }}</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>

{% if total_pages > 1 %}
<div class="flex flex-between items-center mt-2">
  <div class="btn-group">
    {% if page > 1 %}
    <a href="/documents?page={{ page - 1 }}&sort={{ sort }}&q={{ q }}&status={{ status_filter }}" class="btn btn-sm">&larr; Prev</a>
    {% endif %}
    {% for p in range(1, total_pages + 1) %}
      {% if p == page %}
      <span class="btn btn-sm btn-primary">{{ p }}</span>
      {% elif p <= 3 or p >= total_pages - 2 or (p >= page - 2 and p <= page + 2) %}
      <a href="/documents?page={{ p }}&sort={{ sort }}&q={{ q }}&status={{ status_filter }}" class="btn btn-sm">{{ p }}</a>
      {% elif p == 4 or p == total_pages - 3 %}
      <span class="btn btn-sm" style="opacity:.4">...</span>
      {% endif %}
    {% endfor %}
    {% if page < total_pages %}
    <a href="/documents?page={{ page + 1 }}&sort={{ sort }}&q={{ q }}&status={{ status_filter }}" class="btn btn-sm">Next &rarr;</a>
    {% endif %}
  </div>
</div>
{% endif %}
{% endblock %}
{% block scripts %}
<script>
(function(){
  function escHtml(s){
    return String(s ?? '').replace(/[&<>\"']/g, function(ch){
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[ch]);
    });
  }
  function statusTag(doc){
    if(doc.user_flagged){ return '<span class="tag tag-red">Flagged</span>'; }
    if(doc.analysis_completed){ return '<span class="tag tag-green">Analyzed</span>'; }
    if(doc.ocr_completed){ return '<span class="tag tag-yellow">OCR Done</span>'; }
    return '<span class="tag tag-blue">' + escHtml(doc.status || 'downloaded') + '</span>';
  }
  function pollDocumentRowUpdates(){
    const rows = Array.from(document.querySelectorAll('tr[data-doc-id]'));
    if(!rows.length) return;
    const ids = rows
      .map(r => Number.parseInt(r.getAttribute('data-doc-id') || '0', 10))
      .filter(n => Number.isFinite(n) && n > 0);
    if(!ids.length) return;
    apiGet('/api/documents/status?ids=' + ids.join(',')).then(function(payload){
      const docs = (payload && Array.isArray(payload.documents)) ? payload.documents : [];
      docs.forEach(function(doc){
        const id = Number.parseInt(doc.id || 0, 10);
        if(!id) return;
        const p = document.getElementById('doc-priority-' + id);
        if(p){ p.textContent = String(doc.priority_score || 0); }
        const s = document.getElementById('doc-status-' + id);
        if(s){ s.innerHTML = statusTag(doc); }
        const t = document.getElementById('doc-type-' + id);
        if(t){
          const typeName = escHtml(doc.doc_type || '?');
          t.innerHTML = '<span class=\"tag tag-blue\">' + typeName + '</span>';
        }
      });
    }).catch(function(){});
  }
  window.addEventListener('ea:stats', function(evt){
    const stats = evt.detail || {};
    const total = document.getElementById('all-docs-total');
    if(total && typeof stats.total_documents !== 'undefined'){
      total.textContent = String(stats.total_documents);
    }
  });
  window.addEventListener('ea:documents-hint', function(){
    pollDocumentRowUpdates();
  });
  pollDocumentRowUpdates();
  setInterval(pollDocumentRowUpdates, 5000);
})();
</script>
{% endblock %}
"""


@app.route("/documents")
def all_documents():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    sort = request.args.get("sort", "priority")
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    where_clauses = []
    params = []

    if q:
        where_clauses.append(r"original_filename LIKE ? ESCAPE '\'")
        params.append(f"%{escape_like(q)}%")

    if status_filter == "analyzed":
        where_clauses.append("analysis_completed = 1")
    elif status_filter == "downloaded":
        where_clauses.append("analysis_completed = 0 AND status != 'pending'")
    elif status_filter == "pending":
        where_clauses.append("status = 'pending'")
    elif status_filter == "flagged":
        where_clauses.append("user_flagged = 1")

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

    sort_map = {
        "priority": "priority_score DESC",
        "name": "original_filename ASC",
        "newest": "created_at DESC",
        "oldest": "created_at ASC",
        "size": "size_bytes DESC",
    }
    order_sql = sort_map.get(sort, "priority_score DESC")

    total_docs = query_scalar(f"SELECT COUNT(*) FROM documents WHERE {where_sql}", params)
    total_pages = max(1, (total_docs + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    docs = query_all(
        f"SELECT id, original_filename, dataset_id, doc_type, page_count, size_bytes, "
        f"priority_score, status, analysis_completed, ocr_completed, user_flagged, created_at "
        f"FROM documents WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )

    return render_template_string(
        ALL_DOCUMENTS_HTML,
        active="documents",
        docs=docs,
        page=page,
        total_pages=total_pages,
        total_docs=total_docs,
        sort=sort,
        q=q,
        status_filter=status_filter,
    )


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


def _dedupe_ints(values, *, max_items: int = 40) -> list[int]:
    seen = set()
    out: list[int] = []
    for raw in values:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            continue
        if val <= 0 or val in seen:
            continue
        seen.add(val)
        out.append(val)
        if len(out) >= max_items:
            break
    return out


def _parse_csv_ints(raw: str, *, max_items: int = 40) -> list[int]:
    if not raw:
        return []
    return _dedupe_ints((token.strip() for token in str(raw).split(",")), max_items=max_items)


def _extract_tail_numbers(*texts: str) -> list[str]:
    tails = set()
    for text in texts:
        if not text:
            continue
        for match in re.findall(r"\bN\d{1,5}[A-Z]{0,2}\b", str(text).upper()):
            tails.add(match)
    return sorted(tails)


def _find_epstein_entity_ids(conn: sqlite3.Connection, *, limit: int = 25) -> list[int]:
    rows = conn.execute(
        """
        SELECT id
        FROM entities
        WHERE LOWER(COALESCE(entity_type, '')) = 'person'
          AND (
                LOWER(COALESCE(canonical_name, '')) LIKE '%epstein%'
             OR LOWER(COALESCE(name, '')) LIKE '%jeffrey epstein%'
             OR LOWER(COALESCE(name, '')) LIKE '%jeff epstein%'
          )
        ORDER BY COALESCE(user_score, implication_score) DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return _dedupe_ints((r["id"] for r in rows), max_items=limit)


def _graph_entity_card_payload(entity_ids: list[int], *, name_hint: str = "", type_hint: str = "") -> Optional[dict]:
    entity_ids = _dedupe_ints(entity_ids, max_items=40)
    if not entity_ids:
        return None

    conn = get_conn()
    try:
        id_ph = ",".join("?" for _ in entity_ids)
        entity_rows = conn.execute(
            f"""
            SELECT
                id,
                name,
                canonical_name,
                aliases,
                entity_type,
                role,
                COALESCE(user_score, implication_score, 0) AS score,
                COALESCE(document_count, 0) AS document_count,
                COALESCE(evidence_count, 0) AS evidence_count
            FROM entities
            WHERE id IN ({id_ph})
            """,
            tuple(entity_ids),
        ).fetchall()
        if not entity_rows:
            return None

        display_name = (name_hint or "").strip()
        if not display_name:
            display_name = max(
                (
                    (r["canonical_name"] or r["name"] or "").strip()
                    for r in entity_rows
                ),
                key=len,
                default=f"Entity {entity_ids[0]}",
            )
        display_type = (type_hint or "").strip().lower()
        if not display_type:
            display_type = str(entity_rows[0]["entity_type"] or "entity").lower()

        score_max = max(float(r["score"] or 0.0) for r in entity_rows)
        doc_count_sum = sum(int(r["document_count"] or 0) for r in entity_rows)
        evidence_count_sum = sum(int(r["evidence_count"] or 0) for r in entity_rows)
        role_values = []
        for r in entity_rows:
            role = str(r["role"] or "").strip()
            if role and role not in role_values:
                role_values.append(role)

        conn_rows = conn.execute(
            f"""
            SELECT
                other.id,
                COALESCE(NULLIF(other.canonical_name, ''), other.name) AS name,
                LOWER(COALESCE(other.entity_type, 'person')) AS entity_type,
                SUM(COALESCE(r.weight, 1.0)) AS weight_total,
                SUM(COALESCE(r.evidence_count, 1)) AS evidence_total,
                COUNT(*) AS edge_count,
                GROUP_CONCAT(DISTINCT r.relationship_type) AS relationship_types
            FROM relationships r
            JOIN entities other
              ON other.id = CASE
                    WHEN r.source_entity_id IN ({id_ph}) THEN r.target_entity_id
                    ELSE r.source_entity_id
                 END
            WHERE (r.source_entity_id IN ({id_ph}) OR r.target_entity_id IN ({id_ph}))
              AND other.id NOT IN ({id_ph})
            GROUP BY other.id, other.name, other.canonical_name, other.entity_type
            ORDER BY weight_total DESC, evidence_total DESC, edge_count DESC
            LIMIT 14
            """,
            tuple(entity_ids) * 4,
        ).fetchall()

        evidence_rows = conn.execute(
            f"""
            SELECT
                d.id AS document_id,
                d.original_filename,
                d.doc_type,
                MAX(COALESCE(d.priority_score, 0)) AS priority_score,
                MAX(COALESCE(edl.damning_score, 0)) AS damning_score,
                COUNT(*) AS mention_count,
                SUM(CASE WHEN edl.evidence_type = 'flight_log' THEN 1 ELSE 0 END) AS flight_hits
            FROM entity_document_links edl
            JOIN documents d ON d.id = edl.document_id
            WHERE edl.entity_id IN ({id_ph})
            GROUP BY d.id, d.original_filename, d.doc_type
            ORDER BY damning_score DESC, mention_count DESC, priority_score DESC, d.id DESC
            LIMIT 8
            """,
            tuple(entity_ids),
        ).fetchall()

        recent_analyses = conn.execute(
            f"""
            SELECT DISTINCT
                aa.document_id,
                aa.model_name,
                aa.summary,
                aa.created_at
            FROM ai_analyses aa
            JOIN entity_document_links edl ON edl.document_id = aa.document_id
            WHERE edl.entity_id IN ({id_ph})
            ORDER BY aa.created_at DESC
            LIMIT 5
            """,
            tuple(entity_ids),
        ).fetchall()

        epstein_ids = _find_epstein_entity_ids(conn)
        ep_corr = {
            "direct_edge_count": 0,
            "direct_weight": 0.0,
            "direct_evidence": 0,
            "shared_flight_docs": [],
            "correlated_aircraft": [],
            "tail_numbers": [],
        }
        if epstein_ids:
            ep_ph = ",".join("?" for _ in epstein_ids)
            direct_row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS direct_edge_count,
                    SUM(COALESCE(weight, 1.0)) AS direct_weight,
                    SUM(COALESCE(evidence_count, 1)) AS direct_evidence
                FROM relationships
                WHERE (source_entity_id IN ({id_ph}) AND target_entity_id IN ({ep_ph}))
                   OR (target_entity_id IN ({id_ph}) AND source_entity_id IN ({ep_ph}))
                """,
                tuple(entity_ids) + tuple(epstein_ids) + tuple(entity_ids) + tuple(epstein_ids),
            ).fetchone()
            if direct_row:
                ep_corr["direct_edge_count"] = int(direct_row["direct_edge_count"] or 0)
                ep_corr["direct_weight"] = float(direct_row["direct_weight"] or 0.0)
                ep_corr["direct_evidence"] = int(direct_row["direct_evidence"] or 0)

            shared_flights = conn.execute(
                f"""
                SELECT
                    d.id AS document_id,
                    d.original_filename,
                    d.doc_type,
                    MAX(COALESCE(self_link.context_snippet, '')) AS entity_context,
                    MAX(COALESCE(ep_link.context_snippet, '')) AS epstein_context,
                    MAX(COALESCE(self_link.damning_score, 0)) AS entity_score,
                    MAX(COALESCE(ep_link.damning_score, 0)) AS epstein_score
                FROM entity_document_links self_link
                JOIN entity_document_links ep_link ON ep_link.document_id = self_link.document_id
                JOIN documents d ON d.id = self_link.document_id
                WHERE self_link.entity_id IN ({id_ph})
                  AND ep_link.entity_id IN ({ep_ph})
                  AND (
                        d.doc_type = 'flight_log'
                     OR self_link.evidence_type = 'flight_log'
                     OR ep_link.evidence_type = 'flight_log'
                  )
                GROUP BY d.id, d.original_filename, d.doc_type
                ORDER BY COALESCE(d.priority_score, 0) DESC, entity_score DESC, d.id DESC
                LIMIT 10
                """,
                tuple(entity_ids) + tuple(epstein_ids),
            ).fetchall()

            correlated_aircraft = conn.execute(
                f"""
                SELECT
                    a.id,
                    COALESCE(NULLIF(a.canonical_name, ''), a.name) AS name,
                    COUNT(DISTINCT d.id) AS shared_flights
                FROM entity_document_links self_link
                JOIN entity_document_links ep_link
                  ON ep_link.document_id = self_link.document_id
                 AND ep_link.entity_id IN ({ep_ph})
                JOIN entity_document_links air_link ON air_link.document_id = self_link.document_id
                JOIN entities a
                  ON a.id = air_link.entity_id
                 AND LOWER(COALESCE(a.entity_type, '')) = 'aircraft'
                JOIN documents d ON d.id = self_link.document_id
                WHERE self_link.entity_id IN ({id_ph})
                  AND d.doc_type = 'flight_log'
                GROUP BY a.id, a.name, a.canonical_name
                ORDER BY shared_flights DESC, a.id ASC
                LIMIT 8
                """,
                tuple(epstein_ids) + tuple(entity_ids),
            ).fetchall()

            tail_numbers = _extract_tail_numbers(
                display_name,
                *(r["name"] for r in correlated_aircraft),
                *(r["original_filename"] for r in shared_flights),
            )
            ep_corr["shared_flight_docs"] = [dict(r) for r in shared_flights]
            ep_corr["correlated_aircraft"] = [dict(r) for r in correlated_aircraft]
            ep_corr["tail_numbers"] = tail_numbers

        known_tails = _extract_tail_numbers(
            display_name,
            *(str(r["aliases"] or "") for r in entity_rows),
            *(str(r["name"] or "") for r in entity_rows),
        )
        if known_tails:
            merged = sorted(set(ep_corr["tail_numbers"]) | set(known_tails))
            ep_corr["tail_numbers"] = merged

        connections = []
        for r in conn_rows:
            rel_types = [t for t in str(r["relationship_types"] or "").split(",") if t]
            connections.append(
                {
                    "id": int(r["id"]),
                    "name": r["name"] or f"Entity {r['id']}",
                    "entity_type": r["entity_type"] or "entity",
                    "weight_total": float(r["weight_total"] or 0.0),
                    "evidence_total": int(r["evidence_total"] or 0),
                    "edge_count": int(r["edge_count"] or 0),
                    "relationship_types": sorted(set(rel_types)),
                }
            )

        return {
            "entity": {
                "id": int(entity_ids[0]),
                "entity_ids": entity_ids,
                "name": display_name,
                "type": display_type,
                "score": score_max,
                "role": ", ".join(role_values[:3]),
                "doc_count": doc_count_sum,
                "evidence_count": evidence_count_sum,
            },
            "connections": connections,
            "evidence_docs": [dict(r) for r in evidence_rows],
            "recent_analyses": [dict(r) for r in recent_analyses],
            "epstein_correlation": ep_corr,
        }
    finally:
        conn.close()


@app.route("/api/graph/entity-card")
def api_graph_entity_card():
    primary_id = request.args.get("id", type=int)
    merged_ids = _parse_csv_ints(request.args.get("ids", ""), max_items=40)
    entity_ids = _dedupe_ints(([primary_id] if primary_id else []) + merged_ids, max_items=40)
    if not entity_ids:
        return jsonify({"error": "Missing entity id"}), 400

    payload = _graph_entity_card_payload(
        entity_ids,
        name_hint=(request.args.get("name") or "").strip(),
        type_hint=(request.args.get("type") or "").strip(),
    )
    if not payload:
        return jsonify({"error": "Entity not found"}), 404
    return jsonify(payload)


# ============================================================================
#  5.  SPIDERWEB GRAPH  (/graph)
# ============================================================================

GRAPH_HTML = r"""{% extends "base.html" %}
{% block title %}Spiderweb - EpsteinAnalyzer{% endblock %}
{% block head %}
<script src="/static/d3.v7.min.js"></script>
<style>
.graph-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.graph-controls select,.graph-controls input{background:var(--bg2);color:var(--fg);border:1px solid var(--border);
  padding:4px 8px;border-radius:4px;font-size:.82rem}
.graph-controls input::placeholder{color:var(--fg2)}
.graph-legend{display:flex;gap:6px;flex-wrap:wrap;padding:8px 12px;background:var(--bg2);
  border-radius:6px;font-size:.75rem;align-items:center}
.graph-legend .swatch{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:3px}
.graph-legend .item{display:flex;align-items:center;gap:2px;color:var(--fg2)}
.edge-legend{display:flex;gap:8px;flex-wrap:wrap;padding:6px 12px;font-size:.72rem;color:var(--fg2)}
.edge-legend .etype{display:flex;align-items:center;gap:3px;cursor:pointer;padding:2px 6px;
  border-radius:3px;border:1px solid transparent;transition:.15s}
.edge-legend .etype:hover,.edge-legend .etype.active{border-color:var(--accent);color:var(--fg)}
.edge-legend .eline{width:16px;height:2px;display:inline-block}
.graph-tooltip{position:absolute;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);
  border-radius:6px;font-size:.8rem;pointer-events:none;opacity:0;transition:opacity .15s;
  max-width:300px;z-index:100;box-shadow:0 4px 12px rgba(0,0,0,.4)}
.graph-tooltip .tt-name{font-weight:600;color:var(--fg);margin-bottom:2px}
.graph-tooltip .tt-type{font-size:.72rem;color:var(--fg2)}
.graph-tooltip .tt-score{color:var(--orange);font-weight:600}
.graph-tooltip .tt-edge{font-size:.72rem;color:var(--accent)}
#graph-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;color:var(--fg2);gap:12px}
#graph-empty .big{font-size:3rem}
.graph-panel{position:absolute;right:10px;top:10px;width:360px;max-height:78%;overflow:auto;
  background:rgba(13,17,23,.94);backdrop-filter:blur(4px);border:1px solid var(--border);
  border-radius:10px;padding:10px 12px;z-index:20;box-shadow:0 8px 20px rgba(0,0,0,.4)}
.graph-panel h3{font-size:.95rem;margin:0 0 6px}
.graph-panel .meta{font-size:.76rem;color:var(--fg2);margin-bottom:8px}
.graph-panel .rel{font-size:.78rem;padding:6px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;background:var(--bg3)}
.graph-panel .section{margin-top:10px}
.graph-panel .section-title{font-size:.72rem;color:var(--fg2);margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
.graph-panel .chip{display:inline-block;font-size:.68rem;padding:2px 6px;border-radius:10px;border:1px solid var(--border);margin:0 4px 4px 0}
.graph-panel .alert{font-size:.73rem;padding:8px;border:1px solid rgba(240,136,62,.45);border-radius:6px;background:rgba(240,136,62,.08);margin-bottom:8px}
.edge-flow{stroke-dasharray:8 10;animation:edgeFlow 7s linear infinite}
@keyframes edgeFlow{to{stroke-dashoffset:-240}}
.node-selected{stroke:#f0883e !important;stroke-width:3 !important;filter:drop-shadow(0 0 7px rgba(240,136,62,.65))}
</style>
{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>Spiderweb View</h1>
    <p class="subtitle">
      Interactive knowledge graph &middot; {{ node_count }} entities &middot; {{ edge_count }} connections
      {% if center_name %}&middot; Center: <span class="text-orange">{{ center_name }}</span>{% endif %}
    </p>
  </div>
  <div class="graph-controls">
    <input id="nodeSearch" type="search" placeholder="Find entity..." onkeydown="if(event.key==='Enter') focusSearch()">
    <select id="nodeFilter" onchange="applyFilters()" title="Filter by entity type">
      <option value="all">All Entity Types</option>
      <option value="person">People</option>
      <option value="organization">Organizations</option>
      <option value="location">Locations</option>
      <option value="aircraft">Aircraft</option>
      <option value="financial">Financial</option>
      <option value="legal_case">Legal Cases</option>
      <option value="event">Events</option>
      <option value="redacted_entity">Redacted</option>
    </select>
    <select id="edgeFilter" onchange="applyFilters()" title="Filter by relationship type">
      <option value="all">All Relationships</option>
      {% for rt in relationship_types %}
      <option value="{{ rt }}">{{ rt|replace('_',' ')|title }}</option>
      {% endfor %}
    </select>
    <input type="range" id="scoreSlider" min="0" max="100" value="0"
           oninput="document.getElementById('scoreVal').textContent=this.value;applyFilters()"
           title="Minimum entity score">
    <span id="scoreVal" style="font-size:.78rem;color:var(--orange);min-width:20px">0</span>
    <button class="btn btn-sm" onclick="resetZoom()">Reset</button>
    <button class="btn btn-sm" id="pauseBtn" onclick="toggleSimulation()">Pause</button>
    <button class="btn btn-sm" id="clusterBtn" onclick="toggleCluster()">Cluster</button>
    <button class="btn btn-sm" id="isolateBtn" onclick="toggleIsolate()">Isolate</button>
    <button class="btn btn-sm" onclick="toggleLabels()">Labels</button>
  </div>
</div>

<!-- Legend -->
<div class="graph-legend mb-1">
  <span style="font-weight:600;margin-right:4px">Nodes:</span>
  <span class="item"><span class="swatch" style="background:#58a6ff"></span>Person</span>
  <span class="item"><span class="swatch" style="background:#3fb950"></span>Org</span>
  <span class="item"><span class="swatch" style="background:#e3b341"></span>Location</span>
  <span class="item"><span class="swatch" style="background:#d29922"></span>Aircraft</span>
  <span class="item"><span class="swatch" style="background:#f85149"></span>Financial</span>
  <span class="item"><span class="swatch" style="background:#bc8cff"></span>Legal</span>
  <span class="item"><span class="swatch" style="background:#f778ba"></span>Event</span>
  <span class="item"><span class="swatch" style="background:#ff7b72"></span>Redacted</span>
  <span style="margin-left:12px;font-weight:600;margin-right:4px">Size = score</span>
</div>
<div class="edge-legend mb-1" id="edgeLegend">
  <span style="font-weight:600;margin-right:4px">Edges:</span>
</div>

<div class="card" style="padding:0;overflow:hidden;height:calc(100vh - 220px);position:relative;background:
  radial-gradient(1200px 700px at 70% -15%, rgba(88,166,255,.08), transparent 60%),
  radial-gradient(900px 600px at -10% 90%, rgba(188,140,255,.07), transparent 58%),
  var(--bg);">
  {% if node_count == 0 %}
  <div id="graph-empty">
    <div class="big">&#9784;</div>
    <div>No entities or connections yet.</div>
    <div>Process and analyze documents to build the knowledge graph.</div>
  </div>
  {% else %}
  <svg id="graph" style="width:100%;height:100%"></svg>
  <div class="graph-tooltip" id="tooltip"></div>
  <div class="graph-panel hidden" id="graphPanel"></div>
  {% endif %}
</div>
{% endblock %}

{% block scripts %}
{% if node_count > 0 %}
<script>
const graphData = {{ graph_data|tojson }};
const width = document.getElementById('graph').clientWidth || 1200;
const height = document.getElementById('graph').clientHeight || 700;
const svg = d3.select('#graph').attr('viewBox', [0, 0, width, height]);
const tooltip = document.getElementById('tooltip');
const panel = document.getElementById('graphPanel');
const centerNodeId = graphData.center_id || null;
let showLabels = true;
let simulationPaused = false;
let clustered = false;
let isolateMode = false;
let selectedNodeId = null;
let panelRequestToken = 0;

const colorMap = {
  person: '#58a6ff', organization: '#3fb950', location: '#e3b341',
  aircraft: '#d29922', financial: '#f85149', legal_case: '#bc8cff',
  contact_info: '#8b949e', event: '#f778ba', redacted_entity: '#ff7b72'
};

const edgeColorMap = {
  flew_with: '#d29922', emailed: '#58a6ff', financially_linked: '#f85149',
  employed_by: '#3fb950', co_occurs_with: '#484f58', associated_with: '#8b949e',
  traveled_to: '#e3b341', witnessed: '#bc8cff', communicated_with: '#58a6ff',
  paid: '#f85149', received_payment: '#f85149'
};

// Build edge legend dynamically from actual data
const edgeTypes = [...new Set(graphData.links.map(l => l.type).filter(Boolean))];
const legendEl = document.getElementById('edgeLegend');
edgeTypes.forEach(et => {
  const c = edgeColorMap[et] || '#484f58';
  const span = document.createElement('span');
  span.className = 'etype';
  span.dataset.type = et;
  span.innerHTML = '<span class="eline" style="background:'+c+'"></span>' + et.replace(/_/g,' ');
  span.onclick = () => {
    document.getElementById('edgeFilter').value = et;
    applyFilters();
  };
  legendEl.appendChild(span);
});

// Build node lookup + adjacency for fast interaction and filtering.
const nodeById = new Map(graphData.nodes.map(n => [n.id, n]));
const neighborsById = new Map(graphData.nodes.map(n => [n.id, new Set([n.id])]));
for (const l of graphData.links) {
  const sid = typeof l.source === 'object' ? l.source.id : l.source;
  const tid = typeof l.target === 'object' ? l.target.id : l.target;
  if (neighborsById.has(sid)) neighborsById.get(sid).add(tid);
  if (neighborsById.has(tid)) neighborsById.get(tid).add(sid);
}
const centerNode = centerNodeId ? nodeById.get(centerNodeId) : null;
if (centerNode) {
  centerNode.fx = width / 2;
  centerNode.fy = height / 2;
}

const simulation = d3.forceSimulation(graphData.nodes)
  .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(d => {
    return 60 + 80 / Math.max(d.weight || 1, 1);
  }))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide().radius(d => 8 + Math.min(d.score || 0, 80) / 6))
  .force('x', d3.forceX(width / 2).strength(0.03))
  .force('y', d3.forceY(height / 2).strength(0.03));

const g = svg.append('g');
const zoom = d3.zoom().scaleExtent([0.1, 8]).on('zoom', e => g.attr('transform', e.transform));
svg.call(zoom);

const link = g.append('g')
  .selectAll('line')
  .data(graphData.links)
  .join('line')
  .attr('class', d => (d.weight || 1) >= 3 ? 'edge-flow' : '')
  .attr('stroke', d => edgeColorMap[d.type] || '#484f58')
  .attr('stroke-width', d => 0.5 + Math.min(d.weight || 1, 5))
  .attr('stroke-opacity', 0.5)
  .on('mouseover', (e, d) => {
    const src = typeof d.source === 'object' ? d.source : nodeById.get(d.source);
    const tgt = typeof d.target === 'object' ? d.target : nodeById.get(d.target);
    showTooltip(e, '<div class="tt-name">'+(src?.name||'?')+' &harr; '+(tgt?.name||'?')+'</div>'
      +'<div class="tt-edge">'+(d.type||'connected').replace(/_/g,' ')+'</div>'
      +'<div class="tt-type">Weight: '+(d.weight||1).toFixed(1)+'</div>');
  })
  .on('mouseout', hideTooltip);

const node = g.append('g')
  .selectAll('circle')
  .data(graphData.nodes)
  .join('circle')
  .attr('r', d => d.is_center ? 17 : 5 + Math.min(d.score || 0, 80) / 6)
  .attr('fill', d => d.is_center ? '#f0883e' : (colorMap[d.type] || '#8b949e'))
  .attr('stroke', d => d.is_center ? '#ffd28f' : (d.score >= 50 ? '#f0883e' : '#21262d'))
  .attr('stroke-width', d => d.is_center ? 3.5 : (d.score >= 50 ? 2 : 1.5))
  .style('cursor', 'pointer')
  .on('click', (e, d) => { e.stopPropagation(); selectNode(d, true); })
  .on('dblclick', (e, d) => { e.stopPropagation(); window.location = '/entity/' + d.id; })
  .on('mouseover', (e, d) => {
    highlightNeighborhood(d.id);
    showTooltip(e, '<div class="tt-name">'+d.name+'</div>'
      +'<div class="tt-type">'+d.type.replace(/_/g,' ')+(d.role ? ' &middot; '+d.role : '')+'</div>'
      +'<div class="tt-score">Score: '+(d.score||0).toFixed(0)+'</div>'
      +'<div class="tt-type">'+(d.connections||0)+' connections &middot; '+(d.doc_count||0)+' docs</div>');
  })
  .on('mouseout', (e, d) => { applyFilters(); hideTooltip(); })
  .call(d3.drag()
    .on('start', (e, d) => { if(!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end', (e, d) => {
      if(!e.active) simulation.alphaTarget(0);
      // Keep selected node pinned for exploration, let others float again.
      if (selectedNodeId === d.id || d.is_center) return;
      d.fx = null; d.fy = null;
    })
  );

const label = g.append('g')
  .selectAll('text')
  .data(graphData.nodes)
  .join('text')
  .text(d => d.is_center ? (d.name + ' [CENTER]') : (d.name.length > 20 ? d.name.slice(0,18)+'...' : d.name))
  .attr('font-size', d => d.is_center ? 13 : (d.score >= 30 ? 10 : 8))
  .attr('font-weight', d => d.is_center ? 700 : (d.score >= 50 ? 600 : 400))
  .attr('fill', '#e6edf3')
  .attr('dx', d => (d.is_center ? 22 : 8) + Math.min(d.score || 0, 80) / 8)
  .attr('dy', 3)
  .style('pointer-events', 'none')
  .style('text-shadow', '0 0 4px #0d1117, 0 0 8px #0d1117');

simulation.on('tick', () => {
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('cx', d => d.x).attr('cy', d => d.y);
  label.attr('x', d => d.x).attr('y', d => d.y);
});

svg.on('click', (e) => {
  if ((e.target.tagName || '').toLowerCase() === 'svg') clearSelection();
});

function showTooltip(e, html) {
  tooltip.innerHTML = html;
  tooltip.style.opacity = 1;
  const rect = document.getElementById('graph').parentElement.getBoundingClientRect();
  tooltip.style.left = (e.clientX - rect.left + 12) + 'px';
  tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
}
function hideTooltip() { tooltip.style.opacity = 0; }
function resetZoom() { svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity); }
function toggleLabels() { showLabels = !showLabels; label.attr('opacity', showLabels ? 1 : 0); }

function getNeighborSet(nodeId) {
  return neighborsById.get(nodeId) || new Set([nodeId]);
}

function highlightNeighborhood(nodeId) {
  const neigh = getNeighborSet(nodeId);
  link.attr('stroke-opacity', l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return (sid === nodeId || tid === nodeId) ? 1 : 0.08;
  }).attr('stroke-width', l => {
    const sid = typeof l.source === 'object' ? l.source.id : l.source;
    const tid = typeof l.target === 'object' ? l.target.id : l.target;
    return (sid === nodeId || tid === nodeId) ? 2 + Math.min(l.weight || 1, 5) : 0.5;
  });
  node.attr('opacity', n => neigh.has(n.id) ? 1 : 0.12);
  label.attr('opacity', n => showLabels && neigh.has(n.id) ? 1 : 0.03);
}

function escHtml(s){
  return String(s ?? '').replace(/[&<>\"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[ch]));
}

function localConnections(d) {
  return graphData.links
    .map(l => {
      const sid = typeof l.source === 'object' ? l.source.id : l.source;
      const tid = typeof l.target === 'object' ? l.target.id : l.target;
      if (sid !== d.id && tid !== d.id) return null;
      const oid = sid === d.id ? tid : sid;
      const other = nodeById.get(oid);
      if (!other) return null;
      return { other, type: l.type || 'associated_with', weight: l.weight || 1 };
    })
    .filter(Boolean)
    .sort((a, b) => (b.weight - a.weight) || (b.other.score - a.other.score))
    .slice(0, 12);
}

function renderPanelFallback(d, connected) {
  const rows = connected.map(c =>
    '<div class="rel"><strong>'+escHtml(c.other.name)+'</strong><br><span class="text-muted">'
    +(c.type||'associated_with').replace(/_/g,' ')+' &middot; weight '+(c.weight||1).toFixed(1)
    +'</span></div>'
  ).join('');
  panel.innerHTML =
    '<h3>'+escHtml(d.name)+'</h3>'
    +'<div class="meta">'+escHtml((d.type||'entity').replace(/_/g,' '))
    +' &middot; Score '+(d.score||0).toFixed(0)
    +' &middot; '+(d.connections||0)+' links'
    +(d.doc_count ? ' &middot; '+d.doc_count+' docs' : '')
    +'</div>'
    +'<div style="display:flex;gap:6px;margin-bottom:8px">'
    +'<button class="btn btn-sm" onclick="window.location=\'/entity/'+d.id+'\'">Open Entity</button>'
    +'<button class="btn btn-sm" onclick="focusNode('+d.id+')">Center</button>'
    +'</div>'
    +'<div class="section-title">Top connections</div>'
    +(rows || '<div class="meta">No connected edges in current view.</div>');
  panel.classList.remove('hidden');
}

async function renderPanel(d) {
  const connectedFallback = localConnections(d);
  const requestToken = ++panelRequestToken;
  panel.innerHTML = '<div class="meta">Loading entity analysis card...</div>';
  panel.classList.remove('hidden');
  try {
    const mergedIds = Array.isArray(d.entity_ids) && d.entity_ids.length ? d.entity_ids : [d.id];
    const params = new URLSearchParams({
      id: String(d.id),
      ids: mergedIds.join(','),
      name: d.name || '',
      type: d.type || '',
    });
    const payload = await apiGet('/api/graph/entity-card?' + params.toString());
    if (requestToken !== panelRequestToken || selectedNodeId !== d.id) return;

    const entity = payload.entity || {};
    const conns = Array.isArray(payload.connections) ? payload.connections : [];
    const docs = Array.isArray(payload.evidence_docs) ? payload.evidence_docs : [];
    const analyses = Array.isArray(payload.recent_analyses) ? payload.recent_analyses : [];
    const ep = payload.epstein_correlation || {};
    const tails = Array.isArray(ep.tail_numbers) ? ep.tail_numbers : [];
    const sharedFlights = Array.isArray(ep.shared_flight_docs) ? ep.shared_flight_docs : [];
    const aircraft = Array.isArray(ep.correlated_aircraft) ? ep.correlated_aircraft : [];

    const connRows = (conns.length ? conns : connectedFallback.map(c => ({
      id: c.other.id,
      name: c.other.name,
      entity_type: c.other.type,
      weight_total: c.weight || 1,
      evidence_total: 1,
      relationship_types: [c.type || 'associated_with'],
    })))
      .slice(0, 10)
      .map(c => {
        const relText = Array.isArray(c.relationship_types) && c.relationship_types.length
          ? c.relationship_types.slice(0, 2).map(t => String(t).replace(/_/g, ' ')).join(', ')
          : 'associated with';
        return '<div class="rel"><strong>'+escHtml(c.name || ('Entity ' + c.id))+'</strong>'
          +'<br><span class="text-muted">'+escHtml(relText)
          +' &middot; weight '+Number(c.weight_total || 0).toFixed(1)
          +' &middot; evidence '+Number(c.evidence_total || 0)+'</span></div>';
      }).join('');

    const docRows = docs.slice(0, 6).map(doc => {
      const flightFlag = Number(doc.flight_hits || 0) > 0 ? ' &middot; flight signal' : '';
      return '<div class="rel"><strong><a href="/document/'+Number(doc.document_id || 0)+'">'
        +escHtml(doc.original_filename || ('Doc ' + doc.document_id))+'</a></strong>'
        +'<br><span class="text-muted">'+escHtml(doc.doc_type || 'unknown')
        +' &middot; score '+Number(doc.damning_score || 0).toFixed(0)
        +' &middot; mentions '+Number(doc.mention_count || 0)+flightFlag+'</span></div>';
    }).join('');

    const analysisRows = analyses.slice(0, 3).map(a => {
      const raw = String(a.summary || '').trim();
      const shortSummary = raw.length > 160 ? (raw.slice(0, 157) + '...') : raw;
      return '<div class="rel"><strong>Doc '+Number(a.document_id || 0)+'</strong>'
        +'<br><span class="text-muted">'+escHtml(a.model_name || 'model')
        +(a.created_at ? ' &middot; ' + escHtml(String(a.created_at).slice(0, 16).replace('T', ' ')) : '')
        +'</span><div style="font-size:.75rem;margin-top:4px">'+escHtml(shortSummary || 'No summary text.')+'</div></div>';
    }).join('');

    const tailChips = tails.slice(0, 8).map(t => '<span class="chip">'+escHtml(t)+'</span>').join('');
    const epAlert = (Number(ep.direct_edge_count || 0) > 0 || sharedFlights.length > 0)
      ? ('<div class="alert"><strong>Epstein Correlation:</strong> '
        +'direct edges '+Number(ep.direct_edge_count || 0)
        +' &middot; shared flight docs '+sharedFlights.length
        +' &middot; evidence '+Number(ep.direct_evidence || 0)+'</div>')
      : '<div class="meta">No direct Epstein flight correlation found yet.</div>';

    const flightRows = sharedFlights.slice(0, 4).map(f =>
      '<div class="rel"><strong><a href="/document/'+Number(f.document_id || 0)+'">'+escHtml(f.original_filename || ('Doc ' + f.document_id))+'</a></strong>'
      +'<br><span class="text-muted">'+escHtml(f.doc_type || 'flight_log')+'</span></div>'
    ).join('');

    const aircraftRows = aircraft.slice(0, 5).map(a =>
      '<div class="chip">'+escHtml(a.name || ('Aircraft ' + a.id))+' ('+Number(a.shared_flights || 0)+')</div>'
    ).join('');

    panel.innerHTML =
      '<h3>'+escHtml(entity.name || d.name || ('Entity ' + d.id))+'</h3>'
      +'<div class="meta">'+escHtml(String(entity.type || d.type || 'entity').replace(/_/g,' '))
      +' &middot; score '+Number(entity.score || d.score || 0).toFixed(0)
      +' &middot; links '+Number(d.connections || 0)
      +' &middot; docs '+Number(entity.doc_count || d.doc_count || 0)
      +(entity.role ? ' &middot; ' + escHtml(entity.role) : '')
      +'</div>'
      +'<div style="display:flex;gap:6px;margin-bottom:8px">'
      +'<button class="btn btn-sm" onclick="window.location=\'/entity/'+d.id+'\'">Open Entity</button>'
      +'<button class="btn btn-sm" onclick="focusNode('+d.id+')">Center</button>'
      +'</div>'
      +'<div class="section"><div class="section-title">Epstein Travel Correlation</div>'
      +epAlert
      +(tailChips ? ('<div style="margin-bottom:6px">'+tailChips+'</div>') : '')
      +(aircraftRows ? ('<div style="margin-bottom:6px">'+aircraftRows+'</div>') : '')
      +(flightRows || '<div class="meta">No shared flight-log docs currently linked.</div>')
      +'</div>'
      +'<div class="section"><div class="section-title">Top Connections</div>'
      +(connRows || '<div class="meta">No connected edges in current view.</div>')
      +'</div>'
      +'<div class="section"><div class="section-title">Evidence Found Under This Name</div>'
      +(docRows || '<div class="meta">No evidence docs linked yet.</div>')
      +'</div>'
      +'<div class="section"><div class="section-title">Recent Analysis</div>'
      +(analysisRows || '<div class="meta">No analysis summaries linked yet.</div>')
      +'</div>';
  } catch (err) {
    if (requestToken !== panelRequestToken || selectedNodeId !== d.id) return;
    renderPanelFallback(d, connectedFallback);
  }
}

function selectNode(d, centerView) {
  selectedNodeId = d.id;
  if (d.is_center) {
    d.fx = width / 2;
    d.fy = height / 2;
  } else {
    d.fx = d.x;
    d.fy = d.y;
  }
  node.classed('node-selected', n => n.id === d.id);
  renderPanel(d);
  if (centerView) focusNode(d.id);
  applyFilters();
}

function clearSelection() {
  selectedNodeId = null;
  panel.classList.add('hidden');
  node.classed('node-selected', false);
  graphData.nodes.forEach(n => {
    if (n.is_center) {
      n.fx = width / 2;
      n.fy = height / 2;
    } else {
      n.fx = null;
      n.fy = null;
    }
  });
  applyFilters();
}

function focusNode(nodeId) {
  const d = nodeById.get(nodeId);
  if (!d) return;
  const scale = 1.8;
  const x = d.x ?? (width / 2);
  const y = d.y ?? (height / 2);
  svg.transition().duration(650).call(
    zoom.transform,
    d3.zoomIdentity.translate(width / 2 - x * scale, height / 2 - y * scale).scale(scale),
  );
}

function focusSearch() {
  const q = (document.getElementById('nodeSearch').value || '').trim().toLowerCase();
  if (!q) return;
  const match = graphData.nodes.find(n => (n.name || '').toLowerCase().includes(q));
  if (!match) {
    showToast('No entity match for "' + q + '"', 'error');
    return;
  }
  selectNode(match, true);
}

function toggleSimulation() {
  simulationPaused = !simulationPaused;
  const btn = document.getElementById('pauseBtn');
  if (simulationPaused) {
    simulation.stop();
    btn.textContent = 'Resume';
  } else {
    if (centerNode) {
      centerNode.fx = width / 2;
      centerNode.fy = height / 2;
    }
    simulation.alpha(0.8).restart();
    btn.textContent = 'Pause';
  }
}

function _clusterTarget(type) {
  const map = {
    person: [width * 0.25, height * 0.35],
    organization: [width * 0.72, height * 0.30],
    location: [width * 0.25, height * 0.72],
    aircraft: [width * 0.50, height * 0.20],
    financial: [width * 0.74, height * 0.70],
    legal_case: [width * 0.52, height * 0.78],
    event: [width * 0.50, height * 0.50],
    redacted_entity: [width * 0.12, height * 0.55],
  };
  return map[type] || [width / 2, height / 2];
}

function toggleCluster() {
  clustered = !clustered;
  const btn = document.getElementById('clusterBtn');
  if (clustered) {
    simulation
      .force('x', d3.forceX(d => _clusterTarget(d.type)[0]).strength(0.17))
      .force('y', d3.forceY(d => _clusterTarget(d.type)[1]).strength(0.17));
    btn.textContent = 'Uncluster';
  } else {
    simulation
      .force('x', d3.forceX(width / 2).strength(0.03))
      .force('y', d3.forceY(height / 2).strength(0.03));
    btn.textContent = 'Cluster';
  }
  simulation.alpha(0.9).restart();
}

function toggleIsolate() {
  isolateMode = !isolateMode;
  const btn = document.getElementById('isolateBtn');
  btn.textContent = isolateMode ? 'Isolate On' : 'Isolate';
  applyFilters();
}

function updateEdgeLegendState() {
  const edgeType = document.getElementById('edgeFilter').value;
  legendEl.querySelectorAll('.etype').forEach(el => {
    el.classList.toggle('active', edgeType !== 'all' && el.dataset.type === edgeType);
  });
}

function applyFilters() {
  const nodeType = document.getElementById('nodeFilter').value;
  const edgeType = document.getElementById('edgeFilter').value;
  const minScore = parseInt(document.getElementById('scoreSlider').value) || 0;
  const selectedNeighbors = selectedNodeId ? getNeighborSet(selectedNodeId) : null;

  node.attr('opacity', d => {
    if (d.is_center) return 1;
    if (minScore > 0 && (d.score || 0) < minScore) return 0.06;
    if (nodeType !== 'all' && d.type !== nodeType) return 0.06;
    if (isolateMode && selectedNeighbors && !selectedNeighbors.has(d.id)) return 0.04;
    return 1;
  });

  label.attr('opacity', d => {
    if (d.is_center) return 1;
    if (!showLabels) return 0;
    if (minScore > 0 && (d.score || 0) < minScore) return 0;
    if (nodeType !== 'all' && d.type !== nodeType) return 0;
    if (isolateMode && selectedNeighbors && !selectedNeighbors.has(d.id)) return 0;
    return 1;
  });

  link.attr('stroke-opacity', d => {
    if (edgeType !== 'all' && d.type !== edgeType) return 0.03;
    const sid = typeof d.source === 'object' ? d.source.id : d.source;
    const tid = typeof d.target === 'object' ? d.target.id : d.target;
    const sn = nodeById.get(sid);
    const tn = nodeById.get(tid);
    if (minScore > 0 && ((sn?.score||0) < minScore || (tn?.score||0) < minScore)) return 0.03;
    if (nodeType !== 'all' && sn?.type !== nodeType && tn?.type !== nodeType) return 0.03;
    if (isolateMode && selectedNeighbors && (!selectedNeighbors.has(sid) || !selectedNeighbors.has(tid))) return 0.02;
    if (selectedNodeId && (sid === selectedNodeId || tid === selectedNodeId)) return 1;
    return 0.6;
  }).attr('stroke-width', d => {
    const base = 0.5 + Math.min(d.weight || 1, 5);
    const sid = typeof d.source === 'object' ? d.source.id : d.source;
    const tid = typeof d.target === 'object' ? d.target.id : d.target;
    if (selectedNodeId && (sid === selectedNodeId || tid === selectedNodeId)) return base + 1.4;
    return base;
  });

  node.classed('node-selected', d => d.id === selectedNodeId);
  updateEdgeLegendState();
}

window.focusSearch = focusSearch;
window.focusNode = focusNode;
window.toggleSimulation = toggleSimulation;
window.toggleCluster = toggleCluster;
window.toggleIsolate = toggleIsolate;

// Initial render state
applyFilters();
if (centerNode) {
  selectNode(centerNode, false);
}
</script>
{% endif %}
{% endblock %}
"""


@app.route("/graph")
def graph_view():
    # Build graph data with intelligent normalization:
    # - dedupe OCR variants by canonical/type
    # - aggregate duplicate edges
    # - prioritize connected/high-signal entities over orphan noise
    entities_raw = query_all(
        """SELECT e.id, e.name, e.canonical_name, e.entity_type, e.role,
                  e.implication_score, e.document_count, e.evidence_count,
                  COALESCE(e.user_score, e.implication_score) as score
           FROM entities e
           WHERE e.is_victim = 0
           ORDER BY score DESC
           LIMIT 1500"""
    )
    relationships_raw = query_all(
        """SELECT source_entity_id, target_entity_id, relationship_type,
                  weight, confidence, evidence_count
           FROM relationships
           ORDER BY weight DESC
           LIMIT 8000"""
    )

    def _safe_num(value, default=0.0):
        try:
            n = float(value)
            if math.isnan(n) or math.isinf(n):
                return float(default)
            return n
        except (TypeError, ValueError):
            return float(default)

    def _norm_name(text: str) -> str:
        return re.sub(r"\s+", " ", (text or "").strip()).lower()

    def _looks_noisy_entity(name: str) -> bool:
        n = (name or "").strip()
        if len(n) < 3:
            return True
        if "\n" in n or "\r" in n:
            return True
        # Reject strongly non-alphabetic OCR debris while allowing financial strings.
        alpha = sum(1 for c in n if c.isalpha())
        ratio = alpha / max(len(n), 1)
        if ratio < 0.38 and not n.startswith("$"):
            return True
        # Repeated-character garbage patterns.
        if re.search(r"(.)\1{4,}", n):
            return True
        if re.search(r"(.{2})\1{3,}", n):
            return True
        # Control / unusual symbols usually indicate OCR corruption.
        if re.search(r"[^\w\s.,'\-/&()#:$%]", n):
            return True
        return False

    def _norm_rel_type(text: str) -> str:
        t = _norm_name(text).replace(" ", "_")
        if not t:
            return "associated_with"
        rel_map = {
            "co_occurs_with": "co_occurs_with",
            "co_occurs": "co_occurs_with",
            "associated_with": "associated_with",
            "is_associated_with": "associated_with",
            "communicated_with": "communicated_with",
            "emailed": "communicated_with",
            "emailed_with": "communicated_with",
            "employed_by": "employed_by",
            "works_for": "employed_by",
            "traveled_to": "traveled_to",
            "located_at": "located_at",
            "paid": "paid",
            "received_payment": "received_payment",
            "financially_linked": "financially_linked",
            "financially_linked_to": "financially_linked",
            "witnessed": "witnessed",
            "flew_with": "flew_with",
        }
        return rel_map.get(t, "associated_with")

    # 1) Deduplicate entities by canonical key.
    dedup_entities: dict[tuple[str, str], dict] = {}
    id_remap: dict[int, int] = {}
    for e in entities_raw:
        display_name = (e.get("canonical_name") or e.get("name") or "").strip()
        if not display_name:
            continue
        if _looks_noisy_entity(display_name):
            continue
        etype = (e.get("entity_type") or "person").strip().lower()
        key = (_norm_name(display_name), etype)
        cur = dedup_entities.get(key)
        if cur is None:
            cur = {
                "id": int(e["id"]),
                "name": display_name,
                "type": etype,
                "role": e.get("role") or "",
                "score": _safe_num(e.get("score"), 0.0),
                "doc_count": int(_safe_num(e.get("document_count"), 0)),
                "evidence_count": int(_safe_num(e.get("evidence_count"), 0)),
                "_source_ids": {int(e["id"])},
            }
            dedup_entities[key] = cur
        else:
            # Keep the strongest representative metadata.
            cur["score"] = max(cur["score"], _safe_num(e.get("score"), 0.0))
            cur["doc_count"] = max(cur["doc_count"], int(_safe_num(e.get("document_count"), 0)))
            cur["evidence_count"] = max(cur["evidence_count"], int(_safe_num(e.get("evidence_count"), 0)))
            if len(display_name) > len(cur["name"]):
                cur["name"] = display_name
            if e.get("role") and not cur.get("role"):
                cur["role"] = e.get("role")
            cur["_source_ids"].add(int(e["id"]))

    for node in dedup_entities.values():
        for src_id in node["_source_ids"]:
            id_remap[src_id] = node["id"]

    # 2) Remap and aggregate edges by (src, tgt, type).
    aggregated_links: dict[tuple[int, int, str], dict] = {}
    for r in relationships_raw:
        src = id_remap.get(int(r["source_entity_id"])) if r.get("source_entity_id") is not None else None
        tgt = id_remap.get(int(r["target_entity_id"])) if r.get("target_entity_id") is not None else None
        if not src or not tgt or src == tgt:
            continue
        # Make undirected key stable for cleaner spiderweb layout.
        if src > tgt:
            src, tgt = tgt, src
        rtype = _norm_rel_type(r.get("relationship_type"))
        key = (src, tgt, rtype)
        item = aggregated_links.get(key)
        weight = max(1.0, _safe_num(r.get("weight"), 1.0))
        if item is None:
            aggregated_links[key] = {
                "source": src,
                "target": tgt,
                "type": rtype,
                "weight": weight,
                "count": 1,
            }
        else:
            item["weight"] += weight
            item["count"] += 1

    # 3) Build people-first graph centered on Jeffrey Epstein.
    node_by_id = {n["id"]: n for n in dedup_entities.values()}
    conn_counts: dict[int, int] = {}
    adjacency: dict[int, set[int]] = {}
    for l in aggregated_links.values():
        s = l["source"]
        t = l["target"]
        conn_counts[s] = conn_counts.get(s, 0) + 1
        conn_counts[t] = conn_counts.get(t, 0) + 1
        adjacency.setdefault(s, set()).add(t)
        adjacency.setdefault(t, set()).add(s)

    for nid, n in node_by_id.items():
        n["connections"] = conn_counts.get(nid, 0)

    def _priority_for(nid: int) -> float:
        n = node_by_id[nid]
        person_bonus = 25 if n.get("type") == "person" else 0
        return (
            n.get("connections", 0) * 100
            + _safe_num(n.get("score"), 0.0) * 3
            + _safe_num(n.get("doc_count"), 0.0) * 2
            + person_bonus
        )

    # Find Jeffrey Epstein center node.
    center_id = None
    exact_key = (_norm_name("Jeffrey Epstein"), "person")
    if exact_key in dedup_entities:
        center_id = dedup_entities[exact_key]["id"]
    else:
        epstein_candidates = [
            n for n in node_by_id.values()
            if n.get("type") == "person"
            and "jeffrey" in _norm_name(n.get("name", ""))
            and "epstein" in _norm_name(n.get("name", ""))
        ]
        if epstein_candidates:
            center_id = max(epstein_candidates, key=lambda n: _priority_for(n["id"]))["id"]

    keep_ids: set[int] = set()
    max_nodes = 350

    if center_id and center_id in node_by_id:
        first_hop = set(adjacency.get(center_id, set()))
        direct_people = {
            nid for nid in first_hop
            if node_by_id.get(nid, {}).get("type") == "person"
        }
        connector_candidates = {
            nid for nid in first_hop
            if node_by_id.get(nid, {}).get("type") != "person"
        }

        second_hop_people: set[int] = set()
        connectors_to_keep: set[int] = set()
        for cid in connector_candidates:
            neigh = adjacency.get(cid, set())
            people_via_connector = {
                nid for nid in neigh
                if nid != center_id and node_by_id.get(nid, {}).get("type") == "person"
            }
            if people_via_connector:
                connectors_to_keep.add(cid)
                second_hop_people.update(people_via_connector)

        keep_ids = {center_id} | direct_people | second_hop_people | connectors_to_keep

        # If sparse graph around Jeffrey, add highest-signal people.
        if len(keep_ids) < 45:
            ranked_people = [
                nid for nid, n in sorted(
                    node_by_id.items(),
                    key=lambda kv: _priority_for(kv[0]),
                    reverse=True,
                )
                if n.get("type") == "person" and nid != center_id
            ]
            for nid in ranked_people:
                keep_ids.add(nid)
                if len(keep_ids) >= 45:
                    break

    # Fallback when no reliable center is found: still prefer people + connected nodes.
    if not keep_ids:
        ranked = sorted(
            node_by_id.values(),
            key=lambda n: _priority_for(n["id"]),
            reverse=True,
        )
        keep_ids = {
            n["id"] for n in ranked
            if n.get("type") == "person" or n.get("connections", 0) > 0
        }

    # Cap graph size for responsiveness while preserving center.
    if len(keep_ids) > max_nodes:
        ranked_keep = sorted(
            [nid for nid in keep_ids if nid != center_id],
            key=_priority_for,
            reverse=True,
        )[: max_nodes - (1 if center_id else 0)]
        keep_ids = set(ranked_keep)
        if center_id:
            keep_ids.add(center_id)

    # Keep links only within keep set and people-centric (or directly from center).
    links = []
    for l in aggregated_links.values():
        s = l["source"]
        t = l["target"]
        if s not in keep_ids or t not in keep_ids:
            continue
        st = node_by_id.get(s, {}).get("type")
        tt = node_by_id.get(t, {}).get("type")
        if center_id and s != center_id and t != center_id and st != "person" and tt != "person":
            continue
        links.append(l)

    linked_ids: set[int] = set()
    for l in links:
        linked_ids.add(l["source"])
        linked_ids.add(l["target"])

    ordered_ids = sorted(
        [nid for nid in keep_ids if nid in linked_ids or _safe_num(node_by_id[nid].get("score"), 0) >= 75],
        key=lambda nid: (0 if center_id and nid == center_id else 1, -_priority_for(nid)),
    )
    nodes = []
    for nid in ordered_ids:
        n = node_by_id[nid]
        nodes.append({
            "id": nid,
            "name": n["name"],
            "type": n["type"],
            "role": n.get("role") or "",
            "score": n.get("score", 0),
            "doc_count": n.get("doc_count", 0),
            "connections": n.get("connections", 0),
            "entity_ids": sorted(int(x) for x in n.get("_source_ids", {nid})),
            "is_center": bool(center_id and nid == center_id),
        })

    # Keep edge list compact and sorted for deterministic rendering.
    links.sort(key=lambda l: (l["type"], -l["weight"], l["source"], l["target"]))
    links = links[:2500]

    relationship_types = sorted({l["type"] for l in links if l.get("type")})
    center_name = node_by_id.get(center_id, {}).get("name") if center_id else None
    graph_data = {"nodes": nodes, "links": links, "center_id": center_id}

    return render_template_string(
        GRAPH_HTML,
        active="graph",
        graph_data=graph_data,
        node_count=len(nodes),
        edge_count=len(links),
        relationship_types=relationship_types,
        center_name=center_name,
    )


# ============================================================================
#  6.  EMAIL CHAIN RECONSTRUCTOR  (/chains)
# ============================================================================

def _rebuild_email_chains(max_docs: int = 250) -> dict:
    """Backfill email chains from extracted OCR text for docs not yet stitched."""
    try:
        from processor.processor import DocumentClassifier, EmailChainStitcher
    except Exception as exc:
        logger.error("Email rebuild unavailable: %s", exc)
        return {"scanned": 0, "stitched": 0, "failed": 0, "error": str(exc)}

    classifier = DocumentClassifier()
    stitcher = EmailChainStitcher(_get_db(), _get_db().config)
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    scanned = 0
    stitched = 0
    failed = 0

    conn = get_conn()
    try:
        candidates = conn.execute(
            """
            SELECT d.id, d.original_filename
            FROM documents d
            WHERE d.id NOT IN (SELECT document_id FROM email_messages)
              AND d.status IN ('ocr_complete', 'analyzed', 'reviewed')
            ORDER BY d.priority_score DESC, d.id ASC
            LIMIT ?
            """,
            (max_docs,),
        ).fetchall()

        for row in candidates:
            scanned += 1
            doc_id = row["id"]
            text_rows = conn.execute(
                "SELECT text_content FROM document_pages WHERE document_id = ? ORDER BY page_number",
                (doc_id,),
            ).fetchall()
            full_text = "\n\n".join((r["text_content"] or "") for r in text_rows).strip()
            if len(full_text) < 40:
                continue

            try:
                classification = classifier.classify(
                    full_text,
                    {"filename": row["original_filename"] or f"document_{doc_id}.pdf"},
                )
                if classification.get("doc_type") == "email" and classification.get("email_data"):
                    stitcher.on_new_email(classification["email_data"], doc_id)
                    conn.execute(
                        "UPDATE documents SET doc_type = 'email', updated_at = ? WHERE id = ?",
                        (now_iso, doc_id),
                    )
                    stitched += 1
            except Exception as exc:
                failed += 1
                logger.debug("Email rebuild failed for doc %s: %s", doc_id, exc)

        conn.commit()
    finally:
        conn.close()

    return {"scanned": scanned, "stitched": stitched, "failed": failed}


CHAINS_HTML = r"""{% extends "base.html" %}
{% block title %}Email Chains - EpsteinAnalyzer{% endblock %}
{% block content %}
<h1>Email Chain Reconstructor</h1>
<p class="subtitle">{{ chains|length }} reconstructed email threads</p>
{% if rebuild_msg %}
<div class="alert alert-info">{{ rebuild_msg }}</div>
{% endif %}
{% if auto_rebuild_msg %}
<div class="alert alert-warning">{{ auto_rebuild_msg }}</div>
{% endif %}

<div class="card mb-2">
  <div class="flex gap-1">
    <form method="get" action="/chains" class="flex gap-1" style="flex:1">
      <input type="search" name="q" value="{{ q }}" placeholder="Search by subject or participants..." style="flex:1">
      <select name="gaps" style="width:160px">
        <option value="">All Chains</option>
        <option value="1" {% if filter_gaps %}selected{% endif %}>Has Gaps Only</option>
      </select>
      <button class="btn btn-primary" type="submit">Filter</button>
    </form>
    <form method="post" action="/chains/rebuild">
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
      <button class="btn btn-warning" type="submit">Rebuild From OCR</button>
    </form>
  </div>
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
  <div style="padding:20px;text-align:center">
    <p class="text-muted mb-1">No email chains reconstructed yet.</p>
    <p class="text-muted" style="font-size:.82rem">{{ candidate_docs_count }} document(s) currently look email-like from OCR text.</p>
  </div>
  {% if potential_docs %}
  <table>
    <thead><tr><th>Doc</th><th>Filename</th><th>Preview</th><th></th></tr></thead>
    <tbody>
    {% for d in potential_docs %}
    <tr>
      <td class="mono">#{{ d.id }}</td>
      <td>{{ d.original_filename or 'Unknown' }}</td>
      <td class="truncate" style="max-width:360px">{{ d.preview or '(no text preview)' }}</td>
      <td><a href="/document/{{ d.id }}" class="btn btn-sm">Inspect</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
  {% endif %}
</div>
{% endblock %}
"""


@app.route("/chains")
def chains_list():
    q = request.args.get("q", "").strip()
    filter_gaps = request.args.get("gaps", "")
    rebuild_msg = ""
    auto_rebuild_msg = ""

    # If user has no chains yet, attempt one automatic backfill pass from OCR text.
    if not q and not filter_gaps and query_scalar("SELECT COUNT(*) FROM email_chains") == 0:
        auto_result = _rebuild_email_chains(max_docs=250)
        if auto_result.get("stitched", 0) > 0:
            auto_rebuild_msg = (
                f"Auto-rebuild stitched {auto_result['stitched']} chain(s) "
                f"from {auto_result['scanned']} candidate document(s)."
            )

    rebuilt_qs = request.args.get("rebuilt")
    scanned_qs = request.args.get("scanned")
    failed_qs = request.args.get("failed")
    if rebuilt_qs is not None or scanned_qs is not None:
        try:
            rebuilt_n = int(rebuilt_qs or 0)
            scanned_n = int(scanned_qs or 0)
            failed_n = int(failed_qs or 0)
            rebuild_msg = (
                f"Rebuild completed: {rebuilt_n} stitched, "
                f"{scanned_n} scanned, {failed_n} failed."
            )
        except (TypeError, ValueError):
            rebuild_msg = "Rebuild completed."

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
    candidate_docs_count = query_scalar(
        """
        SELECT COUNT(*)
        FROM documents d
        WHERE d.id NOT IN (SELECT document_id FROM email_messages)
          AND d.status IN ('ocr_complete', 'analyzed', 'reviewed')
          AND EXISTS (
              SELECT 1 FROM document_pages dp
              WHERE dp.document_id = d.id
                AND (
                  dp.text_content LIKE '%@%'
                  OR dp.text_content LIKE '%From:%'
                  OR dp.text_content LIKE '%Subject:%'
                  OR dp.text_content LIKE '%Original Message%'
                )
          )
        """
    )
    potential_docs = query_all(
        """
        SELECT d.id, d.original_filename,
               (
                 SELECT substr(replace(dp.text_content, char(10), ' '), 1, 180)
                 FROM document_pages dp
                 WHERE dp.document_id = d.id
                 ORDER BY dp.page_number
                 LIMIT 1
               ) AS preview
        FROM documents d
        WHERE d.id NOT IN (SELECT document_id FROM email_messages)
          AND d.status IN ('ocr_complete', 'analyzed', 'reviewed')
          AND EXISTS (
              SELECT 1 FROM document_pages dp
              WHERE dp.document_id = d.id
                AND (
                  dp.text_content LIKE '%@%'
                  OR dp.text_content LIKE '%From:%'
                  OR dp.text_content LIKE '%Subject:%'
                  OR dp.text_content LIKE '%Original Message%'
                )
          )
        ORDER BY d.priority_score DESC, d.id ASC
        LIMIT 20
        """
    )

    return render_template_string(
        CHAINS_HTML,
        active="chains",
        chains=chains,
        q=q,
        filter_gaps=filter_gaps,
        rebuild_msg=rebuild_msg,
        auto_rebuild_msg=auto_rebuild_msg,
        candidate_docs_count=candidate_docs_count,
        potential_docs=potential_docs,
    )


@app.route("/chains/rebuild", methods=["POST"])
def chains_rebuild():
    result = _rebuild_email_chains(max_docs=500)
    _get_db().log_action(
        "rebuild_email_chains",
        f"scanned={result.get('scanned', 0)} stitched={result.get('stitched', 0)} failed={result.get('failed', 0)}",
    )
    return redirect(
        url_for(
            "chains_list",
            rebuilt=result.get("stitched", 0),
            scanned=result.get("scanned", 0),
            failed=result.get("failed", 0),
        )
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

def _categorize_finding_text(text: str) -> str:
    t = (text or "").lower()
    if any(k in t for k in ("minor", "underage", "traffick", "recruit", "sexual abuse", "sexual assault")):
        return "trafficking"
    if any(k in t for k in ("witness tampering", "obstruction", "destroyed", "deleted evidence")):
        return "obstruction"
    if any(k in t for k in ("cover up", "cover-up", "sealed", "suppressed", "non-prosecution")):
        return "cover_up"
    if any(k in t for k in ("wire", "invoice", "payment", "transfer", "account", "salary", "cash")):
        return "financial"
    if any(k in t for k in ("fraud", "forgery", "false statement", "misrepresent")):
        return "fraud"
    if any(k in t for k in ("senator", "president", "governor", "campaign", "government official", "political")):
        return "political"
    return "other"


def _confidence_from_consensus(top_score: int, agreement_level: str) -> str:
    if top_score >= 85 and agreement_level in ("full", "majority"):
        return "confirmed"
    if top_score >= 60 or agreement_level in ("full", "majority"):
        return "likely"
    return "unverified"


def _auto_sync_findings(max_new: int = 40) -> int:
    """Create findings from consensus analyses so board/export tabs have live data."""
    conn = get_conn()
    try:
        findings_rows = conn.execute(
            "SELECT title, linked_document_ids FROM findings"
        ).fetchall()
        existing_doc_ids = set()
        existing_titles = set()
        for row in findings_rows:
            existing_titles.add((row["title"] or "").strip().lower())
            for did in safe_json(row["linked_document_ids"], []):
                try:
                    existing_doc_ids.add(int(did))
                except (TypeError, ValueError):
                    continue

        candidates = conn.execute(
            """
            SELECT c.document_id,
                   c.consensus_summary,
                   c.consensus_evidence_scores,
                   c.consensus_connections,
                   c.agreement_level,
                   d.original_filename,
                   (
                     SELECT a.flags
                     FROM ai_analyses a
                     WHERE a.document_id = c.document_id
                     ORDER BY a.created_at DESC
                     LIMIT 1
                   ) AS latest_flags
            FROM ai_consensus c
            JOIN documents d ON d.id = c.document_id
            ORDER BY c.created_at DESC
            LIMIT ?
            """,
            (max_new * 8,),
        ).fetchall()

        created = 0
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        for row in candidates:
            if created >= max_new:
                break
            doc_id = int(row["document_id"])
            if doc_id in existing_doc_ids:
                continue

            summary = (row["consensus_summary"] or "").strip()
            scores_raw = safe_json(row["consensus_evidence_scores"], [])
            conns_raw = safe_json(row["consensus_connections"], [])
            flags_raw = safe_json(row["latest_flags"], [])

            scores = [s for s in scores_raw if isinstance(s, dict) and s.get("name")]
            scores.sort(key=lambda s: int(s.get("score", 0)), reverse=True)
            top_score = int(scores[0].get("score", 0)) if scores else 0
            top_names = [s.get("name", "").strip() for s in scores[:3] if s.get("name")]
            if not summary and not scores and not conns_raw and not flags_raw:
                continue
            if top_score < 30 and len(conns_raw) == 0 and len(flags_raw) == 0:
                continue

            headline_name = top_names[0] if top_names else f"Doc #{doc_id}"
            title = f"{headline_name} investigative lead (Doc #{doc_id})"
            title = title[:140]
            if title.lower() in existing_titles:
                continue

            blob = " ".join(
                [
                    summary,
                    " ".join(f for f in flags_raw if isinstance(f, str)),
                    " ".join(str(c.get("relationship", "")) for c in conns_raw if isinstance(c, dict)),
                ]
            )
            category = _categorize_finding_text(blob)
            confidence = _confidence_from_consensus(top_score, row["agreement_level"] or "")

            linked_entity_ids = []
            for nm in top_names:
                ent = conn.execute(
                    """
                    SELECT id FROM entities
                    WHERE lower(name) = lower(?) OR lower(canonical_name) = lower(?)
                    ORDER BY implication_score DESC
                    LIMIT 1
                    """,
                    (nm, nm),
                ).fetchone()
                if ent:
                    linked_entity_ids.append(ent["id"])

            flags_preview = [f for f in flags_raw if isinstance(f, str)][:4]
            notes_lines = [
                "Auto-generated from AI consensus; treat as investigative lead pending corroboration.",
                f"Source document: {row['original_filename']} (id={doc_id})",
            ]
            if top_names:
                notes_lines.append("Top names: " + ", ".join(top_names))
            if flags_preview:
                notes_lines.append("Flags: " + " | ".join(flags_preview))
            if scores:
                score_bits = [f"{s.get('name')}={int(s.get('score', 0))}" for s in scores[:5]]
                notes_lines.append("Evidence scores: " + ", ".join(score_bits))

            auto_summary = summary or (
                f"AI models flagged {', '.join(top_names)} for review in document #{doc_id}."
                if top_names else f"AI models flagged document #{doc_id} for review."
            )

            conn.execute(
                """
                INSERT INTO findings (
                    title, category, summary, detailed_notes, confidence_level,
                    linked_entity_ids, linked_document_ids, tags, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    category,
                    auto_summary[:2000],
                    "\n".join(notes_lines)[:8000],
                    confidence,
                    json.dumps(sorted(set(linked_entity_ids))),
                    json.dumps([doc_id]),
                    json.dumps(["auto", "ai_consensus"]),
                    now_iso,
                ),
            )
            existing_doc_ids.add(doc_id)
            existing_titles.add(title.lower())
            created += 1

        if created:
            conn.commit()
        return created
    finally:
        conn.close()


FINDINGS_HTML = r"""{% extends "base.html" %}
{% block title %}Findings Board - EpsteinAnalyzer{% endblock %}
{% block content %}
<div class="flex flex-between items-center mb-2">
  <div>
    <h1>Findings Board</h1>
    <p class="subtitle">{{ findings|length }} pinned findings across {{ categories|length }} categories</p>
  </div>
  <div class="btn-group">
    <form method="post" action="/findings/sync">
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
      <button class="btn" type="submit">Sync From AI</button>
    </form>
    <button class="btn btn-primary" onclick="document.getElementById('newFinding').classList.toggle('hidden')">+ New Finding</button>
  </div>
</div>

{% if synced_count %}
<div class="alert alert-info">Synced {{ synced_count }} finding(s) from AI consensus.</div>
{% endif %}

<!-- New Finding Form -->
<div id="newFinding" class="card hidden mb-2">
  <h3 class="mb-2">Create New Finding</h3>
  <form method="post" action="/findings/create">
    <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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
    try:
        synced_count = int(request.args.get("synced", "0") or 0)
    except (TypeError, ValueError):
        synced_count = 0
    if request.args.get("autosync", "1") != "0":
        synced_count += _auto_sync_findings(max_new=35)
    findings_raw = query_all("SELECT * FROM findings ORDER BY category, created_at DESC")
    if not findings_raw and synced_count == 0:
        synced_count = _auto_sync_findings(max_new=120)
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
        FINDINGS_HTML,
        active="findings",
        findings=findings,
        categories=categories,
        cat_counts=cat_counts,
        synced_count=synced_count,
    )


@app.route("/findings/create", methods=["POST"])
def findings_create():
    VALID_CATEGORIES = {"financial", "trafficking", "political", "cover_up", "fraud", "obstruction", "other"}
    VALID_CONFIDENCE = {"unverified", "likely", "confirmed"}
    title = request.form.get("title", "").strip()
    if not title:
        return redirect(url_for("findings_board"))
    category = request.form.get("category", "other")
    if category not in VALID_CATEGORIES:
        category = "other"
    confidence = request.form.get("confidence_level", "unverified")
    if confidence not in VALID_CONFIDENCE:
        confidence = "unverified"
    execute(
        """INSERT INTO findings (title, category, summary, detailed_notes, confidence_level)
           VALUES (?, ?, ?, ?, ?)""",
        (
            title,
            category,
            request.form.get("summary", ""),
            request.form.get("detailed_notes", ""),
            confidence,
        ),
    )
    _get_db().log_action("create_finding", f"Created finding: {title}")
    return redirect(url_for("findings_board"))


@app.route("/findings/sync", methods=["POST"])
def findings_sync():
    synced = _auto_sync_findings(max_new=120)
    _get_db().log_action("sync_findings", f"Synced findings from AI consensus: {synced}")
    return redirect(url_for("findings_board", autosync=0, synced=synced))


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
        <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
        <button name="decision" value="discard_victim" class="btn btn-danger w-full mb-1">Discard (Victim Material)</button>
      </form>
      {% else %}
      <form method="post" action="/images/review/{{ image.id }}/decide" class="mt-2">
        <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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
    _emit_live_updates(force=True)
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

    # Try vault decryption first
    if _vault_file_mgr:
        vault_uuid = _vault_file_mgr.get_vault_uuid_for_path(image["file_path"])
        if vault_uuid:
            try:
                buf = _vault_file_mgr.decrypt_to_memory(vault_uuid)
                ext = Path(image["file_path"]).suffix.lower()
                mimetypes = {
                    ".png": "image/png", ".jpg": "image/jpeg",
                    ".jpeg": "image/jpeg", ".gif": "image/gif",
                    ".bmp": "image/bmp", ".tiff": "image/tiff",
                }
                mimetype = mimetypes.get(ext, "image/png")
                return send_file(
                    buf, mimetype=mimetype,
                    download_name=Path(image["file_path"]).name,
                )
            except Exception as e:
                logger.warning("Vault decrypt failed for image %d: %s", image_id, e)

    # Fallback: serve from disk
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
      <span class="text-muted" style="font-size:.82rem">{{ item.doc_type or 'Unknown type' }} &middot; {{ ((item.size_bytes or 0) / 1024)|round(1) }} KB</span>
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
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
      <button name="decision" value="keep" class="btn btn-success btn-sm">Keep</button>
    </form>
    <form method="post" action="/deletions/{{ item.id }}/decide" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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
    if decision not in ("keep", "delete", "pending"):
        abort(400)
    execute(
        "UPDATE deletion_queue SET user_decision = ?, decided_at = ? WHERE id = ?",
        (decision, datetime.now(tz=timezone.utc).isoformat(), item_id),
    )
    if decision == "delete":
        row = query_one("SELECT document_id FROM deletion_queue WHERE id = ?", (item_id,))
        if row:
            execute("UPDATE documents SET status = 'deleted' WHERE id = ?", (row["document_id"],))
    _get_db().log_action("deletion_decision", f"Item {item_id}: {decision}")
    _emit_live_updates(force=True)
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
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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
      <input type="hidden" name="csrf_token" value="{{ session.get('_csrf_token', '') }}">
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


@app.route("/api/activity")
def api_activity():
    snap = _get_activity_snapshot()
    return jsonify(
        {
            "active": bool(snap.get("active")),
            "dataset": snap.get("dataset"),
            "percent": int(snap.get("percent") or 0),
            "message": snap.get("message") or "Idle",
            "level": snap.get("level") or "info",
        }
    )


def _command_center_live_payload() -> dict:
    stats = _get_db().get_stats()
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
    return {
        "stats": stats,
        "pipeline": pipeline,
        "priority_docs": priority_docs,
        "recent_analyses": recent_analyses,
    }


@app.route("/api/command_center/live")
def api_command_center_live():
    return jsonify(_command_center_live_payload())


@app.route("/api/documents/status")
def api_documents_status():
    raw_ids = (request.args.get("ids") or "").strip()
    if not raw_ids:
        return jsonify({"documents": []})
    ids = []
    for token in raw_ids.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            val = int(token)
            if val > 0:
                ids.append(val)
        except (TypeError, ValueError):
            continue
    ids = list(dict.fromkeys(ids))[:200]
    if not ids:
        return jsonify({"documents": []})

    placeholders = ",".join("?" for _ in ids)
    docs = query_all(
        f"""SELECT id, priority_score, status, analysis_completed, ocr_completed, user_flagged, doc_type
            FROM documents
            WHERE id IN ({placeholders})""",
        tuple(ids),
    )
    docs_by_id = {int(d["id"]): d for d in docs}
    ordered = [docs_by_id[i] for i in ids if i in docs_by_id]
    return jsonify({"documents": ordered})


def _dataset_row(dataset_number: int):
    return query_one(
        "SELECT id, dataset_number, status, processed_files FROM datasets WHERE dataset_number = ?",
        (dataset_number,),
    )


def _update_dataset_status(dataset_number: int, status: str):
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE datasets SET status = ?, updated_at = ? WHERE dataset_number = ?",
            (status, datetime.now(tz=timezone.utc).isoformat(), dataset_number),
        )
        conn.commit()
    finally:
        conn.close()


def _dataset_doc_counts(dataset_number: int) -> dict:
    row = query_one(
        """
        SELECT
            COUNT(*) AS total_docs,
            SUM(CASE WHEN d.analysis_completed = 0 THEN 1 ELSE 0 END) AS not_analyzed,
            SUM(CASE WHEN d.analysis_completed = 0 AND d.status != 'analyzing' THEN 1 ELSE 0 END) AS eligible_analyze,
            SUM(CASE WHEN d.status = 'analyzing' THEN 1 ELSE 0 END) AS analyzing_docs,
            SUM(CASE WHEN d.analysis_completed = 1 THEN 1 ELSE 0 END) AS analyzed_docs
        FROM documents d
        JOIN datasets ds ON ds.id = d.dataset_id
        WHERE ds.dataset_number = ?
        """,
        (dataset_number,),
    ) or {}
    return {
        "total_docs": int(row.get("total_docs") or 0),
        "not_analyzed": int(row.get("not_analyzed") or 0),
        "eligible_analyze": int(row.get("eligible_analyze") or 0),
        "analyzing_docs": int(row.get("analyzing_docs") or 0),
        "analyzed_docs": int(row.get("analyzed_docs") or 0),
    }


def _dataset_is_busy(status: Optional[str]) -> bool:
    return (status or "").lower() in {"downloading", "processing", "analyzing"}


def _auto_process_dataset(n):
    """Auto-chain helper: process dataset after successful load."""
    _emit_progress(f"Auto-processing dataset {n}...", "info", active=True, percent=1, dataset=n)
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE datasets SET status = 'processing', updated_at = ? WHERE dataset_number = ?",
            (datetime.now(tz=timezone.utc).isoformat(), n),
        )
        conn.commit()
    finally:
        conn.close()

    try:
        from processor.processor import ProcessorEngine

        def processor_progress(stage, current, total, message=""):
            pct = int(current / total * 100) if total > 0 else 0
            _emit_dataset_progress(
                n,
                pct,
                f"Processing {stage}: {current}/{total} {message}".strip(),
            )

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

        total_docs = result.get("total", 0) if result else 0
        errors = result.get("errors", 0) if result else 0
        _emit_progress(
            f"Dataset {n} processed! {total_docs} docs. Auto-analyzing...",
            "success",
            active=True,
            percent=100,
            dataset=n,
        )

        # Auto-chain: trigger AI analysis
        _auto_analyze_dataset(n)
    except Exception as exc:
        logger.exception("Auto-process dataset %d failed", n)
        conn2 = get_conn()
        try:
            conn2.execute(
                "UPDATE datasets SET status = 'error', updated_at = ? WHERE dataset_number = ?",
                (datetime.now(tz=timezone.utc).isoformat(), n),
            )
            conn2.commit()
        finally:
            conn2.close()
        _emit_progress(
            f"Dataset {n} processing FAILED. Check server logs.",
            "error",
            active=False,
            percent=100,
            dataset=n,
        )


def _auto_analyze_dataset(n):
    """Auto-chain helper: run AI analysis after successful processing."""
    counts_before = _dataset_doc_counts(n)
    if counts_before["total_docs"] <= 0:
        _emit_progress(
            f"Dataset {n}: no documents exist to analyze.",
            "warning",
            active=False,
            percent=100,
            dataset=n,
        )
        return
    if counts_before["eligible_analyze"] <= 0:
        _emit_progress(
            (
                f"Dataset {n}: no eligible docs for AI analysis "
                f"(eligible=0, not_analyzed={counts_before['not_analyzed']}, analyzing={counts_before['analyzing_docs']})."
            ),
            "warning",
            active=False,
            percent=100,
            dataset=n,
        )
        return

    _emit_progress(
        f"Starting AI analysis on dataset {n}...",
        "info",
        active=True,
        percent=1,
        dataset=n,
    )
    _update_dataset_status(n, "analyzing")

    try:
        from ai_pipeline.pipeline import PipelineEngine

        engine = PipelineEngine()
        pipeline_progress, analysis_heartbeat_stop = _build_analysis_progress_callback(n)
        engine.progress_callback = pipeline_progress
        try:
            results = engine.analyze_dataset(n)
        finally:
            analysis_heartbeat_stop.set()

        if not results:
            _update_dataset_status(n, "processed")
            counts_after = _dataset_doc_counts(n)
            _emit_progress(
                (
                    f"Dataset {n}: no documents returned for AI analysis "
                    f"(eligible={counts_after['eligible_analyze']}, not_analyzed={counts_after['not_analyzed']}, analyzing={counts_after['analyzing_docs']})."
                ),
                "warning",
                active=False,
                percent=100,
                dataset=n,
            )
            return

        successes = sum(1 for r in results if "error" not in r.get("result", {}))
        errors = len(results) - successes

        _update_dataset_status(n, "analyzed")

        _emit_dataset_progress(n, 100, f"Complete! {successes} analyzed, {errors} failed")
        _emit_progress(
            f"Dataset {n} fully analyzed! {successes} docs.",
            "success",
            active=False,
            percent=100,
            dataset=n,
        )
    except Exception as exc:
        logger.exception("Auto-analyze dataset %d failed", n)
        _update_dataset_status(n, "error")
        _emit_progress(
            f"Dataset {n} AI analysis FAILED. Check server logs.",
            "error",
            active=False,
            percent=100,
            dataset=n,
        )


@app.route("/api/dataset/<int:n>/load", methods=["POST"])
def api_dataset_load(n):
    """Trigger dataset download via the real HarvesterEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    existing_row = _dataset_row(n)
    if existing_row and _dataset_is_busy(existing_row.get("status")):
        return jsonify({"error": f"Dataset {n} is already {existing_row['status']}."}), 409
    if existing_row and existing_row.get("status") in ("downloaded", "processed", "analyzed"):
        return jsonify({"error": f"Dataset {n} is already loaded (status={existing_row['status']})."}), 409

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
    _emit_progress(f"Dataset {n} download started...", "info", active=True, percent=0, dataset=n)
    _emit_dataset_progress(n, 0, f"Initializing dataset {n}...")

    def _background_load():
        try:
            from harvester.harvester import HarvesterEngine

            def harvester_progress(event):
                msg = event.get("message", "")
                pct = event.get("percent")
                _emit_dataset_progress(n, pct if pct is not None else 0, msg)

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

            _emit_dataset_progress(n, 100, f"Dataset {n}: {len(paths)} files downloaded!")
            _emit_progress(
                f"Dataset {n} loaded! {len(paths)} files. Auto-processing...",
                "success",
                active=True,
                percent=100,
                dataset=n,
            )

            # Auto-chain: trigger processing after successful load
            _auto_process_dataset(n)
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
            _emit_progress(
                f"Dataset {n} load FAILED. Check server logs.",
                "error",
                active=False,
                percent=100,
                dataset=n,
            )

    socketio.start_background_task(_background_load)
    return jsonify({"status": "started", "dataset": n})


@app.route("/api/dataset/<int:n>/process", methods=["POST"])
def api_dataset_process(n):
    """Trigger document processing via the real ProcessorEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    row = _dataset_row(n)
    if not row:
        return jsonify({"error": f"Dataset {n} not found."}), 404
    if _dataset_is_busy(row.get("status")):
        return jsonify({"error": f"Dataset {n} is already {row['status']}."}), 409
    counts = _dataset_doc_counts(n)
    if counts["total_docs"] <= 0:
        return jsonify({"error": f"Dataset {n} has no documents to process."}), 409

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
    _emit_progress(f"Processing dataset {n}...", "info", active=True, percent=1, dataset=n)

    def _background_process():
        try:
            from processor.processor import ProcessorEngine

            def processor_progress(stage, current, total, message=""):
                pct = int(current / total * 100) if total > 0 else 0
                _emit_dataset_progress(n, pct, f"{stage}: {current}/{total} {message}".strip())

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
            _emit_dataset_progress(n, 100, f"Processing complete! {total_docs} docs, {errors} errors")
            _emit_progress(
                f"Dataset {n} processed! {total_docs} documents. Auto-analyzing...",
                "success",
                active=True,
                percent=100,
                dataset=n,
            )

            # Auto-chain: trigger AI analysis after successful processing
            _auto_analyze_dataset(n)
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
            _emit_progress(
                f"Dataset {n} processing FAILED. Check server logs.",
                "error",
                active=False,
                percent=100,
                dataset=n,
            )

    socketio.start_background_task(_background_process)
    return jsonify({"status": "processing", "dataset": n})


@app.route("/api/dataset/<int:n>/analyze", methods=["POST"])
def api_dataset_analyze(n):
    """Trigger AI analysis via the real PipelineEngine in a background thread."""
    if n < 1 or n > 12:
        return jsonify({"error": "Dataset must be 1-12"}), 400

    row = _dataset_row(n)
    if not row:
        return jsonify({"error": f"Dataset {n} not found."}), 404
    if _dataset_is_busy(row.get("status")):
        return jsonify({"error": f"Dataset {n} is already {row['status']}."}), 409
    counts = _dataset_doc_counts(n)
    if counts["total_docs"] <= 0:
        return jsonify({"error": f"Dataset {n} has no documents. Load/process files first."}), 409
    if counts["eligible_analyze"] <= 0:
        return jsonify({
            "error": (
                f"Dataset {n} has no eligible docs for analysis "
                f"(eligible=0, not_analyzed={counts['not_analyzed']}, analyzing={counts['analyzing_docs']}, analyzed={counts['analyzed_docs']})."
            )
        }), 409

    _get_db().log_action("dataset_analyze", f"Started AI analysis on dataset {n}")
    _update_dataset_status(n, "analyzing")
    _emit_progress(
        f"AI analysis started for dataset {n}...",
        "info",
        active=True,
        percent=1,
        dataset=n,
    )

    def _background_analyze():
        try:
            from ai_pipeline.pipeline import PipelineEngine

            engine = PipelineEngine()
            pipeline_progress, analysis_heartbeat_stop = _build_analysis_progress_callback(n)
            engine.progress_callback = pipeline_progress
            try:
                results = engine.analyze_dataset(n)
            finally:
                analysis_heartbeat_stop.set()

            if not results:
                _update_dataset_status(n, "processed")
                _emit_progress(
                    f"Dataset {n}: no documents to analyze.",
                    "warning",
                    active=False,
                    percent=100,
                    dataset=n,
                )
                return

            successes = sum(1 for r in results if "error" not in r.get("result", {}))
            errors = len(results) - successes

            _update_dataset_status(n, "analyzed")

            _emit_dataset_progress(n, 100, f"Analysis complete! {successes} succeeded, {errors} failed")
            _emit_progress(
                f"Dataset {n} analyzed! {successes} succeeded, {errors} failed.",
                "success",
                active=False,
                percent=100,
                dataset=n,
            )
        except Exception as exc:
            logger.exception("Dataset %d analysis failed", n)
            _update_dataset_status(n, "error")
            _emit_progress(
                f"Dataset {n} analysis FAILED. Check server logs.",
                "error",
                active=False,
                percent=100,
                dataset=n,
            )

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
    result = _get_db().auto_compact() or {}
    # Normalize result shape so decoy/proxy DBs cannot trigger 500s.
    freed_bytes = result.get("freed_bytes", 0)
    try:
        freed_bytes = int(freed_bytes)
    except (TypeError, ValueError):
        freed_bytes = 0
    freed_mb = result.get("freed_mb")
    if freed_mb is None:
        freed_mb = round(freed_bytes / (1024 ** 2), 1)
    result["freed_bytes"] = freed_bytes
    result["freed_mb"] = freed_mb
    result.setdefault("actions", [])
    _get_db().log_action("auto_compact", json.dumps(result))
    _emit_progress(f"Compact complete: freed {freed_mb} MB", "success", active=False, percent=100)
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
    _emit_live_updates(force=True)
    return jsonify({"flagged": bool(new_flag)})


# ============================================================================
#  SocketIO events
# ============================================================================

@socketio.on("connect")
def handle_connect():
    from flask import session as flask_session
    if not flask_session.get("authenticated"):
        return False  # Reject unauthenticated Socket.IO connections
    snap = _get_activity_snapshot()
    emit(
        "activity",
        {
            "active": snap.get("active", False),
            "dataset": snap.get("dataset"),
            "percent": snap.get("percent", 0),
            "message": snap.get("message", "Idle"),
            "level": snap.get("level", "info"),
        },
    )
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
    import argparse
    import yaml
    import getpass

    global _vault_auth, _vault_key_mgr, _vault_file_mgr, _vault_mode, _db

    parser = argparse.ArgumentParser(description="EpsteinAnalyzer Dashboard")
    parser.add_argument("--password", "-p", help="Vault password (skips interactive prompt)")
    parser.add_argument("--host", help="Bind host override")
    parser.add_argument("--port", type=int, help="Bind port override")
    args = parser.parse_args()

    config_path = PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    host = args.host or config.get("dashboard", {}).get("host", "127.0.0.1")
    port = args.port or config.get("dashboard", {}).get("port", 8080)
    debug = config.get("dashboard", {}).get("debug", False)

    # --- Vault integration ---
    vault_cfg = config.get("vault", {})
    vault_key_path = PROJECT_ROOT / vault_cfg.get("vault_key_path", "config/vault.key")

    if vault_key_path.exists():
        from security.vault import (
            KeyManager, DashboardAuth, VaultFileManager,
            DatabaseVault, NullDatabaseProxy,
            check_os_hardening, suppress_crash_dumps, prevent_sleep_while_unlocked,
        )

        # OS hardening
        suppress_crash_dumps()
        warnings = check_os_hardening()
        for w in warnings:
            print(f"  [!] WARNING: {w}")

        # First gate: console password prompt (or --password flag)
        _vault_key_mgr = KeyManager(str(vault_key_path))
        print(f"\n{'='*60}")
        print(f"  EpsteinAnalyzer - Vault Unlock")
        print(f"{'='*60}")

        if os.environ.get("EA_PASSWORD"):
            password = os.environ.pop("EA_PASSWORD")  # Read and clear from env
            print("  [*] Using password from EA_PASSWORD env var")
        elif args.password:
            password = args.password
            print("  [*] Using password from --password flag")
        else:
            try:
                password = getpass.getpass("  Enter password: ")
            except (EOFError, OSError):
                # getpass fails in some terminals
                password = input("  Enter password (visible): ")
        try:
            mode, secure_key = _vault_key_mgr.unlock(password)
            _vault_mode = mode
            print(f"  [+] Vault unlocked ({mode} mode)")

            # Derive Flask secret from DEK
            app.config["SECRET_KEY"] = _vault_key_mgr.get_flask_secret()

            # Decrypt database if encrypted
            if vault_cfg.get("encrypt_db_on_shutdown", True):
                db_path = PROJECT_ROOT / "data" / "epstein_analyzer.db"
                db_vault = DatabaseVault(_vault_key_mgr, str(db_path))
                if db_vault.decrypt_db():
                    print("  [+] Database decrypted")

            # Set up decoy mode if needed
            if mode == "decoy":
                schema_path = str(PROJECT_ROOT / "database" / "schema.sql")
                _db = NullDatabaseProxy(schema_path)
                print("  [+] Decoy mode: empty data will be shown")
            else:
                # Initialize vault file manager for serving encrypted files
                data_dir = str(Path(config["project"]["data_dir"]).resolve())
                _vault_file_mgr = VaultFileManager(_vault_key_mgr, data_dir, _get_db())

            # Set up authentication middleware (second gate: browser login)
            _vault_auth = DashboardAuth(app, _vault_key_mgr, config)
            prevent_sleep_while_unlocked()

        except ValueError as e:
            # Wrong password at console - could be decoy
            print(f"  [!] {e}")
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"  [!] {e}")
            sys.exit(1)
    else:
        # No vault configured — fail closed
        print("  [!] FATAL: No vault configured. Authentication is required.")
        print("  [!] Run 'python setup.py init' to set up the security vault.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  EpsteinAnalyzer Dashboard")
    print(f"  http://{host}:{port}")
    print(f"{'='*60}\n")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)

    # --- Shutdown: encrypt DB ---
    if _vault_key_mgr and vault_key_path.exists():
        try:
            from security.vault import DatabaseVault, allow_sleep
            vault_cfg = config.get("vault", {})
            if vault_cfg.get("encrypt_db_on_shutdown", True):
                db_path = PROJECT_ROOT / "data" / "epstein_analyzer.db"
                db_vault = DatabaseVault(_vault_key_mgr, str(db_path))
                conn = _get_db().get_connection()
                db_vault.checkpoint_and_encrypt(conn)
                print("  [+] Database encrypted on shutdown")
            _vault_key_mgr.lock()
            allow_sleep()
        except Exception as e:
            logger.warning("Shutdown encryption failed: %s", e)


if __name__ == "__main__":
    main()
