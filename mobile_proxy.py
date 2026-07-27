#!/usr/bin/env python3
"""
mobile_proxy.py
================
Run with:  mitmproxy -s mobile_proxy.py    (or mitmdump -s mobile_proxy.py)

Spins up a Flask dashboard on :5000 for intercepting/editing/forwarding
or dropping HTTP requests whose path contains "auth" or "login", built
for fast one-thumb editing on a mobile browser.

Architecture notes (read once, then forget about it):
- mitmproxy's `request()` hook runs inside its asyncio event loop. We
  never block that loop directly. Instead, a plain threading.Event is
  waited on inside `loop.run_in_executor(...)`, which hands the wait
  off to a worker thread. Flask (running in its own separate thread)
  just calls `event.set()` when you tap Forward/Drop. No cross-thread
  asyncio calls, no busy-polling sleep loops, no frozen proxy.
- The dashboard itself polls `/api/pending` every 400ms. That's plenty
  fast for interactive interception and far more robust over flaky
  mobile connections than maintaining a WebSocket. If you later want
  true push, swap the poll for `flask-sock` and call `ws.send()` from
  inside the addon when a flow is captured.
"""

import json
import re
import threading
import base64
import binascii
from urllib.parse import urlparse

from flask import Flask, request as flask_request, jsonify, Response
from mitmproxy import http

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
INTERCEPT_KEYWORDS = ("auth", "login")   # path substrings that trigger a freeze
FLASK_PORT = 5000
FLASK_HOST = "0.0.0.0"

# --------------------------------------------------------------------------
# Shared state between the mitmproxy addon thread and the Flask thread.
# Guarded by a single lock since both sides touch it.
# --------------------------------------------------------------------------
_lock = threading.Lock()
pending = {}   # flow.id -> dict(flow=..., event=threading.Event(), action=None, edited_body=None, edited_headers=None)


def _flow_summary(flow_id, entry):
    flow = entry["flow"]
    req = flow.request
    try:
        body_text = req.get_text(strict=False) or ""
    except Exception:
        body_text = req.content.decode("utf-8", errors="replace") if req.content else ""
    return {
        "id": flow_id,
        "method": req.method,
        "url": req.pretty_url,
        "path": req.path,
        "host": req.pretty_host,
        "headers": dict(req.headers),
        "body": body_text,
    }


# --------------------------------------------------------------------------
# mitmproxy addon
# --------------------------------------------------------------------------
class MobileInterceptAddon:

    def should_intercept(self, flow: http.HTTPFlow) -> bool:
        path_lower = flow.request.path.lower()
        return any(k in path_lower for k in INTERCEPT_KEYWORDS)

    async def request(self, flow: http.HTTPFlow):
        if not self.should_intercept(flow):
            return

        flow.intercept()  # visually marks it as intercepted in any console UI too
        ev = threading.Event()

        with _lock:
            pending[flow.id] = {
                "flow": flow,
                "event": ev,
                "action": None,
                "edited_body": None,
                "edited_headers": None,
            }

        # Wait off the asyncio loop -> proxy keeps serving all other traffic.
        import asyncio
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, ev.wait)

        with _lock:
            entry = pending.pop(flow.id, None)

        if entry is None:
            flow.resume()
            return

        action = entry["action"]

        if action == "drop":
            flow.kill()
            return

        # action == "forward" (or anything else defaults to forward-as-is)
        if entry["edited_headers"] is not None:
            flow.request.headers.clear()
            for k, v in entry["edited_headers"].items():
                flow.request.headers[k] = v

        if entry["edited_body"] is not None:
            flow.request.text = entry["edited_body"]

        flow.resume()


addon_instance = MobileInterceptAddon()
addons = [addon_instance]


# --------------------------------------------------------------------------
# Flask dashboard
# --------------------------------------------------------------------------
app = Flask(__name__)


@app.get("/api/pending")
def api_pending():
    with _lock:
        items = [_flow_summary(fid, entry) for fid, entry in pending.items()]
    return jsonify(items)


@app.get("/api/flow/<flow_id>")
def api_flow_detail(flow_id):
    with _lock:
        entry = pending.get(flow_id)
        if entry is None:
            return jsonify({"error": "not found or already resolved"}), 404
        data = _flow_summary(flow_id, entry)
    return jsonify(data)


@app.post("/api/flow/<flow_id>/forward")
def api_forward(flow_id):
    payload = flask_request.get_json(force=True, silent=True) or {}
    with _lock:
        entry = pending.get(flow_id)
        if entry is None:
            return jsonify({"error": "not found or already resolved"}), 404
        entry["edited_body"] = payload.get("body")
        headers = payload.get("headers")
        if isinstance(headers, dict):
            entry["edited_headers"] = headers
        entry["action"] = "forward"
        entry["event"].set()
    return jsonify({"status": "forwarded"})


@app.post("/api/flow/<flow_id>/drop")
def api_drop(flow_id):
    with _lock:
        entry = pending.get(flow_id)
        if entry is None:
            return jsonify({"error": "not found or already resolved"}), 404
        entry["action"] = "drop"
        entry["event"].set()
    return jsonify({"status": "dropped"})


@app.get("/")
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")


# --------------------------------------------------------------------------
# Mobile-first dashboard HTML/CSS/JS
# --------------------------------------------------------------------------
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Mobile Proxy Console</title>
<style>
  :root {
    --bg: #121212;
    --panel: #1b1b1b;
    --panel-border: #2b2b2b;
    --accent: #ff5252;
    --accent-green: #00e676;
    --accent-yellow: #ffd54f;
    --text: #eaeaea;
    --text-dim: #8a8a8a;
    --key-color: #82aaff;
    --string-color: #c3e88d;
    --num-color: #f78c6c;
    --token-color: #ff8a80;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    overscroll-behavior-y: contain;
  }
  #app { display: flex; flex-direction: column; height: 100dvh; }

  header {
    padding: 14px 16px 10px;
    border-bottom: 1px solid var(--panel-border);
    display: flex; align-items: center; justify-content: space-between;
  }
  header h1 { font-size: 1.05rem; margin: 0; font-weight: 700; letter-spacing: .3px; }
  #status-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--text-dim); flex-shrink: 0;
    transition: background .2s;
  }
  #status-dot.live { background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }

  #queue-strip {
    display: flex; gap: 8px; overflow-x: auto; padding: 10px 12px;
    border-bottom: 1px solid var(--panel-border);
    -webkit-overflow-scrolling: touch;
  }
  .queue-chip {
    flex-shrink: 0; padding: 10px 14px; border-radius: 10px;
    background: var(--panel); border: 1px solid var(--panel-border);
    font-size: .85rem; white-space: nowrap; cursor: pointer;
  }
  .queue-chip.active { border-color: var(--accent-yellow); color: var(--accent-yellow); }

  #empty-state {
    flex: 1; display: flex; align-items: center; justify-content: center;
    color: var(--text-dim); font-size: .95rem; text-align: center; padding: 24px;
  }

  #editor-area { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }

  #meta {
    padding: 10px 16px; font-size: .8rem; color: var(--text-dim);
    border-bottom: 1px solid var(--panel-border);
    display: flex; flex-direction: column; gap: 3px;
  }
  #meta .method-url { color: var(--text); font-size: .9rem; word-break: break-all; }
  #meta .method-url b { color: var(--accent-yellow); }

  #jwt-panel {
    display: none;
    margin: 10px 16px 0; padding: 10px 12px; border-radius: 10px;
    background: var(--panel); border: 1px solid var(--panel-border);
    font-size: .78rem;
  }
  #jwt-panel.show { display: block; }
  #jwt-panel h3 { margin: 0 0 6px; font-size: .78rem; color: var(--accent-yellow); }
  #jwt-panel pre {
    margin: 4px 0; padding: 8px; background: #0e0e0e; border-radius: 6px;
    white-space: pre-wrap; word-break: break-all; color: var(--string-color);
    max-height: 110px; overflow-y: auto;
  }
  #jwt-panel button {
    margin-top: 6px; padding: 8px 12px; border-radius: 8px; border: none;
    background: var(--key-color); color: #001; font-weight: 600; font-size: .78rem;
  }

  #macro-row {
    display: flex; gap: 10px; overflow-x: auto; padding: 12px 16px;
    -webkit-overflow-scrolling: touch;
  }
  .macro-btn {
    flex-shrink: 0; padding: 14px 18px; border-radius: 12px; border: none;
    font-size: .95rem; font-weight: 600; white-space: nowrap;
    background: #2a2a2a; color: var(--text);
    border: 1px solid var(--panel-border);
  }
  .macro-btn:active { transform: scale(0.96); }
  .macro-btn.admin { color: var(--token-color); }
  .macro-btn.role { color: var(--key-color); }
  .macro-btn.clear { color: var(--text-dim); }

  #body-wrap { flex: 1; padding: 0 16px 12px; min-height: 0; display: flex; }
  #body-textarea {
    flex: 1; width: 100%; resize: none;
    background: #0e0e0e; color: var(--text);
    border: 1px solid var(--panel-border); border-radius: 12px;
    font-size: 16px; line-height: 1.5;
    padding: 16px 14px; font-family: "SF Mono", Menlo, Consolas, monospace;
  }
  #body-textarea:focus { outline: none; border-color: var(--key-color); }

  #headers-toggle {
    margin: 0 16px 10px; font-size: .8rem; color: var(--text-dim);
    text-align: right; text-decoration: underline;
  }

  #action-bar {
    display: flex; gap: 10px; padding: 12px 16px calc(12px + env(safe-area-inset-bottom));
    border-top: 1px solid var(--panel-border);
  }
  #action-bar button {
    flex: 1; padding: 18px 0; border: none; border-radius: 14px;
    font-size: 1.05rem; font-weight: 800; letter-spacing: .5px;
  }
  #forward-btn { background: var(--accent-green); color: #002b12; }
  #drop-btn { background: var(--accent); color: #2b0000; }
  #forward-btn:active, #drop-btn:active { transform: scale(0.97); }
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>&#128737;&#65039; Mobile Proxy Console</h1>
    <div id="status-dot"></div>
  </header>

  <div id="queue-strip"></div>

  <div id="empty-state">No requests intercepted yet.<br>Waiting for /auth or /login traffic&hellip;</div>

  <div id="editor-area" style="display:none">
    <div id="meta">
      <div class="method-url"><b id="meta-method"></b> <span id="meta-url"></span></div>
      <div id="meta-host"></div>
    </div>

    <div id="jwt-panel">
      <h3>&#128273; JWT detected (editable, will be re-encoded on Forward)</h3>
      <div>Header</div>
      <pre id="jwt-header" contenteditable="true"></pre>
      <div>Payload</div>
      <pre id="jwt-payload" contenteditable="true"></pre>
      <button id="jwt-apply">Apply JWT edits to body</button>
    </div>

    <div id="macro-row">
      <button class="macro-btn admin" data-macro="is_admin">is_admin=true</button>
      <button class="macro-btn role" data-macro="role_admin">Role: Admin</button>
      <button class="macro-btn clear" data-macro="clear">Clear Content</button>
    </div>

    <div id="body-wrap">
      <textarea id="body-textarea" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea>
    </div>

    <div id="action-bar">
      <button id="drop-btn">DROP</button>
      <button id="forward-btn">FORWARD REQUEST</button>
    </div>
  </div>
</div>

<script>
const POLL_MS = 400;
let currentFlowId = null;
let currentHeaders = {};
let flowsCache = {};
let jwtLocation = null; // {source: 'body'|'header', headerName, start, end}

const els = {
  statusDot: document.getElementById('status-dot'),
  queueStrip: document.getElementById('queue-strip'),
  emptyState: document.getElementById('empty-state'),
  editorArea: document.getElementById('editor-area'),
  metaMethod: document.getElementById('meta-method'),
  metaUrl: document.getElementById('meta-url'),
  metaHost: document.getElementById('meta-host'),
  bodyTextarea: document.getElementById('body-textarea'),
  jwtPanel: document.getElementById('jwt-panel'),
  jwtHeader: document.getElementById('jwt-header'),
  jwtPayload: document.getElementById('jwt-payload'),
  jwtApply: document.getElementById('jwt-apply'),
  forwardBtn: document.getElementById('forward-btn'),
  dropBtn: document.getElementById('drop-btn'),
};

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try {
    return decodeURIComponent(atob(str).split('').map(c =>
      '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
  } catch (e) {
    try { return atob(str); } catch (e2) { return null; }
  }
}

function b64urlEncode(str) {
  let b64 = btoa(unescape(encodeURIComponent(str)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function findJwt(text) {
  const re = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}/;
  const m = re.exec(text);
  if (!m) return null;
  const header = b64urlDecode(m[0].split('.')[0]);
  const payload = b64urlDecode(m[0].split('.')[1]);
  if (!header || !payload) return null;
  try { JSON.parse(header); JSON.parse(payload); } catch (e) { return null; }
  return { raw: m[0], header, payload, index: m.index };
}

function prettyJson(str) {
  try { return JSON.stringify(JSON.parse(str), null, 2); } catch (e) { return str; }
}

function updateJwtPanel() {
  const text = els.bodyTextarea.value;
  const jwt = findJwt(text);
  if (!jwt) {
    els.jwtPanel.classList.remove('show');
    jwtLocation = null;
    return;
  }
  jwtLocation = jwt;
  els.jwtPanel.classList.add('show');
  els.jwtHeader.textContent = prettyJson(jwt.header);
  els.jwtPayload.textContent = prettyJson(jwt.payload);
}

els.jwtApply.addEventListener('click', () => {
  if (!jwtLocation) return;
  try {
    const newHeader = b64urlEncode(JSON.stringify(JSON.parse(els.jwtHeader.textContent)));
    const newPayload = b64urlEncode(JSON.stringify(JSON.parse(els.jwtPayload.textContent)));
    // signature segment kept as-is; re-signing needs the server's key
    const oldSig = jwtLocation.raw.split('.')[2];
    const newToken = `${newHeader}.${newPayload}.${oldSig}`;
    els.bodyTextarea.value = els.bodyTextarea.value.replace(jwtLocation.raw, newToken);
    updateJwtPanel();
  } catch (e) {
    alert('JWT JSON is invalid, fix it before applying.');
  }
});

// ---- macros ----
function tryParseJson(text) {
  try { return JSON.parse(text); } catch (e) { return null; }
}

document.querySelectorAll('.macro-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const macro = btn.dataset.macro;
    const text = els.bodyTextarea.value;

    if (macro === 'clear') {
      els.bodyTextarea.value = '';
      updateJwtPanel();
      return;
    }

    if (macro === 'is_admin') {
      const obj = tryParseJson(text);
      if (obj !== null && typeof obj === 'object') {
        obj.is_admin = true;
        els.bodyTextarea.value = JSON.stringify(obj, null, 2);
      } else if (/^[\w.\[\]%-]+=.*/.test(text.trim()) || text.includes('=')) {
        // looks form-encoded
        let newText = text.replace(/([?&]?)is_admin=[^&]*/i, '');
        newText = newText.replace(/&+$/,'').trim();
        newText += (newText.length && !newText.endsWith('&') ? '&' : '') + 'is_admin=true';
        els.bodyTextarea.value = newText;
      } else {
        els.bodyTextarea.value = text + (text.length ? '\n' : '') + 'is_admin=true';
      }
      updateJwtPanel();
      return;
    }

    if (macro === 'role_admin') {
      const obj = tryParseJson(text);
      if (obj !== null && typeof obj === 'object') {
        obj.role = 'admin';
        els.bodyTextarea.value = JSON.stringify(obj, null, 2);
      } else if (/["']?role["']?\s*[:=]/i.test(text)) {
        els.bodyTextarea.value = text.replace(/(["']?role["']?\s*[:=]\s*["']?)([\w-]*)(["']?)/i,
          (m, p1, p2, p3) => `${p1}admin${p3}`);
      } else {
        els.bodyTextarea.value = text + (text.length ? '\n' : '') + 'Role: Admin';
      }
      updateJwtPanel();
      return;
    }
  });
});

// ---- rendering ----
function renderQueue(items) {
  els.queueStrip.innerHTML = '';
  if (items.length === 0) {
    els.emptyState.style.display = 'flex';
    els.editorArea.style.display = 'none';
    currentFlowId = null;
    return;
  }
  els.emptyState.style.display = 'none';

  items.forEach(item => {
    flowsCache[item.id] = item;
    const chip = document.createElement('div');
    chip.className = 'queue-chip' + (item.id === currentFlowId ? ' active' : '');
    chip.textContent = `${item.method} ${new URL(item.url).pathname}`;
    chip.addEventListener('click', () => selectFlow(item.id));
    els.queueStrip.appendChild(chip);
  });

  if (!currentFlowId || !flowsCache[currentFlowId]) {
    selectFlow(items[0].id);
  }
}

function selectFlow(id) {
  currentFlowId = id;
  const item = flowsCache[id];
  if (!item) return;
  els.editorArea.style.display = 'flex';
  els.metaMethod.textContent = item.method;
  els.metaUrl.textContent = item.url;
  els.metaHost.textContent = 'Host: ' + item.host;
  els.bodyTextarea.value = item.body || '';
  currentHeaders = item.headers || {};
  updateJwtPanel();
  document.querySelectorAll('.queue-chip').forEach(c => c.classList.remove('active'));
}

async function poll() {
  try {
    const res = await fetch('/api/pending', { cache: 'no-store' });
    const items = await res.json();
    els.statusDot.classList.add('live');
    renderQueue(items);
  } catch (e) {
    els.statusDot.classList.remove('live');
  } finally {
    setTimeout(poll, POLL_MS);
  }
}
poll();

// ---- actions ----
async function sendAction(action) {
  if (!currentFlowId) return;
  const body = { body: els.bodyTextarea.value, headers: currentHeaders };
  await fetch(`/api/flow/${currentFlowId}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  delete flowsCache[currentFlowId];
  currentFlowId = null;
}

els.forwardBtn.addEventListener('click', () => sendAction('forward'));
els.dropBtn.addEventListener('click', () => sendAction('drop'));
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Boot Flask in a background thread as soon as mitmproxy loads this addon.
# threaded=True lets Flask handle overlapping requests from the dashboard
# (polling + forward/drop) without blocking each other.
# --------------------------------------------------------------------------
def _run_flask():
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False, threaded=True)


_flask_thread = threading.Thread(target=_run_flask, daemon=True, name="flask-dashboard")
_flask_thread.start()
