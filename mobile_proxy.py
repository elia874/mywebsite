#!/usr/bin/env python3
"""
mobile_proxy.py
================
A general-purpose, Burp-Suite-style intercepting proxy console, run as an
inline mitmproxy addon with a mobile-first Flask dashboard.

Run with:  mitmproxy -s mobile_proxy.py    (or mitmdump -s mobile_proxy.py)
Requires:  pip install mitmproxy flask requests --break-system-packages

Dashboard: http://<VPS_IP>:5000

Feature map (mirrors Burp Suite's core workflow, condensed for a phone):
  - Proxy / Intercept : freeze matching requests mid-flight, edit, forward/drop.
  - Scope             : domain include/exclude rules, path regex, HTTP methods,
                         master intercept on/off switch (like Burp's Target > Scope
                         + the big red "Intercept is on" button).
  - HTTP History       : passive log of every request/response that passes through
                         the proxy, whether intercepted or not (like Burp's Proxy
                         > HTTP history / Logger).
  - Repeater           : pick any past request from history, edit it, and fire it
                         again on its own independent connection (does not touch
                         the live traffic flow).
  - Match & Replace    : regex rules applied automatically to every request's URL,
                         headers, or body as it passes through -- no freezing needed.
  - Decoder            : quick base64 / URL / hex encode-decode utility.

Architecture notes:
  - mitmproxy's request()/response() hooks run inside its own asyncio loop.
    Freezing a flow never blocks that loop: we await a threading.Event via
    loop.run_in_executor(), so the rest of your traffic keeps moving while
    one flow sits paused for you to review on your phone.
  - Flask runs in a separate daemon thread (threaded=True) so dashboard
    polling and forward/drop actions don't block each other.
  - The dashboard polls every 400ms. That's fast enough to feel live and is
    far more robust than WebSockets over a shaky mobile connection. Swap in
    flask-sock later if you want true push.
  - Repeater resends use the `requests` library on a totally separate
    connection from mitmproxy's own transport, exactly like Burp Repeater
    does -- it does not replay through the intercepted flow object.
"""

import os
import json
import re
import threading
import itertools
from collections import deque

from flask import Flask, request as flask_request, jsonify, Response
from mitmproxy import http

try:
    import requests as pyrequests
except ImportError:
    pyrequests = None  # Repeater resend will report a clear error if missing

# --------------------------------------------------------------------------
# Config / constants
# --------------------------------------------------------------------------
FLASK_PORT = 5000
FLASK_HOST = "0.0.0.0"
HISTORY_MAXLEN = 400
BODY_PREVIEW_LEN = 400   # truncate body previews in the history list view

# --------------------------------------------------------------------------
# Shared state (all guarded by _lock, touched from both the mitmproxy thread
# and the Flask thread)
# --------------------------------------------------------------------------
_lock = threading.Lock()

SETTINGS = {
    "intercept_enabled": False,  # OFF by default -- user must flip the master switch
    "domain_include": [],   # substrings; empty = all domains in scope
    "domain_exclude": [],   # substrings; if matched, always out of scope
    "path_regex": "",       # empty = match all paths
    "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
}

# Persisted to disk next to this script so a mitmdump restart/crash doesn't
# silently wipe the intercept toggle / scope rules back to hardcoded defaults.
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_settings.json")


def _load_settings_from_disk():
    try:
        with open(SETTINGS_FILE, "r") as f:
            saved = json.load(f)
        SETTINGS.update({k: v for k, v in saved.items() if k in SETTINGS})
    except FileNotFoundError:
        pass
    except Exception:
        pass  # corrupt/unreadable file -- fall back to defaults rather than crash


def _save_settings_to_disk():
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(SETTINGS, f)
    except Exception:
        pass  # best-effort -- never let a disk error break the proxy


_load_settings_from_disk()

MATCH_REPLACE = []          # list of {id, enabled, target, match, replace}
_mr_id_counter = itertools.count(1)

HISTORY_STORE = {}           # id -> entry dict
HISTORY_ORDER = deque(maxlen=HISTORY_MAXLEN)   # ids, oldest first
_history_seq_counter = itertools.count(1)      # Burp-style running request number (#)

pending = {}                 # flow.id -> {flow, event, action, edited_body, edited_headers}


def _new_mr_id():
    return f"mr{next(_mr_id_counter)}"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _get_text_safe(req):
    try:
        return req.get_text(strict=False) or ""
    except Exception:
        try:
            return req.content.decode("utf-8", errors="replace") if req.content else ""
        except Exception:
            return ""


def _short_mime(content_type):
    if not content_type:
        return ""
    base = content_type.split(";")[0].strip().lower()
    # collapse common types down to Burp-style short labels
    if "json" in base:
        return "JSON"
    if "html" in base:
        return "HTML"
    if "xml" in base:
        return "XML"
    if "javascript" in base or base == "text/js":
        return "script"
    if base.startswith("image/"):
        return "image"
    if "css" in base:
        return "CSS"
    if base.startswith("text/"):
        return "text"
    return base or ""


def in_scope(flow: http.HTTPFlow) -> bool:
    req = flow.request
    if req.method not in SETTINGS["methods"]:
        return False

    host = req.pretty_host.lower()
    includes = SETTINGS["domain_include"]
    excludes = SETTINGS["domain_exclude"]

    if any(x.lower() in host for x in excludes if x):
        return False
    if includes and not any(x.lower() in host for x in includes if x):
        return False

    pattern = SETTINGS["path_regex"]
    if pattern:
        try:
            if not re.search(pattern, req.path):
                return False
        except re.error:
            pass  # bad regex -> don't crash the proxy, just don't filter on it

    return True


def apply_match_replace(flow: http.HTTPFlow):
    req = flow.request
    with _lock:
        rules = [r for r in MATCH_REPLACE if r["enabled"]]

    for rule in rules:
        try:
            if rule["target"] == "req_url":
                new_path = re.sub(rule["match"], rule["replace"], req.path)
                req.path = new_path
            elif rule["target"] == "req_header":
                for k in list(req.headers.keys()):
                    v = req.headers[k]
                    new_v = re.sub(rule["match"], rule["replace"], v)
                    if new_v != v:
                        req.headers[k] = new_v
            elif rule["target"] == "req_body":
                body = _get_text_safe(req)
                new_body = re.sub(rule["match"], rule["replace"], body)
                if new_body != body:
                    req.text = new_body
        except re.error:
            continue  # skip malformed rule, keep proxying


def log_request(flow: http.HTTPFlow, intercepted: bool):
    import time
    req_body = _get_text_safe(flow.request)
    has_params = bool(flow.request.query) or bool(req_body)
    entry = {
        "id": flow.id,
        "seq": next(_history_seq_counter),
        "ts": time.strftime("%H:%M:%S"),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "path": flow.request.path,
        "host": flow.request.pretty_host,
        "req_headers": dict(flow.request.headers),
        "req_body": req_body,
        "req_length": len(req_body.encode("utf-8", errors="replace")) if req_body else 0,
        "params": has_params,
        "edited": False,
        "status": None,
        "resp_headers": {},
        "resp_body": "",
        "length": None,
        "mime": "",
        "intercepted": intercepted,
    }

    with _lock:
        HISTORY_STORE[flow.id] = entry
        if flow.id not in HISTORY_ORDER:
            if len(HISTORY_ORDER) == HISTORY_ORDER.maxlen:
                oldest = HISTORY_ORDER[0]
                HISTORY_STORE.pop(oldest, None)
            HISTORY_ORDER.append(flow.id)


def log_response(flow: http.HTTPFlow):
    with _lock:
        entry = HISTORY_STORE.get(flow.id)
        if entry is None:
            return
        resp_body = _get_text_safe(flow.response) if flow.response else ""
        entry["status"] = flow.response.status_code if flow.response else None
        entry["resp_headers"] = dict(flow.response.headers) if flow.response else {}
        entry["resp_body"] = resp_body
        entry["length"] = len(resp_body.encode("utf-8", errors="replace")) if resp_body else 0
        entry["mime"] = _short_mime(entry["resp_headers"].get("content-type", ""))


def _history_summary(entry):
    body = entry["req_body"] or ""
    return {
        "id": entry["id"],
        "seq": entry["seq"],
        "ts": entry["ts"],
        "method": entry["method"],
        "url": entry["url"],
        "path": entry["path"],
        "host": entry["host"],
        "status": entry["status"],
        "intercepted": entry["intercepted"],
        "edited": entry["edited"],
        "params": entry["params"],
        "req_length": entry["req_length"],
        "length": entry["length"],
        "mime": entry["mime"],
        "body_preview": body[:BODY_PREVIEW_LEN],
    }


def _flow_summary(flow_id, entry):
    flow = entry["flow"]
    req = flow.request
    return {
        "id": flow_id,
        "method": req.method,
        "url": req.pretty_url,
        "path": req.path,
        "host": req.pretty_host,
        "headers": dict(req.headers),
        "body": _get_text_safe(req),
    }


# --------------------------------------------------------------------------
# mitmproxy addon
# --------------------------------------------------------------------------
class MobileInterceptAddon:

    async def request(self, flow: http.HTTPFlow):
        apply_match_replace(flow)

        with _lock:
            enabled = SETTINGS["intercept_enabled"]
        should_freeze = enabled and in_scope(flow)

        log_request(flow, intercepted=should_freeze)

        if not should_freeze:
            return

        flow.intercept()
        ev = threading.Event()
        with _lock:
            pending[flow.id] = {
                "flow": flow,
                "event": ev,
                "action": None,
                "edited_body": None,
                "edited_headers": None,
            }

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

        if entry["edited_headers"] is not None:
            flow.request.headers.clear()
            for k, v in entry["edited_headers"].items():
                flow.request.headers[k] = v
        if entry["edited_body"] is not None:
            flow.request.text = entry["edited_body"]

        # reflect the final, edited version in history
        with _lock:
            hist = HISTORY_STORE.get(flow.id)
            if hist is not None:
                hist["req_headers"] = dict(flow.request.headers)
                hist["req_body"] = entry["edited_body"] if entry["edited_body"] is not None else hist["req_body"]
                if entry["edited_body"] is not None or entry["edited_headers"] is not None:
                    hist["edited"] = True
                    hist["req_length"] = len(hist["req_body"].encode("utf-8", errors="replace")) if hist["req_body"] else 0

        flow.resume()

    def response(self, flow: http.HTTPFlow):
        log_response(flow)


addon_instance = MobileInterceptAddon()
addons = [addon_instance]


# --------------------------------------------------------------------------
# Flask dashboard
# --------------------------------------------------------------------------
app = Flask(__name__)


# ---- intercept queue ----
@app.get("/api/pending")
def api_pending():
    with _lock:
        items = [_flow_summary(fid, entry) for fid, entry in pending.items()]
    return jsonify(items)


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


# ---- history / logger ----
@app.get("/api/history")
def api_history():
    with _lock:
        ids = list(HISTORY_ORDER)[::-1]  # newest first
        items = [_history_summary(HISTORY_STORE[i]) for i in ids if i in HISTORY_STORE]
    return jsonify(items)


@app.get("/api/history/<hist_id>")
def api_history_detail(hist_id):
    with _lock:
        entry = HISTORY_STORE.get(hist_id)
        if entry is None:
            return jsonify({"error": "not found"}), 404
        data = dict(entry)
    return jsonify(data)


@app.delete("/api/history")
def api_history_clear():
    with _lock:
        HISTORY_STORE.clear()
        HISTORY_ORDER.clear()
    return jsonify({"status": "cleared"})


# ---- repeater ----
@app.post("/api/repeater/send")
def api_repeater_send():
    if pyrequests is None:
        return jsonify({"error": "the 'requests' package is not installed on the VPS "
                                  "(pip install requests --break-system-packages)"}), 500

    payload = flask_request.get_json(force=True, silent=True) or {}
    method = (payload.get("method") or "GET").upper()
    url = payload.get("url") or ""
    headers = payload.get("headers") or {}
    body = payload.get("body") or ""

    if not url:
        return jsonify({"error": "missing url"}), 400

    try:
        import time as _time
        t0 = _time.monotonic()
        resp = pyrequests.request(
            method, url, headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=20, allow_redirects=False, verify=False,
        )
        elapsed_ms = round((_time.monotonic() - t0) * 1000)
        remote_addr = ""
        try:
            conn = resp.raw._connection.sock.getpeername()
            remote_addr = f"{conn[0]}:{conn[1]}"
        except Exception:
            pass
        return jsonify({
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:20000],
            "elapsed_ms": elapsed_ms,
            "remote_addr": remote_addr,
            "http_version": {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(resp.raw.version, ""),
            "content_type": resp.headers.get("Content-Type", ""),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ---- scope / settings ----
@app.get("/api/settings")
def api_settings_get():
    with _lock:
        return jsonify(SETTINGS)


@app.post("/api/settings")
def api_settings_set():
    payload = flask_request.get_json(force=True, silent=True) or {}
    with _lock:
        if "intercept_enabled" in payload:
            SETTINGS["intercept_enabled"] = bool(payload["intercept_enabled"])
        if "domain_include" in payload:
            SETTINGS["domain_include"] = [x.strip() for x in payload["domain_include"] if x.strip()]
        if "domain_exclude" in payload:
            SETTINGS["domain_exclude"] = [x.strip() for x in payload["domain_exclude"] if x.strip()]
        if "path_regex" in payload:
            SETTINGS["path_regex"] = payload["path_regex"]
        if "methods" in payload and isinstance(payload["methods"], list):
            SETTINGS["methods"] = payload["methods"]
        result = dict(SETTINGS)
    return jsonify(result)


# ---- match & replace ----
@app.get("/api/match-replace")
def api_mr_list():
    with _lock:
        return jsonify(MATCH_REPLACE)


@app.post("/api/match-replace")
def api_mr_add():
    payload = flask_request.get_json(force=True, silent=True) or {}
    rule = {
        "id": _new_mr_id(),
        "enabled": True,
        "target": payload.get("target", "req_header"),   # req_header | req_body | req_url
        "match": payload.get("match", ""),
        "replace": payload.get("replace", ""),
    }
    with _lock:
        MATCH_REPLACE.append(rule)
    return jsonify(rule)


@app.post("/api/match-replace/<rule_id>/toggle")
def api_mr_toggle(rule_id):
    with _lock:
        for r in MATCH_REPLACE:
            if r["id"] == rule_id:
                r["enabled"] = not r["enabled"]
                return jsonify(r)
    return jsonify({"error": "not found"}), 404


@app.delete("/api/match-replace/<rule_id>")
def api_mr_delete(rule_id):
    with _lock:
        MATCH_REPLACE[:] = [r for r in MATCH_REPLACE if r["id"] != rule_id]
    return jsonify({"status": "deleted"})


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
    --bg: #121212; --panel: #1b1b1b; --panel-border: #2b2b2b;
    --accent: #ff5252; --accent-green: #00e676; --accent-yellow: #ffd54f;
    --text: #eaeaea; --text-dim: #8a8a8a;
    --key-color: #82aaff; --string-color: #c3e88d;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body { margin:0; padding:0; height:100%; background:var(--bg); color:var(--text);
    font-family:-apple-system, BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; overscroll-behavior-y:contain; }
  #app { display:flex; flex-direction:column; height:100dvh; }

  header { padding:12px 16px 8px; border-bottom:1px solid var(--panel-border);
    display:flex; align-items:center; justify-content:space-between; }
  header h1 { font-size:1rem; margin:0; font-weight:700; }
  #status-dot { width:10px; height:10px; border-radius:50%; background:var(--text-dim); flex-shrink:0; }
  #status-dot.live { background:var(--accent-green); box-shadow:0 0 8px var(--accent-green); }

  #tabs { display:flex; border-bottom:1px solid var(--panel-border); overflow-x:auto; }
  .tab-btn { flex:1; padding:12px 8px; background:none; border:none; color:var(--text-dim);
    font-size:.78rem; font-weight:700; border-bottom:2px solid transparent; white-space:nowrap; }
  .tab-btn.active { color:var(--accent-yellow); border-bottom-color:var(--accent-yellow); }

  .panel { display:none; flex:1; min-height:0; flex-direction:column; overflow:hidden; }
  .panel.active { display:flex; }

  .scroll-list { flex:1; overflow-y:auto; -webkit-overflow-scrolling:touch; }
  .status-chip { padding:2px 6px; border-radius:6px; font-weight:700; }
  .status-2xx { background:#0d3320; color:var(--accent-green); }
  .status-3xx { background:#332d0d; color:var(--accent-yellow); }
  .status-4xx, .status-5xx { background:#330d0d; color:var(--accent); }

  #queue-strip { display:flex; flex-direction:column; gap:0; overflow-y:auto; max-height:38vh;
    border-bottom:1px solid var(--panel-border); -webkit-overflow-scrolling:touch; }
  .queue-chip { padding:10px 14px; background:var(--panel); border-bottom:1px solid var(--panel-border);
    font-size:.85rem; }
  .queue-chip.active { border-left:3px solid var(--accent-yellow); color:var(--accent-yellow); }

  #intercept-toolbar { display:flex; align-items:center; justify-content:space-between;
    padding:10px 16px; border-bottom:1px solid var(--panel-border); gap:10px; }
  .intercept-pill { display:flex; align-items:center; gap:8px; padding:8px 14px; border-radius:20px;
    background:var(--panel); border:1px solid var(--panel-border); font-size:.8rem; font-weight:700; }
  .intercept-pill .dot { width:9px; height:9px; border-radius:50%; background:var(--text-dim); }
  .intercept-pill.on .dot { background:var(--accent-green); box-shadow:0 0 6px var(--accent-green); }
  .intercept-pill.on { border-color:var(--accent-green); color:var(--accent-green); }
  .intercept-pill.off { color:var(--text-dim); }

  /* Burp-style vertical request row: line 1 = # / time / status / length / mime,
     line 2 = METHOD + URL, line 3 = badges (params / edited / intercepted) */
  .req-row { padding:10px 16px; border-bottom:1px solid var(--panel-border); }
  .req-row .row-top { display:flex; align-items:center; gap:8px; font-size:.72rem; color:var(--text-dim);
    flex-wrap:wrap; }
  .req-row .row-top .seq { color:var(--key-color); font-weight:700; }
  .req-row .row-top .time { }
  .req-row .row-top .len { margin-left:auto; }
  .req-row .row-url { font-size:.85rem; margin-top:4px; word-break:break-all; }
  .req-row .row-url .method { color:var(--key-color); font-weight:700; margin-right:6px; }
  .req-row .row-badges { display:flex; gap:6px; margin-top:6px; flex-wrap:wrap; }
  .req-badge { font-size:.68rem; font-weight:700; padding:2px 7px; border-radius:6px; }
  .badge-params { background:#1b2a3a; color:var(--key-color); }
  .badge-edited { background:#3a2a0d; color:var(--accent-yellow); }
  .badge-intercepted { background:#3a0d1a; color:var(--accent); }
  .badge-mime { background:#222; color:var(--text-dim); }
  .req-row .preview { font-size:.75rem; color:var(--text-dim); margin-top:4px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

  .empty-state { flex:1; display:flex; align-items:center; justify-content:center;
    color:var(--text-dim); font-size:.9rem; text-align:center; padding:24px; }

  #meta { padding:10px 16px; font-size:.8rem; color:var(--text-dim);
    border-bottom:1px solid var(--panel-border); display:flex; flex-direction:column; gap:3px; }
  #meta .method-url { color:var(--text); font-size:.88rem; word-break:break-all; }
  #meta .method-url b { color:var(--accent-yellow); }

  .jwt-panel { display:none; margin:10px 16px 0; padding:10px 12px; border-radius:10px;
    background:var(--panel); border:1px solid var(--panel-border); font-size:.78rem; }
  .jwt-panel.show { display:block; }
  .jwt-panel h3 { margin:0 0 6px; font-size:.78rem; color:var(--accent-yellow); }
  .jwt-panel pre { margin:4px 0; padding:8px; background:#0e0e0e; border-radius:6px;
    white-space:pre-wrap; word-break:break-all; color:var(--string-color); max-height:100px; overflow-y:auto; }
  .jwt-panel button { margin-top:6px; padding:8px 12px; border-radius:8px; border:none;
    background:var(--key-color); color:#001; font-weight:600; font-size:.78rem; }

  .macro-row { display:flex; gap:10px; overflow-x:auto; padding:12px 16px; -webkit-overflow-scrolling:touch; }
  .macro-btn { flex-shrink:0; padding:14px 18px; border-radius:12px; border:1px solid var(--panel-border);
    font-size:.92rem; font-weight:600; white-space:nowrap; background:#2a2a2a; color:var(--text); }
  .macro-btn:active { transform:scale(0.96); }

  .body-wrap { flex:1; padding:0 16px 12px; min-height:0; display:flex; }
  textarea.big-edit { flex:1; width:100%; resize:none; background:#0e0e0e; color:var(--text);
    border:1px solid var(--panel-border); border-radius:12px; font-size:16px; line-height:1.5;
    padding:16px 14px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  textarea.big-edit:focus { outline:none; border-color:var(--key-color); }

  .action-bar { display:flex; gap:10px; padding:12px 16px calc(12px + env(safe-area-inset-bottom));
    border-top:1px solid var(--panel-border); }
  .action-bar button { flex:1; padding:16px 0; border:none; border-radius:14px;
    font-size:1rem; font-weight:800; letter-spacing:.4px; }
  .btn-green { background:var(--accent-green); color:#002b12; }
  .btn-red { background:var(--accent); color:#2b0000; }
  .btn-blue { background:var(--key-color); color:#001; }
  .action-bar button:active { transform:scale(0.97); }

  .settings-scroll { flex:1; overflow-y:auto; padding:14px 16px 40px; }
  .field-block { margin-bottom:18px; }
  .field-block label { display:block; font-size:.8rem; color:var(--text-dim); margin-bottom:6px; font-weight:700; }
  .field-block input[type=text], .field-block textarea {
    width:100%; background:#0e0e0e; color:var(--text); border:1px solid var(--panel-border);
    border-radius:10px; padding:12px; font-size:16px; }
  .method-chip-row { display:flex; flex-wrap:wrap; gap:8px; }
  .method-chip { padding:10px 14px; border-radius:10px; background:#2a2a2a; border:1px solid var(--panel-border);
    font-size:.85rem; font-weight:700; color:var(--text-dim); }
  .method-chip.on { color:var(--accent-green); border-color:var(--accent-green); }
  .toggle-row { display:flex; align-items:center; justify-content:space-between;
    padding:14px; border-radius:12px; background:var(--panel); border:1px solid var(--panel-border); margin-bottom:18px; }
  .toggle-switch { width:52px; height:30px; border-radius:20px; background:#333; position:relative; flex-shrink:0; }
  .toggle-switch.on { background:var(--accent-green); }
  .toggle-switch::after { content:''; position:absolute; top:3px; left:3px; width:24px; height:24px;
    border-radius:50%; background:#fff; transition:left .15s; }
  .toggle-switch.on::after { left:25px; }
  .save-btn { width:100%; padding:16px; border:none; border-radius:12px; background:var(--key-color);
    color:#001; font-weight:800; font-size:.95rem; margin-top:6px; }

  .mr-rule { padding:12px; border-radius:10px; background:var(--panel); border:1px solid var(--panel-border);
    margin-bottom:10px; font-size:.8rem; }
  .mr-rule .row1 { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
  .mr-rule .target-tag { color:var(--key-color); font-weight:700; }
  .mr-rule code { color:var(--string-color); word-break:break-all; }
  .mr-rule .mr-actions { display:flex; gap:8px; margin-top:8px; }
  .mr-rule .mr-actions button { padding:8px 12px; border-radius:8px; border:none; font-size:.75rem; font-weight:700; }

  .decoder-wrap { flex:1; display:flex; flex-direction:column; padding:14px 16px; gap:10px; overflow-y:auto; }
  .decoder-wrap textarea { min-height:110px; }
  .decoder-btns { display:flex; flex-wrap:wrap; gap:8px; }
  .decoder-btns button { padding:12px 14px; border-radius:10px; border:1px solid var(--panel-border);
    background:#2a2a2a; color:var(--text); font-size:.8rem; font-weight:700; }

  /* ---- Repeater (Reqable-style) ---- */
  #rep-urlbar { display:flex; gap:6px; padding:10px 16px; border-bottom:1px solid var(--panel-border); }
  .method-select { flex:0 0 92px; background:#0e0e0e; color:var(--accent-yellow); font-weight:800;
    border:1px solid var(--panel-border); border-radius:8px; padding:0 6px; font-size:.85rem; }
  .url-input { flex:1; min-width:0; background:#0e0e0e; color:var(--text); border:1px solid var(--panel-border);
    border-radius:8px; padding:0 10px; font-size:.82rem; }
  .copy-btn { flex:0 0 auto; background:#2a2a2a; border:1px solid var(--panel-border); border-radius:8px;
    color:var(--text); font-size:.9rem; padding:8px 10px; }
  .copy-btn:active { transform:scale(0.95); }
  .subtabs { display:flex; border-bottom:1px solid var(--panel-border); }
  .subtab-btn { flex:1; padding:10px 4px; background:none; border:none; color:var(--text-dim);
    font-size:.78rem; font-weight:700; border-bottom:2px solid transparent; }
  .subtab-btn.active { color:var(--accent-yellow); border-bottom-color:var(--accent-yellow); }
  .subtab-panel { display:none; }
  .subtab-panel.active { display:flex; flex-direction:column; }
  #rep-tab-headers.active, #rep-tab-resp-headers.active { display:block; padding:8px 16px; overflow-y:auto; }
  .kv-row { display:flex; gap:6px; padding:6px 0; align-items:center; }
  .kv-row input { flex:1; min-width:0; background:#0e0e0e; color:var(--text); border:1px solid var(--panel-border);
    border-radius:8px; padding:8px 10px; font-size:.78rem; }
  .kv-row input.kv-key { flex:0 0 38%; color:var(--key-color); }
  .kv-remove { flex:0 0 auto; background:none; border:none; color:var(--accent); font-size:1.1rem; padding:0 4px; }
  .add-row-btn { margin:8px 0 4px; padding:9px 14px; border-radius:8px; border:1px dashed var(--panel-border);
    background:none; color:var(--text-dim); font-size:.78rem; font-weight:700; align-self:flex-start; }
  #rep-tab-body.active { flex:1; min-height:0; }
  #rep-resp-summary { display:flex; align-items:center; gap:10px; padding:10px 16px; font-size:.78rem;
    color:var(--text-dim); border-top:1px solid var(--panel-border); border-bottom:1px solid var(--panel-border); }
  #rep-resp-summary .status-chip { font-size:.8rem; }
  #rep-response-wrap { display:none; flex-direction:column; flex:1; min-height:0; }
  #rep-tab-resp-body.active { flex:1; overflow-y:auto; padding:12px 16px; }
  #rep-tab-resp-body pre { white-space:pre-wrap; word-break:break-all; font-size:.78rem; margin:0; }
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>&#128737;&#65039; Mobile Proxy Console</h1>
    <div id="status-dot"></div>
  </header>

  <div id="tabs">
    <button class="tab-btn active" data-tab="intercept">Intercept</button>
    <button class="tab-btn" data-tab="history">History</button>
    <button class="tab-btn" data-tab="settings">Scope</button>
    <button class="tab-btn" data-tab="matchreplace">M&amp;R</button>
    <button class="tab-btn" data-tab="decoder">Decoder</button>
  </div>

  <div class="panel active" id="panel-intercept">
    <div id="intercept-toolbar">
      <div class="intercept-pill off" id="intercept-pill"><span class="dot"></span><span id="intercept-pill-label">Intercept OFF</span></div>
      <span style="font-size:.72rem; color:var(--text-dim);">No scope set = all traffic</span>
    </div>
    <div id="queue-strip"></div>
    <div class="empty-state" id="intercept-empty">No requests intercepted yet.<br>Waiting for in-scope traffic&hellip;</div>
    <div id="editor-area" style="display:none; flex:1; flex-direction:column; min-height:0;">
      <div id="meta">
        <div class="method-url"><b id="meta-method"></b> <span id="meta-url"></span></div>
        <div id="meta-host"></div>
      </div>
      <div class="jwt-panel" id="int-jwt-panel">
        <h3>&#128273; JWT detected (editable, re-encoded on Forward)</h3>
        <div>Header</div><pre class="jwt-header" contenteditable="true"></pre>
        <div>Payload</div><pre class="jwt-payload" contenteditable="true"></pre>
        <button class="jwt-apply">Apply JWT edits to body</button>
      </div>
      <div class="macro-row">
        <button class="macro-btn" data-macro="is_admin">is_admin=true</button>
        <button class="macro-btn" data-macro="role_admin">Role: Admin</button>
        <button class="macro-btn" data-macro="clear">Clear Content</button>
      </div>
      <div class="body-wrap"><textarea class="big-edit" id="body-textarea" spellcheck="false"
        autocapitalize="off" autocorrect="off"></textarea></div>
      <div class="action-bar">
        <button class="btn-blue" id="int-to-repeater-btn" style="flex:0 0 60px;">&#128257;</button>
        <button class="btn-red" id="drop-btn">DROP</button>
        <button class="btn-green" id="forward-btn">FORWARD REQUEST</button>
      </div>
    </div>
  </div>

  <div class="panel" id="panel-history">
    <div style="padding:10px 16px 0;">
      <input type="text" id="history-search" class="url-input" style="width:100%; padding:12px; font-size:16px;"
        placeholder="Filter by host, path, or method&hellip;">
    </div>
    <div style="display:flex; gap:8px; padding:10px 16px;">
      <button class="macro-btn" id="history-refresh" style="flex:1">&#8635; Refresh</button>
      <button class="macro-btn" id="history-clear" style="flex:1; color:#ff8a80">Clear Log</button>
    </div>
    <div class="scroll-list" id="history-list"></div>
  </div>

  <div class="panel" id="panel-repeater">
    <div id="rep-urlbar">
      <select class="method-select" id="rep-method-select">
        <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option>
        <option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
      </select>
      <input type="text" class="url-input" id="rep-url-input" spellcheck="false"
        autocapitalize="off" autocorrect="off" placeholder="https://host/path">
      <button class="copy-btn" id="rep-url-copy" title="Copy URL">&#128203;</button>
    </div>
    <div class="subtabs" id="rep-subtabs">
      <button class="subtab-btn active" data-subtab="rep-tab-query">Query <span id="rep-query-count"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-headers">Headers <span id="rep-headers-count"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-body">Body</button>
    </div>
    <div class="subtab-panel active" id="rep-tab-query">
      <div id="rep-query-list"></div>
      <button class="add-row-btn" id="rep-query-add">+ Add param</button>
    </div>
    <div class="subtab-panel" id="rep-tab-headers">
      <div id="rep-headers-list"></div>
      <button class="add-row-btn" id="rep-headers-add">+ Add header</button>
    </div>
    <div class="subtab-panel" id="rep-tab-body">
      <div class="jwt-panel" id="rep-jwt-panel">
        <h3>&#128273; JWT detected (editable, re-encoded on Send)</h3>
        <div>Header</div><pre class="jwt-header" contenteditable="true"></pre>
        <div>Payload</div><pre class="jwt-payload" contenteditable="true"></pre>
        <button class="jwt-apply">Apply JWT edits to body</button>
      </div>
      <div class="macro-row">
        <button class="macro-btn" data-macro="is_admin" data-editor="rep">is_admin=true</button>
        <button class="macro-btn" data-macro="role_admin" data-editor="rep">Role: Admin</button>
        <button class="macro-btn" data-macro="clear" data-editor="rep">Clear Content</button>
      </div>
      <div class="body-wrap"><textarea class="big-edit" id="rep-textarea" spellcheck="false"
        autocapitalize="off" autocorrect="off"></textarea></div>
    </div>
    <div class="action-bar">
      <button class="btn-blue" id="rep-send-btn" style="flex:1">SEND</button>
      <button class="btn-red" id="rep-back-btn" style="flex:0 0 90px">Back</button>
    </div>
    <div id="rep-response-wrap">
      <div id="rep-resp-summary"></div>
      <div class="subtabs" id="rep-resp-subtabs">
        <button class="subtab-btn active" data-subtab="rep-tab-resp-body">Body</button>
        <button class="subtab-btn" data-subtab="rep-tab-resp-headers">Headers</button>
        <button class="subtab-btn" data-subtab="rep-tab-resp-info">Info</button>
      </div>
      <div class="subtab-panel active" id="rep-tab-resp-body">
        <button class="copy-btn" id="rep-body-copy" title="Copy body" style="margin-bottom:6px;">&#128203; Copy body</button>
        <pre id="rep-resp-body"></pre>
      </div>
      <div class="subtab-panel" id="rep-tab-resp-headers"><div id="rep-resp-headers"></div></div>
      <div class="subtab-panel" id="rep-tab-resp-info"><div id="rep-resp-info" style="padding:8px 0; font-size:.8rem;"></div></div>
    </div>
  </div>

  <div class="panel" id="panel-settings">
    <div class="settings-scroll">
      <div class="toggle-row" id="intercept-toggle-row">
        <div><b>Intercept</b><br><span style="color:var(--text-dim); font-size:.75rem;">Freeze in-scope requests for review</span></div>
        <div class="toggle-switch" id="intercept-toggle"></div>
      </div>

      <div class="field-block">
        <label>Domain include (comma-separated substrings, empty = all domains)</label>
        <input type="text" id="set-domain-include" placeholder="discover.com, apiserv.discover.com">
      </div>
      <div class="field-block">
        <label>Domain exclude (comma-separated substrings)</label>
        <input type="text" id="set-domain-exclude" placeholder="analytics.com, doubleclick.net">
      </div>
      <div class="field-block">
        <label>Path regex (empty = all paths)</label>
        <input type="text" id="set-path-regex" placeholder="(auth|login|token)">
      </div>
      <div class="field-block">
        <label>Methods in scope</label>
        <div class="method-chip-row" id="method-chips"></div>
      </div>
      <button class="save-btn" id="settings-save">Save Scope Settings</button>
    </div>
  </div>

  <div class="panel" id="panel-matchreplace">
    <div class="settings-scroll">
      <div class="field-block">
        <label>Target</label>
        <div class="method-chip-row" id="mr-target-chips">
          <div class="method-chip on" data-target="req_header">Header</div>
          <div class="method-chip" data-target="req_body">Body</div>
          <div class="method-chip" data-target="req_url">URL Path</div>
        </div>
      </div>
      <div class="field-block"><label>Match (regex)</label><input type="text" id="mr-match" placeholder="Authorization: .*"></div>
      <div class="field-block"><label>Replace with</label><input type="text" id="mr-replace" placeholder="Authorization: Bearer FUZZ"></div>
      <button class="save-btn" id="mr-add-btn">Add Rule</button>
      <div style="margin-top:20px" id="mr-list"></div>
    </div>
  </div>

  <div class="panel" id="panel-decoder">
    <div class="decoder-wrap">
      <label style="font-size:.8rem; color:var(--text-dim); font-weight:700;">Input</label>
      <textarea class="big-edit" id="dec-input" spellcheck="false"></textarea>
      <div class="decoder-btns">
        <button data-op="b64enc">Base64 Encode</button>
        <button data-op="b64dec">Base64 Decode</button>
        <button data-op="urlenc">URL Encode</button>
        <button data-op="urldec">URL Decode</button>
        <button data-op="hexenc">Hex Encode</button>
        <button data-op="hexdec">Hex Decode</button>
      </div>
      <label style="font-size:.8rem; color:var(--text-dim); font-weight:700;">Output</label>
      <textarea class="big-edit" id="dec-output" spellcheck="false" readonly></textarea>
    </div>
  </div>
</div>

<script>
const POLL_MS = 400;

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'history') loadHistory();
    if (btn.dataset.tab === 'settings') loadSettings();
    if (btn.dataset.tab === 'matchreplace') loadMR();
  });
});

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try {
    return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
  } catch (e) { try { return atob(str); } catch (e2) { return null; } }
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
  return { raw: m[0], header, payload };
}
function prettyJson(str) { try { return JSON.stringify(JSON.parse(str), null, 2); } catch (e) { return str; } }
function tryParseJson(text) { try { return JSON.parse(text); } catch (e) { return null; } }

function setupEditor(prefix, textareaEl, jwtPanelEl) {
  let jwtLocation = null;
  const jwtHeaderEl = jwtPanelEl.querySelector('.jwt-header');
  const jwtPayloadEl = jwtPanelEl.querySelector('.jwt-payload');
  const jwtApplyBtn = jwtPanelEl.querySelector('.jwt-apply');

  function updateJwtPanel() {
    const jwt = findJwt(textareaEl.value);
    if (!jwt) { jwtPanelEl.classList.remove('show'); jwtLocation = null; return; }
    jwtLocation = jwt;
    jwtPanelEl.classList.add('show');
    jwtHeaderEl.textContent = prettyJson(jwt.header);
    jwtPayloadEl.textContent = prettyJson(jwt.payload);
  }

  jwtApplyBtn.addEventListener('click', () => {
    if (!jwtLocation) return;
    try {
      const newHeader = b64urlEncode(JSON.stringify(JSON.parse(jwtHeaderEl.textContent)));
      const newPayload = b64urlEncode(JSON.stringify(JSON.parse(jwtPayloadEl.textContent)));
      const oldSig = jwtLocation.raw.split('.')[2];
      textareaEl.value = textareaEl.value.replace(jwtLocation.raw, `${newHeader}.${newPayload}.${oldSig}`);
      updateJwtPanel();
    } catch (e) { alert('JWT JSON is invalid, fix it before applying.'); }
  });

  document.querySelectorAll('.macro-btn').forEach(btn => {
    const belongsToThis = (prefix === 'int' && !btn.dataset.editor) || (prefix === 'rep' && btn.dataset.editor === 'rep');
    if (!belongsToThis) return;
    btn.addEventListener('click', () => {
      const macro = btn.dataset.macro;
      const text = textareaEl.value;
      if (macro === 'clear') { textareaEl.value = ''; updateJwtPanel(); return; }
      if (macro === 'is_admin') {
        const obj = tryParseJson(text);
        if (obj !== null && typeof obj === 'object') { obj.is_admin = true; textareaEl.value = JSON.stringify(obj, null, 2); }
        else if (text.includes('=')) {
          let nt = text.replace(/([?&]?)is_admin=[^&]*/i, '').replace(/&+$/, '').trim();
          nt += (nt.length && !nt.endsWith('&') ? '&' : '') + 'is_admin=true';
          textareaEl.value = nt;
        } else { textareaEl.value = text + (text.length ? '\n' : '') + 'is_admin=true'; }
        updateJwtPanel(); return;
      }
      if (macro === 'role_admin') {
        const obj = tryParseJson(text);
        if (obj !== null && typeof obj === 'object') { obj.role = 'admin'; textareaEl.value = JSON.stringify(obj, null, 2); }
        else if (/["']?role["']?\s*[:=]/i.test(text)) {
          textareaEl.value = text.replace(/(["']?role["']?\s*[:=]\s*["']?)([\w-]*)(["']?)/i, (m,p1,p2,p3) => `${p1}admin${p3}`);
        } else { textareaEl.value = text + (text.length ? '\n' : '') + 'Role: Admin'; }
        updateJwtPanel(); return;
      }
    });
  });

  return { updateJwtPanel };
}

const intEditor = setupEditor('int', document.getElementById('body-textarea'), document.getElementById('int-jwt-panel'));
const repEditor = setupEditor('rep', document.getElementById('rep-textarea'), document.getElementById('rep-jwt-panel'));

let currentFlowId = null;
let currentHeaders = {};
let flowsCache = {};
const els = {
  statusDot: document.getElementById('status-dot'),
  queueStrip: document.getElementById('queue-strip'),
  emptyState: document.getElementById('intercept-empty'),
  editorArea: document.getElementById('editor-area'),
  metaMethod: document.getElementById('meta-method'),
  metaUrl: document.getElementById('meta-url'),
  metaHost: document.getElementById('meta-host'),
  bodyTextarea: document.getElementById('body-textarea'),
  forwardBtn: document.getElementById('forward-btn'),
  dropBtn: document.getElementById('drop-btn'),
};

function renderQueue(items) {
  els.queueStrip.innerHTML = '';
  if (items.length === 0) {
    els.emptyState.style.display = 'flex';
    els.editorArea.style.display = 'none';
    currentFlowId = null;
    return;
  }
  els.emptyState.style.display = 'none';
  // hide the queue list entirely when there's only one item -- straight to the editor
  els.queueStrip.style.display = items.length > 1 ? 'flex' : 'none';
  items.forEach(item => {
    flowsCache[item.id] = item;
    const row = document.createElement('div');
    row.className = 'queue-chip' + (item.id === currentFlowId ? ' active' : '');
    row.innerHTML = `
      <div class="row-top"><span>&#9203; waiting</span><span>${item.host}</span></div>
      <div class="row-url"><span class="method">${item.method}</span>${(item.path || item.url).replace(/</g,'&lt;')}</div>
    `;
    row.addEventListener('click', () => selectFlow(item.id));
    els.queueStrip.appendChild(row);
  });
  if (!currentFlowId || !flowsCache[currentFlowId]) selectFlow(items[0].id);
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
  intEditor.updateJwtPanel();
}

async function pollPending() {
  try {
    const res = await fetch('/api/pending', { cache: 'no-store' });
    const items = await res.json();
    els.statusDot.classList.add('live');
    renderQueue(items);
  } catch (e) { els.statusDot.classList.remove('live'); }
  finally { setTimeout(pollPending, POLL_MS); }
}
pollPending();
loadSettings();

async function sendAction(action) {
  if (!currentFlowId) return;
  const body = { body: els.bodyTextarea.value, headers: currentHeaders };
  await fetch(`/api/flow/${currentFlowId}/${action}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  delete flowsCache[currentFlowId];
  currentFlowId = null;
}
els.forwardBtn.addEventListener('click', () => sendAction('forward'));
els.dropBtn.addEventListener('click', () => sendAction('drop'));

function fmtBytes(n) {
  if (n === null || n === undefined) return '&ndash;';
  if (n < 1024) return n + ' B';
  return (n / 1024).toFixed(1) + ' KB';
}

let historyCache = [];
async function loadHistory() {
  const res = await fetch('/api/history', { cache: 'no-store' });
  historyCache = await res.json();
  renderHistory();
}
function renderHistory() {
  const q = document.getElementById('history-search').value.trim().toLowerCase();
  const items = q
    ? historyCache.filter(i => (i.url || '').toLowerCase().includes(q) || (i.method || '').toLowerCase().includes(q))
    : historyCache;
  const list = document.getElementById('history-list');
  list.innerHTML = '';
  if (items.length === 0) {
    list.innerHTML = `<div class="empty-state">${historyCache.length === 0 ? 'No traffic logged yet.' : 'No matches.'}</div>`;
    return;
  }
  items.forEach(item => {
    const row = document.createElement('div');
    row.className = 'req-row';
    let statusClass = 'status-2xx';
    if (item.status >= 300 && item.status < 400) statusClass = 'status-3xx';
    if (item.status >= 400) statusClass = 'status-4xx';
    const statusHtml = item.status ? `<span class="status-chip ${statusClass}">${item.status}</span>` : '<span style="color:var(--text-dim)">pending</span>';
    const badges = [];
    if (item.params) badges.push('<span class="req-badge badge-params">params</span>');
    if (item.edited) badges.push('<span class="req-badge badge-edited">edited</span>');
    if (item.intercepted) badges.push('<span class="req-badge badge-intercepted">intercepted</span>');
    if (item.mime) badges.push(`<span class="req-badge badge-mime">${item.mime}</span>`);
    row.innerHTML = `
      <div class="row-top">
        <span class="seq">#${item.seq}</span>
        <span class="time">${item.ts}</span>
        ${statusHtml}
        <span class="len">${fmtBytes(item.length)}</span>
      </div>
      <div class="row-url"><span class="method">${item.method}</span>${item.url.replace(/</g,'&lt;')}</div>
      ${badges.length ? `<div class="row-badges">${badges.join('')}</div>` : ''}
      <div class="preview">${(item.body_preview || '').replace(/</g,'&lt;')}</div>
    `;
    row.addEventListener('click', () => openRepeater(item.id));
    list.appendChild(row);
  });
}
document.getElementById('history-refresh').addEventListener('click', loadHistory);
document.getElementById('history-clear').addEventListener('click', async () => {
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
});
document.getElementById('history-search').addEventListener('input', renderHistory);

let repCurrent = null;
let repHeaders = [];   // [{k, v}, ...] editable rows
let repQuery = [];     // [{k, v}, ...] editable rows, synced with the URL bar

function parseQueryFromUrl(url) {
  try {
    const u = new URL(url);
    return Array.from(u.searchParams.entries()).map(([k, v]) => ({ k, v }));
  } catch (e) { return []; }
}
function syncUrlFromQuery() {
  const urlInput = document.getElementById('rep-url-input');
  try {
    const u = new URL(urlInput.value);
    u.search = '';
    repQuery.forEach(row => { if (row.k) u.searchParams.append(row.k, row.v || ''); });
    urlInput.value = u.toString();
  } catch (e) { /* not a valid absolute URL yet, leave it alone */ }
}
function renderRepQuery() {
  const wrap = document.getElementById('rep-query-list');
  wrap.innerHTML = '';
  document.getElementById('rep-query-count').textContent = repQuery.length ? `(${repQuery.length})` : '';
  repQuery.forEach((row, i) => {
    const el = document.createElement('div');
    el.className = 'kv-row';
    el.innerHTML = `
      <input class="kv-key" value="${(row.k||'').replace(/"/g,'&quot;')}" placeholder="Key">
      <input class="kv-val" value="${(row.v||'').replace(/"/g,'&quot;')}" placeholder="Value">
      <button class="kv-remove">&times;</button>
    `;
    const [keyInput, valInput] = el.querySelectorAll('input');
    keyInput.addEventListener('input', () => { row.k = keyInput.value; syncUrlFromQuery(); });
    valInput.addEventListener('input', () => { row.v = valInput.value; syncUrlFromQuery(); });
    el.querySelector('.kv-remove').addEventListener('click', () => {
      repQuery.splice(i, 1); renderRepQuery(); syncUrlFromQuery();
    });
    wrap.appendChild(el);
  });
}
document.getElementById('rep-query-add').addEventListener('click', () => {
  repQuery.push({ k: '', v: '' });
  renderRepQuery();
});

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else { fallbackCopy(text); }
}
function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
}
document.getElementById('rep-url-copy').addEventListener('click', () => copyToClipboard(document.getElementById('rep-url-input').value));
document.getElementById('rep-body-copy').addEventListener('click', () => copyToClipboard(document.getElementById('rep-resp-body').textContent));

// "Send to Repeater" from the live Intercept editor -- lets you test-fire a
// variant of the frozen request without resolving (forwarding/dropping) it yet.
document.getElementById('int-to-repeater-btn').addEventListener('click', () => {
  if (!currentFlowId) return;
  const item = flowsCache[currentFlowId];
  if (!item) return;
  openRepeaterFromData({
    method: item.method, url: item.url,
    req_headers: currentHeaders, req_body: els.bodyTextarea.value,
  });
});

function renderRepHeaders() {
  const wrap = document.getElementById('rep-headers-list');
  wrap.innerHTML = '';
  document.getElementById('rep-headers-count').textContent = repHeaders.length ? `(${repHeaders.length})` : '';
  repHeaders.forEach((row, i) => {
    const el = document.createElement('div');
    el.className = 'kv-row';
    el.innerHTML = `
      <input class="kv-key" value="${(row.k||'').replace(/"/g,'&quot;')}" placeholder="Header">
      <input class="kv-val" value="${(row.v||'').replace(/"/g,'&quot;')}" placeholder="Value">
      <button class="kv-remove">&times;</button>
    `;
    const [keyInput, valInput] = el.querySelectorAll('input');
    keyInput.addEventListener('input', () => row.k = keyInput.value);
    valInput.addEventListener('input', () => row.v = valInput.value);
    el.querySelector('.kv-remove').addEventListener('click', () => {
      repHeaders.splice(i, 1);
      renderRepHeaders();
    });
    wrap.appendChild(el);
  });
}
document.getElementById('rep-headers-add').addEventListener('click', () => {
  repHeaders.push({ k: '', v: '' });
  renderRepHeaders();
});

// generic sub-tab switching, shared by the request tabs and the response tabs
document.querySelectorAll('#rep-subtabs .subtab-btn, #rep-resp-subtabs .subtab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const group = btn.closest('.subtabs');
    group.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    group.parentElement.querySelectorAll(':scope > .subtab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById(btn.dataset.subtab).classList.add('active');
  });
});

async function openRepeater(histId) {
  const res = await fetch(`/api/history/${histId}`);
  if (!res.ok) return;
  openRepeaterFromData(await res.json());
}

function openRepeaterFromData(data) {
  repCurrent = data;
  document.getElementById('rep-method-select').value = data.method;
  document.getElementById('rep-url-input').value = data.url;
  repHeaders = Object.entries(data.req_headers || {}).map(([k, v]) => ({ k, v }));
  renderRepHeaders();
  repQuery = parseQueryFromUrl(data.url);
  renderRepQuery();
  document.getElementById('rep-textarea').value = data.req_body || '';
  document.getElementById('rep-response-wrap').style.display = 'none';
  repEditor.updateJwtPanel();
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-repeater').classList.add('active');
}
document.getElementById('rep-back-btn').addEventListener('click', () => {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-history').classList.add('active');
  document.querySelector('.tab-btn[data-tab="history"]').classList.add('active');
});
document.getElementById('rep-send-btn').addEventListener('click', async () => {
  const sendBtn = document.getElementById('rep-send-btn');
  const wrap = document.getElementById('rep-response-wrap');
  const summaryEl = document.getElementById('rep-resp-summary');
  const bodyEl = document.getElementById('rep-resp-body');
  const headersEl = document.getElementById('rep-resp-headers');
  wrap.style.display = 'flex';
  summaryEl.innerHTML = 'Sending&hellip;';
  bodyEl.textContent = '';
  headersEl.innerHTML = '';
  sendBtn.disabled = true;
  const headerObj = {};
  repHeaders.forEach(row => { if (row.k) headerObj[row.k] = row.v; });
  const t0 = performance.now();
  try {
    const res = await fetch('/api/repeater/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: document.getElementById('rep-method-select').value,
        url: document.getElementById('rep-url-input').value,
        headers: headerObj, body: document.getElementById('rep-textarea').value,
      }),
    });
    const elapsed = Math.round(performance.now() - t0);
    const data = await res.json();
    if (data.error) {
      summaryEl.innerHTML = `<span style="color:var(--accent)">Error</span>`;
      bodyEl.textContent = data.error;
      return;
    }
    let statusClass = 'status-2xx';
    if (data.status >= 300 && data.status < 400) statusClass = 'status-3xx';
    if (data.status >= 400) statusClass = 'status-4xx';
    const bodyLen = (data.body || '').length;
    const serverElapsed = data.elapsed_ms !== undefined ? data.elapsed_ms : elapsed;
    summaryEl.innerHTML = `<span class="status-chip ${statusClass}">${data.status}</span>
      <span>${serverElapsed} ms</span><span>${fmtBytes(bodyLen)}</span>`;
    bodyEl.textContent = data.body || '';
    Object.entries(data.headers || {}).forEach(([k, v]) => {
      const row = document.createElement('div');
      row.className = 'kv-row';
      row.innerHTML = `<span style="flex:0 0 38%; color:var(--key-color); font-size:.78rem; word-break:break-all;">${k}</span>
        <span style="flex:1; font-size:.78rem; word-break:break-all;">${(v||'').toString().replace(/</g,'&lt;')}</span>`;
      headersEl.appendChild(row);
    });
    const infoEl = document.getElementById('rep-resp-info');
    const infoRows = [
      ['Status', data.status], ['Round trip', serverElapsed + ' ms'],
      ['Body size', fmtBytes(bodyLen)], ['HTTP version', data.http_version || '&ndash;'],
      ['Remote address', data.remote_addr || '&ndash;'], ['Content-Type', data.content_type || '&ndash;'],
    ];
    infoEl.innerHTML = infoRows.map(([k, v]) => `<div class="kv-row"><span style="flex:0 0 42%; color:var(--key-color);">${k}</span><span style="flex:1;">${v}</span></div>`).join('');
  } catch (e) {
    summaryEl.innerHTML = `<span style="color:var(--accent)">Network error</span>`;
    bodyEl.textContent = e.message;
  } finally {
    sendBtn.disabled = false;
  }
});

const ALL_METHODS = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'];
let scopeMethods = new Set();

function syncInterceptPill(enabled) {
  const pill = document.getElementById('intercept-pill');
  const label = document.getElementById('intercept-pill-label');
  pill.classList.toggle('on', enabled);
  pill.classList.toggle('off', !enabled);
  label.textContent = enabled ? 'Intercept ON' : 'Intercept OFF';
  document.getElementById('intercept-toggle').classList.toggle('on', enabled);
}

async function loadSettings() {
  const res = await fetch('/api/settings');
  const s = await res.json();
  syncInterceptPill(!!s.intercept_enabled);
  document.getElementById('set-domain-include').value = (s.domain_include || []).join(', ');
  document.getElementById('set-domain-exclude').value = (s.domain_exclude || []).join(', ');
  document.getElementById('set-path-regex').value = s.path_regex || '';
  scopeMethods = new Set(s.methods || []);
  renderMethodChips();
  return s;
}

// The Intercept tab's pill is a one-tap master switch -- flips immediately,
// no need to go into Scope > Save to turn interception on/off.
document.getElementById('intercept-pill').addEventListener('click', async () => {
  const nowOn = !document.getElementById('intercept-pill').classList.contains('on');
  await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ intercept_enabled: nowOn }),
  });
  syncInterceptPill(nowOn);
});
function renderMethodChips() {
  const wrap = document.getElementById('method-chips');
  wrap.innerHTML = '';
  ALL_METHODS.forEach(m => {
    const chip = document.createElement('div');
    chip.className = 'method-chip' + (scopeMethods.has(m) ? ' on' : '');
    chip.textContent = m;
    chip.addEventListener('click', () => {
      if (scopeMethods.has(m)) scopeMethods.delete(m); else scopeMethods.add(m);
      renderMethodChips();
    });
    wrap.appendChild(chip);
  });
}
document.getElementById('intercept-toggle-row').addEventListener('click', () => {
  const nowOn = !document.getElementById('intercept-toggle').classList.contains('on');
  syncInterceptPill(nowOn);
});
document.getElementById('settings-save').addEventListener('click', async () => {
  const payload = {
    intercept_enabled: document.getElementById('intercept-toggle').classList.contains('on'),
    domain_include: document.getElementById('set-domain-include').value.split(',').map(s => s.trim()).filter(Boolean),
    domain_exclude: document.getElementById('set-domain-exclude').value.split(',').map(s => s.trim()).filter(Boolean),
    path_regex: document.getElementById('set-path-regex').value,
    methods: Array.from(scopeMethods),
  };
  await fetch('/api/settings', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  alert('Scope settings saved.');
});

let mrTarget = 'req_header';
document.querySelectorAll('#mr-target-chips .method-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('#mr-target-chips .method-chip').forEach(c => c.classList.remove('on'));
    chip.classList.add('on');
    mrTarget = chip.dataset.target;
  });
});
document.getElementById('mr-add-btn').addEventListener('click', async () => {
  const match = document.getElementById('mr-match').value;
  const replace = document.getElementById('mr-replace').value;
  if (!match) { alert('Match pattern required.'); return; }
  await fetch('/api/match-replace', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ target: mrTarget, match, replace }) });
  document.getElementById('mr-match').value = '';
  document.getElementById('mr-replace').value = '';
  loadMR();
});
async function loadMR() {
  const res = await fetch('/api/match-replace');
  const rules = await res.json();
  const list = document.getElementById('mr-list');
  list.innerHTML = '';
  if (rules.length === 0) { list.innerHTML = '<div class="empty-state" style="padding:20px 0;">No rules yet.</div>'; return; }
  rules.forEach(r => {
    const div = document.createElement('div');
    div.className = 'mr-rule';
    div.innerHTML = `
      <div class="row1"><span class="target-tag">${r.target}</span><span style="color:${r.enabled ? 'var(--accent-green)' : 'var(--text-dim)'}">${r.enabled ? 'ON' : 'OFF'}</span></div>
      <div>Match: <code>${r.match.replace(/</g,'&lt;')}</code></div>
      <div>Replace: <code>${r.replace.replace(/</g,'&lt;')}</code></div>
      <div class="mr-actions">
        <button class="mr-toggle" style="background:var(--key-color); color:#001;">Toggle</button>
        <button class="mr-delete" style="background:var(--accent); color:#2b0000;">Delete</button>
      </div>`;
    div.querySelector('.mr-toggle').addEventListener('click', async () => { await fetch(`/api/match-replace/${r.id}/toggle`, {method:'POST'}); loadMR(); });
    div.querySelector('.mr-delete').addEventListener('click', async () => { await fetch(`/api/match-replace/${r.id}`, {method:'DELETE'}); loadMR(); });
    list.appendChild(div);
  });
}

function toHex(str) { return Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2,'0')).join(''); }
function fromHex(hex) {
  hex = hex.replace(/\s+/g,'');
  const bytes = new Uint8Array(hex.length/2);
  for (let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
  return new TextDecoder().decode(bytes);
}
document.querySelectorAll('.decoder-btns button').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById('dec-input').value;
    const out = document.getElementById('dec-output');
    try {
      switch (btn.dataset.op) {
        case 'b64enc': out.value = btoa(unescape(encodeURIComponent(input))); break;
        case 'b64dec': out.value = decodeURIComponent(escape(atob(input))); break;
        case 'urlenc': out.value = encodeURIComponent(input); break;
        case 'urldec': out.value = decodeURIComponent(input); break;
        case 'hexenc': out.value = toHex(input); break;
        case 'hexdec': out.value = fromHex(input); break;
      }
    } catch (e) { out.value = 'Error: ' + e.message; }
  });
});
</script>
</body>
</html>
"""


def _run_flask():
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False, threaded=True)


_flask_thread = threading.Thread(target=_run_flask, daemon=True, name="flask-dashboard")
_flask_thread.start()
