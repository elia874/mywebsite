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

REPEATER_MAXLEN = 200
REPEATER_STORE = {}          # id -> repeater entry dict
REPEATER_ORDER = deque(maxlen=REPEATER_MAXLEN)
_repeater_id_counter = itertools.count(1)
_repeater_seq_counter = itertools.count(1)

pending = {}                 # flow.id -> {flow, event, action, edited_body, edited_headers}


def _new_mr_id():
    return f"mr{next(_mr_id_counter)}"


def _new_repeater_id():
    return f"rep{next(_repeater_id_counter)}"


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


def _guess_application(headers):
    ua = (headers.get("user-agent") or headers.get("User-Agent") or "").lower()
    if not ua:
        return "Unknown"
    checks = [
        ("okhttp", "OkHttp client (Android app)"),
        ("cronet", "Cronet client (Android app)"),
        ("dalvik", "Android app (Dalvik VM)"),
        ("crios", "Chrome (iOS)"),
        ("fxios", "Firefox (iOS)"),
        ("chrome", "Chrome"),
        ("firefox", "Firefox"),
        ("safari", "Safari"),
        ("okhttp/", "OkHttp client"),
        ("python-requests", "Python requests"),
        ("curl", "curl"),
        ("postman", "Postman"),
    ]
    for needle, label in checks:
        if needle in ua:
            return label
    return "Unknown"


def _parse_request_cookies(headers):
    raw = headers.get("cookie") or headers.get("Cookie") or ""
    out = []
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        out.append({"name": k.strip(), "value": v.strip()})
    return out


def _parse_response_cookies(flow):
    out = []
    try:
        raw_list = flow.response.headers.get_all("set-cookie") if flow.response else []
    except Exception:
        raw_list = []
    for raw in raw_list:
        first = raw.split(";")[0]
        if "=" in first:
            k, v = first.split("=", 1)
        else:
            k, v = first, ""
        out.append({"name": k.strip(), "value": v.strip(), "raw": raw})
    return out


def _safe_getattr(obj, path, default=None):
    cur = obj
    for part in path.split("."):
        cur = getattr(cur, part, None)
        if cur is None:
            return default
    return cur


def _connection_info(flow):
    """Best-effort extraction of connection/TLS metadata. Wrapped defensively
    because attribute availability varies across mitmproxy versions and
    connection phases -- this must never crash the proxy."""
    info = {
        "http_version": None,
        "client_ip": None, "client_port": None,
        "proxy_client_ip": None, "proxy_client_port": None,
        "server_ip": None, "server_port": None,
        "tls_version": None, "sni": None, "alpn": None,
    }
    try:
        info["http_version"] = flow.request.http_version
    except Exception:
        pass
    try:
        peer = _safe_getattr(flow, "client_conn.peername")
        if peer:
            info["client_ip"], info["client_port"] = peer[0], peer[1]
    except Exception:
        pass
    try:
        sock = _safe_getattr(flow, "client_conn.sockname")
        if sock:
            info["proxy_client_ip"], info["proxy_client_port"] = sock[0], sock[1]
    except Exception:
        pass
    try:
        srv = _safe_getattr(flow, "server_conn.peername") or _safe_getattr(flow, "server_conn.address")
        if srv:
            info["server_ip"], info["server_port"] = srv[0], srv[1]
    except Exception:
        pass
    try:
        info["tls_version"] = _safe_getattr(flow, "client_conn.tls_version")
    except Exception:
        pass
    try:
        info["sni"] = _safe_getattr(flow, "client_conn.sni") or flow.request.pretty_host
    except Exception:
        pass
    try:
        info["alpn"] = _safe_getattr(flow, "client_conn.alpn_proto_negotiated")
        if isinstance(info["alpn"], bytes):
            info["alpn"] = info["alpn"].decode(errors="replace")
    except Exception:
        pass
    return info


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
    req_headers = dict(flow.request.headers)
    entry = {
        "id": flow.id,
        "seq": next(_history_seq_counter),
        "ts": time.strftime("%H:%M:%S"),
        "ts_epoch": time.time(),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "path": flow.request.path,
        "host": flow.request.pretty_host,
        "req_headers": req_headers,
        "req_body": req_body,
        "req_length": len(req_body.encode("utf-8", errors="replace")) if req_body else 0,
        "params": has_params,
        "edited": False,
        "favorite": False,
        "status": None,
        "resp_headers": {},
        "resp_body": "",
        "length": None,
        "mime": "",
        "intercepted": intercepted,
        "conn": _connection_info(flow),
        "application": _guess_application(req_headers),
        "req_cookies": _parse_request_cookies(req_headers),
        "resp_cookies": [],
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
        entry["resp_cookies"] = _parse_response_cookies(flow)


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
        "favorite": entry["favorite"],
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


@app.post("/api/history/<hist_id>/favorite")
def api_history_favorite(hist_id):
    with _lock:
        entry = HISTORY_STORE.get(hist_id)
        if entry is None:
            return jsonify({"error": "not found"}), 404
        entry["favorite"] = not entry["favorite"]
        fav = entry["favorite"]
    return jsonify({"favorite": fav})


# ---- repeater ----
def _do_http_send(method, url, headers, body, follow_redirects=False, verify_tls=False):
    if pyrequests is None:
        return None, {"error": "the 'requests' package is not installed on the VPS "
                                "(pip install requests --break-system-packages)"}
    try:
        resp = pyrequests.request(
            method, url, headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=20, allow_redirects=follow_redirects, verify=verify_tls,
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:20000],
            "length": len(resp.content or b""),
        }, None
    except Exception as e:
        return None, {"error": str(e)}


def _repeater_summary(entry):
    return {
        "id": entry["id"],
        "seq": entry["seq"],
        "method": entry["method"],
        "url": entry["url"],
        "ts_created": entry["ts_created"],
        "has_response": entry["last_response"] is not None,
        "status": entry["last_response"]["status"] if entry["last_response"] else None,
        "source": entry["source"],
    }


@app.get("/api/repeater")
def api_repeater_list():
    with _lock:
        ids = list(REPEATER_ORDER)[::-1]
        items = [_repeater_summary(REPEATER_STORE[i]) for i in ids if i in REPEATER_STORE]
    return jsonify(items)


@app.post("/api/repeater")
def api_repeater_create():
    import time
    payload = flask_request.get_json(force=True, silent=True) or {}
    rid = _new_repeater_id()
    entry = {
        "id": rid,
        "seq": next(_repeater_seq_counter),
        "ts_created": time.strftime("%H:%M:%S"),
        "method": (payload.get("method") or "GET").upper(),
        "url": payload.get("url") or "",
        "headers": payload.get("headers") or {},
        "body": payload.get("body") or "",
        "settings": {
            "follow_redirects": bool(payload.get("follow_redirects", False)),
            "verify_tls": bool(payload.get("verify_tls", False)),
        },
        "source": payload.get("source") or "new",
        "last_response": None,
    }
    with _lock:
        REPEATER_STORE[rid] = entry
        if len(REPEATER_ORDER) == REPEATER_ORDER.maxlen:
            oldest = REPEATER_ORDER[0]
            REPEATER_STORE.pop(oldest, None)
        REPEATER_ORDER.append(rid)
    return jsonify(entry)


@app.get("/api/repeater/<rid>")
def api_repeater_get(rid):
    with _lock:
        entry = REPEATER_STORE.get(rid)
        if entry is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(dict(entry))


@app.post("/api/repeater/<rid>")
def api_repeater_save(rid):
    payload = flask_request.get_json(force=True, silent=True) or {}
    with _lock:
        entry = REPEATER_STORE.get(rid)
        if entry is None:
            return jsonify({"error": "not found"}), 404
        if "method" in payload:
            entry["method"] = (payload["method"] or "GET").upper()
        if "url" in payload:
            entry["url"] = payload["url"] or ""
        if "headers" in payload and isinstance(payload["headers"], dict):
            entry["headers"] = payload["headers"]
        if "body" in payload:
            entry["body"] = payload["body"] or ""
        if "follow_redirects" in payload:
            entry["settings"]["follow_redirects"] = bool(payload["follow_redirects"])
        if "verify_tls" in payload:
            entry["settings"]["verify_tls"] = bool(payload["verify_tls"])
        return jsonify(dict(entry))


@app.delete("/api/repeater/<rid>")
def api_repeater_delete(rid):
    with _lock:
        REPEATER_STORE.pop(rid, None)
        try:
            REPEATER_ORDER.remove(rid)
        except ValueError:
            pass
    return jsonify({"status": "deleted"})


@app.post("/api/repeater/<rid>/send")
def api_repeater_send(rid):
    import time
    payload = flask_request.get_json(force=True, silent=True) or {}
    with _lock:
        entry = REPEATER_STORE.get(rid)
        if entry is None:
            return jsonify({"error": "not found"}), 404
        # sending auto-saves the current editor state, same as Reqable/Burp do
        entry["method"] = (payload.get("method") or entry["method"]).upper()
        entry["url"] = payload.get("url", entry["url"])
        if isinstance(payload.get("headers"), dict):
            entry["headers"] = payload["headers"]
        entry["body"] = payload.get("body", entry["body"])
        if "follow_redirects" in payload:
            entry["settings"]["follow_redirects"] = bool(payload["follow_redirects"])
        if "verify_tls" in payload:
            entry["settings"]["verify_tls"] = bool(payload["verify_tls"])
        method, url, headers, body = entry["method"], entry["url"], entry["headers"], entry["body"]
        follow_redirects = entry["settings"]["follow_redirects"]
        verify_tls = entry["settings"]["verify_tls"]

    if not url:
        return jsonify({"error": "missing url"}), 400

    t0 = time.time()
    result, error = _do_http_send(method, url, headers, body, follow_redirects, verify_tls)
    elapsed_ms = int((time.time() - t0) * 1000)

    with _lock:
        entry = REPEATER_STORE.get(rid)
        if entry is not None:
            if error:
                entry["last_response"] = None
            else:
                result["elapsed_ms"] = elapsed_ms
                result["ts"] = time.strftime("%H:%M:%S")
                entry["last_response"] = result

    if error:
        return jsonify(error), 502
    result["elapsed_ms"] = elapsed_ms
    return jsonify(result)


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

  /* ---- History detail (Reqable-style deep inspection) ---- */
  .detail-header { display:flex; align-items:center; gap:6px; padding:12px 14px; border-bottom:1px solid var(--panel-border); position:relative; }
  .detail-header .back-btn { background:none; border:none; color:var(--text); font-size:1.3rem; padding:2px 6px; }
  .detail-header .title { flex:1; font-weight:700; font-size:.92rem; }
  .icon-btn { background:none; border:none; color:var(--text-dim); font-size:1.1rem; padding:4px 6px; }
  .icon-btn.fav.active { color:var(--accent); }
  .menu-dropdown { position:absolute; top:46px; right:10px; background:var(--panel); border:1px solid var(--panel-border);
    border-radius:10px; overflow:hidden; z-index:50; display:none; box-shadow:0 6px 20px rgba(0,0,0,.4); }
  .menu-dropdown.open { display:block; }
  .menu-dropdown button { display:block; width:190px; text-align:left; padding:12px 14px; background:none; border:none;
    color:var(--text); font-size:.8rem; border-bottom:1px solid var(--panel-border); }
  .menu-dropdown button:last-child { border-bottom:none; }

  .detail-urlrow { display:flex; align-items:center; gap:8px; padding:10px 14px; border-bottom:1px solid var(--panel-border); }
  .method-badge { padding:4px 10px; border-radius:6px; font-weight:800; font-size:.72rem; flex-shrink:0; }
  .method-badge.m-GET { background:#0d2b3a; color:#6cf; }
  .method-badge.m-POST { background:#123a1d; color:var(--accent-green); }
  .method-badge.m-PUT, .method-badge.m-PATCH { background:#3a2a0d; color:var(--accent-yellow); }
  .method-badge.m-DELETE { background:#3a0d1a; color:var(--accent); }
  .method-badge.m-HEAD, .method-badge.m-OPTIONS { background:#222; color:var(--text-dim); }
  .detail-url-text { flex:1; font-size:.76rem; word-break:break-all; min-width:0; }
  .copy-btn { background:none; border:none; color:var(--text-dim); font-size:.95rem; flex-shrink:0; }

  .detail-tabs { display:flex; overflow-x:auto; border-bottom:1px solid var(--panel-border); -webkit-overflow-scrolling:touch; }
  .detail-tab-btn { flex-shrink:0; padding:10px 14px; background:none; border:none; color:var(--text-dim);
    font-size:.76rem; font-weight:700; border-bottom:2px solid transparent; white-space:nowrap; }
  .detail-tab-btn.active { color:var(--accent-yellow); border-bottom-color:var(--accent-yellow); }

  .detail-content { flex:1; overflow-y:auto; padding:12px 16px; }
  .kv-static { display:flex; padding:7px 0; border-bottom:1px solid var(--panel-border); font-size:.78rem; gap:8px; }
  .kv-static .k { flex:0 0 40%; color:var(--text-dim); word-break:break-word; }
  .kv-static .v { flex:1; word-break:break-all; min-width:0; }
  .accordion-head { display:flex; justify-content:space-between; align-items:center; padding:10px 0; font-weight:700;
    font-size:.8rem; color:var(--text); border-top:1px solid var(--panel-border); margin-top:8px; }
  .accordion-head .chev { color:var(--text-dim); transition:transform .15s; }
  .accordion-head.open .chev { transform:rotate(180deg); }
  .accordion-body { display:none; padding-bottom:6px; }
  .accordion-body.open { display:block; }
  .detail-content pre.raw-view { white-space:pre-wrap; word-break:break-all; font-size:.76rem; margin:0; }

  .detail-reqresp-toggle { display:flex; border-top:1px solid var(--panel-border); }
  .detail-reqresp-toggle button { flex:1; padding:14px; background:none; border:none; color:var(--text-dim); font-weight:800; font-size:.82rem; }
  .detail-reqresp-toggle button.active { color:var(--accent-yellow); }

  /* ---- Repeater list + editor extras ---- */
  .tab-dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--accent-green); margin-left:4px; vertical-align:middle; }
  .kv-toolbar { display:flex; gap:14px; padding:8px 0 4px; color:var(--text-dim); }
  .kv-toolbar button { background:none; border:none; color:var(--text-dim); font-size:1rem; padding:2px 4px; }
  .kv-toolbar button:active { color:var(--accent-yellow); }
  .kv-check { flex:0 0 auto; width:18px; height:18px; }
  .raw-toggle-view textarea { width:100%; min-height:140px; background:#0e0e0e; color:var(--text);
    border:1px solid var(--panel-border); border-radius:8px; padding:10px; font-size:.78rem; }
  .auth-row select, .auth-row input { width:100%; background:#0e0e0e; color:var(--text); border:1px solid var(--panel-border);
    border-radius:8px; padding:10px; font-size:.85rem; margin-bottom:8px; }
  .settings-check-row { display:flex; align-items:center; gap:10px; padding:10px 0; font-size:.85rem; }
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
    <button class="tab-btn" data-tab="repeater">Repeater</button>
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
        <button class="btn-red" id="drop-btn">DROP</button>
        <button class="btn-green" id="forward-btn">FORWARD REQUEST</button>
      </div>
    </div>
  </div>

  <div class="panel" id="panel-history">
    <div style="display:flex; gap:8px; padding:10px 16px;">
      <button class="macro-btn" id="history-refresh" style="flex:1">&#8635; Refresh</button>
      <button class="macro-btn" id="history-clear" style="flex:1; color:#ff8a80">Clear Log</button>
    </div>
    <div class="scroll-list" id="history-list"></div>
  </div>

  <div class="panel" id="panel-history-detail">
    <div class="detail-header">
      <button class="back-btn" id="detail-back-btn">&#8592;</button>
      <div class="title">Request &amp; Response</div>
      <button class="icon-btn" id="detail-share-btn" title="Copy raw request">&#8683;</button>
      <button class="icon-btn fav" id="detail-fav-btn" title="Favorite">&#9825;</button>
      <button class="icon-btn" id="detail-menu-btn">&#8942;</button>
      <div class="menu-dropdown" id="detail-menu">
        <button id="detail-send-repeater-btn">Send to Repeater</button>
        <button id="detail-copy-curl-btn">Copy as cURL</button>
      </div>
    </div>
    <div class="detail-urlrow">
      <span class="method-badge" id="detail-method-badge"></span>
      <span class="detail-url-text" id="detail-url-text"></span>
      <button class="copy-btn" id="detail-copy-url-btn" title="Copy URL">&#128203;</button>
    </div>
    <div class="detail-tabs" id="detail-tabs">
      <button class="detail-tab-btn active" data-dtab="summary">Summary</button>
      <button class="detail-tab-btn" data-dtab="raw">Raw</button>
      <button class="detail-tab-btn" data-dtab="headers">Headers <span id="detail-headers-count"></span></button>
      <button class="detail-tab-btn" data-dtab="body">Body</button>
      <button class="detail-tab-btn" data-dtab="cookies">Cookies <span id="detail-cookies-count"></span></button>
    </div>
    <div class="detail-content" id="detail-content"></div>
    <div class="detail-reqresp-toggle" id="detail-reqresp-toggle">
      <button class="active" data-dside="request">&#8593; Request</button>
      <button data-dside="response">&#8595; Response</button>
    </div>
  </div>

  <div class="panel" id="panel-repeater">
    <div style="display:flex; gap:8px; padding:10px 16px;">
      <button class="macro-btn" id="repeater-new-btn" style="flex:1">&#43; New Request</button>
      <button class="macro-btn" id="repeater-refresh-btn" style="flex:0 0 60px">&#8635;</button>
    </div>
    <div class="scroll-list" id="repeater-list"></div>
  </div>

  <div class="panel" id="panel-repeater-editor">
    <div class="detail-header">
      <button class="back-btn" id="rep-back-btn">&#8592;</button>
      <div class="title">Repeater</div>
      <button class="icon-btn" id="rep-save-btn" title="Save">&#128190;</button>
    </div>
    <div id="rep-urlbar">
      <select class="method-select" id="rep-method-select">
        <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option>
        <option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
      </select>
      <input type="text" class="url-input" id="rep-url-input" spellcheck="false"
        autocapitalize="off" autocorrect="off" placeholder="https://host/path">
    </div>
    <div class="subtabs" id="rep-subtabs">
      <button class="subtab-btn active" data-subtab="rep-tab-query">Query <span id="rep-query-dot"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-headers">Headers <span id="rep-headers-count"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-body">Body <span id="rep-body-dot"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-auth">Auth <span id="rep-auth-dot"></span></button>
      <button class="subtab-btn" data-subtab="rep-tab-settings">Settings <span id="rep-settings-dot"></span></button>
    </div>

    <div class="subtab-panel active" id="rep-tab-query">
      <div class="kv-toolbar">
        <button id="rep-query-wand" title="Parse pasted query string">&#10024;</button>
        <button id="rep-query-braces" title="Toggle raw view">{ }</button>
        <button id="rep-query-copy" title="Copy all">&#128203;</button>
        <button id="rep-query-trash" title="Clear all">&#128465;</button>
      </div>
      <div id="rep-query-list"></div>
      <button class="add-row-btn" id="rep-query-add">+ Add param</button>
    </div>

    <div class="subtab-panel" id="rep-tab-headers">
      <div class="kv-toolbar">
        <button id="rep-headers-wand" title="Parse pasted 'Key: Value' lines">&#10024;</button>
        <button id="rep-headers-braces" title="Toggle raw view">{ }</button>
        <button id="rep-headers-copy" title="Copy all">&#128203;</button>
        <button id="rep-headers-trash" title="Clear all">&#128465;</button>
      </div>
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

    <div class="subtab-panel" id="rep-tab-auth">
      <div class="auth-row" style="padding:12px 16px;">
        <select id="rep-auth-type">
          <option value="none">No Auth</option>
          <option value="bearer">Bearer Token</option>
          <option value="basic">Basic Auth</option>
        </select>
        <input type="text" id="rep-auth-bearer" placeholder="Token" style="display:none;">
        <input type="text" id="rep-auth-user" placeholder="Username" style="display:none;">
        <input type="text" id="rep-auth-pass" placeholder="Password" style="display:none;">
        <button class="add-row-btn" id="rep-auth-apply">Apply to Headers</button>
      </div>
    </div>

    <div class="subtab-panel" id="rep-tab-settings">
      <div style="padding:8px 16px;">
        <div class="settings-check-row"><input type="checkbox" id="rep-set-redirects"> <label for="rep-set-redirects">Follow redirects</label></div>
        <div class="settings-check-row"><input type="checkbox" id="rep-set-verify"> <label for="rep-set-verify">Verify TLS certificate</label></div>
      </div>
    </div>

    <div class="action-bar">
      <button class="btn-blue" id="rep-send-btn" style="flex:1">SEND</button>
    </div>
    <div id="rep-response-wrap">
      <div id="rep-resp-summary"></div>
      <div class="subtabs" id="rep-resp-subtabs">
        <button class="subtab-btn active" data-subtab="rep-tab-resp-body">Body</button>
        <button class="subtab-btn" data-subtab="rep-tab-resp-headers">Headers</button>
      </div>
      <div class="subtab-panel active" id="rep-tab-resp-body"><pre id="rep-resp-body"></pre></div>
      <div class="subtab-panel" id="rep-tab-resp-headers"><div id="rep-resp-headers"></div></div>
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
    if (btn.dataset.tab === 'repeater') loadRepeaterList();
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

async function loadHistory() {
  const res = await fetch('/api/history', { cache: 'no-store' });
  const items = await res.json();
  const list = document.getElementById('history-list');
  list.innerHTML = '';
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state">No traffic logged yet.</div>';
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
    row.addEventListener('click', () => openHistoryDetail(item.id));
    list.appendChild(row);
  });
}
document.getElementById('history-refresh').addEventListener('click', loadHistory);
document.getElementById('history-clear').addEventListener('click', async () => {
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
});

function escapeAttr(s) { return (s || '').toString().replace(/"/g, '&quot;'); }
function escapeHtml(s) { return (s || '').toString().replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ---- generic key/value row editor, shared by Repeater's Query and Headers tabs ----
function renderKvList(rows, containerId, countId, onChange) {
  const wrap = document.getElementById(containerId);
  wrap.innerHTML = '';
  if (countId) document.getElementById(countId).innerHTML = rows.length ? `(${rows.length})` : '';
  rows.forEach((row, i) => {
    const el = document.createElement('div');
    el.className = 'kv-row';
    el.innerHTML = `
      <input type="checkbox" class="kv-check" ${row.enabled !== false ? 'checked' : ''}>
      <input class="kv-key" value="${escapeAttr(row.k)}" placeholder="Key">
      <input class="kv-val" value="${escapeAttr(row.v)}" placeholder="Value">
      <button class="kv-remove">&times;</button>
    `;
    const checkbox = el.querySelector('.kv-check');
    const keyInput = el.querySelector('.kv-key');
    const valInput = el.querySelector('.kv-val');
    checkbox.addEventListener('change', () => { row.enabled = checkbox.checked; onChange(); });
    keyInput.addEventListener('input', () => { row.k = keyInput.value; onChange(); });
    valInput.addEventListener('input', () => { row.v = valInput.value; onChange(); });
    el.querySelector('.kv-remove').addEventListener('click', () => {
      rows.splice(i, 1);
      renderKvList(rows, containerId, countId, onChange);
      onChange();
    });
    wrap.appendChild(el);
  });
}

function wireKvToolbar(prefix, getRows, setRows, rerender, toRaw, parseRaw) {
  document.getElementById(`${prefix}-wand`).addEventListener('click', () => {
    const text = prompt('Paste raw text to parse into rows:');
    if (text === null || !text.trim()) return;
    setRows(getRows().concat(parseRaw(text)));
    rerender();
  });
  document.getElementById(`${prefix}-braces`).addEventListener('click', () => {
    const edited = prompt('Raw view -- edit and OK to replace all rows:', toRaw(getRows()));
    if (edited === null) return;
    setRows(parseRaw(edited));
    rerender();
  });
  document.getElementById(`${prefix}-copy`).addEventListener('click', async () => {
    const raw = toRaw(getRows());
    try { await navigator.clipboard.writeText(raw); }
    catch (e) { prompt('Copy this:', raw); }
  });
  document.getElementById(`${prefix}-trash`).addEventListener('click', () => {
    if (getRows().length && !confirm('Clear all rows?')) return;
    setRows([]);
    rerender();
  });
}

function parseHeaderLines(text) {
  return text.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
    const idx = line.indexOf(':');
    return idx === -1 ? { k: line, v: '', enabled: true } : { k: line.slice(0, idx).trim(), v: line.slice(idx + 1).trim(), enabled: true };
  });
}
function headersToRaw(rows) { return rows.map(r => `${r.k}: ${r.v}`).join('\n'); }
function parseQueryString(text) {
  return text.replace(/^\?/, '').split('&').map(p => p.trim()).filter(Boolean).map(p => {
    const idx = p.indexOf('=');
    return idx === -1 ? { k: p, v: '', enabled: true } : { k: decodeURIComponent(p.slice(0, idx)), v: decodeURIComponent(p.slice(idx + 1)), enabled: true };
  });
}
function queryToRaw(rows) { return rows.map(r => `${r.k}=${encodeURIComponent(r.v)}`).join('&'); }

function urlGetQuery(url) {
  try {
    const u = new URL(url);
    const rows = [];
    u.searchParams.forEach((v, k) => rows.push({ k, v, enabled: true }));
    return rows;
  } catch (e) { return []; }
}
function urlSetQuery(url, rows) {
  try {
    const u = new URL(url);
    const params = new URLSearchParams();
    rows.filter(r => r.enabled !== false && r.k).forEach(r => params.append(r.k, r.v));
    const qs = params.toString();
    return qs ? `${u.origin}${u.pathname}?${qs}${u.hash}` : `${u.origin}${u.pathname}${u.hash}`;
  } catch (e) { return url; }
}

let currentRepId = null;
let repHeaders = [];   // [{k, v, enabled}, ...]
let repQuery = [];     // [{k, v, enabled}, ...] -- mirrors the URL's query string

function renderRepHeaders() {
  renderRepHeadersRaw();
  updateRepDots();
}
function renderRepHeadersRaw() {
  renderKvList(repHeaders, 'rep-headers-list', 'rep-headers-count', () => updateRepDots());
}
function renderRepQuery() {
  renderKvList(repQuery, 'rep-query-list', null, () => {
    document.getElementById('rep-url-input').value = urlSetQuery(document.getElementById('rep-url-input').value, repQuery);
    updateRepDots();
  });
  updateRepDots();
}
document.getElementById('rep-headers-add').addEventListener('click', () => { repHeaders.push({ k: '', v: '', enabled: true }); renderRepHeaders(); });
document.getElementById('rep-query-add').addEventListener('click', () => { repQuery.push({ k: '', v: '', enabled: true }); renderRepQuery(); });

wireKvToolbar('rep-headers',
  () => repHeaders, (v) => { repHeaders = v; }, renderRepHeaders, headersToRaw, parseHeaderLines);
wireKvToolbar('rep-query',
  () => repQuery, (v) => { repQuery = v; }, renderRepQuery, queryToRaw, parseQueryString);

document.getElementById('rep-url-input').addEventListener('change', () => {
  repQuery = urlGetQuery(document.getElementById('rep-url-input').value);
  renderRepQuery();
});

function updateRepDots() {
  document.getElementById('rep-query-dot').innerHTML = repQuery.some(r => r.k) ? '<span class="tab-dot"></span>' : '';
  document.getElementById('rep-body-dot').innerHTML = document.getElementById('rep-textarea').value.trim() ? '<span class="tab-dot"></span>' : '';
  document.getElementById('rep-auth-dot').innerHTML = repHeaders.some(r => (r.k || '').toLowerCase() === 'authorization') ? '<span class="tab-dot"></span>' : '';
  document.getElementById('rep-settings-dot').innerHTML =
    (document.getElementById('rep-set-redirects').checked || document.getElementById('rep-set-verify').checked) ? '<span class="tab-dot"></span>' : '';
}
document.getElementById('rep-textarea').addEventListener('input', updateRepDots);
document.getElementById('rep-set-redirects').addEventListener('change', updateRepDots);
document.getElementById('rep-set-verify').addEventListener('change', updateRepDots);

// ---- Auth tab: builds/overwrites the Authorization header from a preset ----
document.getElementById('rep-auth-type').addEventListener('change', () => {
  const t = document.getElementById('rep-auth-type').value;
  document.getElementById('rep-auth-bearer').style.display = t === 'bearer' ? 'block' : 'none';
  document.getElementById('rep-auth-user').style.display = t === 'basic' ? 'block' : 'none';
  document.getElementById('rep-auth-pass').style.display = t === 'basic' ? 'block' : 'none';
});
document.getElementById('rep-auth-apply').addEventListener('click', () => {
  const t = document.getElementById('rep-auth-type').value;
  repHeaders = repHeaders.filter(r => (r.k || '').toLowerCase() !== 'authorization');
  if (t === 'bearer') {
    const tok = document.getElementById('rep-auth-bearer').value;
    if (tok) repHeaders.push({ k: 'Authorization', v: `Bearer ${tok}`, enabled: true });
  } else if (t === 'basic') {
    const u = document.getElementById('rep-auth-user').value, p = document.getElementById('rep-auth-pass').value;
    if (u || p) repHeaders.push({ k: 'Authorization', v: `Basic ${btoa(u + ':' + p)}`, enabled: true });
  }
  renderRepHeaders();
  alert('Authorization header updated.');
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

function goToPanel(panelId, tabName) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById(panelId).classList.add('active');
  if (tabName) {
    const tabBtn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (tabBtn) tabBtn.classList.add('active');
  }
}

async function loadRepeaterList() {
  const res = await fetch('/api/repeater', { cache: 'no-store' });
  const items = await res.json();
  const list = document.getElementById('repeater-list');
  list.innerHTML = '';
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state">No saved requests yet. Send one from History, or tap + New Request.</div>';
    return;
  }
  items.forEach(item => {
    const row = document.createElement('div');
    row.className = 'req-row';
    const statusHtml = item.status
      ? `<span class="status-chip ${item.status >= 400 ? 'status-4xx' : (item.status >= 300 ? 'status-3xx' : 'status-2xx')}">${item.status}</span>`
      : '<span style="color:var(--text-dim)">not sent</span>';
    row.innerHTML = `
      <div class="row-top"><span class="seq">#${item.seq}</span>${statusHtml}</div>
      <div class="row-url"><span class="method">${item.method}</span>${escapeHtml(item.url)}</div>
    `;
    row.addEventListener('click', () => openRepeaterEditor(item.id));
    list.appendChild(row);
  });
}
document.getElementById('repeater-refresh-btn').addEventListener('click', loadRepeaterList);
document.getElementById('repeater-new-btn').addEventListener('click', async () => {
  const res = await fetch('/api/repeater', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method: 'GET', url: '', headers: {}, body: '', source: 'new' }),
  });
  const entry = await res.json();
  openRepeaterEditor(entry.id);
});

async function openRepeaterEditor(repId) {
  const res = await fetch(`/api/repeater/${repId}`);
  if (!res.ok) return;
  const data = await res.json();
  currentRepId = data.id;
  document.getElementById('rep-method-select').value = data.method;
  document.getElementById('rep-url-input').value = data.url;
  repHeaders = Object.entries(data.headers || {}).map(([k, v]) => ({ k, v, enabled: true }));
  repQuery = urlGetQuery(data.url);
  document.getElementById('rep-textarea').value = data.body || '';
  document.getElementById('rep-set-redirects').checked = !!(data.settings && data.settings.follow_redirects);
  document.getElementById('rep-set-verify').checked = !!(data.settings && data.settings.verify_tls);
  renderRepHeaders();
  renderRepQuery();
  repEditor.updateJwtPanel();
  const wrap = document.getElementById('rep-response-wrap');
  if (data.last_response) {
    renderRepResponse(data.last_response, data.last_response.elapsed_ms || 0);
  } else {
    wrap.style.display = 'none';
  }
  goToPanel('panel-repeater-editor', null);
}
document.getElementById('rep-back-btn').addEventListener('click', () => {
  goToPanel('panel-repeater', 'repeater');
  loadRepeaterList();
});
document.getElementById('rep-save-btn').addEventListener('click', async () => {
  if (!currentRepId) return;
  const headerObj = {};
  repHeaders.filter(r => r.enabled !== false && r.k).forEach(r => headerObj[r.k] = r.v);
  await fetch(`/api/repeater/${currentRepId}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: document.getElementById('rep-method-select').value,
      url: document.getElementById('rep-url-input').value,
      headers: headerObj, body: document.getElementById('rep-textarea').value,
      follow_redirects: document.getElementById('rep-set-redirects').checked,
      verify_tls: document.getElementById('rep-set-verify').checked,
    }),
  });
  alert('Saved.');
});

function renderRepResponse(data, elapsedMs) {
  const wrap = document.getElementById('rep-response-wrap');
  const summaryEl = document.getElementById('rep-resp-summary');
  const bodyEl = document.getElementById('rep-resp-body');
  const headersEl = document.getElementById('rep-resp-headers');
  wrap.style.display = 'flex';
  let statusClass = 'status-2xx';
  if (data.status >= 300 && data.status < 400) statusClass = 'status-3xx';
  if (data.status >= 400) statusClass = 'status-4xx';
  summaryEl.innerHTML = `<span class="status-chip ${statusClass}">${data.status}</span>
    <span>${elapsedMs} ms</span><span>${fmtBytes(data.length != null ? data.length : (data.body || '').length)}</span>`;
  bodyEl.textContent = data.body || '';
  headersEl.innerHTML = '';
  Object.entries(data.headers || {}).forEach(([k, v]) => {
    const row = document.createElement('div');
    row.className = 'kv-static';
    row.innerHTML = `<span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml((v || '').toString())}</span>`;
    headersEl.appendChild(row);
  });
}
document.getElementById('rep-send-btn').addEventListener('click', async () => {
  if (!currentRepId) return;
  const sendBtn = document.getElementById('rep-send-btn');
  const wrap = document.getElementById('rep-response-wrap');
  const summaryEl = document.getElementById('rep-resp-summary');
  wrap.style.display = 'flex';
  summaryEl.innerHTML = 'Sending&hellip;';
  document.getElementById('rep-resp-body').textContent = '';
  document.getElementById('rep-resp-headers').innerHTML = '';
  sendBtn.disabled = true;
  const headerObj = {};
  repHeaders.filter(r => r.enabled !== false && r.k).forEach(r => headerObj[r.k] = r.v);
  try {
    const res = await fetch(`/api/repeater/${currentRepId}/send`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: document.getElementById('rep-method-select').value,
        url: document.getElementById('rep-url-input').value,
        headers: headerObj, body: document.getElementById('rep-textarea').value,
        follow_redirects: document.getElementById('rep-set-redirects').checked,
        verify_tls: document.getElementById('rep-set-verify').checked,
      }),
    });
    const data = await res.json();
    if (data.error) {
      summaryEl.innerHTML = `<span style="color:var(--accent)">Error</span>`;
      document.getElementById('rep-resp-body').textContent = data.error;
      return;
    }
    renderRepResponse(data, data.elapsed_ms || 0);
  } catch (e) {
    summaryEl.innerHTML = `<span style="color:var(--accent)">Network error</span>`;
    document.getElementById('rep-resp-body').textContent = e.message;
  } finally {
    sendBtn.disabled = false;
  }
});

// ---- Send-to-Repeater, used from both History Detail and (later) Intercept ----
async function sendToRepeater(method, url, headers, body) {
  const res = await fetch('/api/repeater', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method, url, headers, body, source: 'history' }),
  });
  const entry = await res.json();
  openRepeaterEditor(entry.id);
}

// ---- History Detail (Reqable-style Request & Response deep inspection) ----
let detailData = null;
let detailSide = 'request';   // 'request' | 'response'

async function openHistoryDetail(histId) {
  const res = await fetch(`/api/history/${histId}`);
  if (!res.ok) return;
  detailData = await res.json();
  detailSide = 'request';
  document.querySelectorAll('#detail-reqresp-toggle button').forEach(b => b.classList.toggle('active', b.dataset.dside === 'request'));
  document.getElementById('detail-fav-btn').classList.toggle('active', !!detailData.favorite);
  document.getElementById('detail-fav-btn').innerHTML = detailData.favorite ? '&#9829;' : '&#9825;';
  document.getElementById('detail-method-badge').textContent = detailData.method;
  document.getElementById('detail-method-badge').className = `method-badge m-${detailData.method}`;
  document.getElementById('detail-url-text').textContent = detailData.url;
  const reqHCount = Object.keys(detailData.req_headers || {}).length;
  const respHCount = Object.keys(detailData.resp_headers || {}).length;
  document.getElementById('detail-headers-count').textContent = `(${reqHCount + respHCount})`;
  const cookieCount = (detailData.req_cookies || []).length + (detailData.resp_cookies || []).length;
  document.getElementById('detail-cookies-count').textContent = cookieCount ? `(${cookieCount})` : '';
  document.querySelectorAll('.detail-tab-btn').forEach(b => b.classList.toggle('active', b.dataset.dtab === 'summary'));
  renderDetailContent();
  goToPanel('panel-history-detail', null);
}
document.getElementById('detail-back-btn').addEventListener('click', () => {
  goToPanel('panel-history', 'history');
});
document.querySelectorAll('.detail-tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.detail-tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderDetailContent();
  });
});
document.querySelectorAll('#detail-reqresp-toggle button').forEach(btn => {
  btn.addEventListener('click', () => {
    detailSide = btn.dataset.dside;
    document.querySelectorAll('#detail-reqresp-toggle button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderDetailContent();
  });
});
document.getElementById('detail-fav-btn').addEventListener('click', async () => {
  const res = await fetch(`/api/history/${detailData.id}/favorite`, { method: 'POST' });
  const data = await res.json();
  detailData.favorite = data.favorite;
  document.getElementById('detail-fav-btn').classList.toggle('active', data.favorite);
  document.getElementById('detail-fav-btn').innerHTML = data.favorite ? '&#9829;' : '&#9825;';
});
document.getElementById('detail-copy-url-btn').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(detailData.url); }
  catch (e) { prompt('Copy this URL:', detailData.url); }
});
document.getElementById('detail-share-btn').addEventListener('click', async () => {
  const raw = buildRawText('request', detailData);
  if (navigator.share) {
    try { await navigator.share({ title: 'Request', text: raw }); return; } catch (e) { /* fall through to copy */ }
  }
  try { await navigator.clipboard.writeText(raw); alert('Raw request copied to clipboard.'); }
  catch (e) { prompt('Copy this:', raw); }
});
document.getElementById('detail-menu-btn').addEventListener('click', () => {
  document.getElementById('detail-menu').classList.toggle('open');
});
document.addEventListener('click', (e) => {
  const menu = document.getElementById('detail-menu');
  if (!menu.contains(e.target) && e.target.id !== 'detail-menu-btn') menu.classList.remove('open');
});
document.getElementById('detail-send-repeater-btn').addEventListener('click', () => {
  document.getElementById('detail-menu').classList.remove('open');
  sendToRepeater(detailData.method, detailData.url, detailData.req_headers, detailData.req_body);
});
document.getElementById('detail-copy-curl-btn').addEventListener('click', async () => {
  document.getElementById('detail-menu').classList.remove('open');
  let cmd = `curl -X ${detailData.method} '${detailData.url}'`;
  Object.entries(detailData.req_headers || {}).forEach(([k, v]) => { cmd += ` \\\n  -H '${k}: ${v}'`; });
  if (detailData.req_body) cmd += ` \\\n  -d '${detailData.req_body.replace(/'/g, "'\\''")}'`;
  try { await navigator.clipboard.writeText(cmd); alert('cURL command copied.'); }
  catch (e) { prompt('Copy this:', cmd); }
});

function buildRawText(side, d) {
  if (side === 'request') {
    let out = `${d.method} ${d.path || d.url} HTTP/1.1\n`;
    Object.entries(d.req_headers || {}).forEach(([k, v]) => out += `${k}: ${v}\n`);
    out += '\n' + (d.req_body || '');
    return out;
  } else {
    let out = `HTTP/1.1 ${d.status || ''}\n`;
    Object.entries(d.resp_headers || {}).forEach(([k, v]) => out += `${k}: ${v}\n`);
    out += '\n' + (d.resp_body || '');
    return out;
  }
}

function renderDetailContent() {
  const tab = document.querySelector('.detail-tab-btn.active').dataset.dtab;
  const el = document.getElementById('detail-content');
  const d = detailData;
  const side = detailSide;
  if (tab === 'summary') {
    const conn = d.conn || {};
    const rows = side === 'request' ? [
      ['Method', d.method], ['URL', d.url], ['Protocol', conn.http_version || '-'],
      ['Host', d.host], ['Application', d.application || 'Unknown'], ['Time', d.ts],
    ] : [
      ['Status', d.status != null ? d.status : 'pending'], ['Content-Type', d.mime || '-'],
      ['Length', fmtBytes(d.length)],
    ];
    let html = rows.map(([k, v]) => `<div class="kv-static"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml((v || '').toString())}</span></div>`).join('');
    html += `
      <div class="accordion-head" data-acc="app">Application <span class="chev">&#9660;</span></div>
      <div class="accordion-body" id="acc-app">
        <div class="kv-static"><span class="k">Guessed client</span><span class="v">${escapeHtml(d.application || 'Unknown')}</span></div>
        <div class="kv-static"><span class="k">User-Agent</span><span class="v">${escapeHtml((d.req_headers||{})['User-Agent'] || (d.req_headers||{})['user-agent'] || '-')}</span></div>
      </div>
      <div class="accordion-head" data-acc="conn">Connection <span class="chev">&#9660;</span></div>
      <div class="accordion-body" id="acc-conn">
        <div class="kv-static"><span class="k">Time</span><span class="v">${escapeHtml(d.ts || '-')}</span></div>
        <div class="kv-static"><span class="k">Frontend Client</span><span class="v">${escapeHtml((conn.client_ip||'-') + ':' + (conn.client_port||'-'))}</span></div>
        <div class="kv-static"><span class="k">Frontend Proxy</span><span class="v">${escapeHtml((conn.proxy_client_ip||'-') + ':' + (conn.proxy_client_port||'-'))}</span></div>
        <div class="kv-static"><span class="k">Backend Server</span><span class="v">${escapeHtml((conn.server_ip||'-') + ':' + (conn.server_port||'-'))}</span></div>
      </div>
      <div class="accordion-head" data-acc="tls">TLS <span class="chev">&#9660;</span></div>
      <div class="accordion-body" id="acc-tls">
        <div class="kv-static"><span class="k">Version</span><span class="v">${escapeHtml(conn.tls_version || '-')}</span></div>
        <div class="kv-static"><span class="k">SNI</span><span class="v">${escapeHtml(conn.sni || '-')}</span></div>
        <div class="kv-static"><span class="k">ALPN</span><span class="v">${escapeHtml(conn.alpn || '-')}</span></div>
      </div>
    `;
    el.innerHTML = html;
    el.querySelectorAll('.accordion-head').forEach(h => {
      h.addEventListener('click', () => {
        h.classList.toggle('open');
        document.getElementById('acc-' + h.dataset.acc).classList.toggle('open');
      });
    });
  } else if (tab === 'raw') {
    el.innerHTML = `<pre class="raw-view">${escapeHtml(buildRawText(side, d))}</pre>`;
  } else if (tab === 'headers') {
    const headers = side === 'request' ? d.req_headers : d.resp_headers;
    el.innerHTML = Object.entries(headers || {}).map(([k, v]) =>
      `<div class="kv-static"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml((v || '').toString())}</span></div>`
    ).join('') || '<div class="empty-state">No headers.</div>';
  } else if (tab === 'body') {
    const body = side === 'request' ? d.req_body : d.resp_body;
    el.innerHTML = `<pre class="raw-view">${escapeHtml(body || '(empty body)')}</pre>`;
  } else if (tab === 'cookies') {
    const cookies = side === 'request' ? d.req_cookies : d.resp_cookies;
    el.innerHTML = (cookies || []).map(c =>
      `<div class="kv-static"><span class="k">${escapeHtml(c.name)}</span><span class="v">${escapeHtml(c.value)}</span></div>`
    ).join('') || '<div class="empty-state">No cookies.</div>';
  }
}

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
