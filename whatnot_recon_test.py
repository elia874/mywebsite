#!/usr/bin/env python3
"""
whatnot_recon_test.py

Hand-built from analysis of www_whatnot_com_2026_07_26_09_34_11.har
(11 requests total). NOT a generic HAR fuzzer -- targets exactly the two
endpoints in that capture that are safe to test automatically:

    GET /api/v1/realtime/settings
    GET /services/live/socket/v3/session

Why only these two:
  - Every mutating call in the HAR (SetPhoneNumberV2 GraphQL) sits behind
    KasadaSDK (x-kpsdk-ct/v/cd/h headers) + a per-request encrypted
    "session" blob. That's not testable by replay/mutation -- this script
    deliberately does NOT touch it, and never will (bot-detection bypass
    is out of scope, always).
  - The /services/events/v1/t and datadog log calls are telemetry beacons,
    not app logic -- nothing to test.
  - The two targets above have no Kasada headers and no per-request token
    in the URL, so they're legitimate candidates for auth_drop and
    method_switch testing.

Modules implemented (see MODULES section):
  1. baseline_replay      - confirm captured session still works before
                             wasting requests on the rest
  2. auth_drop             - variant a/b/c per spec
  3. method_matrix         - GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS
  4. csrf_token_behavior   - Stage 1.6 style: fetch twice, diff tokens,
                             classify reusable vs single-use
  5. baseline_diff engine  - structural diff (status/keys/types/len bucket)

Safety:
  - Dry-run by default. Nothing fires until --live is passed.
  - Rate-limited (default 2.5s between requests) -- the HAR itself shows
    this account already got rate-limited once during normal use.
  - Read-only targets only. No mutating endpoint is in scope here.
  - Every finding's raw request/response is saved to disk so you can
    re-verify in Burp without re-running anything.

Usage:
  python3 whatnot_recon_test.py --har /path/to/file.har --dry-run
  python3 whatnot_recon_test.py --har /path/to/file.har --live --delay 3
"""

import argparse
import base64
import copy
import json
import os
import sys
import time
import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] pip install requests --break-system-packages", file=sys.stderr)
    sys.exit(1)

BASE = "https://www.whatnot.com"

TARGETS = [
    {
        "name": "realtime_settings",
        "method": "GET",
        "path": "/api/v1/realtime/settings",
        "baseline_status": 200,
    },
    {
        "name": "live_socket_session",
        "method": "GET",
        "path": "/services/live/socket/v3/session",
        "baseline_status": 200,
    },
]

METHOD_MATRIX = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

# Headers from the HAR that look session/context-bound rather than just
# fingerprinting noise -- these are what auth_drop variant b strips.
SESSION_CONTEXT_HEADERS = [
    "x-whatnot-app-session-id",
    "x-whatnot-app-user-session-id",
]

CARRY_HEADERS = [
    "x-whatnot-app-session-id",
    "x-whatnot-app-user-session-id",
    "x-whatnot-app-version",
    "x-whatnot-app-context",
    "x-whatnot-app",
    "x-whatnot-app-pathname",
    "x-whatnot-app-screen",
    "x-client-timezone",
    "user-agent",
    "accept",
    "content-type",
]


# ---------------------------------------------------------------------------
# HAR session loader -- pulls the real cookies/headers captured for these
# two endpoints so you don't hand-copy 50 cookies into a config file.
# ---------------------------------------------------------------------------
def load_session_from_har(har_path):
    with open(har_path) as f:
        har = json.load(f)

    entries = har["log"]["entries"]
    cookies = {}
    headers = {}

    for e in entries:
        req = e["request"]
        path = urlparse(req["url"]).path
        if path not in ("/api/v1/realtime/settings", "/services/live/socket/v3/session"):
            continue
        for c in req.get("cookies", []):
            cookies[c["name"]] = c["value"]
        for h in req["headers"]:
            name = h["name"].lower()
            if name in CARRY_HEADERS:
                headers[name] = h["value"]

    if not cookies:
        raise RuntimeError(
            "Couldn't find either target endpoint in this HAR. "
            "Make sure it's the same capture the endpoints were found in."
        )

    return cookies, headers


def check_token_freshness(cookies):
    """
    __Secure-access-token is a JWT. Decode (no verification, we don't have
    the key, don't need it) just to read `exp` and warn if it's already
    expired -- this HAR's token expires within minutes of capture, so by
    the time you run --live it's very likely stale.
    """
    token = cookies.get("__Secure-access-token")
    if not token or token.count(".") != 2:
        return None
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None

    exp = payload.get("exp")
    if exp is None:
        return None

    now = time.time()
    delta = exp - now
    return {"exp": exp, "seconds_remaining": delta, "identity": payload.get("identity")}


# ---------------------------------------------------------------------------
# Baseline diff engine -- structural, not string diff
# ---------------------------------------------------------------------------
def json_shape(obj):
    if isinstance(obj, dict):
        return {k: json_shape(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_shape(obj[0])] if obj else []
    return type(obj).__name__


def length_bucket(n):
    for edge in (0, 50, 200, 1000, 5000, 20000):
        if n <= edge:
            return f"<= {edge}"
    return "> 20000"


def baseline_diff(baseline_resp, actual_resp):
    diff = {
        "status_delta": None,
        "keys_added": [],
        "keys_removed": [],
        "type_deltas": [],
        "length_bucket_delta": None,
        "anomaly_score": 0,
    }

    if baseline_resp["status"] != actual_resp["status"]:
        diff["status_delta"] = f"{baseline_resp['status']} -> {actual_resp['status']}"
        diff["anomaly_score"] += 2

    try:
        b_json = json.loads(baseline_resp["body"]) if baseline_resp["body"] else {}
    except Exception:
        b_json = None
    try:
        a_json = json.loads(actual_resp["body"]) if actual_resp["body"] else {}
    except Exception:
        a_json = None

    if isinstance(b_json, dict) and isinstance(a_json, dict):
        b_keys, a_keys = set(b_json.keys()), set(a_json.keys())
        diff["keys_added"] = sorted(a_keys - b_keys)
        diff["keys_removed"] = sorted(b_keys - a_keys)
        if diff["keys_added"]:
            diff["anomaly_score"] += 1
        if diff["keys_removed"]:
            diff["anomaly_score"] += 1
        for k in b_keys & a_keys:
            bt, at = type(b_json[k]).__name__, type(a_json[k]).__name__
            if bt != at:
                diff["type_deltas"].append({"key": k, "baseline_type": bt, "actual_type": at})
        if diff["type_deltas"]:
            diff["anomaly_score"] += 1

    b_len_bucket = length_bucket(len(baseline_resp["body"] or ""))
    a_len_bucket = length_bucket(len(actual_resp["body"] or ""))
    if b_len_bucket != a_len_bucket:
        diff["length_bucket_delta"] = f"{b_len_bucket} -> {a_len_bucket}"

    return diff


# ---------------------------------------------------------------------------
# Test case generation (Stage 2 modules, hand-scoped to these 2 endpoints)
# ---------------------------------------------------------------------------
def gen_baseline_replay(target):
    return [{
        "module": "baseline_replay",
        "variant": "as_captured",
        "target": target["name"],
        "method": target["method"],
        "path": target["path"],
        "header_overrides": {},
        "strip_cookies": False,
        "tamper_token": False,
    }]


def gen_auth_drop(target):
    return [
        {
            "module": "auth_drop",
            "variant": "a_no_cookies",
            "target": target["name"],
            "method": target["method"],
            "path": target["path"],
            "header_overrides": {},
            "strip_cookies": True,
            "tamper_token": False,
        },
        {
            "module": "auth_drop",
            "variant": "b_context_headers_stripped",
            "target": target["name"],
            "method": target["method"],
            "path": target["path"],
            "header_overrides": {h: None for h in SESSION_CONTEXT_HEADERS},
            "strip_cookies": False,
            "tamper_token": False,
        },
        {
            "module": "auth_drop",
            "variant": "c_tampered_access_token",
            "target": target["name"],
            "method": target["method"],
            "path": target["path"],
            "header_overrides": {},
            "strip_cookies": False,
            "tamper_token": True,
        },
    ]


def gen_method_matrix(target):
    cases = []
    for m in METHOD_MATRIX:
        if m == target["method"]:
            continue
        cases.append({
            "module": "method_matrix",
            "variant": m,
            "target": target["name"],
            "method": m,
            "path": target["path"],
            "header_overrides": {},
            "strip_cookies": False,
            "tamper_token": False,
        })
    return cases


def build_test_plan():
    plan = []
    for t in TARGETS:
        plan += gen_baseline_replay(t)
        plan += gen_auth_drop(t)
        plan += gen_method_matrix(t)
    # csrf_token_behavior is handled separately (needs 2 live calls back to
    # back, not a single fire-and-diff case) -- see run_csrf_probe()
    return plan


# ---------------------------------------------------------------------------
# Firing requests
# ---------------------------------------------------------------------------
def build_request(case, cookies, base_headers):
    headers = dict(base_headers)
    for k, v in case["header_overrides"].items():
        if v is None:
            headers.pop(k, None)
        else:
            headers[k] = v

    req_cookies = {} if case["strip_cookies"] else dict(cookies)

    if case["tamper_token"] and "__Secure-access-token" in req_cookies:
        tok = req_cookies["__Secure-access-token"]
        # flip signature bytes -> same shape, invalid signature
        req_cookies["__Secure-access-token"] = tok[:-8] + "AAAAAAAA"

    return {
        "method": case["method"],
        "url": BASE + case["path"],
        "headers": headers,
        "cookies": req_cookies,
    }


def fire(built_request, timeout=15):
    resp = requests.request(
        built_request["method"],
        built_request["url"],
        headers=built_request["headers"],
        cookies=built_request["cookies"],
        timeout=timeout,
        allow_redirects=False,
    )
    return {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": resp.text,
    }


def run_csrf_probe(cookies, base_headers, delay):
    """
    Stage 1.6 style detection, applied to the one endpoint in this HAR that
    actually mints tokens: /services/live/socket/v3/session returns
    csrf_token + session_extension_token fresh in its body every time it's
    called. Two identical calls, same cookies -- if the tokens differ,
    that's session-scoped-per-fetch (expected); if either token is IDENTICAL
    across both calls, note it (could mean caching or token reuse window).
    """
    path = "/services/live/socket/v3/session"
    case = {"method": "GET", "path": path, "header_overrides": {}, "strip_cookies": False, "tamper_token": False}
    req1 = build_request(case, cookies, base_headers)
    resp1 = fire(req1)
    time.sleep(delay)
    req2 = build_request(case, cookies, base_headers)
    resp2 = fire(req2)

    try:
        j1 = json.loads(resp1["body"])
        j2 = json.loads(resp2["body"])
    except Exception:
        return {"error": "non-JSON response, can't compare tokens", "resp1": resp1, "resp2": resp2}

    result = {
        "csrf_token_1": j1.get("csrf_token"),
        "csrf_token_2": j2.get("csrf_token"),
        "csrf_token_identical": j1.get("csrf_token") == j2.get("csrf_token"),
        "session_extension_token_1": j1.get("session_extension_token"),
        "session_extension_token_2": j2.get("session_extension_token"),
        "session_extension_token_identical": j1.get("session_extension_token") == j2.get("session_extension_token"),
        "status_1": resp1["status"],
        "status_2": resp2["status"],
    }
    result["classification"] = (
        "reusable/session-scoped (identical across calls)"
        if result["csrf_token_identical"]
        else "fresh-per-fetch (expected for a token-issuing endpoint)"
    )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--har", required=True, help="Path to the HAR file to load session/cookies from")
    ap.add_argument("--live", action="store_true", help="Actually fire requests. Without this, dry-run only.")
    ap.add_argument("--delay", type=float, default=2.5, help="Seconds between requests (default 2.5)")
    ap.add_argument("--out-dir", default="./findings", help="Where to save raw req/resp per finding")
    args = ap.parse_args()

    cookies, base_headers = load_session_from_har(args.har)
    print(f"[+] Loaded {len(cookies)} cookies and {len(base_headers)} headers from {args.har}")

    freshness = check_token_freshness(cookies)
    if freshness:
        if freshness["seconds_remaining"] <= 0:
            print(f"[!] __Secure-access-token looks EXPIRED (exp was {freshness['seconds_remaining']:.0f}s ago).")
            print("    Live requests will likely 401. Re-export a fresh HAR from an active session before --live.")
        else:
            print(f"[+] __Secure-access-token expires in {freshness['seconds_remaining']:.0f}s ({freshness.get('identity')})")

    plan = build_test_plan()

    print(f"\n[+] Test plan: {len(plan)} requests across {len(TARGETS)} endpoints")
    by_module = {}
    for c in plan:
        by_module.setdefault(c["module"], 0)
        by_module[c["module"]] += 1
    for mod, count in by_module.items():
        print(f"    {mod:20s} {count} requests")
    print(f"    {'csrf_token_behavior':20s} 2 requests (separate probe)")
    total = len(plan) + 2
    est_seconds = total * args.delay
    print(f"\n[+] Total requests if run: {total}  (~{est_seconds:.0f}s at {args.delay}s delay)")
    print("[+] Scope: read-only endpoints only. No Kasada-gated or mutating calls included.")

    if not args.live:
        print("\n[dry-run] Nothing fired. Re-run with --live to execute.")
        return

    os.makedirs(args.out_dir, exist_ok=True)
    findings = []

    print("\n[+] Firing baseline_replay first for each target to confirm session validity...")
    baseline_responses = {}
    for case in plan:
        if case["module"] != "baseline_replay":
            continue
        built = build_request(case, cookies, base_headers)
        resp = fire(built)
        baseline_responses[case["target"]] = resp
        print(f"    {case['target']}: {resp['status']}")
        time.sleep(args.delay)

    for target_name, resp in baseline_responses.items():
        target = next(t for t in TARGETS if t["name"] == target_name)
        if resp["status"] != target["baseline_status"]:
            print(f"[!] {target_name} baseline returned {resp['status']}, expected {target['baseline_status']}.")
            print("    Session is likely stale/expired -- results below will mostly reflect that, not real findings.")

    print("\n[+] Running auth_drop + method_matrix...")
    for case in plan:
        if case["module"] == "baseline_replay":
            continue
        built = build_request(case, cookies, base_headers)
        resp = fire(built)
        baseline = baseline_responses.get(case["target"])
        diff = baseline_diff(baseline, resp) if baseline else None

        flagged = False
        reason = None
        if case["module"] == "auth_drop" and resp["status"] == 200 and baseline and baseline["status"] != 200:
            flagged = True
            reason = "auth-dropped request returned 200 where baseline did not"
        if case["module"] == "auth_drop" and resp["status"] not in (401, 403):
            flagged = True
            reason = reason or f"auth-dropped request returned {resp['status']} (expected 401/403)"
        if case["module"] == "method_matrix" and resp["status"] not in (404, 405, 401, 403):
            flagged = True
            reason = reason or f"unexpected method {case['method']} returned {resp['status']}"

        record = {
            "module": case["module"],
            "variant": case["variant"],
            "target": case["target"],
            "request": {"method": built["method"], "url": built["url"],
                        "headers": {k: v for k, v in built["headers"].items()},
                        "cookie_names_sent": list(built["cookies"].keys())},
            "response": {"status": resp["status"], "body_snippet": resp["body"][:500]},
            "diff_vs_baseline": diff,
            "flagged": flagged,
            "reason": reason,
        }
        findings.append(record)

        tag = "FLAG" if flagged else "ok"
        print(f"    [{tag}] {case['module']:15s} {case['variant']:30s} -> {resp['status']}")
        time.sleep(args.delay)

    print("\n[+] Running csrf_token_behavior probe...")
    csrf_result = run_csrf_probe(cookies, base_headers, args.delay)
    print(f"    classification: {csrf_result.get('classification')}")
    findings.append({"module": "csrf_token_behavior", "result": csrf_result})

    out_path = os.path.join(args.out_dir, f"findings_{int(time.time())}.json")
    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] Saved {len(findings)} records to {out_path}")

    flagged_count = sum(1 for r in findings if r.get("flagged"))
    print(f"[+] {flagged_count} flagged for manual review out of {len(findings) - 1} auth/method test cases")


if __name__ == "__main__":
    main()
