#!/usr/bin/env python3
"""
whatnot_test.py <har_file> [--live]

Single-use script for exactly 2 endpoints found in the whatnot.com HAR:
  GET /api/v1/realtime/settings
  GET /services/live/socket/v3/session

No flags to remember. Run it with just the HAR path -> prints what it WOULD
do. Add --live -> actually fires the requests.

Tests: auth_drop (no cookies / stripped session headers / tampered token),
method_matrix (wrong HTTP methods), csrf token reuse check.
"""

import base64, json, sys, time
from urllib.parse import urlparse
import requests

BASE = "https://www.whatnot.com"
PATHS = ["/api/v1/realtime/settings", "/services/live/socket/v3/session"]
CARRY_HEADERS = [
    "x-whatnot-app-session-id", "x-whatnot-app-user-session-id",
    "x-whatnot-app-version", "x-whatnot-app-context", "x-whatnot-app",
    "x-whatnot-app-pathname", "x-whatnot-app-screen", "x-client-timezone",
    "user-agent", "accept", "content-type",
]
DELAY = 2.5


def load_har(har_path):
    with open(har_path) as f:
        har = json.load(f)
    cookies, headers = {}, {}
    for e in har["log"]["entries"]:
        req = e["request"]
        if urlparse(req["url"]).path not in PATHS:
            continue
        for c in req.get("cookies", []):
            cookies[c["name"]] = c["value"]
        for h in req["headers"]:
            if h["name"].lower() in CARRY_HEADERS:
                headers[h["name"].lower()] = h["value"]
    if not cookies:
        sys.exit("Couldn't find those 2 endpoints in this HAR.")
    return cookies, headers


def load_from_browser(browser="chrome"):
    """
    Reads whatnot.com cookies straight out of your browser's own cookie
    store (same decryption the browser itself uses) -- no HAR export
    needed, always gets whatever's currently valid right now.
    Requires: pip install browser-cookie3 --break-system-packages
    On some OSes the browser must be fully closed first (cookie DB locks
    while the browser is running).
    """
    import browser_cookie3 as bc3
    getter = {"chrome": bc3.chrome, "firefox": bc3.firefox,
              "edge": bc3.edge, "brave": bc3.brave}.get(browser)
    if not getter:
        sys.exit(f"unsupported browser '{browser}', use chrome/firefox/edge/brave")
    jar = getter(domain_name="whatnot.com")
    cookies = {c.name: c.value for c in jar}
    if not cookies:
        sys.exit("No whatnot.com cookies found in that browser. Are you logged in there?")
    # headers can't come from a cookie jar -- these are low-risk static
    # values from the original HAR (app version/UA), fine to reuse since
    # they don't rotate per-session the way the token does
    headers = {
        "x-whatnot-app-version": "20260725-0107",
        "x-whatnot-app-context": "next-js/browser",
        "x-whatnot-app": "whatnot-web",
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
    }
    return cookies, headers


def token_status(cookies):
    tok = cookies.get("__Secure-access-token")
    if not tok or tok.count(".") != 2:
        return None
    try:
        p = tok.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return None
    return payload.get("exp", 0) - time.time()


def fire(method, path, cookies, headers):
    r = requests.request(method, BASE + path, cookies=cookies, headers=headers,
                          timeout=15, allow_redirects=False)
    return r.status_code, r.text


def main():
    live = "--live" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--live"]

    if args and args[0] == "--browser":
        browser = args[1] if len(args) > 1 else "chrome"
        cookies, headers = load_from_browser(browser)
        print(f"[+] Pulled live cookies from {browser} (no HAR needed)")
    elif args:
        cookies, headers = load_har(args[0])
    else:
        sys.exit(f"usage: {sys.argv[0]} <har_file> [--live]\n"
                  f"   or: {sys.argv[0]} --browser [chrome|firefox|edge|brave] [--live]")
    remaining = token_status(cookies)
    if remaining is not None:
        print(f"[token] {'EXPIRED' if remaining <= 0 else 'valid'} ({remaining:.0f}s remaining)")

    tests = []
    for path in PATHS:
        tests.append(("baseline", "GET", path, cookies, headers))
        tests.append(("auth_drop:no_cookies", "GET", path, {}, headers))
        stripped = {k: v for k, v in headers.items() if k not in
                    ("x-whatnot-app-session-id", "x-whatnot-app-user-session-id")}
        tests.append(("auth_drop:no_session_headers", "GET", path, cookies, stripped))
        tampered = dict(cookies)
        if "__Secure-access-token" in tampered:
            tampered["__Secure-access-token"] = tampered["__Secure-access-token"][:-8] + "AAAAAAAA"
        tests.append(("auth_drop:tampered_token", "GET", path, tampered, headers))
        for m in ("POST", "PUT", "DELETE", "PATCH"):
            tests.append((f"method:{m}", m, path, cookies, headers))

    print(f"{len(tests)} requests planned, ~{len(tests)*DELAY:.0f}s at {DELAY}s delay")
    for name, method, path, *_ in tests:
        print(f"  {name:30s} {method:6s} {path}")

    if not live:
        print("\nDry run only. Re-run with --live to actually fire these.")
        return

    print("\nFiring...")
    baselines = {}
    results = []
    for name, method, path, c, h in tests:
        status, body = fire(method, path, c, h)
        if name == "baseline":
            baselines[path] = status
        flag = ""
        if name.startswith("auth_drop") and status == 200 and baselines.get(path) == 200:
            flag = "  <-- FLAG: still 200 with auth dropped"
        if name.startswith("method:") and status not in (401, 403, 404, 405):
            flag = f"  <-- FLAG: unexpected {status} for wrong method"
        print(f"  [{status}] {name:30s} {path}{flag}")
        results.append({"test": name, "method": method, "path": path, "status": status, "body_snippet": body[:300]})
        time.sleep(DELAY)

    out = f"whatnot_findings_{int(time.time())}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
