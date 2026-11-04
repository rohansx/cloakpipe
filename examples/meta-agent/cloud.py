#!/usr/bin/env python3
"""Connect the demo to a CloakPipe Cloud (the attention plane), for local runs.

    cloud.py setup   --api URL --out DIR [--gate NAME ...]
                                           sign in (the api's test login), take an
                                           approver seat, create the gates, fetch their
                                           approver keys; writes DIR/cloud.json
    cloud.py approve --state DIR FPRINT    approve the pending request for this call
                                           fingerprint, as the dashboard's button does

The test login exists only on an api started with AUTH_TEST_LOGIN=1, which
the api refuses in production. With a real Cloud, sign in on the dashboard,
create the gate there, and pass its secret file instead.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

EMAIL = os.environ.get("CLOUD_EMAIL", "demo@cloakpipe.test")
GATE_NAME = os.environ.get("CLOUD_GATE_NAME", "support-desk")


def call(api: str, method: str, path: str, token: str | None = None, body: Any = None) -> tuple[int, Any]:
    headers = {"content-type": "application/json", "user-agent": "cloakpipe-meta-agent/0.1"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


def need(ok: bool, what: str, detail: Any) -> None:
    if not ok:
        sys.exit(f"cloud: {what} failed: {detail}")


def login(api: str) -> str:
    status, body = call(api, "POST", "/api/auth/test-login", body={"email": EMAIL})
    need(status in (200, 201) and isinstance(body, dict) and body.get("token"),
         "test login (is the api running with AUTH_TEST_LOGIN=1?)", body)
    return body["token"]


def setup(a: argparse.Namespace) -> int:
    api = a.api.rstrip("/")
    os.makedirs(a.out, exist_ok=True)
    token = login(api)
    status, me = call(api, "GET", "/api/team/me", token)
    need(status == 200, "read the signed-in user", me)
    status, seats = call(api, "GET", "/api/approvals/seats", token)
    taken = status == 200 and any(s.get("user_id") == me["id"] for s in (seats or {}).get("seats", []))
    if not taken:
        status, body = call(api, "POST", "/api/approvals/seats", token, {"user_id": me["id"]})
        need(status in (200, 201), "take an approver seat", body)
    status, gates = call(api, "GET", "/api/gates", token)
    need(status == 200, "list gates", gates)
    state = {"api": api, "gates": {}}
    for name in a.gate or [GATE_NAME]:
        for g in gates.get("gates", []):  # start each setup from a fresh gate
            if g.get("name") == name:
                call(api, "DELETE", f"/api/gates/{g['id']}", token)
        status, body = call(api, "POST", "/api/gates", token, {"name": name})
        need(status == 201 and body.get("secret"), f"create gate {name}", body)
        gate_id, secret = body["gate"]["id"], body["secret"]
        secret_file = os.path.join(a.out, f"{name}.secret")
        with open(os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(secret + "\n")
        gate_url = f"{api}/v1/gates/{gate_id}"
        keys = os.path.join(a.out, f"{name}-approver-keys")
        done = subprocess.run([a.cloakpipe, "approvals", "keys", "--approvals-url", gate_url,
                               "--approvals-secret-file", secret_file, "--out", keys], capture_output=True, text=True)
        need(done.returncode == 0, "fetch the approver keys", done.stderr)
        state["gates"][name] = {"gate_id": gate_id, "gate_url": gate_url, "events_url": f"{gate_url}/events",
                                "secret_file": secret_file,
                                "approver_keys": sorted(os.path.join(keys, k) for k in os.listdir(keys))}
        print(f"cloud: gate {name} ({gate_id}) on {api}")
    with open(os.path.join(a.out, "cloud.json"), "w") as f:
        json.dump(state, f, indent=1)
    return 0



def approve(a: argparse.Namespace) -> int:
    with open(os.path.join(a.state, "cloud.json")) as f:
        state = json.load(f)
    api = state["api"]
    token = login(api)
    want = a.fingerprint.removeprefix("sha256:")
    deadline = time.time() + 60
    while time.time() < deadline:
        status, body = call(api, "GET", "/api/approvals?status=pending", token)
        for r in (body or {}).get("approvals", []) if status == 200 else []:
            if r.get("fingerprint", "").removeprefix("sha256:") == want:
                status, out = call(api, "POST", f"/api/approvals/{r['id']}/approve", token)
                need(status == 200, "approve", out)
                print(f"cloud: approved request {r['id']}")
                return 0
        time.sleep(1)
    sys.exit(f"cloud: no pending request for {a.fingerprint} after 60s")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--api", default=os.environ.get("CLOUD_API", "http://localhost:8080"))
    s.add_argument("--out", required=True)
    s.add_argument("--gate", action="append", help="a gate to create (repeatable); default: support-desk")
    s.add_argument("--cloakpipe", default=os.environ.get("CLOAKPIPE", "cloakpipe"))
    ap = sub.add_parser("approve")
    ap.add_argument("--state", required=True)
    ap.add_argument("fingerprint")
    a = p.parse_args()
    return setup(a) if a.cmd == "setup" else approve(a)


if __name__ == "__main__":
    sys.exit(main())
