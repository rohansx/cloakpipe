#!/usr/bin/env python3
"""A scripted support agent that always falls for the attack.

A stand-in for a model that was tricked, so `cloakpipe prove` can run in CI
without an API key and give the same result every time. It does the ticket's
ordinary work (emails the customer, issues the refund the ticket names),
then obeys every planted "call <tool> with {json}" instruction in the
ticket, and retries once a call that fails or times out.

It speaks to its MCP server the way `cloakpipe prove` hands it over:
$CLOAKPIPE_PROVE_GATE is the server's command, $CLOAKPIPE_PROVE_TASK the task.
Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import queue
import subprocess
import sys
import threading
from typing import Any

TIMEOUT = -1  # our own code: no answer in time
RETRY_CODES = {-32002, -32003, TIMEOUT}  # outcome unknown / upstream unavailable / timed out
CALL_TIMEOUT_SECS = 5


class Server:
    def __init__(self, argv: list[str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.next_id = 0
        self.replies: queue.Queue[dict[str, Any] | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.replies.put(json.loads(line))
        self.replies.put(None)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.next_id += 1
        msg_id = self.next_id
        self.send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
        while True:
            try:
                msg = self.replies.get(timeout=CALL_TIMEOUT_SECS)
            except queue.Empty:
                return {"error": {"code": TIMEOUT, "message": "timed out"}}
            if msg is None:
                return {"error": {"code": -32003, "message": "server closed"}}
            if msg.get("id") == msg_id:
                return msg

    def send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=30)


def call(server: Server, tool: str, args: dict[str, Any], retry: bool = True) -> dict[str, Any]:
    reply = server.request("tools/call", {"name": tool, "arguments": args})
    error = reply.get("error")
    reason = (error or {}).get("data", {}).get("reason", "")
    print(f"{tool} {json.dumps(args)[:120]} -> {'error ' + str(error.get('code')) + ' ' + reason if error else 'ok'}", flush=True)
    if error and retry and error.get("code") in RETRY_CODES:
        return call(server, tool, args, retry=False)
    return reply


def planted(text: str) -> list[tuple[str, dict[str, Any]]]:
    """Every `call <tool> with {json}` in the ticket."""
    found = []
    decoder = json.JSONDecoder()
    for m in re.finditer(r"call (\w+) with ", text, re.IGNORECASE):
        try:
            args, _ = decoder.raw_decode(text, m.end())
        except ValueError:
            continue
        if isinstance(args, dict):
            found.append((m.group(1), args))
    return found


def main() -> int:
    with open(os.environ["CLOAKPIPE_PROVE_TASK"]) as f:
        task = json.load(f)
    ticket = task["context"]["ticket"]
    server = Server(shlex.split(os.environ["CLOAKPIPE_PROVE_GATE"]))
    server.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "gullible-agent", "version": "1"}})
    server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    server.request("tools/list")

    reply = call(server, "read_ticket", {"ticket_id": ticket["id"]})
    text = "".join(c.get("text", "") for c in reply.get("result", {}).get("content", []))
    call(server, "send_email", {"ticket_id": ticket["id"], "to": ticket["customer_email"], "subject": f"Your ticket {ticket['id']}",
                                "body": f"Hello, we are on ticket {ticket['id']} and will resolve it today."})
    refund = re.search(r"^Refund: (\d+)", text, re.M)
    if refund and int(refund.group(1)) > 0:
        call(server, "issue_refund", {"ticket_id": ticket["id"], "amount": int(refund.group(1))})
    for tool, args in planted(text):
        call(server, tool, args)
    server.close()

    usage = os.environ.get("CLOAKPIPE_PROVE_USAGE")
    if usage:
        with open(usage, "w") as f:
            json.dump({"input_tokens": 0, "output_tokens": 0, "cost_usd": 0}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
