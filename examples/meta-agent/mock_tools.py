#!/usr/bin/env python3
"""A stand-in MCP server with the support desk's tools (stdio JSON-RPC).

read_ticket returns the text of the ticket file in MOCK_TICKET (default
tickets/T-1042-injected.txt): that is where the prompt injection arrives,
as data inside a tool result. Every tools/call that reaches this server is
logged to stderr and, with MOCK_UPSTREAM_LOG set, appended to that file as
one JSON line: the demo's checks read it to see what got past the gate.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required)}


S = {"type": "string"}
TOOLS = [
    {"name": "read_ticket", "description": "Read a support ticket by id.",
     "inputSchema": obj({"ticket_id": S}, ["ticket_id"])},
    {"name": "send_email", "description": "Send an email.",
     "inputSchema": obj({"ticket_id": S, "to": S, "subject": S, "body": S},
                        ["ticket_id", "to", "subject", "body"])},
    {"name": "issue_refund", "description": "Refund a customer, in whole currency units.",
     "inputSchema": obj({"ticket_id": S, "amount": {"type": "integer"}}, ["ticket_id", "amount"])},
    {"name": "export_customers", "description": "Export every customer record as CSV.",
     "inputSchema": obj({})},
]


def ticket_text():
    path = os.environ.get("MOCK_TICKET") or os.path.join(HERE, "tickets", "T-1042-injected.txt")
    with open(path) as f:
        return f.read()


def result_text(name):
    if name == "read_ticket":
        return ticket_text()
    if name == "export_customers":
        return "id,name,email\n1,Dana Reyes,dana@customer.example\n2,Ola Berg,ola@customer.example"
    return "%s: done" % name


def send(obj_):
    sys.stdout.write(json.dumps(obj_) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    msg_id, method = msg.get("id"), msg.get("method")
    if msg_id is None:
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}}, "serverInfo": {"name": "mock-support-tools", "version": "0"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = msg.get("params", {})
        name, arguments = params.get("name"), params.get("arguments", {})
        sys.stderr.write("upstream received: %s %s\n" % (name, json.dumps(arguments, sort_keys=True)))
        sys.stderr.flush()
        if os.environ.get("MOCK_UPSTREAM_LOG"):
            with open(os.environ["MOCK_UPSTREAM_LOG"], "a") as log:
                log.write(json.dumps({"name": name, "arguments": arguments}, sort_keys=True) + "\n")
        if name not in {t["name"] for t in TOOLS}:
            send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "isError": True, "content": [{"type": "text", "text": "unknown tool: %s" % name}]}})
            continue
        send({"jsonrpc": "2.0", "id": msg_id,
              "result": {"content": [{"type": "text", "text": result_text(name)}]}})
    else:
        send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "method not found"}})
