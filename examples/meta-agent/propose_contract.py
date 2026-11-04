#!/usr/bin/env python3
"""A Meta model drafts the agent's contract; CloakPipe's own validator decides.

Model proposes, code disposes, applied to writing the rules themselves:

  1. Run the agent in shadow mode on ordinary tickets (every call is
     forwarded, and recorded in calls.jsonl).
  2. This script gives a Meta model what the agent was offered (tools.json),
     what it actually did (calls.jsonl), the trusted task context, and the
     manifest grammar (read from docs/MANIFEST.md, so it cannot drift), and
     asks for a least-privilege cloakpipe.manifest.yaml.
  3. The draft must pass `cloakpipe manifest validate`. A rejection is sent
     back to the model with the validator's error, up to MAX_ATTEMPTS times.
     The gate itself never calls a model: the model only writes a file that
     a human reviews and the validator accepts or refuses.

usage: propose_contract.py --calls calls.jsonl --tools tools.json
                           --task-context task-context.json --out proposed.manifest.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any

import model as model_mod

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "..", "..", "docs", "MANIFEST.md")
MAX_ATTEMPTS = 3

INSTRUCTIONS = """You write CloakPipe manifests: least-privilege contracts for an AI agent's tool calls.
Below are the manifest grammar, the tools the agent was offered, the calls it made while working
ordinary tickets (all legitimate), and the trusted task context the orchestrator writes per task.

Write the manifest for this agent. Rules:
- release: support-agent-proposed, version: "1". No policy key.
- Declare only tools the agent actually used. Anything else must stay undeclared.
- Declare only arguments the agent actually sent; mark them required: true.
- When an observed string value equals a value in the task context, bind the argument to it with
  one_of_context (the dotted path into the task context, e.g. ticket.id). Never hard-code such values.
- Other strings: type string with a generous max_len. Integers: type integer with min and max;
  max is a hard ceiling, about ten times the largest observed value, never the observed value itself.
- Tools that change something outside the agent (sending, paying, deleting) get side_effect: true.
- A side-effecting tool that moves money gets an approval block for amounts larger than the ones observed
  (the approval, not max, is what stops an unusual amount),
  with approvers: ["slack:#support-leads"] and ttl: 15m.
- Answer with the YAML document only: no prose, no code fences.

Where each key goes (an unrelated calendar agent; `side_effect` and `approval` sit on the tool,
next to `args`, never inside an argument):

release: calendar-agent
version: "1"
tools:
  list_events:
    args:
      calendar_id: { type: string, one_of_context: ["user.calendar_id"], required: true }
  book_room:
    args:
      calendar_id: { type: string, one_of_context: ["user.calendar_id"], required: true }
      seats: { type: integer, min: 1, max: 12, required: true }
    side_effect: true
    approval:
      when: "seats > 8"
      approvers: ["slack:#facilities"]
      ttl: 15m"""


def grammar() -> str:
    with open(SPEC) as f:
        text = f.read()
    start, end = text.index("## Top level"), text.index("## Digests")
    return text[start:end]


def strip_fences(text: str) -> str:
    match = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.S)
    return (match.group(1) if match else text).strip() + "\n"


def validate(cloakpipe: str, path: str) -> str | None:
    """None when the manifest is valid, else the validator's message."""
    done = subprocess.run([cloakpipe, "manifest", "validate", path], capture_output=True, text=True)
    return None if done.returncode == 0 else (done.stderr or done.stdout).strip()


def load_calls(path: str) -> list[dict[str, Any]]:
    with open(path) as f:
        calls = [json.loads(line) for line in f if line.strip()]
    return [{"tool": c["tool"], "arguments": c["arguments"]} for c in calls]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--calls", required=True)
    p.add_argument("--tools", required=True)
    p.add_argument("--task-context", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--fixture", help="record to / replay from this file")
    p.add_argument("--model-mode", choices=["live", "record", "replay"], default="live")
    p.add_argument("--cloakpipe", default=os.environ.get("CLOAKPIPE", "cloakpipe"))
    a = p.parse_args()
    try:
        llm = model_mod.from_env(a.fixture, a.model_mode)
        llm.max_tokens = 16384  # a reasoning model thinks before it writes the YAML
    except model_mod.ModelError as e:
        print(f"model error: {e}", file=sys.stderr)
        return 2
    with open(a.tools) as f:
        tools = json.load(f)
    with open(a.task_context) as f:
        context = json.load(f)
    calls = load_calls(a.calls)
    print(f"PROPOSE   {llm.label} drafts a contract from {len(calls)} observed calls", flush=True)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": INSTRUCTIONS},
        {"role": "user", "content": "\n\n".join([
            "# Manifest grammar\n" + grammar(),
            "# Tools offered\n" + json.dumps(tools, indent=1),
            "# Calls observed (shadow mode)\n" + "\n".join(json.dumps(c) for c in calls),
            "# Task context\n" + json.dumps(context, indent=1)])}]
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            reply = llm.chat(messages, [])
        except model_mod.ModelError as e:
            print(f"model error: {e}", file=sys.stderr)
            return 2
        draft = strip_fences(reply["text"])
        with open(a.out, "w") as f:
            f.write(draft)
        error = validate(a.cloakpipe, a.out)
        if error is None:
            print(f"VALID     draft {attempt} accepted by `cloakpipe manifest validate`: {a.out}", flush=True)
            return 0
        print(f"REJECTED  draft {attempt}: {error.splitlines()[0]}", flush=True)
        messages += [{"role": "assistant", "content": reply["text"]},
                     {"role": "user", "content": f"cloakpipe manifest validate refused it:\n{error}\n"
                                                 "Fix it and answer with the whole corrected YAML only."}]
    print(f"no valid manifest after {MAX_ATTEMPTS} drafts", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
