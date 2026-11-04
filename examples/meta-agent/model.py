"""Chat-with-tools client for the agent: one function, several providers.

Standard library only. Every provider is driven through the same normalized
shape:

    messages: OpenAI-style chat messages (system / user / assistant with
              tool_calls / tool)
    tools:    [{"name", "description", "parameters"}]  (JSON Schema)
    reply:    {"text": str, "tool_calls": [{"id", "name", "arguments": dict}]}

Providers (MODEL_PROVIDER):
    ollama     local Llama through Ollama's OpenAI-compatible API (default)
    fireworks  Meta open-weights models on Fireworks   (FIREWORKS_API_KEY)
    baseten    Meta open-weights models on Baseten     (BASETEN_API_KEY)
    meta       the Meta Model API, e.g. Muse Spark     (META_API_KEY, META_BASE_URL)
    openrouter Muse Spark and Llama via OpenRouter     (OPENROUTER_API_KEY)
    modal      Muse Spark Open on a Modal endpoint     (MODAL_API_KEY = wk-<id>.ws-<secret>, MODAL_BASE_URL)
    openai     any other OpenAI-compatible endpoint    (OPENAI_API_KEY, OPENAI_BASE_URL)
    anthropic  Claude, for development only            (ANTHROPIC_API_KEY)

MODEL overrides the provider's default model. Hosted providers have no
default: their model catalogs change, so name the model you have access to.

Record / replay: with a fixture path, `record` appends every reply to the
fixture and `replay` answers from it in order without any network call, so
a recorded run can be played back identically (the video, CI, a judge
without an API key). The fixture names the provider and model that produced
it, and replay prints them: a replay never pretends to be another model.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# provider -> (base URL, API-key env var, base-URL env override, default model)
PROVIDERS: dict[str, tuple[str, str | None, str | None, str | None]] = {
    "ollama": ("http://localhost:11434/v1", None, "OLLAMA_BASE_URL", "llama3.1:8b"),
    "fireworks": ("https://api.fireworks.ai/inference/v1", "FIREWORKS_API_KEY", None, None),
    "baseten": ("https://inference.baseten.co/v1", "BASETEN_API_KEY", "BASETEN_BASE_URL", None),
    "meta": ("", "META_API_KEY", "META_BASE_URL", None),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", None, "meta/muse-spark-1.3"),
    "modal": ("", "MODAL_API_KEY", "MODAL_BASE_URL", "meta-models/Muse-Spark-Open-816B-A42B"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", "OPENAI_BASE_URL", None),
    "anthropic": ("https://api.anthropic.com/v1", "ANTHROPIC_API_KEY", None, "claude-haiku-5-5"),
}
TIMEOUT_S = 180
MAX_TOKENS = 2048


class ModelError(RuntimeError):
    pass


def digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class Model:
    provider: str
    model: str
    base_url: str
    api_key: str | None
    temperature: float = 0.0
    max_tokens: int = MAX_TOKENS
    fixture: str | None = None
    mode: str = "live"  # live | record | replay
    _replies: list[dict[str, Any]] = field(default_factory=list)
    _cursor: int = 0

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        if self.mode == "replay":
            return self._replay(messages, tools)
        if self.provider == "anthropic":
            reply = _anthropic_chat(self, messages, tools)
        else:
            reply = _openai_chat(self, messages, tools)
        if self.mode == "record":
            self._replies.append({"request": digest([messages, tools]), "reply": reply})
            self._save()
        return reply

    def _replay(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        if self._cursor >= len(self._replies):
            raise ModelError(f"replay fixture {self.fixture} has no reply #{self._cursor + 1}")
        entry = self._replies[self._cursor]
        self._cursor += 1
        if entry["request"] != digest([messages, tools]):
            print(f"  (replay: request #{self._cursor} differs from the recorded one)", file=sys.stderr)
        return entry["reply"]

    def _save(self) -> None:
        assert self.fixture
        doc = {"provider": self.provider, "model": self.model, "replies": self._replies}
        with open(self.fixture, "w") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")


def from_env(fixture: str | None = None, mode: str = "live") -> Model:
    """Build the Model from MODEL_PROVIDER / MODEL / the provider's env vars."""
    if mode == "replay":
        if not fixture or not os.path.exists(fixture):
            raise ModelError(f"replay needs a recorded fixture: {fixture} not found")
        with open(fixture) as f:
            doc = json.load(f)
        m = Model(doc["provider"], doc["model"], "", None, fixture=fixture, mode="replay")
        m._replies = doc["replies"]
        return m
    provider = os.environ.get("MODEL_PROVIDER", "ollama")
    if provider not in PROVIDERS:
        raise ModelError(f"MODEL_PROVIDER={provider}: expected one of {', '.join(PROVIDERS)}")
    base, key_env, base_env, default_model = PROVIDERS[provider]
    base = (os.environ.get(base_env) if base_env else None) or base
    model = os.environ.get("MODEL") or default_model
    if not model:
        raise ModelError(f"MODEL_PROVIDER={provider} needs MODEL (the model id you have access to)")
    if not base:
        raise ModelError(f"MODEL_PROVIDER={provider} needs {base_env}")
    key = os.environ.get(key_env) if key_env else None
    if key_env and not key:
        raise ModelError(f"MODEL_PROVIDER={provider} needs {key_env}")
    if mode == "record" and not fixture:
        raise ModelError("record needs a fixture path")
    return Model(provider, model, base.rstrip("/"), key, fixture=fixture, mode=mode)


def _post(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "user-agent": "cloakpipe-meta-agent/0.1", **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise ModelError(f"{url}: HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise ModelError(f"{url}: {e}") from e


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"_unparsed": raw}
    return value if isinstance(value, dict) else {"_unparsed": raw}


def _openai_chat(m: Model, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    body: dict[str, Any] = {"model": m.model, "messages": messages, "temperature": m.temperature,
                            "max_tokens": m.max_tokens}
    if tools:
        body["tools"] = [{"type": "function", "function": t} for t in tools]
    headers = {"authorization": f"Bearer {m.api_key}"} if m.api_key else {}
    data = _post(f"{m.base_url}/chat/completions", headers, body)
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError) as e:
        raise ModelError(f"unexpected reply: {json.dumps(data)[:300]}") from e
    calls = [{"id": c.get("id") or f"call_{i}", "name": c["function"]["name"],
              "arguments": _parse_args(c["function"].get("arguments"))}
             for i, c in enumerate(msg.get("tool_calls") or [])]
    text = msg.get("content") or ""
    if not calls and tools:
        calls = _text_tool_call(text, {t["name"] for t in tools})
    return {"text": "" if calls and not msg.get("tool_calls") else text, "tool_calls": calls}


def _text_tool_call(text: str, names: set[str]) -> list[dict[str, Any]]:
    """Llama 3.x served without a tool-call parser sometimes answers with the
    call as JSON text ({"name": ..., "parameters": {...}}). Accept exactly
    that shape. A name that was not offered is still a call: the gate refuses
    it as undeclared_tool and the model hears why. Anything else stays text."""
    # ponytail: one JSON object per reply; a list of calls in text is left as text.
    del names  # every name goes to the gate; it, not the client, decides
    stripped = text.strip().removeprefix("<|python_tag|>").strip()
    if not stripped.startswith("{"):
        stripped = stripped[stripped.find("{"):] if "{\"name\"" in stripped else ""
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return []
    if not isinstance(obj, dict) or not isinstance(obj.get("name"), str):
        return []
    args = obj.get("parameters", obj.get("arguments", {}))
    return [{"id": "call_text_0", "name": obj["name"], "arguments": _parse_args(args)}]


def _to_anthropic(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system, out = "", []
    for msg in messages:
        role = msg["role"]
        if role == "system":
            system += msg["content"]
            continue
        if role == "tool":
            block = {"type": "tool_result", "tool_use_id": msg["tool_call_id"], "content": msg["content"]}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
            continue
        if role == "assistant":
            blocks: list[dict[str, Any]] = [{"type": "text", "text": msg["content"]}] if msg.get("content") else []
            for c in msg.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": c["id"], "name": c["function"]["name"],
                               "input": _parse_args(c["function"]["arguments"])})
            out.append({"role": "assistant", "content": blocks})
            continue
        out.append({"role": "user", "content": msg["content"]})
    return system, out


def _anthropic_chat(m: Model, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    system, msgs = _to_anthropic(messages)
    body: dict[str, Any] = {"model": m.model, "max_tokens": 2048, "system": system, "messages": msgs,
                            "temperature": m.temperature,
                            "tools": [{"name": t["name"], "description": t.get("description", ""),
                                       "input_schema": t["parameters"]} for t in tools]}
    headers = {"x-api-key": m.api_key or "", "anthropic-version": "2023-06-01"}
    data = _post(f"{m.base_url}/messages", headers, body)
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    calls = [{"id": b["id"], "name": b["name"], "arguments": b.get("input") or {}}
             for b in data.get("content", []) if b.get("type") == "tool_use"]
    return {"text": text, "tool_calls": calls}
