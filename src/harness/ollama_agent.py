"""Local model adapter (FR-01): Qwen via Ollama's /api/chat with native tool calling.

The adapter only proposes tool calls; the runner authorizes and executes them.
Failures map to AgentError subclasses so a run is recorded as failed, never as
a successful defense (NFR-04). Standard library only (urllib), local host only.
"""

from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any

from harness.interfaces import AgentTimeout, AgentUnavailable, MalformedResponse
from harness.models import AgentTurn, Message, ToolCall, ToolSpec

# qwen2.5 sometimes prints a tool call as text instead of using the tool-call channel
TEXT_TOOL_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


class OllamaAgent:
    def __init__(self, model: str | None = None, host: str | None = None, temperature: float = 0.0,
                 seed: int = 0, num_ctx: int = 8192, timeout: float = 300.0):
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}
        self.timeout = timeout
        self.name = f"ollama:{self.model}"
        self._digest: str | None = None

    def describe(self) -> dict[str, Any]:
        if self._digest is None:
            try:
                tags = self._post("/api/tags", None)
                self._digest = next((m["digest"] for m in tags.get("models", []) if m["name"] == self.model), "")
            except Exception:  # describe must not fail a run; step() reports unavailability
                self._digest = ""
        return {"adapter": "ollama", "model": self.model, "digest": self._digest or None, "host": self.host,
                "options": self.options}

    def step(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> AgentTurn:
        body = {"model": self.model, "stream": False, "options": self.options,
                "messages": to_ollama(messages),
                "tools": [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                            "parameters": t.parameters}} for t in tools]}
        raw = self._post("/api/chat", body)
        return parse_reply(raw)

    def _post(self, path: str, body: dict | None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.host + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                text = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            if e.code == 404:
                raise AgentUnavailable(f"model {self.model!r} not found on {self.host} (ollama pull {self.model}): {detail}") from e
            raise AgentUnavailable(f"Ollama HTTP {e.code}: {detail}") from e
        except (TimeoutError, socket.timeout) as e:
            raise AgentTimeout(f"no reply from {self.host} within {self.timeout}s") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise AgentTimeout(f"no reply from {self.host} within {self.timeout}s") from e
            raise AgentUnavailable(f"cannot reach Ollama at {self.host}: {e.reason}") from e
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise MalformedResponse(f"non-JSON reply from Ollama: {text[:200]!r}") from e


def to_ollama(messages: Sequence[Message]) -> list[dict]:
    names = {c.call_id: c.tool for m in messages for c in m.tool_calls}
    out = []
    for m in messages:
        msg: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            msg["tool_calls"] = [{"function": {"name": c.tool, "arguments": c.arguments}} for c in m.tool_calls]
        if m.role == "tool" and m.tool_call_id in names:
            msg["tool_name"] = names[m.tool_call_id]
        out.append(msg)
    return out


def parse_reply(raw: dict) -> AgentTurn:
    msg = raw.get("message")
    if not isinstance(msg, dict):
        raise MalformedResponse(f"reply has no message: {str(raw)[:200]}")
    content = msg.get("content") or ""
    calls = [(c.get("function") or {}) for c in msg.get("tool_calls") or []]
    if not calls and (found := TEXT_TOOL_CALL.findall(content)):
        try:
            calls = [json.loads(f) for f in found]
        except json.JSONDecodeError as e:
            raise MalformedResponse(f"unparseable tool call in text: {found[0][:200]!r}") from e
        content = TEXT_TOOL_CALL.sub("", content).strip()
    parsed = []
    for f in calls:
        args = f.get("arguments", {})
        if isinstance(args, str):  # some templates return a JSON string
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError as e:
                raise MalformedResponse(f"tool arguments are not JSON: {args[:200]!r}") from e
        if not isinstance(f.get("name"), str) or not isinstance(args, dict):
            raise MalformedResponse(f"malformed tool call: {str(f)[:200]}")
        parsed.append(ToolCall(tool=f["name"], arguments=args))
    stats = {k: raw.get(k) for k in ("total_duration", "prompt_eval_count", "eval_count", "done_reason")}
    return AgentTurn(text=content or None, tool_calls=tuple(parsed), raw={"message": msg, **stats})
