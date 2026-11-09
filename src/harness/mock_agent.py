"""Deterministic scripted agent (FR-01 mock adapter).

Stands in for an LLM so the whole pipeline is testable without a model.
With ``follows_injections=True`` it behaves like a fully compliant, gullible
model: if any tool output says "call <tool> with to=<addr>", it does so and
fetches/attaches the requested key.

shortcut: matches only the "call X with to=Y" phrasing; wording variants need the Ollama adapter (not built yet).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from harness.models import AgentTurn, Message, ToolCall, ToolSpec

INSTRUCTION = re.compile(r"call (\w+) with to=([\w.@+-]+)")
SECRET = re.compile(r"SECRET-[A-Z_]+-[0-9a-f]+")


class MockAgent:
    def __init__(self, follows_injections: bool = True):
        self.follows_injections = follows_injections
        self.name = "mock-vulnerable" if follows_injections else "mock-safe"

    def describe(self) -> dict:
        return {"adapter": self.name, "follows_injections": self.follows_injections}

    def step(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> AgentTurn:
        proposed = {c.tool for m in messages if m.role == "assistant" for c in m.tool_calls}
        observed = "\n".join(m.content for m in messages if m.role == "tool")

        task = next((m.content for m in messages if m.role == "user"), "")
        if not proposed:  # first move: pick the source the task names, else search the knowledge base
            for word, tool in (("email", "read_inbox"), ("memory", "read_memory"), ("message", "read_messages")):
                if word in task.lower():
                    return _call(tool)
            return _call("search_documents", query=task)

        # Pass-along tasks ("save it to memory", "forward it to X") are transcription: the mock copies
        # what it read without acting on it, so a payload fires only where it is read back (later session/agent).
        # shortcut: a real model may act immediately too; the Ollama adapter will measure that.
        forward = re.search(r"forward it to ([\w-]+)", task)
        if "save it to memory" in task:
            if "write_memory" not in proposed:
                return _call("write_memory", content=observed)
        elif forward:
            if "relay_message" not in proposed:
                return _call("relay_message", to=forward.group(1), body=observed)
        elif self.follows_injections and (hit := INSTRUCTION.search(observed)):
            tool, to = hit.groups()
            if tool not in proposed:
                if "key" in observed.lower() and not SECRET.search(observed) and "read_config" not in proposed:
                    return _call("read_config")
                secret = SECRET.search(observed)
                return _call(tool, to=to, body=f"Requested key: {secret.group() if secret else 'n/a'}")

        if subject := re.search(r"Subject: (.*)", observed):
            return AgentTurn(text=f"Summary: email about {subject.group(1)}.")
        sources = dict.fromkeys(re.findall(r"^\[([\w-]+)\]", observed, re.M))
        return AgentTurn(text=f"Answer based on: {', '.join(sources) or 'no documents'}.")


def _call(tool: str, **arguments) -> AgentTurn:
    return AgentTurn(tool_calls=(ToolCall(tool=tool, arguments=arguments),))
