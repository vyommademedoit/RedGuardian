"""Component interfaces (Phase 1 contracts).

Structural protocols: implementations need not inherit, only match.
Each boundary between components is one of these, so the runner can swap a
mock for a real implementation without changing code (NFR-03).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from harness.models import (
    AgentTurn,
    AttackScenario,
    Check,
    CheckPoint,
    Event,
    Message,
    PolicyDecision,
    RunEvaluation,
    RunRecord,
    ToolCall,
    ToolResult,
    ToolSpec,
)


class AgentError(Exception):
    """Base for adapter failures. The runner records these as a failed run,
    never as a successful defense (NFR-04)."""


class AgentUnavailable(AgentError):
    """Model server down or model not pulled."""


class AgentTimeout(AgentError):
    pass


class MalformedResponse(AgentError):
    """Unparseable model output or tool call."""


@runtime_checkable
class AgentAdapter(Protocol):
    name: str

    def describe(self) -> dict[str, Any]:
        """Model name, tag, and generation parameters, recorded on every run."""
        ...

    def step(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> AgentTurn:
        """One model turn. Proposes tool calls; never executes them.
        Raises AgentError subclasses on failure."""
        ...


@runtime_checkable
class Tool(Protocol):
    spec: ToolSpec

    def run(self, call: ToolCall, run_id: str) -> ToolResult:
        """Execute against sandbox fixtures only. OUTBOUND tools record intent
        and return a receipt; they never perform real I/O."""
        ...


@runtime_checkable
class Defense(Protocol):
    defense_id: str
    points: frozenset[CheckPoint]  # checkpoints this defense inspects

    def evaluate(self, check: Check) -> PolicyDecision | None:
        """Return a decision, or None to abstain. The policy layer applies the
        most restrictive decision across all enabled defenses."""
        ...


@runtime_checkable
class EventLogger(Protocol):
    def emit(self, event: Event) -> None:
        """Append one event. Never updates or deletes (PRD §9.3)."""
        ...

    def events(self, run_id: str) -> list[Event]:
        """All events for a run, ordered by seq."""
        ...


@runtime_checkable
class Evaluator(Protocol):
    def evaluate(
        self, run: RunRecord, scenario: AttackScenario, events: Sequence[Event]
    ) -> RunEvaluation:
        """Pure function of persisted evidence; no model calls, no dashboard state."""
        ...
