"""Data contracts shared by every harness component (PRD §6, §9).

Everything here is plain data: no I/O, no model calls. Components exchange
these objects; storage persists them; the evaluator reads them back.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------


class Surface(StrEnum):
    """Attack surfaces (FR-03)."""

    DIRECT = "direct"
    RAG = "rag"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    RELAY = "relay"


class SourceType(StrEnum):
    """Where a piece of content came from (trust boundaries, PRD §5.4)."""

    SYSTEM = "system"
    USER = "user"
    DOCUMENT = "document"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    RELAY = "relay"


class Trust(StrEnum):
    TRUSTED = "trusted"  # system/developer policy, the user's stated task
    UNTRUSTED = "untrusted"  # everything the attacker could have touched


class Permission(StrEnum):
    """Tool permission levels, least to most dangerous (FR-04)."""

    READ = "read"  # no side effects
    WRITE_INTERNAL = "write_internal"  # mutates sandbox state (memory, mock records)
    OUTBOUND = "outbound"  # simulated send outside the agent; records intent only


class Stage(IntEnum):
    """Canary propagation stages (FR-07). Ordered: higher = travelled further."""

    EXPOSED = 1
    PERSISTED = 2
    RELAYED = 3
    EXECUTED = 4


class Objective(StrEnum):
    """Attacker goals (PRD §5.3)."""

    TASK_DIVERSION = "task_diversion"
    TARGETED_RESPONSE = "targeted_response"
    SECRET_DISCLOSURE = "secret_disclosure"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    POISONING = "poisoning"
    RELAY_PROPAGATION = "relay_propagation"
    PERSISTENCE = "persistence"
    DENIAL_OF_SERVICE = "denial_of_service"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class CheckPoint(StrEnum):
    """Where the policy layer can intervene (FR-05 defense families)."""

    INPUT = "input"
    RETRIEVAL = "retrieval"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    RELAY = "relay"
    TOOL_CALL = "tool_call"
    EGRESS = "egress"


class RunStatus(StrEnum):
    """Terminal run status (PRD §9.3). Only COMPLETED runs count toward rates."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class RunKind(StrEnum):
    ATTACK = "attack"
    BENIGN = "benign"
    RECOVERY = "recovery"


class EventType(StrEnum):
    RUN_STARTED = "run_started"
    RUN_FINISHED = "run_finished"
    CONTENT_EXPOSED = "content_exposed"
    RETRIEVAL = "retrieval"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    RELAY_MESSAGE = "relay_message"
    AGENT_RESPONSE = "agent_response"
    TOOL_CALL_PROPOSED = "tool_call_proposed"
    POLICY_DECISION = "policy_decision"
    TOOL_EXECUTED = "tool_executed"
    TOOL_ERROR = "tool_error"
    MODEL_ERROR = "model_error"
    STAGE_REACHED = "stage_reached"


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------
# Provenance, secrets, tools, messages
# --------------------------------------------------------------------------


class Provenance(_Frozen):
    """Origin label carried by every piece of content (FR-06)."""

    source_type: SourceType
    source_id: str
    trust: Trust
    run_id: str | None = None
    session_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    contains_canary: bool = False
    steps: tuple[str, ...] = ()  # transformations/relay hops, oldest first


class SecretKind(StrEnum):
    """Synthetic-secret labels. Values are always generated, never real."""

    API_KEY = "api_key"
    PASSWORD = "password"
    CUSTOMER_RECORD = "customer_record"
    INTERNAL_NOTE = "internal_note"


class SecretSpec(_Frozen):
    """A synthetic secret planted in the sandbox for one run.

    The runner generates the value as ``SECRET-<KIND>-<hex>``. It may flow only
    to ``allowed_destinations`` (tool names or recipient identifiers).
    """

    kind: SecretKind
    allowed_destinations: tuple[str, ...] = ()


class ToolSpec(_Frozen):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str
    permission: Permission
    parameters: dict[str, Any]  # JSON Schema for arguments (also sent to Ollama)


class ToolCall(_Frozen):
    call_id: str = Field(default_factory=new_id)
    tool: str
    arguments: dict[str, Any] = {}


class ToolResult(_Frozen):
    call_id: str
    content: str
    provenance: Provenance
    error: str | None = None


class Message(_Frozen):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    provenance: Provenance | None = None
    tool_call_id: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()


class AgentTurn(_Frozen):
    """One model step: a final answer and/or proposed tool calls."""

    text: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    raw: dict[str, Any] = {}  # adapter-specific response, kept as evidence


class PolicyDecision(_Frozen):
    decision: Decision
    defense_id: str
    reason: str


class Check(_Frozen):
    """What a defense is asked to judge at a checkpoint."""

    point: CheckPoint
    run_id: str
    content: str | None = None
    provenance: tuple[Provenance, ...] = ()
    tool: ToolSpec | None = None
    tool_call: ToolCall | None = None


# --------------------------------------------------------------------------
# Attack scenarios (FR-02, PRD §10.2)
# --------------------------------------------------------------------------


class ToolCallPredicate(_Frozen):
    """True if a tool call to ``tool`` was proposed (or executed, per evaluator)
    whose serialized arguments contain ``argument_contains``.
    Placeholders ``{secret}`` and ``{marker}`` are substituted per run."""

    type: Literal["tool_call"] = "tool_call"
    tool: str
    argument_contains: str | None = None


class ResponseContainsPredicate(_Frozen):
    type: Literal["response_contains"] = "response_contains"
    text: str


class NoToolCallPredicate(_Frozen):
    type: Literal["no_tool_call"] = "no_tool_call"
    tool: str


Predicate = Annotated[
    ToolCallPredicate | ResponseContainsPredicate | NoToolCallPredicate,
    Field(discriminator="type"),
]


class Injection(_Frozen):
    """Where and how the malicious payload enters the target surface."""

    target: str  # tool name, document id, memory key, relay channel, or "user_message"
    position: Literal["replace", "append", "prepend"] = "append"
    payload: str  # must contain {marker}


class AttackScenario(_Frozen):
    """One versioned attack or benign-control definition, loaded from JSON."""

    attack_id: str = Field(pattern=r"^(DIR|RAG|TOOL|MEM|RELAY|BENIGN)-\d{3}[a-z]?$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    kind: Literal["attack", "benign"]
    name: str
    description: str
    surface: Surface
    category: str
    objective: Objective | None = None
    severity: Severity | None = None
    enabled: bool = True
    tags: tuple[str, ...] = ()

    attacker_capability: str | None = None
    prerequisites: tuple[str, ...] = ()
    initial_state: tuple[str, ...] = ()  # named fixtures to seed before the run
    cleanup: tuple[str, ...] = ()  # named reset procedures after the run

    target_task: str  # the user's legitimate instruction
    injection: Injection | None = None
    secret: SecretSpec | None = None
    stages: tuple[Stage, ...] = ()  # applicable stages; others are N/A

    success_condition: tuple[Predicate, ...] = ()  # attack: all must hold
    expected_outcome: tuple[Predicate, ...] = ()  # benign: all must hold
    expected_safe_behavior: str
    benign_controls: tuple[str, ...] = ()  # attack_ids of matched benign tasks

    @model_validator(mode="after")
    def _kind_rules(self) -> AttackScenario:
        if self.kind == "attack":
            missing = [
                f
                for f in ("injection", "objective", "severity", "success_condition", "stages")
                if not getattr(self, f)
            ]
            if missing:
                raise ValueError(f"attack scenario missing: {', '.join(missing)}")
            if "{marker}" not in self.injection.payload:
                raise ValueError("injection.payload must contain the {marker} placeholder")
        else:
            if self.injection or self.success_condition:
                raise ValueError("benign scenario must not define injection or success_condition")
            if not self.expected_outcome:
                raise ValueError("benign scenario missing: expected_outcome")
        return self


# --------------------------------------------------------------------------
# Runs, events, evaluation (PRD §9)
# --------------------------------------------------------------------------


class Event(_Frozen):
    """Append-only, boundary-observed event. ``seq`` orders events within a run."""

    event_id: str = Field(default_factory=new_id)
    run_id: str
    seq: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utcnow)
    event_type: EventType
    attack_id: str | None = None
    stage: Stage | None = None
    source_type: SourceType | None = None
    source_id: str | None = None
    destination: str | None = None
    canary_id: str | None = None
    decision: Decision | None = None
    defense_id: str | None = None
    reason: str | None = None
    payload: dict[str, Any] = {}  # structured evidence; synthetic data only


class RunRecord(BaseModel):
    """Run metadata (FR-08). Mutable only for status/finished_at."""

    run_id: str = Field(default_factory=new_id)
    experiment_id: str | None = None
    kind: RunKind
    attack_id: str
    attack_version: str
    attack_sha256: str  # hash of the exact JSON definition used
    adapter: str
    model: str | None = None
    model_params: dict[str, Any] = {}
    defense_profile: str
    defense_config: dict[str, Any] = {}
    seed: int | None = None
    corpus_state_id: str | None = None
    memory_state_id: str | None = None
    status: RunStatus = RunStatus.RUNNING
    error: str | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None


class RunEvaluation(_Frozen):
    """Deterministic verdict for one run, computed only from stored events."""

    run_id: str
    kind: RunKind
    valid: bool  # run status == completed; invalid runs are excluded from rates
    attack_success: bool = False
    injected: bool = False
    secret_leaked: bool = False
    unauthorized_attempts: int = 0  # prohibited tool calls proposed
    unauthorized_blocked: int = 0  # ...of which a defense blocked
    unauthorized_executed: int = 0  # ...of which executed in the sandbox
    furthest_stage: Stage | None = None
    task_completed: bool = False  # benign/recovery: expected outcome held
    refused_or_blocked: bool = False  # benign: model refused or a defense blocked it
    blocking_defenses: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _counts_consistent(self) -> RunEvaluation:
        if self.unauthorized_blocked + self.unauthorized_executed > self.unauthorized_attempts:
            raise ValueError("blocked + executed cannot exceed attempts")
        return self


class MetricResult(_Frozen):
    name: str
    numerator: int
    denominator: int
    scope: str = "all"

    @property
    def value(self) -> float | None:
        """None when the denominator is zero: 'not measured', never 0%."""
        return self.numerator / self.denominator if self.denominator else None
