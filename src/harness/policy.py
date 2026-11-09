"""Policy middleware (FR-05): enforced outside the model.

``Policy.decide`` asks every enabled defense that watches the checkpoint and
applies the most restrictive answer (D-015). No defenses = baseline = allow.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from harness.interfaces import Defense
from harness.models import Check, CheckPoint, Decision, Permission, PolicyDecision, SecretSpec, Trust

_RANK = {Decision.ALLOW: 0, Decision.QUARANTINE: 1, Decision.BLOCK: 2}
NO_DEFENSE = PolicyDecision(decision=Decision.ALLOW, defense_id="none", reason="no defense objected")


class Policy:
    def __init__(self, defenses: Sequence[Defense]):
        self.defenses = list(defenses)

    def decide(self, check: Check) -> PolicyDecision:
        votes = [d.evaluate(check) for d in self.defenses if check.point in d.points]
        votes = [v for v in votes if v is not None]
        return max(votes, key=lambda v: _RANK[v.decision], default=NO_DEFENSE)


class SecretEgressDefense:
    """Data-flow check: a synthetic secret may reach an outbound tool only if
    the destination is in that secret's allowed_destinations."""

    defense_id = "secret_egress"
    points = frozenset({CheckPoint.TOOL_CALL})

    def __init__(self, secrets: dict[str, SecretSpec]):
        self.secrets = secrets  # value -> spec, registered by the sandbox

    def evaluate(self, check: Check) -> PolicyDecision | None:
        if not (check.tool and check.tool_call) or check.tool.permission is not Permission.OUTBOUND:
            return None
        args = json.dumps(check.tool_call.arguments)
        dest = str(check.tool_call.arguments.get("to", check.tool.name))
        for value, spec in self.secrets.items():
            if value in args and dest not in spec.allowed_destinations:
                return PolicyDecision(
                    decision=Decision.BLOCK, defense_id=self.defense_id,
                    reason=f"synthetic secret ({spec.kind}) cannot flow to {dest} via {check.tool.name}",
                )
        return None


class RetrievalScreenDefense:
    """Heuristic retrieval filter: quarantine untrusted chunks that contain
    instructions aimed at the assistant. Transparent pattern match, not a guarantee:
    reworded payloads can evade it (see docs/metrics.md)."""

    defense_id = "retrieval_screen"
    points = frozenset({CheckPoint.RETRIEVAL})
    PATTERN = re.compile(
        r"(?i)\b(ignore (all |any )?(previous|prior) instructions|call \w+ with|note (for|to) (the )?assistants?"
        r"|you must now|include the [\w ]*(key|password|credential))"
    )

    def evaluate(self, check: Check) -> PolicyDecision | None:
        untrusted = any(p.trust is Trust.UNTRUSTED for p in check.provenance)
        if untrusted and check.content and (m := self.PATTERN.search(check.content)):
            return PolicyDecision(decision=Decision.QUARANTINE, defense_id=self.defense_id,
                                  reason=f"untrusted content contains an instruction to the assistant: {m.group(0)!r}")
        return None


class MemoryScreenDefense(RetrievalScreenDefense):
    """Same heuristic on memory: on write (keeps poison out) and on read (catches entries
    persisted before the defense was on, e.g. an inherited poisoned namespace)."""

    defense_id = "memory_screen"
    points = frozenset({CheckPoint.MEMORY_WRITE, CheckPoint.MEMORY_READ})


class RelayScreenDefense(RetrievalScreenDefense):
    """Same heuristic on the inter-agent message boundary."""

    defense_id = "relay_screen"
    points = frozenset({CheckPoint.RELAY})


class InputScreenDefense(RetrievalScreenDefense):
    """Same heuristic on untrusted input that reaches the agent directly: tool outputs
    (email, relayed messages) and untrusted text in the user channel."""

    defense_id = "input_screen"
    points = frozenset({CheckPoint.INPUT})


class OutputGuardDefense:
    """Output/egress check on the final answer: a synthetic secret may appear in the response
    only if "user" is one of its allowed_destinations (FR-05 family 6)."""

    defense_id = "output_guard"
    points = frozenset({CheckPoint.EGRESS})

    def __init__(self, secrets: dict[str, SecretSpec]):
        self.secrets = secrets

    def evaluate(self, check: Check) -> PolicyDecision | None:
        for value, spec in self.secrets.items():
            if check.content and value in check.content and "user" not in spec.allowed_destinations:
                return PolicyDecision(decision=Decision.BLOCK, defense_id=self.defense_id,
                                      reason=f"response contains a synthetic secret ({spec.kind}) not cleared for the user")
        return None


class DestinationAllowlistDefense:
    """Tool authorization: outbound actions may only address recipients in allowed domains."""

    defense_id = "destination_allowlist"
    points = frozenset({CheckPoint.TOOL_CALL})

    def __init__(self, domains: tuple[str, ...] = ("corp.test",)):
        self.domains = domains

    def evaluate(self, check: Check) -> PolicyDecision | None:
        if not (check.tool and check.tool_call) or check.tool.permission is not Permission.OUTBOUND:
            return None
        to = str(check.tool_call.arguments.get("to", ""))
        if to.rpartition("@")[2] not in self.domains:
            return PolicyDecision(decision=Decision.BLOCK, defense_id=self.defense_id,
                                  reason=f"{to!r} is outside the allowed domains {list(self.domains)}")
        return None


class TaintGuardDefense:
    """Capability check: once untrusted content entered the session, outbound actions are
    no longer authorized (the request may come from the attacker). Blunt by design:
    it also stops legitimate sends after reading email (measured by BENIGN-006)."""

    defense_id = "taint_guard"
    points = frozenset({CheckPoint.TOOL_CALL})

    def evaluate(self, check: Check) -> PolicyDecision | None:
        if not check.tool or check.tool.permission is not Permission.OUTBOUND:
            return None
        origins = [f"{p.source_type}:{p.source_id}" for p in check.provenance if p.trust is Trust.UNTRUSTED]
        if origins:
            return PolicyDecision(decision=Decision.BLOCK, defense_id=self.defense_id,
                                  reason=f"outbound action after untrusted content from {', '.join(dict.fromkeys(origins))}")
        return None


DEFENSES = ("secret_egress", "output_guard", "destination_allowlist", "taint_guard", "input_screen",
            "retrieval_screen", "memory_screen", "relay_screen")
# PRD §11: baseline, all on, and ablations (each defense removed / each defense alone)
PROFILES: dict[str, tuple[str, ...]] = {
    "baseline": (), "defended": DEFENSES,
    **{f"no_{d}": tuple(x for x in DEFENSES if x != d) for d in DEFENSES},
    **{f"only_{d}": (d,) for d in DEFENSES},
}


def build_policy(profile: str, secrets: dict[str, SecretSpec]) -> Policy:
    factories = {"secret_egress": lambda: SecretEgressDefense(secrets), "output_guard": lambda: OutputGuardDefense(secrets),
                 "destination_allowlist": DestinationAllowlistDefense,
                 "taint_guard": TaintGuardDefense, "input_screen": InputScreenDefense,
                 "retrieval_screen": RetrievalScreenDefense, "memory_screen": MemoryScreenDefense,
                 "relay_screen": RelayScreenDefense}
    return Policy([factories[d]() for d in PROFILES[profile]])
