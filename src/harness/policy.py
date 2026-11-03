"""Policy middleware (FR-05): enforced outside the model.

``Policy.decide`` asks every enabled defense that watches the checkpoint and
applies the most restrictive answer (D-015). No defenses = baseline = allow.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from harness.interfaces import Defense
from harness.models import Check, CheckPoint, Decision, Permission, PolicyDecision, SecretSpec

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


PROFILES: dict[str, tuple[str, ...]] = {
    "baseline": (),
    "defended": ("secret_egress",),
}


def build_policy(profile: str, secrets: dict[str, SecretSpec]) -> Policy:
    factories = {"secret_egress": lambda: SecretEgressDefense(secrets)}
    return Policy([factories[d]() for d in PROFILES[profile]])
