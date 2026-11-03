"""Load and validate the JSON attack library (FR-02)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from harness.models import AttackScenario


class AttackDefinitionError(ValueError):
    pass


def load_scenario(path: Path) -> tuple[AttackScenario, str]:
    """Return the validated scenario and the sha256 of its exact bytes."""
    raw = path.read_bytes()
    try:
        scenario = AttackScenario.model_validate_json(raw)
    except ValidationError as e:
        raise AttackDefinitionError(f"{path}: invalid attack definition\n{e}") from e
    if path.stem != scenario.attack_id:
        raise AttackDefinitionError(f"{path}: file name must equal attack_id {scenario.attack_id!r}")
    return scenario, hashlib.sha256(raw).hexdigest()


def load_library(root: Path, include_disabled: bool = False) -> dict[str, tuple[AttackScenario, str]]:
    """All scenarios under ``root`` keyed by attack_id, in sorted (deterministic) order."""
    library: dict[str, tuple[AttackScenario, str]] = {}
    for path in sorted(root.rglob("*.json")):
        if path.name == "schema.json":
            continue
        scenario, digest = load_scenario(path)
        if scenario.attack_id in library:
            raise AttackDefinitionError(f"{path}: duplicate attack_id {scenario.attack_id}")
        if scenario.enabled or include_disabled:
            library[scenario.attack_id] = (scenario, digest)
    for scenario, _ in library.values():
        unknown = [b for b in scenario.benign_controls if b not in library]
        if unknown:
            raise AttackDefinitionError(f"{scenario.attack_id}: unknown benign_controls {unknown}")
    return library


def json_schema() -> str:
    """Canonical text of attacks/schema.json (generated from the pydantic model)."""
    return json.dumps(AttackScenario.model_json_schema(), indent=2) + "\n"
