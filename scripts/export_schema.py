"""Regenerate attacks/schema.json from the AttackScenario model."""

from pathlib import Path

from harness.attacks import json_schema

out = Path(__file__).resolve().parent.parent / "attacks" / "schema.json"
out.write_text(json_schema(), encoding="utf-8")
print(f"wrote {out}")
