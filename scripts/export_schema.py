"""Regenerate attacks/schema.json (AttackScenario) and db/schema_v<N>.mysql.sql (table DDL)."""

from pathlib import Path

from harness import storage
from harness.attacks import json_schema

ROOT = Path(__file__).resolve().parent.parent
for out, text in ((ROOT / "attacks" / "schema.json", json_schema()),
                  (ROOT / "db" / f"schema_v{storage.SCHEMA_VERSION}.mysql.sql", storage.ddl("mysql"))):
    out.parent.mkdir(exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
