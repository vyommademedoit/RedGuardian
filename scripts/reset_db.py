"""Reset the results database to an empty, versioned schema (clean seeded state for a benchmark).

    uv run python scripts/reset_db.py            # shows what would be dropped, changes nothing
    uv run python scripts/reset_db.py --yes      # drops every harness table (runs, events, memory) and recreates them

Seeds are data, not state: fixtures live in harness.sandbox and every run derives its tokens from
its seed, so an empty database plus `run_experiment.py --seed N` reproduces a benchmark.
"""

import argparse

from sqlalchemy import func, inspect, select

from harness import storage

ap = argparse.ArgumentParser()
ap.add_argument("--db", help="SQLAlchemy URL (default: MYSQL_URL or .data/redguardian.db)")
ap.add_argument("--yes", action="store_true", help="really drop and recreate the tables")
args = ap.parse_args()

engine = storage.connect(args.db)
where = engine.url.render_as_string(hide_password=True)
present = set(inspect(engine).get_table_names())
with engine.connect() as c:
    counts = {t.name: c.execute(select(func.count()).select_from(t)).scalar() for t in storage.metadata.sorted_tables
              if t.name in present}
print(f"database: {where}")
for name, n in counts.items():
    print(f"  {name:<16} {n} rows")
if not args.yes:
    print("dry run: nothing changed. Re-run with --yes to drop and recreate these tables.")
else:
    storage.reset(engine)
    print(f"reset done: empty schema v{storage.SCHEMA_VERSION}")
