"""Verify a stored experiment against its raw events; exit 1 on any disagreement.

    uv run python scripts/verify_metrics.py                    # newest experiment with runs
    uv run python scripts/verify_metrics.py --experiment <id>
"""

import argparse
import sys
from pathlib import Path

from harness import reporting, storage
from harness.attacks import load_library
from harness.verify import verify

ROOT = Path(__file__).resolve().parent.parent

ap = argparse.ArgumentParser()
ap.add_argument("--experiment", help="experiment_id (default: newest with runs)")
ap.add_argument("--db", help="SQLAlchemy URL (default: MYSQL_URL or .data/redguardian.db)")
args = ap.parse_args()

engine = storage.connect(args.db)
exps = [x for x in reporting.experiments(engine) if x["runs"]]
if not exps:
    sys.exit("no experiments with runs")
experiment_id = args.experiment or exps[0]["experiment_id"]
checks, problems = verify(engine, experiment_id, load_library(ROOT / "attacks"))
print(f"experiment {experiment_id}: {checks} checks, {len(problems)} problem(s)")
for p in problems:
    print(f"  - {p}")
sys.exit(1 if problems else 0)
