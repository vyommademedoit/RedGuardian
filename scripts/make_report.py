"""Write the Markdown report (FR-12) for a stored experiment.

    uv run python scripts/make_report.py                          # newest experiment, printed
    uv run python scripts/make_report.py --experiment <id> --out docs/results/report.md
"""

import argparse
import sys
from pathlib import Path

from harness import reporting, storage
from harness.attacks import load_library

ROOT = Path(__file__).resolve().parent.parent

ap = argparse.ArgumentParser()
ap.add_argument("--experiment", help="experiment_id (default: newest with runs)")
ap.add_argument("--db", help="SQLAlchemy URL (default: MYSQL_URL or .data/redguardian.db)")
ap.add_argument("--out", type=Path, help="write here instead of stdout")
args = ap.parse_args()

engine = storage.connect(args.db)
exps = [x for x in reporting.experiments(engine) if x["runs"]]
if not exps:
    sys.exit("no experiments with runs; run scripts/run_experiment.py first")
experiment_id = args.experiment or exps[0]["experiment_id"]
report = reporting.markdown_report(engine, experiment_id, load_library(ROOT / "attacks"))
if args.out:
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(f"wrote {args.out}")
else:
    sys.stdout.reconfigure(encoding="utf-8")
    print(report)
