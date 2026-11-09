"""Run scenarios under defense profiles and print metrics.

    uv run python scripts/run_experiment.py                      # every enabled scenario under every profile
    uv run python scripts/run_experiment.py --attacks TOOL-001 --profiles defended --db sqlite://
"""

import argparse
from pathlib import Path

from sqlalchemy import insert

from harness import storage
from harness.attacks import load_library
from harness.metrics import compute_metrics
from harness.mock_agent import MockAgent
from harness.models import new_id, utcnow
from harness.policy import PROFILES
from harness.retrieval import EMBEDDERS
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent

ap = argparse.ArgumentParser()
ap.add_argument("--attacks", nargs="*", help="attack_ids (default: all enabled)")
ap.add_argument("--profiles", nargs="*", default=list(PROFILES), choices=list(PROFILES))
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--db", help="SQLAlchemy URL (default: MYSQL_URL or .data/redguardian.db)")
ap.add_argument("--embedder", default="hash", choices=list(EMBEDDERS), help="RAG embeddings: hash (offline) or ollama")
args = ap.parse_args()

library = load_library(ROOT / "attacks")
ids = args.attacks or list(library)
engine = storage.connect(args.db)
print(f"db: {engine.url.render_as_string(hide_password=True)}")

experiment_id = new_id()
with engine.begin() as c:
    c.execute(insert(storage.experiments), {
        "experiment_id": experiment_id, "name": "cli", "objective": "baseline vs defended",
        "config": {"attacks": ids, "profiles": args.profiles, "seed": args.seed, "agent": "mock-vulnerable", "embedder": args.embedder},
        "created_at": utcnow()})

agent = MockAgent(follows_injections=True)
for profile in args.profiles:
    evals = []
    print(f"\n== profile: {profile}")
    for attack_id in ids:
        scenario, digest = library[attack_id]
        r = run_scenario(scenario, digest, agent, profile, engine, seed=args.seed, experiment_id=experiment_id, embedder=args.embedder)
        e = r.evaluation
        evals.append(e)
        print(f"  {attack_id:<11} status={r.run.status:<10} success={e.attack_success!s:<5} "
              f"leaked={e.secret_leaked!s:<5} stage={e.furthest_stage.name if e.furthest_stage else '-':<8} "
              f"blocked_by={','.join(e.blocking_defenses) or '-':<14} task_ok={e.task_completed}")
    rows = compute_metrics(evals, scope=profile)
    with engine.begin() as c:
        c.execute(insert(storage.metric_results), [
            {"experiment_id": experiment_id, "scope": m.scope, "name": m.name,
             "numerator": m.numerator, "denominator": m.denominator, "value": m.value} for m in rows])
    for m in rows:
        if m.denominator and not m.name.startswith("furthest_stage"):
            print(f"    {m.name:<34} {m.numerator}/{m.denominator}")
print(f"\nexperiment_id: {experiment_id}")
