"""Run scenarios under defense profiles, then recovery checks, and print a comparison.

    uv run python scripts/run_experiment.py                      # every enabled scenario under every profile
    uv run python scripts/run_experiment.py --attacks TOOL-001 --profiles defended --db sqlite://
    uv run python scripts/run_experiment.py --report docs/results/benchmark.md

Recovery (PRD 11.1), per profile and memory attack: poison memory under baseline,
identify the poisoned entries (untrusted entries written by that run), quarantine them,
rerun the recovery task on the same memory under the profile, verify from its events.
"""

import argparse
from pathlib import Path

from sqlalchemy import insert

from harness import storage
from harness.attacks import load_library
from harness.memory import MemoryStore
from harness.metrics import compute_metrics
from harness.mock_agent import MockAgent
from harness.models import new_id, utcnow
from harness.policy import PROFILES
from harness.retrieval import EMBEDDERS
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
COLUMNS = ["attack_success_rate", "secret_leakage_rate", "unauthorized_tool_execution_rate", "defense_block_rate",
           "benign_task_utility", "false_refusal_rate", "recovery_success", "invalid_runs"]

ap = argparse.ArgumentParser()
ap.add_argument("--attacks", nargs="*", help="attack_ids (default: all enabled)")
ap.add_argument("--profiles", nargs="*", default=list(PROFILES), choices=list(PROFILES))
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--db", help="SQLAlchemy URL (default: MYSQL_URL or .data/redguardian.db)")
ap.add_argument("--embedder", default="hash", choices=list(EMBEDDERS), help="RAG embeddings: hash (offline) or ollama")
ap.add_argument("--report", type=Path, help="also write the comparison table (Markdown) here")
args = ap.parse_args()

library = load_library(ROOT / "attacks")
ids = args.attacks or list(library)
engine = storage.connect(args.db)
print(f"db: {engine.url.render_as_string(hide_password=True)}")

experiment_id = new_id()
with engine.begin() as c:
    c.execute(insert(storage.experiments), {
        "experiment_id": experiment_id, "name": "cli", "objective": "baseline vs defended vs ablations",
        "config": {"attacks": ids, "profiles": args.profiles, "seed": args.seed, "agent": "mock-vulnerable", "embedder": args.embedder},
        "created_at": utcnow()})

agent = MockAgent(follows_injections=True)


def run(attack_id, profile, **kw):
    scenario, digest = library[attack_id]
    return run_scenario(scenario, digest, agent, profile, engine, seed=args.seed, experiment_id=experiment_id,
                        embedder=args.embedder, **kw)


table = {}
for profile in args.profiles:
    evals = []
    print(f"\n== profile: {profile}")
    for attack_id in ids:
        r = run(attack_id, profile)
        e = r.evaluation
        evals.append(e)
        print(f"  {attack_id:<11} status={r.run.status:<10} success={e.attack_success!s:<5} "
              f"leaked={e.secret_leaked!s:<5} stage={e.furthest_stage.name if e.furthest_stage else '-':<8} "
              f"blocked_by={','.join(e.blocking_defenses) or '-':<14} task_ok={e.task_completed}")
    for attack_id in ids:
        scenario = library[attack_id][0]
        if scenario.kind != "attack" or scenario.surface.value != "memory":
            continue
        poisoned = run(attack_id, "baseline").run
        store = MemoryStore(engine, poisoned.memory_state_id)
        quarantined = store.quarantine(run_id=poisoned.run_id, trust="untrusted")
        for control in scenario.benign_controls:
            if "recovery" in library[control][0].tags:
                e = run(control, profile, memory_namespace=poisoned.memory_state_id).evaluation
                evals.append(e)
                print(f"  recovery {attack_id} -> {control}: quarantined={quarantined} task_ok={e.task_completed}")
    rows = compute_metrics(evals, scope=profile)
    with engine.begin() as c:
        c.execute(insert(storage.metric_results), [
            {"experiment_id": experiment_id, "scope": m.scope, "name": m.name,
             "numerator": m.numerator, "denominator": m.denominator, "value": m.value} for m in rows])
    table[profile] = {m.name: m for m in rows}


def cell(m):
    return "n/a" if m.value is None else f"{m.value:.0%} ({m.numerator}/{m.denominator})"


lines = [f"| profile | {' | '.join(COLUMNS)} |", f"|{'---|' * (len(COLUMNS) + 1)}"]
lines += [f"| {p} | {' | '.join(cell(table[p][c]) for c in COLUMNS)} |" for p in table]
report = "\n".join(lines)
print(f"\n{report}\n\nexperiment_id: {experiment_id}")
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        f"# Comparison (experiment `{experiment_id}`)\n\nAgent: `mock-vulnerable` (scripted, deterministic; not a model evaluation). "
        f"Seed {args.seed}, embedder `{args.embedder}`, scenarios: {', '.join(ids)}.\n"
        "Rates show raw counts; denominators are defined in docs/metrics.md.\n\n" + report + "\n", encoding="utf-8")
    print(f"wrote {args.report}")
