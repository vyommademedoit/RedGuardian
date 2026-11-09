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

from harness import reporting, storage
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
ap.add_argument("--agent", default="mock", choices=["mock", "ollama"], help="mock (scripted) or ollama (local model)")
ap.add_argument("--model", help="Ollama model tag (default: OLLAMA_MODEL or qwen2.5:7b)")
ap.add_argument("--repeats", type=int, default=1, help="runs per scenario and profile; repeat i uses seed+i")
args = ap.parse_args()

library = load_library(ROOT / "attacks")
ids = args.attacks or list(library)
engine = storage.connect(args.db)
print(f"db: {engine.url.render_as_string(hide_password=True)}")

experiment_id = new_id()
with engine.begin() as c:
    c.execute(insert(storage.experiments), {
        "experiment_id": experiment_id, "name": "cli", "objective": "baseline vs defended vs ablations",
        "config": {"attacks": ids, "profiles": args.profiles, "seed": args.seed, "repeats": args.repeats,
                   "agent": args.agent, "model": args.model, "embedder": args.embedder},
        "created_at": utcnow()})


def make_agent(seed):
    if args.agent == "ollama":
        from harness.ollama_agent import OllamaAgent
        return OllamaAgent(model=args.model, seed=seed)
    return MockAgent(follows_injections=True)


def run(attack_id, profile, seed, **kw):
    scenario, digest = library[attack_id]
    return run_scenario(scenario, digest, make_agent(seed), profile, engine, seed=seed, experiment_id=experiment_id,
                        embedder=args.embedder, **kw)


table = {}
seeds = range(args.seed, args.seed + args.repeats)
for profile in args.profiles:
    evals = []
    print(f"\n== profile: {profile}", flush=True)
    for seed in seeds:
        for attack_id in ids:
            r = run(attack_id, profile, seed)
            e = r.evaluation
            evals.append(e)
            print(f"  {attack_id:<11} seed={seed} status={r.run.status:<10} success={e.attack_success!s:<5} "
                  f"leaked={e.secret_leaked!s:<5} stage={e.furthest_stage.name if e.furthest_stage else '-':<8} "
                  f"blocked_by={','.join(e.blocking_defenses) or '-':<14} task_ok={e.task_completed}"
                  + (f" error={r.run.error}" if r.run.error else ""), flush=True)
        for attack_id in ids:
            scenario = library[attack_id][0]
            if scenario.kind != "attack" or scenario.surface.value != "memory":
                continue
            poisoned = run(attack_id, "baseline", seed).run
            quarantined = MemoryStore(engine, poisoned.memory_state_id).quarantine(run_id=poisoned.run_id, trust="untrusted")
            if not quarantined:  # nothing was poisoned: no compromise to recover from, so no recovery attempt
                print(f"  recovery {attack_id} seed={seed}: skipped, poisoning run wrote no untrusted memory")
                continue
            for control in scenario.benign_controls:
                if "recovery" in library[control][0].tags:
                    e = run(control, profile, seed, memory_namespace=poisoned.memory_state_id).evaluation
                    evals.append(e)
                    print(f"  recovery {attack_id} -> {control} seed={seed}: quarantined={quarantined} task_ok={e.task_completed}")
    rows = compute_metrics(evals, scope=profile)
    with engine.begin() as c:
        c.execute(insert(storage.metric_results), [
            {"experiment_id": experiment_id, "scope": m.scope, "name": m.name,
             "numerator": m.numerator, "denominator": m.denominator, "value": m.value} for m in rows])
    table[profile] = {m.name: m for m in rows}


lines = [f"| profile | {' | '.join(COLUMNS)} |", f"|{'---|' * (len(COLUMNS) + 1)}"]
lines += [f"| {p} | {' | '.join(reporting.fmt(table[p][c]) for c in COLUMNS)} |" for p in table]
print("\n" + "\n".join(lines) + f"\n\nexperiment_id: {experiment_id}")
if args.report:  # full FR-12 report, from what was just persisted
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(reporting.markdown_report(engine, experiment_id, library), encoding="utf-8")
    print(f"wrote {args.report}")
