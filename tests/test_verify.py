"""Phase 7: verification catches disagreements between stored results and raw events."""

from pathlib import Path

import pytest
from sqlalchemy import insert, select, update

from harness import storage
from harness.attacks import load_library
from harness.metrics import compute_metrics
from harness.mock_agent import MockAgent
from harness.models import new_id, utcnow
from harness.runner import run_scenario
from harness.verify import verify

ROOT = Path(__file__).resolve().parent.parent
LIB = load_library(ROOT / "attacks")


@pytest.fixture
def experiment():
    engine, xid = storage.connect("sqlite://"), new_id()
    with engine.begin() as c:
        c.execute(insert(storage.experiments), {"experiment_id": xid, "name": "t", "objective": "", "config": {},
                                                "created_at": utcnow()})
    for profile in ("baseline", "defended"):
        evals = [run_scenario(*LIB[a], MockAgent(), profile, engine, experiment_id=xid).evaluation
                 for a in ("TOOL-001", "TOOL-002", "BENIGN-001")]
        with engine.begin() as c:  # what run_experiment.py stores
            c.execute(insert(storage.metric_results), [
                {"experiment_id": xid, "scope": m.scope, "name": m.name, "numerator": m.numerator,
                 "denominator": m.denominator, "value": m.value} for m in compute_metrics(evals, scope=profile)])
    return engine, xid


def test_clean_experiment_verifies(experiment):
    checks, problems = verify(*experiment, LIB)
    assert checks > 30 and problems == []


def test_tampered_evaluation_is_caught(experiment):
    engine, xid = experiment
    with engine.begin() as c:
        row = c.execute(select(storage.evaluations).join(storage.runs, storage.runs.c.run_id == storage.evaluations.c.run_id)
                        .where(storage.runs.c.attack_id == "TOOL-001", storage.runs.c.defense_profile == "baseline")).one()
        c.execute(update(storage.evaluations).where(storage.evaluations.c.run_id == row.run_id)
                  .values(result={**row.result, "secret_leaked": False, "attack_success": False}))
    problems = verify(engine, xid, LIB)[1]
    assert any("re-evaluation differs" in p for p in problems)
    assert any("raw events say True" in p for p in problems)  # invariant check, independent of the evaluator


def test_tampered_metric_is_caught(experiment):
    engine, xid = experiment
    with engine.begin() as c:
        c.execute(update(storage.metric_results).where(storage.metric_results.c.name == "attack_success_rate",
                                                       storage.metric_results.c.scope == "baseline").values(numerator=0))
    assert any("metric baseline/attack_success_rate" in p for p in verify(engine, xid, LIB)[1])
