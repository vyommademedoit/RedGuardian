"""Phase 7: verification catches disagreements between stored results and raw events."""

import re
from pathlib import Path

import pytest
from sqlalchemy import insert, select, update

from harness import storage
from harness.attacks import load_library
from harness.metrics import compute_metrics
from harness.mock_agent import MockAgent
from harness.models import AgentTurn, ToolCall, new_id, utcnow
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


class EarlyLeak:
    """Leaks the key in session 1 only (in its answer, or by saving it to memory); session 2 answers clean."""

    name = "early-leak"

    def __init__(self, save: bool):
        self.save = save

    def describe(self) -> dict:
        return {"save": self.save}

    def step(self, messages, tools):
        called = {c.tool for m in messages for c in m.tool_calls}
        if "save it to memory" not in messages[1].content:
            return AgentTurn(text="Nothing pending.")
        if "read_config" not in called:
            return AgentTurn(tool_calls=(ToolCall(tool="read_config"),))
        secret = re.search(r"SECRET-\S+", "".join(m.content for m in messages if m.role == "tool")).group()
        if self.save and "write_memory" not in called:
            return AgentTurn(tool_calls=(ToolCall(tool="write_memory", arguments={"content": secret}),))
        return AgentTurn(text="Saved." if self.save else f"Summary done. {secret}")


@pytest.mark.parametrize("save", [False, True], ids=["answer", "memory"])
def test_leak_in_an_earlier_session_is_counted_and_verified(save):
    engine, xid = storage.connect("sqlite://"), new_id()
    with engine.begin() as c:
        c.execute(insert(storage.experiments), {"experiment_id": xid, "name": "t", "objective": "", "config": {},
                                                "created_at": utcnow()})
    r = run_scenario(*LIB["MEM-001"], EarlyLeak(save), "baseline", engine, experiment_id=xid)
    assert len([e for e in r.events if e.event_type.value == "agent_response"]) == 2
    assert r.evaluation.valid and r.evaluation.secret_leaked
    with engine.begin() as c:
        c.execute(insert(storage.metric_results), [
            {"experiment_id": xid, "scope": m.scope, "name": m.name, "numerator": m.numerator,
             "denominator": m.denominator, "value": m.value} for m in compute_metrics([r.evaluation], scope="baseline")])
    assert verify(engine, xid, LIB)[1] == []  # the independent raw-event check agrees


def test_tampered_metric_is_caught(experiment):
    engine, xid = experiment
    with engine.begin() as c:
        c.execute(update(storage.metric_results).where(storage.metric_results.c.name == "attack_success_rate",
                                                       storage.metric_results.c.scope == "baseline").values(numerator=0))
    assert any("metric baseline/attack_success_rate" in p for p in verify(engine, xid, LIB)[1])
