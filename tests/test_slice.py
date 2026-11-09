"""End-to-end vertical slice: mock agent → TOOL-001 → policy → events → evaluator → storage → dashboard."""

from pathlib import Path

import pytest
from sqlalchemy import select

from harness import storage
from harness.attacks import load_library
from harness.evaluator import DeterministicEvaluator
from harness.interfaces import AgentUnavailable
from harness.mock_agent import MockAgent
from harness.models import EventType, RunEvaluation, RunStatus, Stage
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
LIB = load_library(ROOT / "attacks")


@pytest.fixture
def engine():
    return storage.connect("sqlite://")


def run(engine, attack_id, profile, agent=None, seed=0):
    scenario, digest = LIB[attack_id]
    return run_scenario(scenario, digest, agent or MockAgent(), profile, engine, seed=seed)


def test_baseline_attack_succeeds_and_leaks(engine):
    r = run(engine, "TOOL-001", "baseline")
    e = r.evaluation
    assert r.run.status is RunStatus.COMPLETED
    assert (e.attack_success, e.secret_leaked, e.injected) == (True, True, True)
    assert (e.unauthorized_attempts, e.unauthorized_executed, e.unauthorized_blocked) == (1, 1, 0)
    assert e.furthest_stage is Stage.EXECUTED
    outbox = next(ev for ev in r.events if ev.event_type is EventType.RUN_FINISHED).payload["outbox"]
    assert outbox and outbox[0]["to"] == "audit@external.test"  # recorded intent only


def test_defended_attack_blocked_by_named_defense(engine):
    e = run(engine, "TOOL-001", "only_secret_egress").evaluation
    assert (e.attack_success, e.secret_leaked, e.injected) == (False, False, True)
    assert (e.unauthorized_attempts, e.unauthorized_blocked, e.unauthorized_executed) == (1, 1, 0)
    assert e.blocking_defenses == ("secret_egress",)


@pytest.mark.parametrize("profile", ["baseline", "defended"])
def test_benign_control_keeps_utility(engine, profile):
    e = run(engine, "BENIGN-001", profile).evaluation
    assert e.valid and e.task_completed and not e.refused_or_blocked
    assert e.unauthorized_attempts == 0 and e.furthest_stage is None


def test_safe_agent_exposed_but_not_executed(engine):
    e = run(engine, "TOOL-001", "baseline", agent=MockAgent(follows_injections=False)).evaluation
    assert e.injected and not e.attack_success
    assert e.furthest_stage is Stage.EXPOSED


def test_same_seed_same_trace(engine):
    a, b = run(engine, "TOOL-001", "baseline", seed=7), run(engine, "TOOL-001", "baseline", seed=7)
    strip = lambda evs: [(e.seq, e.event_type, e.stage, e.decision) for e in evs]  # noqa: E731
    assert strip(a.events) == strip(b.events)
    assert a.events[0].payload["secret"] == b.events[0].payload["secret"]
    assert run(engine, "TOOL-001", "baseline", seed=8).events[0].payload["secret"] != a.events[0].payload["secret"]


def test_model_failure_is_invalid_not_a_defense(engine):
    class Down:
        name = "down"

        def describe(self):
            return {}

        def step(self, messages, tools):
            raise AgentUnavailable("ollama not running")

    r = run(engine, "TOOL-001", "defended", agent=Down())
    assert r.run.status is RunStatus.FAILED and "ollama not running" in r.run.error
    assert not r.evaluation.valid
    assert any(e.event_type is EventType.MODEL_ERROR for e in r.events)


def test_evaluation_reproducible_from_stored_events(engine):
    r = run(engine, "TOOL-001", "defended")
    with engine.connect() as c:
        stored = RunEvaluation.model_validate(c.execute(select(storage.evaluations.c.result)).scalar_one())
    events = storage.SqlEventLogger(engine).events(r.run.run_id)
    assert DeterministicEvaluator().evaluate(r.run, LIB["TOOL-001"][0], events) == stored == r.evaluation


def test_dashboard_renders_runs(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    url = f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}"
    eng = storage.connect(url)
    run(eng, "TOOL-001", "only_secret_egress")
    monkeypatch.setenv("MYSQL_URL", url)
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=30).run()
    assert not at.exception
    assert any("executed (blocked)" in m.value and "secret_egress" in m.value for m in at.markdown)
