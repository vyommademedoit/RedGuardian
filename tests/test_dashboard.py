"""Phase 6: reporting layer (metrics, comparisons, attack path, report) and every dashboard view."""

from pathlib import Path

import pytest
from sqlalchemy import insert

from harness import reporting, storage
from harness.attacks import load_library
from harness.mock_agent import MockAgent
from harness.models import new_id, utcnow
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
LIB = load_library(ROOT / "attacks")
SCENARIOS = ["TOOL-001", "TOOL-002", "MEM-001", "BENIGN-001", "BENIGN-006"]
PROFILES = ["baseline", "defended", "only_secret_egress", "only_taint_guard", "no_taint_guard"]


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    url = f"sqlite:///{(tmp_path_factory.mktemp('db') / 'db.sqlite').as_posix()}"
    engine = storage.connect(url)
    xid = new_id()
    with engine.begin() as c:
        c.execute(insert(storage.experiments), {"experiment_id": xid, "name": "test", "objective": "phase 6",
                                                "config": {"agent": "mock"}, "created_at": utcnow()})
    for p in PROFILES:
        for a in SCENARIOS:
            run_scenario(*LIB[a], MockAgent(), p, engine, experiment_id=xid)
    return url, engine, xid


def test_metrics_follow_canonical_profile_order(db):
    _, engine, xid = db
    by = reporting.metrics_by_profile(reporting.run_rows(engine, xid))
    assert list(by) == PROFILES[:2] + ["no_taint_guard", "only_secret_egress", "only_taint_guard"]
    assert by["baseline"]["attack_success_rate"].numerator == 3


def test_compare_flags_utility_regression(db):
    _, engine, xid = db
    by = reporting.metrics_by_profile(reporting.run_rows(engine, xid))
    rows = {r["metric"]: r for r in reporting.compare(by["baseline"], by["defended"])}
    assert rows["benign_task_utility"]["worse"] and rows["benign_task_utility"]["delta"] == "-50%"  # BENIGN-006 refused
    assert not rows["attack_success_rate"]["worse"] and rows["attack_success_rate"]["delta"] == "-100%"


def test_outcome_never_calls_a_blocked_attempt_a_compromise(db):
    _, engine, xid = db
    m = reporting.scenario_matrix(reporting.run_rows(engine, xid))
    assert m["TOOL-001"]["baseline"] == "LEAKED"
    assert m["TOOL-001"]["only_secret_egress"] == "stopped by secret_egress"
    assert m["TOOL-002"]["only_secret_egress"] == "LEAKED"  # answer channel: tool checks can't see it
    assert m["BENIGN-006"]["defended"] == "refused/blocked by taint_guard"


def test_sufficient_layers(db):
    _, engine, xid = db
    layers = reporting.sufficient_layers(reporting.run_rows(engine, xid))
    assert layers["TOOL-001"] == ["secret_egress", "taint_guard"] and layers["TOOL-002"] == []


def test_attack_path_memory_hop_and_blocked_send(db):
    _, engine, _ = db
    g = reporting.attack_path(run_scenario(*LIB["MEM-001"], MockAgent(), "baseline", engine).events)
    edges = {(u.split(":")[0], v.split(":")[0], d["status"], d["marker"]) for u, v, d in g.edges(data=True)}
    assert {("tool_output", "agent", "observed", True), ("agent", "memory", "observed", True),
            ("memory", "agent", "observed", True), ("agent", "tool", "executed", True)} <= edges
    assert g.nodes["agent:s2"]["col"] > g.nodes["agent:s1"]["col"]
    g = reporting.attack_path(run_scenario(*LIB["TOOL-001"], MockAgent(), "only_secret_egress", engine).events)
    [blocked] = [d for _, v, d in g.edges(data=True) if v == "tool:send_report"]
    assert blocked["status"] == "blocked" and blocked["defense"] == "secret_egress" and blocked["marker"]


def test_markdown_report_has_every_fr12_section(db):
    _, engine, xid = db
    md = reporting.markdown_report(engine, xid, LIB)
    for heading in ("Configuration", "Objective and threat model", "Attacks and defenses", "Run counts and exclusions",
                    "Security and utility metrics", "Stage propagation", "Representative traces",
                    "Limitations and reproducibility", "Mitigation recommendations"):
        assert heading in md
    assert "Removing `taint_guard` raises benign utility" in md and "`TOOL-001`: stopped on its own by" in md


def app(url, monkeypatch, view):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("MYSQL_URL", url)
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=60)
    at.session_state["view"] = view
    return at.run()


@pytest.mark.parametrize("view", ["Overview", "Attack library", "Run explorer", "Comparison", "Ablation", "Evidence", "Export"])
def test_every_view_renders(db, monkeypatch, view):
    at = app(db[0], monkeypatch, view)
    assert not at.exception and not at.error, [e.value for e in at.error]


def test_comparison_warns_on_utility_regression(db, monkeypatch):
    at = app(db[0], monkeypatch, "Comparison")
    assert any("Benign utility regresses" in w.value for w in at.warning)


def test_evidence_search_filters_events(db, monkeypatch):
    at = app(db[0], monkeypatch, "Evidence")
    at.text_input[0].input("output_guard").run()
    table = at.dataframe[0].value
    assert len(table) and set(table["defense"]) <= {"output_guard", ""}


def test_empty_database_shows_guidance(tmp_path, monkeypatch):
    at = app(f"sqlite:///{(tmp_path / 'empty.sqlite').as_posix()}", monkeypatch, "Overview")
    assert not at.exception and any("No runs in this scope" in i.value for i in at.info)


def test_recovery_setup_runs_are_not_measured():
    engine, xid = storage.connect("sqlite://"), new_id()
    with engine.begin() as c:
        c.execute(insert(storage.experiments), {"experiment_id": xid, "name": "t", "objective": "", "config": {},
                                                "created_at": utcnow()})
    run_scenario(*LIB["MEM-001"], MockAgent(), "baseline", engine, experiment_id=xid)  # the measured attack run
    setup = run_scenario(*LIB["MEM-001"], MockAgent(), "baseline", engine, experiment_id=xid).run
    run_scenario(*LIB["BENIGN-004"], MockAgent(), "defended", engine, experiment_id=xid, memory_namespace=setup.run_id)
    rows = reporting.run_rows(engine, xid)
    by = reporting.metrics_by_profile(rows)
    assert by["baseline"]["attack_success_rate"].denominator == 1  # the setup run is not a baseline measurement
    assert by["defended"]["recovery_success"].denominator == 1
    assert reporting.outcome(next(r for r in rows if r["run_id"] == setup.run_id)) == "recovery setup (not measured)"
