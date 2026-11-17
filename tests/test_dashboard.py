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
    assert rows["benign_task_utility"]["worse"] and rows["benign_task_utility"]["delta"] == "-50 pp"  # BENIGN-006 refused
    assert not rows["attack_success_rate"]["worse"] and rows["attack_success_rate"]["delta"] == "-100 pp"


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


def test_sufficient_layers_counts_unauthorized_actions_and_skips_harmless_attacks():
    def row(attack, profile, success=False, ran=0):
        return {"kind": "attack", "attack_id": attack, "defense_profile": profile, "ev": {
            "valid": True, "attack_success": success, "secret_leaked": False, "unauthorized_executed": ran}}
    rows = [row("A", "baseline", ran=1), row("A", "only_x", ran=1), row("A", "only_y"),
            row("B", "baseline"), row("B", "only_x")]  # B never did anything: nothing to stop
    assert reporting.sufficient_layers(rows) == {"A": ["y"]}
    assert reporting.sufficient_layers(rows + [row("A", "only_y", success=True)]) == {"A": []}  # must hold every repeat


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
    assert any("Normal tasks done drops" in w.value for w in at.warning)


def test_evidence_search_filters_events(db, monkeypatch):
    at = app(db[0], monkeypatch, "Evidence")
    at.text_input[0].input("output guard").run()  # plain words find the id too
    table = at.dataframe[0].value
    assert len(table) and set(table["defense"]) <= {"output guard", ""}


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


def test_setup_run_without_recovery_is_not_measured():
    # the model wrote no memory, so run_experiment skips recovery: the setup run must still be excluded
    engine, ns = storage.connect("sqlite://"), f"{reporting.SETUP_PREFIX}{new_id()}"
    run_scenario(*LIB["MEM-001"], MockAgent(), "baseline", engine, memory_namespace=ns)
    [row] = reporting.run_rows(engine)
    assert row["setup"] and reporting.metrics_by_profile([row]) == {}
    # the recovery run on that memory shares the namespace but is a measurement
    run_scenario(*LIB["BENIGN-004"], MockAgent(), "defended", engine, memory_namespace=ns)
    by = reporting.metrics_by_profile(reporting.run_rows(engine))
    assert list(by) == ["defended"] and by["defended"]["recovery_success"].denominator == 1


def test_vocab_covers_every_metric_and_stage_in_order():
    import sys

    sys.path.insert(0, str(ROOT / "dashboard"))
    from harness.models import Stage
    from vocab import LABELS, SEVERITY, label, yes_no

    assert set(reporting.HEADLINE) <= set(LABELS)
    assert list(SEVERITY) == ["none"] + [s.name.lower() for s in sorted(Stage)]
    assert label("no_taint_guard") == "all but taint guard" and label("only_secret_egress") == "only secret egress"
    assert label("baseline") == "baseline" and "_" not in label("attack_success_rate")
    assert (yes_no(True), yes_no(False)) == ("Yes", "No")


def test_plain_answer_is_not_drawn_as_an_executed_action(db):
    _, engine, _ = db
    g = reporting.attack_path(run_scenario(*LIB["BENIGN-001"], MockAgent(), "baseline", engine).events)
    to_user = {d["status"] for _, v, d in g.edges(data=True) if v == "user_response"}
    assert to_user and "executed" not in to_user and to_user <= {"answered", "blocked"}


def test_overview_speaks_plain_words_and_percentage_points(db, monkeypatch):
    at = app(db[0], monkeypatch, "Overview")
    tiles = [m for m in at.metric if m.delta]
    assert tiles and all("_" not in m.label for m in at.metric)
    assert all(m.delta == "no change" or m.delta.endswith(" pp") for m in tiles)
    assert sorted(t.value for t in at.title) == ["Overview", "RedGuardian"]  # page title + sidebar brand, once each


def _vocab():
    import sys

    sys.path.insert(0, str(ROOT / "dashboard"))
    import vocab

    return vocab


def _contrast(a: str, b: str) -> float:
    def lum(h):
        c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        c = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_every_event_type_has_a_plain_name():
    from harness.models import EventType

    v = _vocab()
    assert {e.value for e in EventType} <= set(v.EVENTS) and "_" not in v.label("policy_decision")


def test_severity_ramp_reads_in_order_without_colour():
    v = _vocab()
    bg, ramp = "#0E1117", list(v.SEVERITY.values())
    on_bg = [_contrast(c, bg) for c in ramp]
    assert all(x >= 3 for x in on_bg) and on_bg == sorted(on_bg) and len(set(on_bg)) == len(on_bg)  # strictly brighter
    assert all(_contrast(a, b) >= 1.2 for a, b in zip(ramp, ramp[1:]))
    assert list(v.PATTERN) == list(v.SEVERITY) and len(set(v.PATTERN.values())) == len(v.PATTERN)


def test_run_views_show_profile_names_but_export_keeps_ids(db, monkeypatch):
    at = app(db[0], monkeypatch, "Run explorer")
    assert not any("_" in p for p in at.dataframe[0].value["profile"])
    at = app(db[0], monkeypatch, "Evidence")
    table = at.dataframe[0].value
    assert not any("_" in p for p in table["profile"]) and not any("_" in e for e in table["event"])
    # Export still builds from summary_rows (raw ids); only the display copy shown() is labelled.


def test_stage_drilldown_by_keyboard_matches_the_chart_count(db, monkeypatch):
    _, engine, xid = db
    at = app(db[0], monkeypatch, "Overview")
    at.selectbox(key="ovw_profile").select("defended").run()
    at.selectbox(key="ovw_stage").select("none").run()
    want = reporting.stage_distribution(reporting.run_rows(engine, xid))["defended"]["none"]
    assert not at.exception and want and len(at.dataframe[0].value) == want


def test_defenses_and_library_values_read_as_words(db, monkeypatch):
    at = app(db[0], monkeypatch, "Run explorer")
    table = at.dataframe[0].value
    assert not any("_" in str(c) for col in ("profile", "surface", "outcome", "blocked by") for c in table[col])
    at = app(db[0], monkeypatch, "Attack library")
    options = at.multiselect(key="lib_surface").options
    assert options and not any("_" in o for o in options)
    at.multiselect(key="lib_surface").select(at.multiselect(key="lib_surface").options[0]).run()
    assert not at.exception and len(at.dataframe[0].value) >= 1


def test_run_lists_open_only_after_a_row_is_selected(db, monkeypatch):
    at = app(db[0], monkeypatch, "Overview")
    at.selectbox(key="ovw_profile").select("baseline").run()
    assert at.button(key="open_stage_runs").disabled
    at = app(db[0], monkeypatch, "Attack library")
    assert at.button(key="open_lib").disabled
    at = app(db[0], monkeypatch, "Comparison")  # one way to open a run on every page
    assert at.button(key="open_cmp").disabled and not [s for s in at.selectbox if s.key == "pick_cmp"]


def test_worse_rows_have_their_own_readable_colour():
    v = _vocab()
    assert v.WORSE not in v.SEVERITY.values() and v.WORSE != v.OBSERVED
    bg = tuple(int("0E1117"[i:i + 2], 16) for i in (0, 2, 4))
    fg = tuple(int(v.WORSE[1:][i:i + 2], 16) for i in (0, 2, 4))
    mixed = "#" + "".join(f"{round(0.25 * f + 0.75 * b):02X}" for f, b in zip(fg, bg))  # 0x40 alpha ≈ 25 %
    assert _contrast("#FAFAFA", mixed) >= 4.5
    assert v.plain("stopped by output_guard, input_screen") == "stopped by output guard, input screen"



def test_dashboard_is_pinned_to_the_dark_theme_the_colours_are_tuned_for():
    import tomllib

    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["theme"]["base"] == "dark"  # severity ramp contrast is checked against #0E1117 only
