import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, insert, select

from harness import storage
from harness.attacks import AttackDefinitionError, json_schema, load_library, load_scenario
from harness.metrics import compute_metrics
from harness.models import (
    AgentTurn,
    Check,
    CheckPoint,
    Decision,
    Event,
    EventType,
    Message,
    PolicyDecision,
    RunEvaluation,
    RunKind,
    RunRecord,
    Stage,
    ToolSpec,
    Permission,
)
from harness.interfaces import AgentAdapter, Defense

ROOT = Path(__file__).resolve().parent.parent
ATTACKS = ROOT / "attacks"


# --- attack library -------------------------------------------------------


def test_library_loads_shipped_scenarios():
    lib = load_library(ATTACKS)
    assert list(lib) == [  # sorted, deterministic
        "BENIGN-001", "BENIGN-001b", "BENIGN-002", "BENIGN-003", "BENIGN-004", "BENIGN-005", "BENIGN-006", "BENIGN-007",
        "BENIGN-008", "DIR-001", "MEM-001", "MEM-001b", "RAG-001", "RAG-001b", "RELAY-001", "TOOL-001", "TOOL-001b", "TOOL-001c", "TOOL-002"]
    scenario, digest = lib["TOOL-001"]
    assert scenario.stages == (Stage.EXPOSED, Stage.EXECUTED)
    assert len(digest) == 64


def test_mysql_ddl_in_sync_and_versioned(tmp_path):
    from harness import storage

    ddl = ATTACKS.parent / "db" / f"schema_v{storage.SCHEMA_VERSION}.mysql.sql"
    assert ddl.read_text(encoding="utf-8") == storage.ddl("mysql"), "run: uv run python scripts/export_schema.py"
    assert "DATETIME(6)" in ddl.read_text(encoding="utf-8")  # sub-second timestamps on MySQL
    url = f"sqlite:///{(tmp_path / 'v.sqlite').as_posix()}"
    storage.connect(url), storage.connect(url)  # second connect: already stamped, no duplicate
    eng = storage.connect(url)
    with eng.begin() as c:
        assert c.execute(storage.select(storage.schema_info.c.version)).scalars().all() == [storage.SCHEMA_VERSION]
        c.execute(storage.update(storage.schema_info).values(version=storage.SCHEMA_VERSION + 1))
    with pytest.raises(RuntimeError, match="schema v"):
        storage.connect(url)


def test_schema_json_in_sync():
    assert (ATTACKS / "schema.json").read_text(encoding="utf-8") == json_schema(), (
        "run: uv run python scripts/export_schema.py"
    )


def _write(tmp_path, data, name=None):
    p = tmp_path / f"{name or data['attack_id']}.json"
    p.write_text(json.dumps(data))
    return p


def _tool001():
    return json.loads((ATTACKS / "tool_output" / "TOOL-001.json").read_text())


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d.pop("success_condition"), "success_condition"),
        (lambda d: d["injection"].update(payload="no placeholder"), "{marker}"),
        (lambda d: d.update(surface="email"), "surface"),
        (lambda d: d.update(attack_id="X-1"), "attack_id"),
        (lambda d: d.update(unexpected=1), "unexpected"),
    ],
)
def test_invalid_definition_rejected_with_useful_error(tmp_path, mutate, message):
    data = _tool001()
    mutate(data)
    with pytest.raises(AttackDefinitionError, match="invalid attack definition") as e:
        load_scenario(_write(tmp_path, data, name="TOOL-001"))
    assert message in str(e.value)


def test_filename_must_match_id(tmp_path):
    with pytest.raises(AttackDefinitionError, match="file name"):
        load_scenario(_write(tmp_path, _tool001(), name="TOOL-999"))


def test_unknown_benign_control_rejected(tmp_path):
    _write(tmp_path, _tool001())
    with pytest.raises(AttackDefinitionError, match="benign_controls"):
        load_library(tmp_path)


def test_disabled_scenarios_skipped(tmp_path):
    d = _tool001() | {"enabled": False, "benign_controls": []}
    _write(tmp_path, d)
    assert load_library(tmp_path) == {}
    assert list(load_library(tmp_path, include_disabled=True)) == ["TOOL-001"]


def test_benign_cannot_carry_injection():
    data = json.loads((ATTACKS / "benign" / "BENIGN-001.json").read_text())
    data["injection"] = _tool001()["injection"]
    with pytest.raises(ValidationError, match="must not define injection"):
        __import__("harness.models").models.AttackScenario.model_validate(data)


# --- models & protocols ---------------------------------------------------


def test_events_are_immutable():
    e = Event(run_id="r", seq=0, event_type=EventType.RUN_STARTED)
    with pytest.raises(ValidationError):
        e.seq = 1


def test_evaluation_counts_consistent():
    with pytest.raises(ValidationError):
        RunEvaluation(run_id="r", kind=RunKind.ATTACK, valid=True,
                      unauthorized_attempts=1, unauthorized_blocked=1, unauthorized_executed=1)


def test_protocols_are_satisfiable():
    class Mock:
        name = "mock"

        def describe(self):
            return {}

        def step(self, messages, tools):
            return AgentTurn(text="ok")

    class DenyOutbound:
        defense_id = "deny_outbound"
        points = frozenset({CheckPoint.TOOL_CALL})

        def evaluate(self, check):
            if check.tool and check.tool.permission is Permission.OUTBOUND:
                return PolicyDecision(decision=Decision.BLOCK, defense_id=self.defense_id, reason="outbound")
            return None

    assert isinstance(Mock(), AgentAdapter)
    d = DenyOutbound()
    assert isinstance(d, Defense)
    spec = ToolSpec(name="send_report", description="", permission=Permission.OUTBOUND, parameters={})
    assert d.evaluate(Check(point=CheckPoint.TOOL_CALL, run_id="r", tool=spec)).decision is Decision.BLOCK
    assert Mock().step([Message(role="user", content="hi")], [spec]).text == "ok"


# --- metrics --------------------------------------------------------------


def test_metrics_denominators():
    A, B = RunKind.ATTACK, RunKind.BENIGN
    evals = [
        RunEvaluation(run_id="1", kind=A, valid=True, attack_success=True, injected=True,
                      unauthorized_attempts=2, unauthorized_executed=2, furthest_stage=Stage.EXECUTED),
        RunEvaluation(run_id="2", kind=A, valid=True, injected=True,
                      unauthorized_attempts=1, unauthorized_blocked=1, furthest_stage=Stage.EXPOSED),
        RunEvaluation(run_id="3", kind=A, valid=False, attack_success=True),  # failed run: excluded
        RunEvaluation(run_id="4", kind=B, valid=True, task_completed=True),
    ]
    m = {r.name: r for r in compute_metrics(evals)}
    assert (m["attack_success_rate"].numerator, m["attack_success_rate"].denominator) == (1, 2)
    assert (m["defense_block_rate"].numerator, m["defense_block_rate"].denominator) == (1, 3)
    assert (m["invalid_runs"].numerator, m["invalid_runs"].denominator) == (1, 4)
    assert m["benign_task_utility"].value == 1.0
    assert m["recovery_success"].value is None  # not measured, not 0%
    assert m["furthest_stage:executed"].numerator == 1
    assert sum(r.numerator for n, r in m.items() if n.startswith("furthest_stage:")) == 2


# --- storage --------------------------------------------------------------


def test_tables_roundtrip_run_and_event():
    engine = create_engine("sqlite://")
    storage.metadata.create_all(engine)
    run = RunRecord(kind=RunKind.ATTACK, attack_id="TOOL-001", attack_version="1.0.0",
                    attack_sha256="0" * 64, adapter="mock", defense_profile="baseline")
    ev = Event(run_id=run.run_id, seq=0, event_type=EventType.RUN_STARTED, stage=Stage.EXPOSED)
    with engine.begin() as c:
        c.execute(insert(storage.runs), run.model_dump())
        c.execute(insert(storage.events), ev.model_dump())
        row = c.execute(select(storage.events)).one()
    assert Event.model_validate(row._asdict()) == ev
