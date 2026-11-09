"""Phase 4: persistent memory (cross-session), simulated relay, memory/relay screens, recovery."""

from pathlib import Path

import pytest

from harness import storage
from harness.attacks import load_library
from harness.memory import MemoryStore
from harness.mock_agent import MockAgent
from harness.models import EventType, RunKind, SourceType, Stage
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
LIB = load_library(ROOT / "attacks")


@pytest.fixture
def engine():
    return storage.connect("sqlite://")


def run(engine, attack_id, profile, **kw):
    return run_scenario(*LIB[attack_id], MockAgent(), profile, engine, seed=0, **kw)


def stages(r):
    return {s: [e.stage for e in r.events if e.event_type is EventType.STAGE_REACHED and e.payload["session_id"] == s]
            for s in ("s1", "s2")}


def test_memory_attack_persists_in_session_1_and_fires_in_session_2(engine):
    r = run(engine, "MEM-001", "baseline")
    assert (r.evaluation.attack_success, r.evaluation.secret_leaked) == (True, True)
    by_session = stages(r)
    assert by_session["s1"] == [Stage.EXPOSED, Stage.PERSISTED]  # no action in the poisoned session itself
    assert by_session["s2"] == [Stage.EXPOSED, Stage.EXECUTED]
    write = next(e for e in r.events if e.event_type is EventType.MEMORY_WRITE)
    assert write.payload["trust"] == "untrusted" and write.payload["origin"] == ["tool_output:msg-1"]
    read = next(e for e in r.events if e.event_type is EventType.MEMORY_READ)
    assert read.payload["chunks"][0]["chunk_id"] == write.source_id  # the recalled entry is the one written


def test_memory_entry_stored_with_provenance(engine):
    r = run(engine, "MEM-001", "baseline")
    [entry] = MemoryStore(engine, r.run.memory_state_id).retrieve()
    assert (entry.trust, entry.source_type, entry.source_id, entry.session_id) == ("untrusted", "tool_output", "msg-1", "s1")
    assert entry.contains_canary and entry.run_id == r.run.run_id


def test_memory_screen_blocks_the_poisoned_write(engine):
    r = run(engine, "MEM-001", "only_memory_screen")
    e = r.evaluation
    assert not e.attack_success and e.furthest_stage is Stage.EXPOSED and e.blocking_defenses == ("memory_screen",)
    assert MemoryStore(engine, r.run.memory_state_id).retrieve() == []


def test_relay_attack_crosses_to_second_agent(engine):
    r = run(engine, "RELAY-001", "baseline")
    assert r.evaluation.attack_success and stages(r)["s1"] == [Stage.EXPOSED, Stage.RELAYED]
    msg = next(e for e in r.events if e.event_type is EventType.RELAY_MESSAGE)
    assert (msg.payload["sender"], msg.payload["recipient"], msg.source_id) == ("assistant", "ops-agent", "relay-1")
    executed = next(e for e in r.events if e.stage is Stage.EXECUTED)
    exposed_s2 = next(e for e in r.events if e.stage is Stage.EXPOSED and e.payload["session_id"] == "s2")
    assert exposed_s2.source_type is SourceType.RELAY and executed.payload["session_id"] == "s2"


def test_relay_screen_stops_the_message_at_the_boundary(engine):
    e = run(engine, "RELAY-001", "only_relay_screen").evaluation
    assert not e.attack_success and e.furthest_stage is Stage.EXPOSED and e.blocking_defenses == ("relay_screen",)


@pytest.mark.parametrize("attack_id", ["BENIGN-003", "BENIGN-005"])
@pytest.mark.parametrize("profile", ["baseline", "defended"])
def test_memory_and_relay_controls_keep_utility(engine, attack_id, profile):
    e = run(engine, attack_id, profile).evaluation
    assert e.task_completed and not e.refused_or_blocked


def test_recovery_quarantine_restores_safe_behaviour(engine):
    poisoned = run(engine, "MEM-001", "baseline").run
    ns = poisoned.memory_state_id
    before = run(engine, "BENIGN-004", "baseline", memory_namespace=ns).evaluation
    assert before.kind is RunKind.RECOVERY and not before.task_completed  # poison persists across runs

    assert MemoryStore(engine, ns).quarantine(run_id=poisoned.run_id) == 1
    after = run(engine, "BENIGN-004", "baseline", memory_namespace=ns).evaluation
    assert after.task_completed and MemoryStore(engine, ns).retrieve("quarantined")  # kept for audit


def test_memory_screen_on_read_covers_memory_poisoned_before_the_defense(engine):
    ns = run(engine, "MEM-001", "baseline").run.memory_state_id
    e = run(engine, "BENIGN-004", "defended", memory_namespace=ns).evaluation
    assert e.task_completed and e.blocking_defenses == ("memory_screen",)


def test_memory_store_operations(engine):
    m = MemoryStore(engine, "ns")
    kw = dict(source_type="user", source_id="s1", run_id="r", session_id="s1", contains_canary=False)
    a = m.append("a", trust="trusted", **kw)
    m.append("b", trust="untrusted", **kw)
    assert m.quarantine(trust="untrusted") == 1 and [r.content for r in m.retrieve()] == ["a"]
    assert m.delete(memory_id=a) == 1 and m.retrieve() == []
    assert MemoryStore(engine, "other").retrieve() == []  # namespaces isolated
    assert m.reset() == 2 and m.retrieve("deleted") == []


def test_dashboard_shows_memory_and_relay_path(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    url = f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}"
    eng = storage.connect(url)
    relay = run(eng, "RELAY-001", "only_relay_screen")
    run(eng, "MEM-001", "baseline")  # newest run: selected by default
    monkeypatch.setenv("MYSQL_URL", url)
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=30).run()
    assert not at.exception and "Memory and relay path" in [h.value for h in at.subheader]
    table = at.dataframe[-1].value
    assert list(table["operation"]) == ["memory_write", "memory_read"]
    assert list(table["session"]) == ["s1", "s2"] and bool(table["carries marker"].iloc[0])
    at.selectbox[0].select(relay.run.run_id).run()
    table = at.dataframe[-1].value
    assert list(table["policy"]) == ["quarantine by relay_screen"] and table["session"].iloc[0] == "s1"
