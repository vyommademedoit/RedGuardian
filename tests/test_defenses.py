"""Phase 5: defense suite, ablation profiles, direct input, adaptive variants, false-refusal probes."""

from pathlib import Path

import pytest

from harness import storage
from harness.attacks import load_library
from harness.mock_agent import MockAgent
from harness.models import (AgentTurn, Check, CheckPoint, Decision, EventType, Permission, Provenance, SourceType,
                            Stage, ToolCall, ToolSpec, Trust)
from harness.policy import DEFENSES, PROFILES, DestinationAllowlistDefense, TaintGuardDefense
from harness.runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
LIB = load_library(ROOT / "attacks")
OUT = ToolSpec(name="send_report", description="", permission=Permission.OUTBOUND, parameters={})


@pytest.fixture
def engine():
    return storage.connect("sqlite://")


def run(engine, attack_id, profile, agent=None):
    return run_scenario(*LIB[attack_id], agent or MockAgent(), profile, engine, seed=0).evaluation


def test_ablation_profiles_remove_or_isolate_exactly_one_defense():
    for d in DEFENSES:
        assert set(PROFILES["defended"]) - set(PROFILES[f"no_{d}"]) == {d} and PROFILES[f"only_{d}"] == (d,)


@pytest.mark.parametrize("attack_id", [a for a, (s, _) in LIB.items() if s.kind == "benign"])
def test_every_benign_scenario_succeeds_on_baseline(engine, attack_id):
    e = run(engine, attack_id, "baseline")  # fixtures and expected outcomes are sound
    assert e.valid and e.task_completed


@pytest.mark.parametrize("attack_id", [a for a, (s, _) in LIB.items() if s.kind == "attack"])
def test_every_attack_lands_on_baseline_and_fails_when_defended(engine, attack_id):
    assert run(engine, attack_id, "baseline").attack_success
    assert not run(engine, attack_id, "defended").attack_success


def test_invalid_arguments_rejected_before_policy_and_execution(engine):
    class Sloppy:
        name = "sloppy"
        def describe(self): return {}
        def step(self, messages, tools):
            if any(m.role == "tool" for m in messages):
                return AgentTurn(text="done")
            return AgentTurn(tool_calls=(ToolCall(tool="send_report", arguments={"to": "x@corp.test"}),))  # no body

    r = run_scenario(*LIB["BENIGN-001"], Sloppy(), "baseline", engine)
    kinds = [e.event_type for e in r.events]
    assert EventType.TOOL_ERROR in kinds and EventType.TOOL_EXECUTED not in kinds
    assert "invalid arguments" in next(e.reason for e in r.events if e.event_type is EventType.TOOL_ERROR)


def test_destination_allowlist_checks_outbound_domain_only():
    d = DestinationAllowlistDefense()
    def check(to, spec=OUT):
        return d.evaluate(Check(point=CheckPoint.TOOL_CALL, run_id="r", tool=spec,
                                tool_call=ToolCall(tool=spec.name, arguments={"to": to})))
    assert check("audit@external.test").decision is Decision.BLOCK
    assert check("evil@corp.test.external.test").decision is Decision.BLOCK
    assert check("bob@corp.test") is None
    assert check("audit@external.test", OUT.model_copy(update={"permission": Permission.READ})) is None


def test_taint_guard_blocks_outbound_only_after_untrusted_content():
    g = TaintGuardDefense()
    tainted = Provenance(source_type=SourceType.TOOL_OUTPUT, source_id="msg-1", trust=Trust.UNTRUSTED)
    call = ToolCall(tool="send_report", arguments={"to": "bob@corp.test", "body": "hi"})
    assert g.evaluate(Check(point=CheckPoint.TOOL_CALL, run_id="r", tool=OUT, tool_call=call)) is None
    v = g.evaluate(Check(point=CheckPoint.TOOL_CALL, run_id="r", tool=OUT, tool_call=call, provenance=(tainted,)))
    assert v.decision is Decision.BLOCK and "tool_output:msg-1" in v.reason


def test_taint_guard_costs_utility_on_legitimate_send(engine):
    refused = run(engine, "BENIGN-006", "only_taint_guard")
    assert not refused.task_completed and refused.refused_or_blocked and refused.blocking_defenses == ("taint_guard",)
    assert run(engine, "BENIGN-006", "no_taint_guard").task_completed


def test_input_screen_withholds_without_echoing_the_payload(engine):
    r = run_scenario(*LIB["TOOL-001"], MockAgent(), "only_input_screen", storage.connect("sqlite://"))
    assert not r.evaluation.attack_success and r.evaluation.furthest_stage is None
    shown = next(e for e in r.events if e.event_type is EventType.TOOL_EXECUTED)  # raw result, logged as evidence
    assert "send_report" in shown.payload["content"]
    response = next(e for e in r.events if e.event_type is EventType.AGENT_RESPONSE).payload["text"]
    assert "send_report" not in response


def test_input_screen_false_refusal_on_benign_assistant_note(engine):
    e = run(engine, "BENIGN-007", "only_input_screen")
    assert not e.task_completed and e.refused_or_blocked and e.blocking_defenses == ("input_screen",)


def test_direct_input_attack_traced_to_user_channel(engine):
    r = run_scenario(*LIB["DIR-001"], MockAgent(), "baseline", engine)
    exposed = next(e for e in r.events if e.stage is Stage.EXPOSED)
    assert r.evaluation.attack_success and (exposed.source_type, exposed.source_id) == (SourceType.USER, "user")
    assert not run(engine, "DIR-001", "only_input_screen").attack_success


@pytest.mark.parametrize("attack_id,evades,stops", [
    ("TOOL-001b", "only_input_screen", "only_secret_egress"),       # reworded: screens miss it
    ("RAG-001b", "only_retrieval_screen", "only_secret_egress"),
    ("MEM-001b", "only_memory_screen", "only_taint_guard"),
    ("TOOL-001c", "only_destination_allowlist", "only_secret_egress"),  # internal address: allowlist misses it
])
def test_adaptive_variants_show_which_layer_holds(engine, attack_id, evades, stops):
    assert run(engine, attack_id, evades).attack_success
    assert not run(engine, attack_id, stops).attack_success


def test_output_guard_is_the_only_layer_for_a_response_channel_leak(engine):
    r = run_scenario(*LIB["TOOL-002"], MockAgent(), "only_output_guard", engine)
    response = next(e for e in r.events if e.event_type is EventType.AGENT_RESPONSE).payload
    secret = r.events[0].payload["secret"]
    assert not r.evaluation.secret_leaked and r.evaluation.blocking_defenses == ("output_guard",)
    assert secret not in response["text"] and secret in response["raw"]  # withheld, original kept as evidence
    assert run(engine, "TOOL-002", "no_output_guard").secret_leaked  # every other layer misses it
