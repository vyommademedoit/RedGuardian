"""Words and colours the dashboard shows. Display only: storage and exports keep the raw ids."""

from harness.policy import DEFENSES

# Plain names for reporting.HEADLINE ids; meanings from docs/metrics.md.
LABELS = {
    "attack_success_rate": "Attack succeeded",
    "injection_success_rate": "Payload reached the agent",
    "secret_leakage_rate": "Secret leaked",
    "unauthorized_tool_attempt_rate": "Forbidden tool requested",
    "unauthorized_tool_execution_rate": "Forbidden tool ran",
    "defense_block_rate": "Forbidden calls blocked",
    "benign_task_utility": "Normal tasks done",
    "false_refusal_rate": "Normal tasks refused",
    "recovery_success": "Recovered after cleanup",
    "invalid_runs": "Invalid runs",
}

# Plain names for harness.models.EventType values (Evidence and Timeline tables).
EVENTS = {
    "run_started": "run started",
    "run_finished": "run finished",
    "session_started": "session started",
    "content_exposed": "payload reached the agent",
    "retrieval": "documents retrieved",
    "memory_write": "memory written",
    "memory_read": "memory read",
    "relay_message": "message relayed",
    "agent_response": "agent answered",
    "tool_call_proposed": "tool call requested",
    "policy_decision": "defense decision",
    "tool_executed": "tool ran",
    "tool_error": "tool error",
    "model_error": "model error",
    "stage_reached": "stage reached",
}

# Furthest canary stage, calm to worst. On Streamlit's dark background (#0E1117) contrast rises strictly
# (3.1 → 11.1:1), so "executed" is always the strongest mark; PATTERN is the second, colour-free channel.
SEVERITY = {
    "none": "#5C6370",
    "exposed": "#94700A",
    "persisted": "#D2742A",
    "relayed": "#FF7266",
    "executed": "#FFB3AD",
}
PATTERN = {"none": "", "exposed": ".", "persisted": "/", "relayed": "x", "executed": "+"}
NEUTRAL = "#8B949E"  # things that are not a severity: graph nodes, blocked hops, plain answers
OBSERVED = "#6CB6FF"  # content reached the next hop; deliberately outside the severity ramp
WORSE = "#BC8CFF"  # comparison rows that changed in the wrong direction; not a stage, so not a stage colour
STAGE_HELP = "How far the attack canary travelled: none → exposed → persisted → relayed → executed."


def label(name: str) -> str:
    """Metric, event or profile id -> words: no_taint_guard -> 'all but taint guard'."""
    if name in LABELS:
        return LABELS[name]
    if name in EVENTS:
        return EVENTS[name]
    for prefix, words in (("no_", "all but "), ("only_", "only ")):
        if name.startswith(prefix):
            return words + name.removeprefix(prefix).replace("_", " ")
    return name.replace("_", " ")


def plain(text: str) -> str:
    """Defense ids inside a sentence -> words ('stopped by input_screen' -> 'stopped by input screen')."""
    for d in sorted(DEFENSES, key=len, reverse=True):  # longest first: no id is replaced partly
        text = text.replace(d, label(d))
    return text


def yes_no(value: bool | None) -> str:
    return "-" if value is None else "Yes" if value else "No"
