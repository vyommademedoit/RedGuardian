"""Minimal run explorer (Phase 2). Reads persisted data only.

    uv run streamlit run dashboard/app.py
"""

import json

import streamlit as st
from sqlalchemy import select

from harness import storage
from harness.models import Stage

st.set_page_config(page_title="RedGuardian", layout="wide")
st.title("RedGuardian — run explorer")

engine = storage.connect()
with engine.connect() as c:
    runs = [r._asdict() for r in c.execute(select(storage.runs).order_by(storage.runs.c.started_at.desc()))]
    evals = {r.run_id: r.result for r in c.execute(select(storage.evaluations))}

if not runs:
    st.info("No runs yet. Run: `uv run python scripts/run_experiment.py`")
    st.stop()


def stage_label(ev: dict | None) -> str:
    if not ev or ev.get("furthest_stage") is None:
        return "-"
    name = Stage(ev["furthest_stage"]).name.lower()
    # Never present a blocked attempt as a compromise (FR-10).
    return f"{name} (blocked)" if ev["unauthorized_blocked"] and not ev["unauthorized_executed"] else name


st.subheader("Runs")
st.dataframe([{
    "started": r["started_at"].strftime("%Y-%m-%d %H:%M:%S"), "scenario": r["attack_id"],
    "kind": r["kind"], "profile": r["defense_profile"], "status": r["status"],
    "attack success": evals.get(r["run_id"], {}).get("attack_success"),
    "furthest stage": stage_label(evals.get(r["run_id"])),
    "blocked by": ", ".join(evals.get(r["run_id"], {}).get("blocking_defenses", [])) or "-",
    "run_id": r["run_id"],
} for r in runs], hide_index=True, width="stretch")

labels = {r["run_id"]: f'{r["attack_id"]} · {r["defense_profile"]} · {r["started_at"]:%H:%M:%S} · {r["run_id"][:8]}'
          for r in runs}
run_id = st.selectbox("Inspect run", list(labels), format_func=labels.get)
run, ev = next(r for r in runs if r["run_id"] == run_id), evals.get(run_id)

cols = st.columns(4)
cols[0].metric("Status", run["status"])
cols[1].metric("Attack success", "n/a" if run["kind"] != "attack" else str(bool(ev and ev["attack_success"])))
cols[2].metric("Secret leaked", str(bool(ev and ev["secret_leaked"])))
cols[3].metric("Benign task ok", "n/a" if run["kind"] == "attack" else str(bool(ev and ev["task_completed"])))
# Own line, not a metric tile: a truncated tile could hide "(blocked)".
st.markdown(f"**Furthest stage:** {stage_label(ev)}  ·  **Blocked by:** "
            f"{', '.join(ev['blocking_defenses']) if ev and ev['blocking_defenses'] else '-'}")
if run["error"]:
    st.error(run["error"])

st.subheader("Timeline")
events = storage.SqlEventLogger(engine).events(run_id)
st.dataframe([{
    "seq": e.seq, "event": e.event_type.value, "stage": e.stage.name.lower() if e.stage else "",
    "source": f"{e.source_type.value}:{e.source_id}" if e.source_type else "",
    "destination": e.destination or "", "decision": e.decision.value if e.decision else "",
    "defense": e.defense_id or "", "reason": e.reason or "",
} for e in events], hide_index=True, width="stretch")

with st.expander("Raw event payloads (synthetic data)"):
    for e in events:
        st.caption(f"#{e.seq} {e.event_type.value}")
        st.code(json.dumps(e.payload, indent=2, default=str), language="json")  # code block: never rendered as HTML
