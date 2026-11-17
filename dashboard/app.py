"""RedGuardian dashboard (FR-10). Reads persisted data only; never runs the agent.

    uv run streamlit run dashboard/app.py
"""

import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from sqlalchemy import select

from harness import reporting, storage
from harness.attacks import load_library
from harness.models import EventType, Stage
from vocab import NEUTRAL, OBSERVED, PATTERN, SEVERITY, STAGE_HELP, WORSE, label, plain, yes_no

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["Overview", "Attack library", "Run explorer", "Comparison", "Ablation", "Evidence", "Export"]
STAGES = list(SEVERITY)  # none … executed
STATUS_STYLE = {"observed": (OBSERVED, "solid"), "blocked": (NEUTRAL, "dash"),
                "executed": (SEVERITY["executed"], "solid"), "answered": (NEUTRAL, "solid")}

st.set_page_config(page_title="RedGuardian", layout="wide", initial_sidebar_state="expanded")


# --------------------------------------------------------------------------- data access

try:
    engine = storage.connect()
except Exception as e:  # unreachable MySQL, locked or old SQLite file, ...
    st.title("RedGuardian")
    st.error(f"Cannot open the results database: {e}")
    st.caption("Set MYSQL_URL in .env, or remove it to use the local SQLite file .data/redguardian.db.")
    st.stop()

try:
    LIBRARY = load_library(ROOT / "attacks")
except Exception as e:  # an invalid scenario file should not take the whole dashboard down
    LIBRARY = {}
    st.sidebar.error(f"Attack library failed to load: {e}")


def stage_label(ev: dict | None) -> str:
    if not ev or ev.get("furthest_stage") is None:
        return "-"
    name = Stage(ev["furthest_stage"]).name.lower()
    # Never present a blocked attempt as a compromise (FR-10).
    return f"{name} (blocked)" if ev["unauthorized_blocked"] and not ev["unauthorized_executed"] else name


def surface(attack_id: str) -> str:
    return LIBRARY[attack_id][0].surface.value if attack_id in LIBRARY else "?"


def summary_rows(rows: list[dict]) -> list[dict]:
    return [{
        "started": r["started_at"].strftime("%Y-%m-%d %H:%M:%S"), "scenario": r["attack_id"], "surface": surface(r["attack_id"]),
        "kind": r["kind"], "profile": r["defense_profile"], "agent": r["model"] or r["adapter"], "seed": r["seed"],
        "status": r["status"], "outcome": reporting.outcome(r), "furthest stage": stage_label(r["ev"]),
        "blocked by": ", ".join((r["ev"] or {}).get("blocking_defenses", [])) or "-", "run_id": r["run_id"],
    } for r in rows]


def shown(rows: list[dict]) -> list[dict]:
    """summary_rows for display: plain profile names. Export keeps summary_rows' raw ids."""
    return [{**r, "profile": label(r["profile"]), "surface": label(r["surface"]), "outcome": plain(r["outcome"]), "blocked by": plain(r["blocked by"])}
            for r in summary_rows(rows)]


def stage_runs(profile: str, stage: str) -> list[dict]:
    """Valid attack runs of one profile whose furthest stage is ``stage`` (same rule as stage_distribution)."""
    return [r for r in reporting.measured(rows) if r["defense_profile"] == profile and r["kind"] == "attack" and r["ev"]
            and r["ev"]["valid"] and (Stage(r["ev"]["furthest_stage"]).name.lower() if r["ev"]["furthest_stage"] else "none") == stage]


def pick_from_chart() -> None:
    """Chart click -> the profile/stage selectboxes, so mouse and keyboard share one path."""
    pts = st.session_state["stages"].selection.points
    if pts:
        st.session_state["ovw_profile"], st.session_state["ovw_stage"] = pts[0]["x"], STAGES[pts[0]["curve_number"]]


def open_run(run_id: str) -> None:
    st.session_state["run_id"], st.session_state["view"] = run_id, "Run explorer"
    st.session_state.pop("runs", None)


def run_list(rows: list[dict], key: str) -> None:
    """The runs as a table; select a row, then open it (no second picker for the same runs)."""
    sel = st.dataframe(shown(rows), hide_index=True, width="stretch", key=key, on_select="rerun",
                       selection_mode="single-row").selection.rows
    sel = [i for i in sel if i < len(rows)]  # a selection left over from a longer list is no selection
    st.button("Open in run explorer", key=f"open_{key}", disabled=not sel, on_click=open_run,
              args=(rows[sel[0]]["run_id"],) if sel else None, help="Select a row, then open it.")


# --------------------------------------------------------------------------- sidebar: view + scope

st.sidebar.title("RedGuardian")
view = st.sidebar.radio("View", PAGES, key="view")
exps = reporting.experiments(engine)
scope_labels = {"": "All runs"} | {x["experiment_id"]: f'{x["created_at"]:%m-%d %H:%M} · {x["name"]} · {x["runs"]} runs'
                                   for x in exps if x["runs"]}
experiment_id = st.sidebar.selectbox("Experiment", list(scope_labels), format_func=scope_labels.get, key="experiment",
                                     index=1 if len(scope_labels) > 1 else 0)  # newest experiment by default
with st.spinner("Loading runs…"):
    rows = reporting.run_rows(engine, experiment_id or None)
if experiment_id:
    cfg = next(x for x in exps if x["experiment_id"] == experiment_id)["config"]
    st.sidebar.caption(f"agent: {cfg.get('agent')} {cfg.get('model') or ''} · seeds: {cfg.get('seed')}"
                       f"×{cfg.get('repeats', 1)} · embedder: {cfg.get('embedder')}")

st.title(view)  # the sidebar already carries the product name
if not rows and view != "Attack library":
    st.info("No runs in this scope yet. Run: `uv run python scripts/run_experiment.py` (add `--agent ollama` for the local model).")
    st.stop()


# --------------------------------------------------------------------------- pages

def page_overview() -> None:
    by = reporting.metrics_by_profile(rows)
    valid = sum(r["status"] == "completed" for r in rows)
    c = st.columns(4)
    c[0].metric("Runs", len(rows))
    c[1].metric("Valid", valid)
    c[2].metric("Invalid (excluded)", len(rows) - valid)
    c[3].metric("Profiles", len(by))
    base, dfd = by.get("baseline"), by.get("defended")
    if base and dfd:
        st.subheader("Baseline vs defended")
        names = ["attack_success_rate", "injection_success_rate", "secret_leakage_rate", "unauthorized_tool_attempt_rate",
                 "unauthorized_tool_execution_rate", "false_refusal_rate", "benign_task_utility"]
        cols = st.columns(4) + st.columns(4)  # two rows: values stay readable in narrow windows
        for col, n in zip(cols, names):
            b, d = base[n], dfd[n]
            diff = None if b.value is None or d.value is None else d.value - b.value
            col.metric(label(n), reporting.fmt(d),
                       None if diff is None else f"{diff * 100:+.0f} pp" if diff else "no change", delta_arrow="off",
                       delta_color="off" if not diff else "inverse" if n in reporting.LOWER_IS_BETTER else "normal",
                       help=f"defended {reporting.fmt(d)} vs baseline {reporting.fmt(b)}")
        st.caption("Tiles show the defended value with its change from baseline in percentage points (pp). Read "
                   "attack success next to normal tasks done and refused: blocking everything is not a defense.")
    else:
        st.caption("Run both `baseline` and `defended` in one experiment for the side-by-side summary.")
    st.subheader("Furthest propagation stage (valid attack runs)")
    dist = reporting.stage_distribution(rows)
    if dist:
        profiles = [p for p in by if p in dist]
        fig = go.Figure([go.Bar(name=s, x=profiles, y=[dist[p][s] for p in profiles], marker_color=SEVERITY[s],
                                marker_pattern_shape=PATTERN[s], marker_pattern_fillmode="overlay") for s in STAGES])
        fig.update_layout(barmode="stack", height=380, xaxis_title="profile", yaxis_title="attack runs", legend_title="stage",
                          xaxis={"tickvals": profiles, "ticktext": [label(p) for p in profiles]})
        st.plotly_chart(fig, width="stretch", key="stages", on_select=pick_from_chart, selection_mode="points")
        st.caption("'executed' = an action *request* carried the canary; whether it ran is in the outcome column, never implied "
                   "here. Click a bar segment, or choose below, to list its runs.")
        if st.session_state.get("ovw_profile") not in profiles:
            st.session_state["ovw_profile"] = profiles[0]
        st.session_state.setdefault("ovw_stage", "executed")  # worst case first
        c1, c2 = st.columns(2)
        p = c1.selectbox("Profile", profiles, format_func=label, key="ovw_profile")
        s = c2.selectbox("Furthest stage", STAGES, key="ovw_stage", help=STAGE_HELP)
        hits = stage_runs(p, s)
        st.markdown(f"**{label(p)} · furthest stage {s}:** {len(hits)} runs")
        if hits:
            run_list(hits, "stage_runs")
    st.caption("Every metric for every profile is on the Ablation view.")


def page_library() -> None:
    if not LIBRARY:
        st.warning("No scenarios loaded.")
        return
    lib = [{"id": a, "name": s.name, "kind": s.kind, "surface": s.surface.value, "category": s.category,
            "objective": s.objective.value if s.objective else "-", "severity": s.severity.value if s.severity else "-",
            "status": "enabled" if s.enabled else "disabled", "tags": ", ".join(s.tags), "version": s.version}
           for a, (s, _) in LIBRARY.items()]
    df = pd.DataFrame(lib)
    f = st.columns(4)
    picks = {c: f[i].multiselect(c, sorted(df[c].unique()), format_func=label, key=f"lib_{c}")
             for i, c in enumerate(["kind", "surface", "category", "severity"])}
    for c, v in picks.items():
        if v:
            df = df[df[c].isin(v)]  # filter on raw values; only the display copy below is labelled
    st.dataframe(df.assign(**{c: df[c].map(label) for c in ("surface", "category", "objective")}), hide_index=True,
                 width="stretch")
    if df.empty:
        st.info("No scenario matches these filters.")
        return
    aid = st.selectbox("Inspect scenario", list(df["id"]), key="lib_pick")
    scenario, digest = LIBRARY[aid]
    st.caption(f"sha256 {digest[:16]}… · expected safe behaviour: {scenario.expected_safe_behavior}")
    st.code(f"uv run python scripts/run_experiment.py --attacks {aid} --profiles baseline defended", language="bash")
    st.caption("Launching stays in the CLI so the dashboard never runs the agent (NFR-03).")
    mine = [r for r in rows if r["attack_id"] == aid]
    if mine:
        run_list(mine, "lib")
    else:
        st.info("No runs of this scenario in the current scope.")
    with st.expander("Definition (JSON)"):
        st.json(scenario.model_dump(mode="json"))


def draw_path(events) -> None:
    g = reporting.attack_path(events)
    if not g.number_of_nodes():
        st.info("No boundary crossings recorded for this run.")
        return
    cols: dict[int, list[str]] = {}
    for n, d in g.nodes(data=True):
        cols.setdefault(d["col"], []).append(n)
    pos = {n: (c, -i) for c, ns in cols.items() for i, n in enumerate(sorted(ns))}
    fig = go.Figure()
    for u, v, d in g.edges(data=True):
        color, dash = STATUS_STYLE[d["status"]]
        (x0, y0), (x1, y1) = pos[u], pos[v]
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", showlegend=False, hoverinfo="skip",
                                 line={"color": color, "dash": dash, "width": 5 if d["marker"] else 2}))
        info = f"{d['status']}{' · canary' if d['marker'] else ''}{' · ' + d['defense'] if d.get('defense') else ''}"
        fig.add_trace(go.Scatter(x=[(x0 + x1) / 2], y=[(y0 + y1) / 2], mode="markers+text", text=[d["status"]],
                                 textposition="top center", marker={"color": color, "size": 9}, showlegend=False,
                                 hovertext=[f"{u} → {v}<br>{info}<br>{d.get('detail') or ''}"], hoverinfo="text"))
    kinds = {"source": "square", "agent": "circle", "store": "diamond", "action": "triangle-up"}  # shape, not colour
    for kind, symbol in kinds.items():
        ns = [n for n, d in g.nodes(data=True) if d["kind"] == kind]
        if ns:
            fig.add_trace(go.Scatter(x=[pos[n][0] for n in ns], y=[pos[n][1] for n in ns], mode="markers+text", name=kind,
                                     text=[g.nodes[n]["label"] for n in ns], textposition="bottom center",
                                     marker={"size": 22, "color": NEUTRAL, "symbol": symbol}))
    for status, (color, dash) in STATUS_STYLE.items():  # legend entries for edge styles
        fig.add_trace(go.Scatter(x=[None], y=[None], mode="lines", name=f"edge: {status}", line={"color": color, "dash": dash}))
    fig.update_layout(height=420, xaxis={"visible": False}, yaxis={"visible": False}, margin={"l": 10, "r": 10, "t": 10, "b": 10},
                      legend={"orientation": "h"})
    st.plotly_chart(fig, width="stretch")
    st.caption("Thick edges carried the attack canary. Light red = an action ran in the sandbox · blue = content reached "
               "the next hop · grey dashed = a defense stopped it there · grey solid = the agent answered the user. "
               "Hover an edge midpoint for provenance and the policy reason.")


def page_explorer() -> None:
    st.subheader("Runs")
    picked = st.dataframe(shown(rows), hide_index=True, width="stretch", key="runs", on_select="rerun",
                          selection_mode="single-row").selection.rows
    picked = [i for i in picked if i < len(rows)]  # a selection left over from a longer list (other scope) is no selection
    ids = [r["run_id"] for r in rows]
    want = st.session_state.get("run_id")
    run_id = ids[picked[0]] if picked else want if want in ids else ids[0]
    st.session_state["run_id"] = run_id
    run = rows[ids.index(run_id)]
    st.caption(f"Inspecting **{run['attack_id']} · {label(run['defense_profile'])} · {run['started_at']:%H:%M:%S} · "
               f"{run_id[:8]}**. Select a row above to switch.")
    ev = run["ev"]
    cols = st.columns(4)
    cols[0].metric("Status", run["status"])
    cols[1].metric("Attack succeeded", "n/a" if run["kind"] != "attack" else yes_no(ev and ev["attack_success"]))
    cols[2].metric("Secret leaked", yes_no(ev and ev["secret_leaked"]))
    cols[3].metric("Normal task done", "n/a" if run["kind"] == "attack" else yes_no(ev and ev["task_completed"]))
    # Own line, not a metric tile: a truncated tile could hide "(blocked)".
    st.markdown(f"**Furthest stage:** {stage_label(ev)}  ·  **Blocked by:** "
                f"{', '.join(map(label, ev['blocking_defenses'])) if ev and ev['blocking_defenses'] else '-'}  ·  "
                f"**Outcome:** {plain(reporting.outcome(run))}")
    if run["error"]:
        st.error(run["error"])
    if run["status"] == "running":
        st.info("This run is still in progress; its evaluation appears when it finishes (reload the page).")
    elif not ev:
        st.warning("This run has no stored evaluation (it may have crashed before evaluation).")
    if run.get("setup"):
        st.info("Recovery setup run: it poisoned memory for a later recovery check and is excluded from every metric.")
    with st.spinner("Loading events…"):
        events = storage.SqlEventLogger(engine).events(run_id)

    st.subheader("Attack path")
    draw_path(events)

    st.subheader("Timeline")
    st.dataframe([{
        "seq": e.seq, "session": e.payload.get("session_id", ""), "event": label(e.event_type.value),
        "stage": e.stage.name.lower() if e.stage else "",
        "source": reporting.source(e),
        "destination": e.destination or "", "decision": e.decision.value if e.decision else "",
        "defense": label(e.defense_id) if e.defense_id else "", "reason": e.reason or "",
    } for e in events], hide_index=True, width="stretch")

    retrievals = [e for e in events if e.event_type.value == "retrieval"]
    if retrievals:
        st.subheader("Retrieved sources")
        chunk_decisions = {e.payload["chunk_id"]: e for e in events if e.event_type.value == "policy_decision" and "chunk_id" in e.payload}
        with engine.connect() as c:  # ground truth is for the reviewer only; defenses never see it
            poisoned = {d.doc_id for d in c.execute(select(storage.documents).where(
                storage.documents.c.corpus_id == run_id, storage.documents.c.poisoned))}
        st.dataframe([{
            "rank": ch["rank"], "chunk": ch["chunk_id"], "document": ch["doc_id"], "score": ch["score"],
            "trust": ch["trust"], "source": ch["source"],
            "policy": chunk_decisions[ch["chunk_id"]].decision.value if ch["chunk_id"] in chunk_decisions else "-",
            "defense": chunk_decisions[ch["chunk_id"]].defense_id if ch["chunk_id"] in chunk_decisions else "-",
            "poisoned (ground truth)": yes_no(ch["doc_id"] in poisoned),
        } for e in retrievals for ch in e.payload["chunks"]], hide_index=True, width="stretch")

    path = []  # memory writes/reads and relay messages, incl. writes a defense stopped at the boundary
    for e in events:
        p, t = e.payload, e.event_type.value
        if t in ("memory_write", "relay_message"):
            path.append({"seq": e.seq, "session": p.get("session_id"), "operation": t, "item": e.source_id,
                         "from → to": f'{p["sender"]} → {p["recipient"]}', "trust": p["trust"],
                         "origin": ", ".join(p["origin"]) or "-", "carries marker": yes_no(p["contains_canary"]), "policy": "allow"})
        elif t == "memory_read":
            path += [{"seq": e.seq, "session": p.get("session_id"), "operation": t, "item": ch["chunk_id"],
                      "from → to": "memory → agent", "trust": ch["trust"], "origin": ch["source"], "carries marker": "-",
                      "policy": next((d.decision.value for d in events if d.event_type.value == "policy_decision"
                                      and d.payload.get("chunk_id") == ch["chunk_id"] and d.seq > e.seq), "-")}
                     for ch in p["chunks"]]
        elif t == "policy_decision" and p.get("point") in ("memory_write", "relay") and e.decision.value != "allow":
            path.append({"seq": e.seq, "session": p.get("session_id"), "operation": f'{p["point"]} (stopped)',
                         "item": "-", "from → to": e.destination, "trust": "-", "origin": "-", "carries marker": "-",
                         "policy": f"{e.decision.value} by {e.defense_id}"})
    if path:
        st.subheader("Memory and relay path")
        st.dataframe(path, hide_index=True, width="stretch")

    with st.expander("Raw event payloads (synthetic data)"):
        for e in events:
            st.caption(f"#{e.seq} {e.event_type.value}")
            st.code(json.dumps(e.payload, indent=2, default=str), language="json")  # code block: never rendered as HTML


def page_comparison() -> None:
    by = reporting.metrics_by_profile(rows)
    profiles = list(by)
    if len(profiles) < 2:
        st.info("This scope has a single profile; run at least two (e.g. baseline and defended) to compare.")
        return
    c1, c2 = st.columns(2)
    a = c1.selectbox("A (reference)", profiles, format_func=label,
                     index=profiles.index("baseline") if "baseline" in profiles else 0)
    b = c2.selectbox("B", profiles, format_func=label, index=profiles.index("defended") if "defended" in profiles else 1)
    table = reporting.compare(by[a], by[b])
    df = pd.DataFrame(table).rename(columns={"A": label(a), "B": label(b)})
    df["metric"] = df["metric"].map(label)
    st.dataframe(df.style.apply(lambda r: [f"background-color: {WORSE}40" if r["worse"] else ""] * len(r), axis=1),
                 hide_index=True, width="stretch", column_order=[c for c in df.columns if c != "worse"])
    st.caption("Shaded rows changed in the wrong direction. Changes are in percentage points (pp).")
    if next(t for t in table if t["metric"] == "benign_task_utility")["worse"]:
        st.warning(f"Normal tasks done drops from {label(a)} to {label(b)}: check the refused row above before calling "
                   f"{label(b)} better.")
    if not experiment_id:
        st.caption("Scope is 'All runs': pick one experiment in the sidebar for matched conditions (same scenarios, seeds, agent).")
    st.subheader("Per scenario")
    m = reporting.scenario_matrix(rows)
    st.dataframe(pd.DataFrame([{"scenario": s, "surface": surface(s), label(a): plain(v.get(a, "-")), label(b): plain(v.get(b, "-"))} for s, v in sorted(m.items())]),
                 hide_index=True, width="stretch")
    st.subheader("Runs of these two profiles")
    run_list([r for r in rows if r["defense_profile"] in (a, b)], "cmp")


def outcome_bg(cell: str) -> str:
    """Severity shade for a scenario_matrix cell (repeats are joined, so the worst label present wins)."""
    worst = ("executed" if "LEAKED" in cell or "SUCCEEDED" in cell else "persisted" if "unauthorized action ran" in cell
             else None if cell == "-" else "none")
    return f"background-color: {SEVERITY[worst]}66" if worst else ""


def page_ablation() -> None:
    by = reporting.metrics_by_profile(rows)
    st.subheader("Metrics by profile")
    st.dataframe(pd.DataFrame([{"profile": label(p), **{label(n): reporting.fmt(m.get(n)) for n in reporting.HEADLINE}}
                               for p, m in by.items()]), hide_index=True, width="stretch")
    m = reporting.scenario_matrix(rows)
    attacks = sorted(a for a in m if surface(a) != "?" and LIBRARY[a][0].kind == "attack") or sorted(m)
    profiles = list(by)
    st.subheader("Attack outcome per profile, and which layer stopped it")
    df = pd.DataFrame([{"scenario": a, **{label(p): plain(m[a].get(p, "-")) for p in profiles}} for a in attacks])
    st.dataframe(df.style.map(outcome_bg, subset=[label(p) for p in profiles]), hide_index=True, width="stretch")
    st.caption("Grey = stopped or no effect · orange = an unauthorized action ran without leaking · "
               "pink = objective achieved.")
    layers = reporting.sufficient_layers(rows)
    if any(layers.values()):
        st.subheader("Single layers that suffice on their own")
        st.dataframe(pd.DataFrame([{"scenario": a, "stopped by (alone)": ", ".join(map(label, d)) or "none"} for a, d in layers.items()]),
                     hide_index=True, width="stretch")


def page_evidence() -> None:
    scoped = rows if experiment_id else rows[:200]
    if not experiment_id and len(rows) > 200:
        st.caption("Showing the 200 newest runs; choose an experiment in the sidebar to search all of its runs.")
    f = st.columns(5)
    attacks = f[0].multiselect("attack", sorted({r["attack_id"] for r in scoped}))
    surfaces = f[1].multiselect("surface", sorted({surface(r["attack_id"]) for r in scoped}), format_func=label)
    profiles = f[2].multiselect("profile", sorted({r["defense_profile"] for r in scoped}), format_func=label)
    types = f[3].multiselect("event", sorted(t.value for t in EventType), format_func=label)
    stages = f[4].multiselect("stage", [s.name.lower() for s in Stage],
                              help=STAGE_HELP)
    run_ids = st.multiselect("run", [r["run_id"] for r in scoped], format_func=lambda x: x[:8])
    text = st.text_input("search payload / reason / source (case-insensitive)")
    keep = [r for r in scoped if (not attacks or r["attack_id"] in attacks) and (not profiles or r["defense_profile"] in profiles)
            and (not surfaces or surface(r["attack_id"]) in surfaces) and (not run_ids or r["run_id"] in run_ids)]
    meta = {r["run_id"]: r for r in keep}
    events = reporting.events_for(engine, list(meta))
    out = []
    for e in events:
        if types and e.event_type.value not in types or stages and (not e.stage or e.stage.name.lower() not in stages):
            continue
        blob = (json.dumps(e.payload, default=str) + (e.reason or "") + (e.source_id or "") + (e.destination or "")
                + (e.defense_id or "")).lower()
        t = text.lower()
        if t and t not in blob and t.replace(" ", "_") not in blob:  # "output guard" finds output_guard too
            continue
        out.append(e)
    st.caption(f"{len(out)} events from {len(meta)} runs")
    if not out:
        st.info("No events match these filters.")
        return
    st.dataframe([{"run": e.run_id[:8], "attack": e.attack_id, "profile": label(meta[e.run_id]["defense_profile"]), "seq": e.seq,
                   "event": label(e.event_type.value), "stage": e.stage.name.lower() if e.stage else "",
                   "source": reporting.source(e), "destination": e.destination or "",
                   "decision": e.decision.value if e.decision else "", "defense": label(e.defense_id) if e.defense_id else "", "reason": e.reason or ""}
                  for e in out[:2000]], hide_index=True, width="stretch")
    pick = st.selectbox("Inspect payload", range(min(len(out), 2000)),
                        format_func=lambda i: f"{out[i].run_id[:8]} #{out[i].seq} {label(out[i].event_type.value)}")
    st.code(json.dumps(out[pick].payload, indent=2, default=str), language="json")  # never rendered as HTML
    st.button("Open this run in the run explorer", on_click=open_run, args=(out[pick].run_id,))


def page_export() -> None:
    summaries = summary_rows(rows)
    by = reporting.metrics_by_profile(rows)
    metrics = [{"profile": p, "metric": n, "numerator": x.numerator, "denominator": x.denominator, "value": x.value}
               for p, ms in by.items() for n, x in ms.items()]
    name = experiment_id[:8] if experiment_id else "all-runs"
    st.subheader("Run summaries")
    c = st.columns(2)
    c[0].download_button("Runs CSV", pd.DataFrame(summaries).to_csv(index=False), f"runs_{name}.csv", "text/csv")
    c[1].download_button("Runs JSON", json.dumps([{**r, "evaluation": x["ev"]} for r, x in zip(summaries, rows)], indent=2, default=str),
                         f"runs_{name}.json", "application/json")
    st.subheader("Metrics (per profile, raw counts)")
    c = st.columns(2)
    c[0].download_button("Metrics CSV", pd.DataFrame(metrics).to_csv(index=False), f"metrics_{name}.csv", "text/csv")
    c[1].download_button("Metrics JSON", json.dumps(metrics, indent=2), f"metrics_{name}.json", "application/json")
    st.subheader("Markdown report")
    if not experiment_id:
        st.info("Choose an experiment in the sidebar: reports describe one experiment's matched conditions.")
        return
    report = reporting.markdown_report(engine, experiment_id, LIBRARY)
    st.download_button("Download report.md", report, f"report_{name}.md", "text/markdown")
    with st.expander("Preview", expanded=True):
        st.markdown(report)


{"Overview": page_overview, "Attack library": page_library, "Run explorer": page_explorer, "Comparison": page_comparison,
 "Ablation": page_ablation, "Evidence": page_evidence, "Export": page_export}[view]()
