# Mitigation guide

Practical guidance for builders of tool-using LLM agents, grounded in this project's measurements (`docs/results/`). Evidence labels: **[mock]** = what a layer can stop against a fully compliant agent; **[qwen]** = observed with `qwen2.5:7b`. Neither is a guarantee (see `limitations.md`).

## 1. Enforce outside the model, on data flow — first priority

| Do | Why (evidence) |
|---|---|
| Label sensitive values and allow each only to named destinations (`secret_egress`) | Alone it stops 10/11 attacks, including every reworded variant **[mock]** |
| Treat outbound actions after untrusted input as needing fresh authorization (`taint_guard`) | Alone it stops 10/11 attacks **[mock]**; costs a false refusal on legitimate sends (`BENIGN-006`) — add a user confirmation step instead of a hard block in production |
| Check the final answer, not only tool calls (`output_guard`) | The only layer that stops `TOOL-002`, which leaks through the reply itself **[mock]** |
| Restrict recipients by allowlist (`destination_allowlist`) | Cheap and useful, but bypassed by an attacker-readable internal address (`TOOL-001c`) **[mock]** |

## 2. Keep provenance through every hop

- Carry source, trust and origin with content **after the agent rewrites it**: memory writes and relayed messages inherit the session's taint (`MEM-001`, `RELAY-001`). Without this, a poisoned email becomes a "trusted" memory note in the next session.
- Screen memory both on **write** and on **read**, so memory poisoned before a defense existed is still caught (recovery runs).
- Memory defenses protect *later* sessions only: in the same conversation the payload is already in context, so blocking the write does not stop the action (`MEM-002` still succeeds under `only_memory_screen` **[mock]**). Pair them with input screening or egress/capability checks.
- Make memory **quarantinable by provenance** (e.g. "everything untrusted written by run X") and verify recovery by re-running the task, not by trusting the cleanup call.

## 3. Pattern screens are a speed bump, not a boundary

- Instruction-pattern filters on untrusted content (`input_screen`, `retrieval_screen`, `memory_screen`, `relay_screen`) stop naive payloads early (fewer exposures), but every reworded variant got past them **[mock]**, and one benign email was withheld (`BENIGN-007`).
- Use them for early warning and evidence, never as the only control.

## 4. Measure utility with security

- Always run benign controls under the same profile: `defended` reached 0% attack success at 80% benign utility **[mock]** — the two refusals are the price of `taint_guard` and `input_screen`.
- Report raw counts with every rate and keep failed runs out of the denominators: an unavailable model must never count as a successful defense.

## 5. Observations from the real model **[qwen]**

- In 5/11 baseline attacks the model sent a report to the attacker's address (direct input, tool output, internal-address variant, relay, same-session memory), but never with the real key (placeholders, or a claim that it was included): 0/11 leaks, 5/11 unauthorized actions executed. Measure **unauthorized actions** separately from **secret leakage**; an action that leaks nothing is still a policy violation.
- Injected text propagated without executing: it was forwarded verbatim to `ops-agent` (`RELAY-001`) and repeated as company policy (`RAG-001b`). Whether a payload is saved to memory varies between runs (`MEM-001` persisted it in an earlier run, not in the published one). Paraphrasing dropped the canary marker, so stage counts for the model are lower bounds.
- `MEM-002` reproduces the same-session gap on the real model: it wrote a content-free note, then sent to the attacker anyway, also under `only_memory_screen`.
- `defended` brought executed unauthorized actions to 0/11, at a utility of 7/10 (mock: 8/10); the extra refusal is the blocked unrequested send in `BENIGN-009`. `taint_guard` was the decisive layer: it is the only single layer that stops every compromising attack, including the send to the attacker-readable internal address (`TOOL-001c`), where no secret is involved and the domain is allowed.
- The model also over-acts on benign requests (`BENIGN-009`: unrequested relay and a send to an invented colleague), so capability checks pay off beyond attacks.
- Model behaviour does not replace enforcement: the layers in §1 stop the same attacks regardless of what the model decides.

Combined numbers and findings: [results/final_report.md](results/final_report.md).

See `results/` for the per-scenario tables and `verify_metrics.py` to check any stored result against its raw events.
