# Mitigation guide

Practical guidance for builders of tool-using LLM agents, grounded in this project's measurements (`docs/results/`). Evidence labels: **[mock]** = what a layer can stop against a fully compliant agent; **[qwen]** = observed with `qwen2.5:7b`. Neither is a guarantee (see `limitations.md`).

## 1. Enforce outside the model, on data flow — first priority

| Do | Why (evidence) |
|---|---|
| Label sensitive values and allow each only to named destinations (`secret_egress`) | Alone it stops 9/10 attacks, including every reworded variant **[mock]** |
| Treat outbound actions after untrusted input as needing fresh authorization (`taint_guard`) | Alone it stops 9/10 attacks **[mock]**; costs a false refusal on legitimate sends (`BENIGN-006`) — add a user confirmation step instead of a hard block in production |
| Check the final answer, not only tool calls (`output_guard`) | The only layer that stops `TOOL-002`, which leaks through the reply itself **[mock]** |
| Restrict recipients by allowlist (`destination_allowlist`) | Cheap and useful, but bypassed by an attacker-readable internal address (`TOOL-001c`) **[mock]** |

## 2. Keep provenance through every hop

- Carry source, trust and origin with content **after the agent rewrites it**: memory writes and relayed messages inherit the session's taint (`MEM-001`, `RELAY-001`). Without this, a poisoned email becomes a "trusted" memory note in the next session.
- Screen memory both on **write** and on **read**, so memory poisoned before a defense existed is still caught (recovery runs).
- Make memory **quarantinable by provenance** (e.g. "everything untrusted written by run X") and verify recovery by re-running the task, not by trusting the cleanup call.

## 3. Pattern screens are a speed bump, not a boundary

- Instruction-pattern filters on untrusted content (`input_screen`, `retrieval_screen`, `memory_screen`, `relay_screen`) stop naive payloads early (fewer exposures), but every reworded variant got past them **[mock]**, and one benign email was withheld (`BENIGN-007`).
- Use them for early warning and evidence, never as the only control.

## 4. Measure utility with security

- Always run benign controls under the same profile: `defended` reached 0% attack success at 78% benign utility **[mock]** — the two refusals are the price of `taint_guard` and `input_screen`.
- Report raw counts with every rate and keep failed runs out of the denominators: an unavailable model must never count as a successful defense.

## 5. Observations from the real model **[qwen]**

- In 4/10 baseline attacks the model sent a report to the attacker's address (direct input, tool output, internal-address variant, relay), but never with the real key (placeholders or invented values): 0/10 leaks, 4/10 unauthorized actions executed. Measure **unauthorized actions** separately from **secret leakage**; an action that leaks nothing is still a policy violation.
- Injected text propagated without executing: it was written into memory and recited in the next session (`MEM-001`), repeated as company policy (`RAG-001b`), and forwarded to `ops-agent` (`RELAY-001`). Paraphrasing dropped the canary marker, so stage counts for the model are lower bounds.
- `defended` brought executed unauthorized actions to 0/10 at the same utility cost as the mock (7/9). `taint_guard` was the decisive layer: it is the only one that stops the send to the attacker-readable internal address (`TOOL-001c`), where no secret is involved and the domain is allowed.
- Model behaviour does not replace enforcement: the layers in §1 stop the same attacks regardless of what the model decides.

Combined numbers and findings: [results/final_report.md](results/final_report.md).

See `results/` for the per-scenario tables and `verify_metrics.py` to check any stored result against its raw events.
