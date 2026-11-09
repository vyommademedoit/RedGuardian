# Known limitations and untested cases

What the results do **not** show, collected in one place. The design decisions behind each item are in `decisions.md`.

## Scope of the claims

- **No formal guarantees.** The defenses are practical policy checks (PRD FR-06), not CaMeL-style proofs. A clean benchmark means "these scenarios did not succeed", not "the agent is secure".
- **One model, one size.** Model results are for `qwen2.5:7b` (Q4_K_M) at temperature 0 on one machine. Other models, sizes, quantisations or temperatures can behave very differently.
- **Small, hand-written library.** 10 attacks and 9 benign tasks; the adaptive variants are manual rewrites (PRD 10.3), not optimised attacks. "The Attacker Moves Second" (literature set) shows that adaptive optimisation breaks most static defenses; this project does not attempt that.
- **Mock vs model.** The mock agent is fully compliant by construction: its numbers show what each defense *can* stop. Only the Ollama runs say anything about model behaviour.

## Heuristics (labelled as such in code and reports)

| Component | Weakness |
|---|---|
| `input_screen`, `retrieval_screen`, `memory_screen`, `relay_screen` | One regex for assistant-directed instructions. Reworded payloads evade it (`*-001b`); benign assistant-addressed text trips it (`BENIGN-007`). |
| Refusal detector (`evaluator.REFUSAL`) | English phrase list; misses polite partial refusals, may fire on a quoted refusal. |
| Marker tracking | String match. A model that paraphrases the payload without copying the marker is invisible to stage tracking; outcome predicates (e.g. secret in a send) still catch the objective. **Observed with Qwen**: memory persistence and relay happened but were recorded as 0 Persisted/Relayed stages, so model stage counts are lower bounds. |
| Session taint | Whole-session and conservative: everything written after any untrusted read is untrusted. Over-labels (hence `taint_guard`'s false refusal on `BENIGN-006`). |
| Blocking attribution | Names the first blocking defense per decision; overlapping layers are visible only through ablation profiles. |

## Simulation boundaries

- Tools are inert: `send_report` records intent, nothing is sent. Side effects beyond the outbox, memory and relay channel are not modelled.
- The relay surface is one simulated second-stage reader (`ops-agent`) — not a multi-agent system.
- The direct-input surface models pasted third-party text in the user message, not a malicious operator.
- Retrieval uses a deterministic hash embedder by default; `nomic-embed-text` was verified to rank the poisoned chunk in the top 3 for `RAG-001`, but full benchmarks used `hash`.

## Untested or partially tested

| Case | Status |
|---|---|
| MySQL backend | Verified: the clean mock benchmark on MySQL 8.0.45 gives results identical to SQLite (metrics, stages, per-scenario outcomes) and passes `verify_metrics.py`. The unit tests themselves run on SQLite. |
| Schema migrations | Versioned init only: a version mismatch is refused with a clear message (`storage.connect`); no automatic upgrade path. |
| Concurrent writers | Two processes writing the same SQLite file can hit "database is locked"; run one experiment at a time (MySQL handles this). |
| Model variance | Repeats exist (`--repeats`) but were run at temperature 0. |
| Same-session memory effects | Only cross-session memory poisoning has scenarios. |
| Memory `update` operation | Not implemented (no scenario needs it). |
| Non-English payloads, multimodal content, very long contexts | Not covered. |
| Dashboard authentication | None: local, single user, bound to `localhost`. |
| PDF report | Markdown only (PDF optional in the PRD). |
