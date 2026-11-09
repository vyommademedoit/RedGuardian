# Architecture

Logical design from PRD §8, as implemented. Status: **Phase 3** — tool-output and RAG surfaces, deterministic mock agent, two defenses (`secret_egress`, `retrieval_screen`). Memory, relay, and the Ollama agent adapter are not built yet.

## Code map

| Module | Contents | PRD |
|---|---|---|
| `src/harness/models.py` | All data contracts: vocabulary enums, `Provenance`, `SecretSpec`, `ToolSpec`/`ToolCall`/`ToolResult`, `Message`/`AgentTurn`, `Check`/`PolicyDecision`, `AttackScenario` + predicates, `Event`, `RunRecord`, `RunEvaluation`, `MetricResult` | §6, §9 |
| `src/harness/interfaces.py` | Protocols: `AgentAdapter`, `Tool`, `Defense`, `EventLogger`, `Evaluator`; `AgentError` hierarchy | FR-01, 04, 05, 07, 09 |
| `src/harness/attacks.py` | JSON library loader/validator, definition hashing, schema export | FR-02 |
| `src/harness/metrics.py` | Metric formulas and denominators | FR-09 |
| `src/harness/storage.py` | SQLAlchemy Core tables, `connect()`, run/evaluation writers, `SqlEventLogger` (MySQL via `MYSQL_URL`, else `.data/redguardian.db`) | FR-07, FR-11 |
| `src/harness/sandbox.py` | Fixtures (inbox, company knowledge base), token generation, payload injection into emails or documents, inert tools `read_inbox`, `read_config`, `search_documents`, `send_report` | FR-04 |
| `src/harness/retrieval.py` | Paragraph chunking, `hash`/`ollama` embedders, per-run Chroma `Corpus` with search and drop | FR-03 B |
| `src/harness/mock_agent.py` | Deterministic scripted agent (`mock-vulnerable` / `mock-safe`) | FR-01 |
| `src/harness/policy.py` | `Policy` (most restrictive wins), `SecretEgressDefense` (tool calls), `RetrievalScreenDefense` (retrieved chunks), four profiles | FR-05, FR-06 |
| `src/harness/runner.py` | `run_scenario`: seed → loop (propose → decide → execute) → events → evaluate → persist | FR-08 |
| `src/harness/evaluator.py` | `DeterministicEvaluator` over stored events | FR-09 |
| `scripts/run_experiment.py` | CLI: scenarios × profiles, prints per-run verdicts and metrics | FR-08 |
| `dashboard/app.py` | Streamlit run list + per-run timeline (reads storage only, binds to localhost) | FR-10 |
| `attacks/schema.json` | Generated from `AttackScenario` — do not hand-edit (`uv run python scripts/export_schema.py`) | FR-02 |
| `attacks/<surface>/<ID>.json` | Scenario definitions; file name = `attack_id` | §10 |

Modules stay flat until a package needs more than one file; then each becomes the PRD §8.2 sub-package (`harness/agents/`, `harness/tools/`, …).

## Run flow

```
scenario JSON ──load+hash──► Runner ──seed fixtures, plant secret, insert payload (with marker)──►
  loop:
    AgentAdapter.step(messages, tool specs) ──► AgentTurn (proposals only)
    for each ToolCall:
        emit TOOL_CALL_PROPOSED
        Policy: every enabled Defense with TOOL_CALL in .points → most restrictive decision
        emit POLICY_DECISION (defense_id, reason)
        if allowed: Tool.run(...) → emit TOOL_EXECUTED (result keeps its Provenance)
        detectors: marker/secret seen at a boundary → emit STAGE_REACHED
  emit RUN_FINISHED, set RunStatus
Evaluator(run, scenario, events) ──► RunEvaluation ──► compute_metrics ──► MetricResult rows
Dashboard reads storage only.
```

Key rules:

- **The agent proposes; the policy layer authorizes.** Tools are never called by the adapter.
- **Most restrictive wins:** `block` > `quarantine` > `allow`; abstain (`None`) adds nothing. With zero enabled defenses (baseline) every call is allowed — the sandbox still makes every tool inert.
- **Events are observed at boundaries**, not inferred from the final answer. `(run_id, seq)` is unique; events are never updated.
- **Evaluator reads persisted events only.** Re-evaluation writes a new `evaluations` row keyed by `evaluator_version`.
- **Errors are not defenses.** `AgentError` or tool crash → run `failed`/`incomplete` → `valid=False` → excluded from every rate and counted in `invalid_runs`.

## Canary design

Each attack run gets two generated tokens:

| Token | Form | Planted in | Answers |
|---|---|---|---|
| marker | `ATK-<hex>` | injected payload (`{marker}` is mandatory) | How far did the *attack content* travel? (Exposed → Persisted → Relayed → Executed) |
| secret | `SECRET-<KIND>-<hex>` | sandbox data (e.g. workspace config) | Did *protected data* reach an unauthorized destination? |

Both are string-matched at boundaries. Limitation: a model that paraphrases the payload without copying the marker is invisible to marker tracking; the success predicate (e.g. secret in `send_report` args) still catches the outcome.

## Storage

MySQL tables (`storage.py`): `experiments`, `runs`, `events`, `evaluations`, `metric_results`, `documents`, `memory_entries`. Datetimes are stored as naive UTC and returned as aware UTC.

ChromaDB (Phase 3): one collection per corpus state, `corpus_<corpus_id>`, in a `PersistentClient` at `.data/chroma`. Chunk metadata: `doc_id`, `chunk_id`, `corpus_id`, `trust`, `source`. Ground-truth `poisoned` lives only in MySQL `documents`, so defenses cannot cheat by reading it. Reset = delete and rebuild the collection; `corpus_state_id` on the run records which state was used. Embeddings via Ollama `nomic-embed-text`.

## Tool permission levels

| Level | Meaning | Examples |
|---|---|---|
| `read` | No side effects | `read_inbox`, `search_documents`, `read_memory` |
| `write_internal` | Mutates sandbox state only | `write_memory`, `update_mock_record` |
| `outbound` | Simulated send; records intent, returns a receipt | `send_report` |

No tool runs shell commands, touches the real filesystem, or opens a network connection.
