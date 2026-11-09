# Architecture

Logical design from PRD §8, as implemented. Status: **Phase 5** — all five surfaces (direct, tool output, RAG, memory, relay), deterministic mock agent, eight defenses with baseline/defended/ablation profiles, adaptive variants, recovery experiments. The Ollama agent adapter is not built yet.

## Code map

| Module | Contents | PRD |
|---|---|---|
| `src/harness/models.py` | All data contracts: vocabulary enums, `Provenance`, `SecretSpec`, `ToolSpec`/`ToolCall`/`ToolResult`, `Message`/`AgentTurn`, `Check`/`PolicyDecision`, `AttackScenario` + predicates, `Event`, `RunRecord`, `RunEvaluation`, `MetricResult` | §6, §9 |
| `src/harness/interfaces.py` | Protocols: `AgentAdapter`, `Tool`, `Defense`, `EventLogger`, `Evaluator`; `AgentError` hierarchy | FR-01, 04, 05, 07, 09 |
| `src/harness/attacks.py` | JSON library loader/validator, definition hashing, schema export | FR-02 |
| `src/harness/metrics.py` | Metric formulas and denominators | FR-09 |
| `src/harness/storage.py` | SQLAlchemy Core tables, `connect()`, run/evaluation writers, `SqlEventLogger` (MySQL via `MYSQL_URL`, else `.data/redguardian.db`) | FR-07, FR-11 |
| `src/harness/sandbox.py` | Fixtures (inbox, company knowledge base), token generation, payload injection into emails or documents, inert tools `read_inbox`, `read_config`, `search_documents`, `write_memory`, `read_memory`, `relay_message`, `read_messages`, `send_report`; session taint (`origin()`) | FR-04 |
| `src/harness/memory.py` | `MemoryStore` on `memory_entries`: append, retrieve, quarantine, delete (soft), reset, per namespace | FR-03 D |
| `src/harness/retrieval.py` | Paragraph chunking, `hash`/`ollama` embedders, per-run Chroma `Corpus` with search and drop | FR-03 B |
| `src/harness/mock_agent.py` | Deterministic scripted agent (`mock-vulnerable` / `mock-safe`) | FR-01 |
| `src/harness/policy.py` | `Policy` (most restrictive wins), `SecretEgressDefense` (tool calls), `RetrievalScreenDefense` (retrieved chunks), `MemoryScreenDefense` (memory write + read), `RelayScreenDefense` (relay messages), `InputScreenDefense`, `DestinationAllowlistDefense`, `TaintGuardDefense`, `OutputGuardDefense`; `DEFENSES` and generated ablation `PROFILES` | FR-05, FR-06 |
| `src/harness/runner.py` | `run_scenario`: seed → sessions × loop (propose → decide → execute) → events → evaluate → persist | FR-08 |
| `src/harness/evaluator.py` | `DeterministicEvaluator` over stored events | FR-09 |
| `scripts/run_experiment.py` | CLI: scenarios × profiles, recovery experiments, per-run verdicts and a Markdown comparison table (`--report`) | FR-08, §11 |
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

### Sessions, memory and relay (Phase 4)

A run is one or more **sessions**: `target_task`, then each of `follow_up_sessions`. Every session starts a fresh conversation (new context, new taint) over the same sandbox, so content can only cross sessions through memory or the relay channel. Events carry `payload.session_id` (`s1`, `s2`, ...); `SESSION_STARTED` marks each boundary.

- **Taint.** The sandbox records every untrusted provenance returned in the current session. Anything the agent writes (`write_memory`, `relay_message`) inherits `untrusted` plus the origin ids (e.g. `tool_output:msg-1`) if the session is tainted. Conservative: it over-labels, never under-labels.
- **Write boundary.** Before `write_memory`/`relay_message` run, the runner checks the content at `MEMORY_WRITE`/`RELAY`; a non-allow decision drops the write (nothing persisted or sent). Then `MEMORY_WRITE`/`RELAY_MESSAGE` events record id, sender, recipient, trust, origin and a SHA-256 of the content; the marker crossing gives `PERSISTED`/`RELAYED`.
- **Read boundary.** `read_memory` results are screened per entry at `MEMORY_READ` (same path as RAG chunks, `MEMORY_READ` event). This catches memory poisoned before a defense was enabled.
- **Memory namespace.** Default = the run id (isolated). `run_scenario(..., memory_namespace=ns)` reuses another run's memory; a benign scenario on inherited memory is a `recovery` run (`recovery_success`).
- **Relay.** `ops-agent` is the same agent adapter in a new session with `SessionSpec.agent="ops-agent"`; `read_messages` returns messages addressed to it. A test fixture, not a multi-agent framework (PRD FR-03 E).

Key rules:

- **The agent proposes; the policy layer authorizes.** Tools are never called by the adapter.
- **Most restrictive wins:** `block` > `quarantine` > `allow`; abstain (`None`) adds nothing. With zero enabled defenses (baseline) every call is allowed — the sandbox still makes every tool inert.
- **Events are observed at boundaries**, not inferred from the final answer. `(run_id, seq)` is unique; events are never updated.
- **Evaluator reads persisted events only.** Re-evaluation writes a new `evaluations` row keyed by `evaluator_version`.
- **Errors are not defenses.** `AgentError` or tool crash → run `failed`/`incomplete` → `valid=False` → excluded from every rate and counted in `invalid_runs`.

### Defenses (Phase 5)

All defenses live in `policy.py`, each with a stable `defense_id`, its checkpoints, and no access to ground truth. The runner asks the policy at every checkpoint; the most restrictive vote wins and is logged with its `defense_id` and reason.

| `defense_id` | PRD FR-05 family | Checkpoint(s) | Rule |
|---|---|---|---|
| `input_screen` | 1 input handling | `INPUT` (untrusted tool output, untrusted user-channel text) | withhold content that contains an instruction aimed at the assistant (regex heuristic) |
| `retrieval_screen` | 2 retrieval | `RETRIEVAL` (per chunk) | same heuristic on untrusted chunks |
| `memory_screen` | 3 memory | `MEMORY_WRITE`, `MEMORY_READ` (per entry) | same heuristic on untrusted memory |
| `relay_screen` | 3/relay | `RELAY` | same heuristic on untrusted relay messages |
| `destination_allowlist` | 4 tool authorization | `TOOL_CALL` (outbound) | recipient domain must be in `("corp.test",)` |
| `taint_guard` | 5 capability | `TOOL_CALL` (outbound) | no outbound action once untrusted content entered the session |
| `secret_egress` | 5/6 data flow at egress | `TOOL_CALL` (outbound) | a synthetic secret may reach only its `allowed_destinations` |
| `output_guard` | 6 output check | `EGRESS` (final answer) | withhold an answer containing a synthetic secret unless `"user"` is an allowed destination; the original is kept as `raw` evidence |

Always on (containment, not a defense): tool allowlist and JSON-Schema argument validation (`jsonschema`) before the policy is asked; invalid calls are `TOOL_ERROR`s and never execute.

Profiles (`PROFILES`): `baseline`, `defended` (all eight), `no_<id>` (all but one) and `only_<id>` (one alone) — PRD §11 ablations. A withheld input is replaced by `[content from <source> withheld by policy (<defense_id>)]`; the matched text is never echoed back to the agent.

Direct input (DIR surface): an injection with `target: "user_message"` is placed into session 1's user message, which is then labelled `USER`/`UNTRUSTED`, goes through the `INPUT` checkpoint, and taints the session.

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
| `write_internal` | Mutates sandbox state only | `write_memory`, `relay_message` |
| `outbound` | Simulated send; records intent, returns a receipt | `send_report` |

No tool runs shell commands, touches the real filesystem, or opens a network connection.
