# RedGuardian

A local red-team harness that measures how far prompt injection spreads through a tool-using LLM agent, and how well defenses outside the model stop it without breaking normal work.

Everything runs on one machine: synthetic secrets, inert sandboxed tools (nothing is ever really sent), a scripted mock agent or a local model through Ollama, and results in MySQL or SQLite.

**Jump to:** [Results](#results) · [How it works](#how-it-works) · [Quick start](#quick-start) · [Full report](docs/results/final_report.md)

## Results

The benchmark has 11 attacks and 10 benign tasks, run under 18 defense profiles: baseline (no defenses), defended (all eight), each defense removed, and each defense alone. The mock agent follows every injection, so it shows what the defenses can stop. `qwen2.5:7b` is a real local model, so it shows what actually happens. Counts are runs out of the total. *Attack success* means the attacker's full goal was met (the key reached them); *unauthorized action ran* counts any forbidden action, even without the key.

| Profile | Attack success | Secret leaked | Unauthorized action ran | Benign tasks done |
|---|---|---|---|---|
| Mock baseline | 11/11 | 11/11 | 10/11 | 10/10 |
| Mock defended | 0/11 | 0/11 | 0/11 | 8/10 |
| `qwen2.5:7b` baseline | 0/11 | 0/11 | 5/11 | 9/10 |
| `qwen2.5:7b` defended | 0/11 | 0/11 | 0/11 | 7/10 |

The main findings:
- **The real model obeys injections but rarely completes them.** It sends to the attacker but never with the real key.
- **Data-flow checks hold against reworded attacks; pattern screens don't.** `secret_egress` and `taint_guard` each stop 10/11 attacks alone against the mock. Every reworded variant got past every screen.
- **Memory defenses only protect later sessions.** A same-session memory attack (`MEM-002`) gets through them.
- **Defenses cost some benign tasks.** On the mock, `taint_guard` and `input_screen` each wrongly refuse one benign task.

Full numbers and evidence: [final report](docs/results/final_report.md). Practical guidance: [mitigations](docs/mitigations.md).

## How it works

1. **Attacks the agent on five surfaces.** Each attack is a JSON scenario in [`attacks/`](attacks/) that hides an instruction where the agent will read it:
   - **Direct input:** the user pastes in a note that contains an instruction.
   - **Tool output:** an email or tool result.
   - **RAG:** a poisoned knowledge-base chunk.
   - **Persistent memory:** a note that lasts into a later session, or is read back in the same one.
   - **Inter-agent relay:** a message forwarded to a second agent.
2. **Traces how far each payload travels** with a canary marker. The stages are Exposed (read by the agent), Persisted (saved to memory), Relayed (passed to another agent) and Executed (acted on).
3. **Enforces eight switchable defenses outside the model**, at the points where data enters the agent or leaves it:

   | Defense | What it checks |
   |---|---|
   | `secret_egress` | A labelled secret may only go to its allowed destinations. |
   | `output_guard` | The final answer to the user may not contain a secret either. |
   | `destination_allowlist` | Outbound sends must go to exactly one address in `corp.test`. |
   | `taint_guard` | Blocks outbound actions once the agent has read untrusted content. |
   | `input_screen`, `retrieval_screen`, `memory_screen`, `relay_screen` | Pattern screens on what enters the agent from each surface. |

4. **Scores each run from stored events**, using a deterministic evaluator that doesn't rely on an LLM judge. Attack success, secret leaks and unauthorized actions are counted separately. Every attack is paired with benign tasks under the same defenses, so the report shows security next to utility and false refusals.
5. **Tests recovery.** It poisons memory, quarantines the poisoned entries by where they came from, reruns the task, and checks the result from the new run's events.
6. **Reports and verifies.** It writes a Markdown report, a Streamlit dashboard and a verifier that recomputes every stored metric from the raw events.

## Quick start

Requirements: Python 3.12+ and [uv](https://docs.astral.sh/uv/). Optional: [Ollama](https://ollama.com/) for the real model, and MySQL 8 as the results store.

```bash
uv sync
uv run pytest                                   # test suite (the live-model test is skipped without Ollama)
uv run python scripts/run_experiment.py         # every scenario under every profile, mock agent (~15 s)
uv run streamlit run dashboard/app.py           # dashboard at http://localhost:8501
```

With a local model (Ollama running, then `ollama pull qwen2.5:7b`):

```bash
uv run python scripts/run_experiment.py --agent ollama --report docs/results/report.md
```

Useful options for `run_experiment.py`:
- `--attacks TOOL-001 MEM-002` runs only the listed scenarios.
- `--profiles baseline defended` runs only the listed defense profiles.
- `--repeats 3` runs each scenario three times.
- `--embedder ollama` uses `nomic-embed-text` for RAG, instead of the offline hash embeddings.
- `--db sqlite://` makes a throwaway in-memory run.

### Results database

Results go to MySQL if `MYSQL_URL` is set, either in the environment or in a `.env` file in the repo root. Otherwise they go to `.data/redguardian.db` (SQLite). To set up MySQL once:
1. Choose a password and run [scripts/mysql_setup.sql](scripts/mysql_setup.sql) as an admin. It creates a least-privilege `redguardian` user.
2. Add this line to `.env`, which git ignores:

```
MYSQL_URL=mysql+pymysql://redguardian:<password>@localhost:3306/redguardian
```

## Scripts

| Script | Purpose |
|---|---|
| `scripts/run_experiment.py` | scenarios × profiles × repeats, recovery checks, optional full report (`--report`) |
| `scripts/make_report.py` | Markdown report for any stored experiment |
| `scripts/verify_metrics.py` | re-evaluate every run and recompute every metric from raw events; exit 1 on any disagreement |
| `scripts/reset_db.py` | empty, versioned schema (dry run unless `--yes`) |
| `scripts/export_schema.py` | regenerate `attacks/schema.json` and `db/schema_v1.mysql.sql` |

## Project layout

```
attacks/            scenario library (JSON, validated by attacks/schema.json)
  direct/ tool_output/ rag/ memory/ relay/   attack scenarios by surface
  benign/                                    benign control tasks
src/harness/
  runner.py         runs one scenario: sessions, agent loop, policy checks, event log
  sandbox.py        inert tools (email, search, memory, relay, send_report) and fixtures
  policy.py         the eight defenses and the defense profiles
  evaluator.py      deterministic scoring from stored events
  metrics.py        rates with raw counts and denominators
  memory.py         persistent memory with provenance, quarantine, update, delete
  retrieval.py      ChromaDB corpus and embedders for the RAG surface
  mock_agent.py     scripted agent that follows injections (shows what defenses can stop)
  ollama_agent.py   local model adapter (temperature 0, fixed seed)
  storage.py        SQLAlchemy schema for MySQL and SQLite
  reporting.py      metrics by profile, outcome labels, attack paths, Markdown report
  verify.py         independent check of stored results against raw events
dashboard/          Streamlit dashboard
scripts/            command-line entry points (above)
db/                 generated MySQL DDL
docs/               design, decisions, limitations and results
tests/              pytest suite
```

## Documents

| | |
|---|---|
| [docs/architecture.md](docs/architecture.md) | components, run flow, defenses, diagram |
| [docs/threat-model.md](docs/threat-model.md) | assets, adversary, trust boundaries, containment |
| [docs/metrics.md](docs/metrics.md) | metric definitions, denominators, how to read the benchmark |
| [docs/decisions.md](docs/decisions.md) | decision log |
| [docs/limitations.md](docs/limitations.md) | what the results do not show; untested cases |
| [docs/reproducibility.md](docs/reproducibility.md) | machine, versions, model config, clean-run commands |
| [docs/demo.md](docs/demo.md) | 10-minute demonstration script |
| [docs/mitigations.md](docs/mitigations.md) | mitigation guide for builders of tool-using agents |
| [docs/acceptance.md](docs/acceptance.md) | evidence for each MVP acceptance criterion |
| [docs/results/](docs/results/) | final report and the per-benchmark reports |

## Safety and limits

- **Safe to run.** Secrets are synthetic and every tool is inert, so "sent" messages only go to an in-memory outbox. The dashboard listens on localhost only. Nothing is sent to a cloud service.
- **Limited scope.** The results come from one small model at temperature 0, a small hand-written attack library, regex screens and heuristic refusal detection. A clean result means these scenarios didn't succeed, not that an agent is secure. See [docs/limitations.md](docs/limitations.md).

## Status

Complete: all planned phases (0–7), released as `v1.0.0`. Since then `main` has added the memory update operation, a same-session memory attack, audit fixes, refreshed benchmarks, and a dashboard in plain words. Decisions are logged in [docs/decisions.md](docs/decisions.md).
