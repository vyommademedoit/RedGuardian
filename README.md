# RedGuardian

Local prompt-injection red-team harness for one tool-using LLM agent. Synthetic data and inert, sandboxed tools only. Product intent: [PRD.md](PRD.md); design: [docs/](docs/).

It runs data-driven attacks on five surfaces (direct input, tool output, RAG, persistent memory, inter-agent relay) against a scripted mock agent or a local Qwen model, enforces eight independently switchable defenses outside the model, traces how far each payload travels (Exposed → Persisted → Relayed → Executed), and reports security next to benign utility.

## Quick start

```bash
uv sync
uv run pytest
uv run python scripts/run_experiment.py      # every scenario under every profile (mock agent, ~15 s)
uv run streamlit run dashboard/app.py         # http://localhost:8501
```

Local model (Ollama running, `ollama pull qwen2.5:7b`):

```bash
uv run python scripts/run_experiment.py --agent ollama --profiles baseline defended --report docs/results/report.md
```

| Command | Purpose |
|---|---|
| `scripts/run_experiment.py` | scenarios × profiles × repeats, recovery checks, optional full report (`--report`) |
| `scripts/make_report.py` | Markdown report (FR-12) for any stored experiment |
| `scripts/verify_metrics.py` | recompute every metric from raw events; exit 1 on any disagreement |
| `scripts/reset_db.py` | empty, versioned schema (dry run unless `--yes`) |
| `scripts/export_schema.py` | regenerate `attacks/schema.json` and `db/schema_v1.mysql.sql` |

Results go to MySQL if `MYSQL_URL` is set (env or `.env`; one-time setup in `scripts/mysql_setup.sql`), otherwise to `.data/redguardian.db` (SQLite). Use `--db sqlite://` for a throwaway in-memory run.

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
| [docs/results/final_report.md](docs/results/final_report.md) | final benchmark and mitigation report; per-run reports alongside |
| [docs/mitigations.md](docs/mitigations.md) | mitigation guide |
| [docs/acceptance.md](docs/acceptance.md) | evidence for each MVP acceptance criterion |

## Status

All phases (0–7) done; tagged `v1.0.0`. Final results: [docs/results/final_report.md](docs/results/final_report.md) — mock and `qwen2.5:7b` benchmarks on fresh databases (MySQL and SQLite), each verified against its raw events. RAG runs use offline hash embeddings by default; add `--embedder ollama` to use `nomic-embed-text`.
