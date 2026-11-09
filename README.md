# RedGuardian

Local prompt-injection red-team harness for one tool-using LLM agent. Synthetic data and inert, sandboxed tools only. Product intent: [PRD.md](PRD.md); design: [docs/](docs/).

## Quick start

```bash
uv sync
uv run pytest
uv run python scripts/run_experiment.py      # every scenario under every profile
uv run streamlit run dashboard/app.py         # http://localhost:8501
```

Results go to MySQL if `MYSQL_URL` is set (env or `.env`, see `.env.example`), otherwise to `.data/redguardian.db` (SQLite). Use `--db sqlite://` for a throwaway in-memory run.

## Status

Phases 0–5 done: contracts, JSON attack library, mock agent, attacks on all five surfaces (`DIR`, `TOOL`, `RAG`, `MEM`, `RELAY`) with adaptive variants (`*-001b`, `TOOL-001c`) and a response-channel leak (`TOOL-002`), benign controls and false-refusal probes, ChromaDB retrieval, persistent memory with quarantine/reset, eight defenses (incl. a final-answer output check) with baseline/defended/ablation profiles, recovery experiments, event trace, evaluator, metrics, run explorer. Latest comparison: [docs/results/phase5_benchmark.md](docs/results/phase5_benchmark.md) (mock agent). Next: dashboard and reporting (Phase 6); the Ollama agent adapter is still pending.

RAG runs use offline hash embeddings by default; add `--embedder ollama` to use `nomic-embed-text` (Ollama must be running).
