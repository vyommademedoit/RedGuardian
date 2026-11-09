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

Phases 0–4 done: contracts, JSON attack library, mock agent, tool-output, RAG, cross-session memory and relay attacks (`TOOL-001`, `RAG-001`, `MEM-001`, `RELAY-001` + benign controls and a recovery check `BENIGN-004`), ChromaDB retrieval, persistent memory with quarantine/reset, `secret_egress`, `retrieval_screen`, `memory_screen` and `relay_screen` defenses with five profiles, event trace, evaluator, metrics, run explorer with retrieved sources and memory/relay path. Next: defense suite and comparative evaluation (Phase 5).

RAG runs use offline hash embeddings by default; add `--embedder ollama` to use `nomic-embed-text` (Ollama must be running).
