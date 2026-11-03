# RedGuardian

Local prompt-injection red-team harness for one tool-using LLM agent. Synthetic data and inert, sandboxed tools only. Product intent: [PRD.md](PRD.md); design: [docs/](docs/).

## Quick start

```bash
uv sync
uv run pytest
uv run python scripts/run_experiment.py      # TOOL-001 + BENIGN-001, baseline vs defended
uv run streamlit run dashboard/app.py         # http://localhost:8501
```

Results go to MySQL if `MYSQL_URL` is set (env or `.env`, see `.env.example`), otherwise to `.data/redguardian.db` (SQLite). Use `--db sqlite://` for a throwaway in-memory run.

## Status

Phases 0–2 done: contracts, JSON attack library, mock agent, tool-output attack, `secret_egress` defense, event trace, evaluator, metrics, run explorer. Next: RAG surface (Phase 3).
