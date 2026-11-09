# Reproducibility

How the published results were produced, and how to reproduce them from a clean state.

## Machine

| | |
|---|---|
| CPU | AMD Ryzen 7 7435HS |
| RAM | 23.7 GB |
| GPU | NVIDIA GeForce RTX 4050 Laptop GPU, 6 GB VRAM (driver 610.62) |
| OS | Windows 11 Home Single Language 10.0.26200 |

## Software

| Component | Version |
|---|---|
| Python | 3.14.6 (via uv 0.13.7; exact packages pinned in `uv.lock`) |
| pydantic / SQLAlchemy / PyMySQL | 2.14.2 / 2.1.7 / 1.2.3 |
| ChromaDB | 1.5.9 (in-memory client, one collection per run, telemetry off) |
| Streamlit / Plotly / NetworkX / pandas | 1.66.1 / 7.1.0 / 3.7 / 3.1.0 |
| jsonschema | 4.26.0 |
| MySQL | Community Server 8.0.45 (schema v1, `db/schema_v1.mysql.sql`) |
| Ollama | 0.40.14 |

## Model configuration (Ollama adapter)

| Setting | Value |
|---|---|
| Model | `qwen2.5:7b` — Qwen2 family, 7.6 B parameters, GGUF `Q4_K_M` |
| Digest | `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e` (also stored per run in `runs.model_params`) |
| Endpoint | `POST /api/chat`, `stream: false`, native tool calls |
| Options | `temperature 0`, `seed` = run seed, `num_ctx 8192` |
| Timeout | 300 s per call (first call cold-loads the model, ~50 s observed) |
| System prompt | `harness.runner.SYSTEM_PROMPT` (tool content is untrusted data) |
| Embeddings | `hash` (default, offline, deterministic) or `nomic-embed-text` via `--embedder ollama` |

Observed speed on this machine: ~0.9 s per warm model call, ~7.5 s per run.

## Determinism

- The mock agent is fully deterministic; the same seed gives byte-identical event payloads apart from ids and timestamps.
- Each run's marker and synthetic secret derive from its seed (`sandbox.make_tokens`).
- At temperature 0 the model is near-deterministic, so repeats (`--repeats N`, seeds `seed..seed+N-1`) mostly re-confirm rather than measure variance. Use a higher temperature (an adapter argument) for variance studies.
- Every run stores the SHA-256 of the exact scenario JSON it used; `verify_metrics.py` refuses to re-evaluate a run whose scenario file has since changed.

## Clean benchmark (end to end)

```bash
uv sync
uv run pytest                                                      # 117 passed, 1 skipped (live model test)
uv run python scripts/reset_db.py --yes                            # empty, versioned schema (MySQL if MYSQL_URL is set)
uv run python scripts/run_experiment.py --report docs/results/mock_benchmark.md
uv run python scripts/run_experiment.py --agent ollama --report docs/results/ollama_benchmark.md
uv run python scripts/verify_metrics.py --experiment <id>          # exit 0 = stored results match raw events
uv run streamlit run dashboard/app.py
```

## Published runs

| Report | Agent | Backend | Verification |
|---|---|---|---|
| `results/mock_benchmark_mysql.md` | mock | MySQL 8.0.45, fresh schema v1 | `verify_metrics.py`: 1926 checks, 0 problems |
| `results/mock_benchmark.md` | mock | SQLite, fresh file | 1926 checks, 0 problems; metrics, stages and outcomes identical to the MySQL run |
| `results/ollama_qwen2.5-7b_benchmark.md` | qwen2.5:7b | SQLite, fresh file | 1926 checks, 0 problems |

`reset_db.py` without `--yes` only prints what it would drop. MySQL setup: `scripts/mysql_setup.sql` (dedicated least-privilege user), then `MYSQL_URL=mysql+pymysql://redguardian:<password>@localhost:3306/redguardian` in `.env`.
