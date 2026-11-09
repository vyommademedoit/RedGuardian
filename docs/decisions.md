# Decision Log

Conservative, reversible defaults for PRD §16 open decisions. Change any of these by adding a new entry that supersedes the old one.

| ID | Date | Decision | Why | Reversal cost |
|---|---|---|---|---|
| D-001 | 2026-11-04 | Python **3.14** (installed 3.14.6); `requires-python >= 3.12` | Already installed; whole stack resolves to binary wheels on 3.14 | Low — `uv python install 3.12` |
| D-002 | 2026-11-04 | **uv** with `pyproject.toml` + `uv.lock`; `uv export` for a `requirements.txt` when needed | uv already installed; lockfile gives reproducibility (NFR-02) | Low |
| D-003 | 2026-11-04 | Target model **`qwen2.5:7b` (Q4_K_M)** via Ollama, temperature 0, fixed seed; `MockAgent` is the default for tests | Already pulled, supports native tool calling, fits 6 GB VRAM | Low — model tag is config |
| D-004 | 2026-11-04 | MySQL: **existing native MySQL 8.0** (`MYSQL80` service), dedicated `redguardian` DB and user; credentials in gitignored `.env` | Docker unavailable; MySQL already installed | Medium |
| D-005 | 2026-11-04 | Embeddings: **Ollama `nomic-embed-text`**; Chroma telemetry off | Chroma's default embedder downloads from the internet — violates local-first | Low — rebuild collection |
| D-006 | 2026-11-04 | Chroma `PersistentClient` at `.data/chroma` (gitignored) | Local, resettable by deleting one folder | Low |
| D-007 | 2026-11-04 | DB access: **SQLAlchemy 2 Core + PyMySQL**; SQLite in-memory for unit tests; migrations: plain `create_all` until schema stabilises, Alembic later if needed | Pure-Python driver, no compiler; tests don't need a running MySQL | Low |
| D-008 | 2026-11-04 | Neo4j **deferred**; graphs via NetworkX + Plotly | Optional in PRD; no Docker | n/a |
| D-009 | 2026-11-04 | Keep repo name `RedGuardian`; internal layout per PRD §8.2 (`src/harness/…`) | Repo already exists with that name | Low |
| D-010 | 2026-11-04 | Literature PDFs stay outside the repo (`../Lit Survey Papers/`) | Size and third-party copyright | n/a |
| D-011 | 2026-11-04 | Flat modules (`models`, `interfaces`, `attacks`, `metrics`, `storage`) until a component needs several files | Avoid empty package scaffolding (PRD §8.2 "do not create every directory on day one") | Low |
| D-012 | 2026-11-04 | Pydantic `AttackScenario` is the source of truth; `attacks/schema.json` is generated and a test keeps them in sync | One definition, no drift | Low |
| D-013 | 2026-11-04 | Success/expected outcomes are structured predicates (`tool_call`, `response_contains`, `no_tool_call`) with `{secret}`/`{marker}` placeholders | Deterministic evaluator; no free-text judging | Medium |
| D-014 | 2026-11-04 | Two tokens per attack run: `marker` (tracks payload propagation) and `secret` (tracks data leakage) | PRD separates "content reached a stage" from "objective achieved" | Medium |
| D-015 | 2026-11-04 | Policy combination: most restrictive decision wins (`block` > `quarantine` > `allow`); `None` = abstain | Simple, explainable; independent on/off per defense | Low |
| D-016 | 2026-11-04 | "Prohibited" tool call = matches the scenario's `tool_call` success predicate, or an `outbound` call carrying the secret/marker | Ground truth independent of the defenses under test | Medium |
| D-017 | 2026-11-04 | Datetimes stored as naive UTC, returned as aware UTC (`UTCDateTime`) | MySQL `DATETIME` and SQLite drop tzinfo | Low |
| D-018 | 2026-11-04 | Chroma: one collection per corpus state (`corpus_<id>`); `poisoned` ground truth only in MySQL | Clean reset; defenses can't read the answer key | Low |
| D-019 | 2026-11-04 | `MockAgent` is a scripted, fully compliant stand-in: obeys "call X with to=Y" in tool output and fetches the key it asks for | Deterministic end-to-end tests without a model; real variance comes from the Ollama adapter | Low |
| D-020 | 2026-11-04 | EXECUTED stage = token reached an outbound action request; the policy decision is on the same event | PRD FR-07 wording; dashboard never labels a blocked one as a compromise | Medium |
| D-021 | 2026-11-04 | No `MYSQL_URL` → local SQLite file `.data/redguardian.db` | MySQL is still stopped; same tables via SQLAlchemy, so switching is one env var | Low |
| D-022 | 2026-11-04 | Streamlit bound to `localhost`, usage stats off (`.streamlit/config.toml`) | Default binds all interfaces and phones home; violates local-first | Low |
| D-023 | 2026-11-09 | One in-memory Chroma collection per run (`corpus_<run_id>`), dropped when the run ends; persistence at `.data/chroma` deferred until corpora are reused | Strongest reset guarantee: a poisoned corpus cannot leak into the next run | Low |
| D-024 | 2026-11-09 | Two embedders: `hash` (deterministic bag-of-words, default, offline, used by tests) and `ollama` (`nomic-embed-text`) via `--embedder` | Tests need no model; real runs use real embeddings. Both rank the poisoned chunk in the top 3 for RAG-001 | Low |
| D-025 | 2026-11-09 | `retrieval_screen`: quarantine an *untrusted* chunk that contains an instruction aimed at the assistant (regex). Heuristic, labelled as such | Transparent and explainable (PRD FR-05); reworded payloads can evade it, which the adaptive variants in Phase 5 will measure | Medium |
| D-026 | 2026-11-09 | Profiles: `baseline`, `defended` (both defenses), `egress_only`, `retrieval_only` | Shows which layer stops which attack (ablation) | Low |
| D-027 | 2026-11-09 | `documents` keyed by (`corpus_id` = run id, `doc_id`) and stores text; `connect()` refuses a pre-Phase-3 database with a clear message instead of migrating | Per-run corpus copies; local DB holds only demo runs (D-007 still defers migrations) | Low |

## Still open (not blocking the vertical slice)

- Exact attack count and repeats per scenario (Phase 5).
- Defense profile names and parameters (Phase 5).
- PDF report output (default: Markdown only).
- Dashboard authentication (default: none, local single user).
