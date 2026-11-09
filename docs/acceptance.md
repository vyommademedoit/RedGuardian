# MVP acceptance evidence (PRD §13)

Each criterion with the test, command or artifact that demonstrates it. Tests are in `tests/`; run `uv run pytest`.

## 13.1 Core runtime

| Criterion | Evidence |
|---|---|
| Starts locally from documented setup | `README.md` quick start; `docs/reproducibility.md` clean-run commands |
| Mock agent runs without Ollama | whole suite runs offline; `test_every_benign_scenario_succeeds_on_baseline` |
| Qwen/Ollama adapter selectable | `run_experiment.py --agent ollama`; `test_runner_drives_adapter_end_to_end`, `test_live_benign_run_completes` (with `RG_OLLAMA_TESTS=1`) |
| Benign task with a sandboxed tool | `test_benign_control_keeps_utility`, `test_live_benign_run_completes` |

## 13.2 Attack execution

| Criterion | Evidence |
|---|---|
| A valid attack per surface | `DIR-001`, `TOOL-001`, `RAG-001`, `MEM-001`, `RELAY-001` (+ variants); `test_every_attack_lands_on_baseline_and_fails_when_defended` |
| JSON definitions loaded and validated | `test_library_loads_shipped_scenarios`, `test_invalid_definition_rejected_with_useful_error`, `test_schema_json_in_sync` |
| Single and batch runs | `run_scenario` (single); `run_experiment.py --attacks/--profiles/--repeats` (batch) |
| Run records attack, model, configuration, initial state | `runs`: `attack_sha256`, `model`, `model_params` (incl. digest), `defense_config`, `seed`, `corpus_state_id`, `memory_state_id`; `RUN_STARTED` payload lists fixtures; `test_tables_roundtrip_run_and_event`, `test_runner_drives_adapter_end_to_end` |

## 13.3 Safety and defenses

| Criterion | Evidence |
|---|---|
| Synthetic secrets only | `sandbox.make_tokens` (`SECRET-<KIND>-<hex>` per seed); `test_same_seed_same_trace` |
| No host resources / external network from tools | `test_tools_reach_no_network_or_host_files` (all scenarios with sockets and sandbox file access forbidden) |
| Permissions enforced outside the LLM | policy middleware + schema validation before execution; `test_invalid_arguments_rejected_before_policy_and_execution`, `test_defended_attack_blocked_by_named_defense` |
| A defense blocks an unauthorized action | `test_defended_attack_blocked_by_named_defense`, `test_adaptive_variants_show_which_layer_holds` |
| Decisions and reasons logged | `POLICY_DECISION` events with `defense_id` and `reason`; Evidence view |
| Defenses individually switchable | generated `no_<id>` / `only_<id>` profiles; `test_ablation_profiles_remove_or_isolate_exactly_one_defense` |

## 13.4 Evidence and metrics

| Criterion | Evidence |
|---|---|
| Events persisted and linked to a run | `events` table (`run_id`, unique `seq`); `test_events_are_immutable`, `test_evaluation_reproducible_from_stored_events` |
| Canary tracked through applicable stages | `test_memory_attack_persists_in_session_1_and_fires_in_session_2`, `test_relay_attack_crosses_to_second_agent`, `test_baseline_rag_attack_leaks_via_poisoned_document` |
| All required metrics | `metrics.compute_metrics`; `test_metrics_denominators`, `test_recovery_quarantine_restores_safe_behaviour` |
| Denominators and raw counts visible | every report/dashboard cell is `rate (n/d)`; `docs/metrics.md` |
| Failed runs not counted as defended | `test_model_failure_is_an_invalid_run_not_a_defense`, `test_model_failure_is_invalid_not_a_defense`; `invalid_runs` metric |

## 13.5 Visualization

| Criterion | Evidence |
|---|---|
| Aggregate results | Overview view; `test_every_view_renders` |
| Select a run, inspect timeline | Run explorer; `test_dashboard_renders_runs` |
| Attack path / provenance graph | Run explorer attack path; `test_attack_path_memory_hop_and_blocked_send` |
| Baseline vs defended comparison | Comparison view; `test_compare_flags_utility_regression`, `test_comparison_warns_on_utility_regression` |
| Aggregates traceable to events | "Open in run explorer" from library, comparison and evidence views; `test_evidence_search_filters_events`; `verify_metrics.py` |

## 13.6 Reproducibility and documentation

| Criterion | Evidence |
|---|---|
| Reset/seed workflow | `scripts/reset_db.py` (versioned schema), seeds per run; `test_mysql_ddl_in_sync_and_versioned` |
| Repeatable experiment command | `scripts/run_experiment.py`; `test_same_seed_same_trace`; `verify_metrics.py` exit 0 on stored experiments |
| Tests cover critical boundaries | 117 tests: policy, sandbox, adapter failures, evaluator, storage, dashboard, verification |
| README, architecture, threat model, metrics, mitigation guide | `README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/metrics.md`, `docs/mitigations.md` |
| Report states limitations, no formal guarantees | report §9 "Limitations and reproducibility"; `docs/limitations.md` ("No formal guarantees") |
