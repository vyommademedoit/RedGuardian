# Product Requirements Document (PRD)

## Prompt-Injection Red-Team Harness for Local Tool-Using Agents

**Document status:** Project baseline / agent handoff\
**Version:** 0.1\
**Prepared:** 4 November 2026\
**Intended reader:** Claude Code, Codex, or another repository-aware
software engineering agent\
**Project type:** Personal, academic, local-first security engineering
project

------------------------------------------------------------------------

## 0. Instructions to the coding agent

You are the engineering agent assisting with the implementation of this
project. Treat this document as the current source of truth for product
intent and scope.

### Your operating rules

1.  **Inspect before implementing.** First inspect the repository,
    existing files, installed dependencies, runtime constraints, and
    current implementation. Do not overwrite or restructure existing
    work without explaining why.
2.  **Preserve the agreed scope.** The target is one local tool-using
    LLM agent, the first version has balanced scope, and the primary
    differentiator is visualization. Do not silently turn this into a
    full multi-agent platform or enterprise security product.
3.  **Work incrementally.** Break work into small, testable milestones.
    For each milestone, state the goal, files to create/change,
    dependencies, acceptance tests, and known risks before
    implementation.
4.  **Prefer a working vertical slice.** Establish an end-to-end
    baseline attack and evidence trail before expanding the attack
    library or dashboard.
5.  **Keep it local-first.** Use local models and local services. Do not
    send project data, synthetic secrets, prompts, attack payloads, or
    logs to external services. No real credentials or real confidential
    data.
6.  **Keep attacks safely contained.** All attacks must target only the
    intentionally vulnerable local demo agent. Tools must be simulated
    or sandboxed. No real email, shell, browser, filesystem mutation,
    network exfiltration, or external target actions.
7.  **Make results reproducible.** Fix random seeds where possible,
    version attack definitions, record model/runtime/configuration
    details, and preserve raw run evidence.
8.  **Do not overclaim security.** A defense passing the included test
    suite is not proof of general robustness. Clearly label heuristic
    defenses, limitations, and untested cases.
9.  **Do not fabricate results.** Never invent attack success rates,
    benchmark outcomes, model capabilities, or completed features. Mark
    unrun experiments as pending.
10. **Maintain project documentation.** Keep the PRD, architecture
    notes, setup instructions, threat model, experiment methodology, and
    decision log aligned with the code.

### First response expected from the coding agent

Before writing implementation code, return: - a concise repository and
environment assessment; - a proposed architecture mapped to this PRD; -
a dependency and service checklist; - a milestone plan; - any conflicts
between the existing repository and this PRD; - the smallest end-to-end
vertical slice you recommend implementing first.

Ask a question only if a missing decision blocks safe implementation.
Otherwise, record assumptions explicitly and proceed with the smallest
reversible choice.

------------------------------------------------------------------------

# 1. Executive summary

The **Prompt-Injection Red-Team Harness for Local Tool-Using Agents** is
a local, reproducible security testing framework that evaluates how
prompt injections and poisoned content can manipulate an LLM agent that
can retrieve information, retain memory, and invoke tools.

The system will provide:

-   one intentionally vulnerable local LLM agent as the target;
-   a Python-based attack runner and experiment orchestrator;
-   a structured, data-driven attack library;
-   five attack surfaces: direct input, retrieval/RAG, tool outputs,
    persistent memory, and simulated inter-agent messages;
-   sandboxed tools and synthetic secrets;
-   a layered defense pipeline that can be enabled, disabled, and tested
    independently;
-   deterministic event logging and stage-level attack propagation
    tracking;
-   an evaluator that computes security and utility metrics;
-   a Streamlit dashboard that visualizes attack paths, propagation,
    blocked actions, evidence, and baseline-versus-defended results.

The project is a **personal/academic prototype**, not an enterprise
product. It should demonstrate a complete security evaluation workflow
locally and make the attack lifecycle understandable through
visualization.

## 1.1 Agreed foundational decisions

  -----------------------------------------------------------------------
  Decision                            Agreed direction
  ----------------------------------- -----------------------------------
  Target architecture                 **Single target agent**

  First-version scope                 **Balanced**

  Main differentiator                 **Visualization**

  Model approach                      Local Qwen model served through
                                      Ollama; support a
                                      mock/deterministic model adapter
                                      for tests and development

  Main implementation language        Python

  RAG store                           ChromaDB

  Canonical memory and                MySQL
  experiment/event records            

  UI                                  Streamlit

  Visualization                       Plotly and NetworkX

  Graph database                      Neo4j optional; not required for
                                      MVP

  Attack definitions                  Data-driven JSON attack library

  Tool execution                      Simulated/sandboxed tools only

  Data                                Synthetic secrets and synthetic
                                      documents

  Operating model                     Local-first; no external targets or
                                      cloud dependency
  -----------------------------------------------------------------------

**Important interpretation of "single target":** the product evaluates
one local target agent. Inter-agent-message attacks remain in scope as a
simulated relay/message channel or controlled second-stage reader, not
as a commitment to build a general-purpose multi-agent ecosystem.

## 1.2 Product thesis

A single end-state metric such as "attack succeeded" is not enough to
understand why an agent was compromised or where a defense worked. This
harness should show the complete path from adversarial content entering
the system to its possible persistence, retrieval, influence on
reasoning, and attempted or completed tool action.

The core value is therefore not merely generating attacks. It is
**reproducible attack execution plus evidence-based, stage-level
visualization of what happened**.

------------------------------------------------------------------------

# 2. Problem statement

Tool-using LLM agents combine natural-language reasoning with access to
external content, retrieval systems, memory, and executable tools. This
creates several trust boundaries:

-   untrusted user input may contain malicious instructions;
-   retrieved documents may contain poisoned or instruction-like
    content;
-   tool outputs may return adversarial text;
-   an agent may store unsafe content in persistent memory and retrieve
    it in later sessions;
-   messages passed between agents or components may relay malicious
    instructions.

A successful injection can cause the agent to ignore the user's intended
task, disclose synthetic confidential data, misuse a tool, alter data,
or preserve unsafe behavior across sessions.

Simple prompt-only defenses are insufficient as a complete evaluation
strategy. The project should test the whole agent pipeline, including
data ingestion, retrieval, memory writes, tool authorization, and
outbound actions. It should also measure whether defenses preserve
legitimate task utility.

## 2.1 Project objective

Build a local red-team harness that can:

1.  run controlled attacks against a local tool-using agent;
2.  compare vulnerable and defended configurations;
3.  trace the progression of attacks through system stages;
4.  record machine-readable evidence for every run;
5.  calculate security and benign-utility metrics;
6.  visualize attack paths and defense outcomes;
7.  produce a repeatable benchmark and mitigation report.

## 2.2 Non-goals

The first version will **not**:

-   attack public websites, production systems, third-party agents, or
    real users;
-   use real credentials, private records, or actual secrets;
-   execute real data exfiltration, email sending, destructive shell
    commands, or external API actions;
-   build a production-grade multi-agent orchestration platform;
-   reproduce AgentDojo or another published benchmark in full;
-   implement every published attack or defense;
-   train or fine-tune an LLM;
-   implement reinforcement-learning-based attack generation;
-   include multimodal attacks (image/audio/video) in the MVP;
-   depend on cloud-hosted models or services;
-   claim formal security guarantees.

These are exclusions for the current project scope, not statements that
the topics are unimportant.

------------------------------------------------------------------------

# 3. Users and use cases

## 3.1 Primary user

The primary user is the project developer/researcher operating the
harness locally. The system is intended for learning, experimentation,
demonstration, and academic evaluation.

## 3.2 Core use cases

1.  **Run a baseline attack:** select an attack scenario and run it
    against the vulnerable agent.
2.  **Run a defended attack:** repeat the same scenario with one or more
    defenses enabled.
3.  **Compare configurations:** compare baseline, defended, and
    defense-ablation runs.
4.  **Inspect an attack trace:** identify where malicious content
    entered, whether it was retrieved or persisted, whether it
    influenced a tool call, and where it was stopped.
5.  **Inspect evidence:** review tool calls, retrieved chunks, memory
    writes, policy decisions, canary events, and agent outputs.
6.  **Measure utility:** run benign tasks to check whether defenses
    block legitimate work.
7.  **Evaluate recovery:** remove or quarantine poisoned data, reset
    state, and rerun affected tasks.
8.  **Export findings:** generate a run summary and a
    benchmark/mitigation report.

------------------------------------------------------------------------

# 4. Scope and release strategy

The first version is balanced: it should cover the agreed attack
surfaces and provide meaningful defense and visualization functionality,
but it must remain achievable as a personal project.

## 4.1 MVP scope

The MVP must include:

-   one local target agent;
-   a mock agent adapter and a local Qwen/Ollama adapter;
-   a Python orchestration and attack-runner layer;
-   a small, curated JSON attack library;
-   direct-input, RAG, tool-output, memory, and simulated
    inter-agent-message scenarios;
-   ChromaDB-backed retrieval;
-   persistent memory with provenance metadata;
-   synthetic secrets and sandboxed tools;
-   an independent policy/defense middleware;
-   stage-level event/canary tracking;
-   a deterministic evaluator and metric calculations;
-   MySQL-backed experiment/event persistence;
-   a Streamlit dashboard with attack-trace and comparison views;
-   setup, usage, architecture, and mitigation documentation.

## 4.2 Recommended implementation order

The scope covers all five surfaces, but implementation should be staged:

**Milestone 1 --- Vertical slice:** mock/local agent → one sandboxed
tool → one attack → deterministic evaluator → event log → basic trace
visualization.

**Milestone 2 --- Retrieval and poisoning:** add ChromaDB, document
ingestion, retrieval provenance, and RAG poisoning scenarios.

**Milestone 3 --- Persistent memory:** add memory writes, retrieval
across sessions, poisoning scenarios, and recovery/reset behavior.

**Milestone 4 --- Defense layer:** add independently switchable controls
for untrusted input, retrieval, memory, and tool execution.

**Milestone 5 --- Full evaluation and dashboard:** add attack batches,
benign tasks, ablations, metrics, comparisons, and exportable reports.

**Milestone 6 --- Hardening and documentation:** reproducibility, test
coverage, failure handling, packaging, and final project report.

This sequencing is an implementation strategy, not a reduction of the
agreed final MVP surfaces.

## 4.3 Deferred/stretch features

-   optional Neo4j graph view of provenance and attack relationships;
-   additional local model adapters;
-   more advanced adaptive attack variants;
-   more sophisticated trust scoring and memory sanitization;
-   richer multi-agent simulations;
-   benchmark import/export compatibility;
-   multimodal document or audio attack surfaces;
-   automated attack generation and optimization.

Do not begin deferred work until the MVP acceptance criteria are met.

------------------------------------------------------------------------

# 5. Threat model

## 5.1 Protected assets

All protected assets must be synthetic and local:

-   synthetic secret values (e.g., `SECRET-...` canary tokens);
-   synthetic user/task data;
-   simulated tool data and records;
-   integrity of the memory store;
-   integrity of the retrieval corpus;
-   tool permissions and authorization state;
-   user-intended task objectives;
-   run logs and experiment evidence.

## 5.2 Adversary

Assume an attacker can control or contribute untrusted content that the
agent may process. Depending on the scenario, the attacker may:

-   submit a malicious user message;
-   add a poisoned document to the test corpus;
-   control text returned by a simulated tool;
-   introduce content that may be summarized into long-term memory;
-   send a malicious message through a simulated agent-relay channel.

The attacker does not have access to model weights, host secrets, the
real host filesystem, unrestricted network access, or the actual runtime
configuration. Attack scenarios should state their assumptions
explicitly.

## 5.3 Attacker goals

The controlled test objectives are:

-   override or divert the intended task;
-   induce a targeted incorrect response;
-   cause disclosure of a synthetic secret;
-   induce unauthorized or out-of-scope tool use;
-   poison retrieval or persistent memory;
-   cause malicious content to propagate through a simulated relay;
-   create persistent behavior that survives a session boundary;
-   cause denial of service or unnecessary refusal.

## 5.4 Trust boundaries

The harness must distinguish:

1.  trusted system/developer policy;
2.  trusted user task and explicit user-authorized data;
3.  untrusted user-provided or externally sourced content;
4.  retrieved documents and chunks;
5.  tool outputs;
6.  persistent memory records;
7.  inter-agent/simulated relay messages;
8.  tool arguments and outbound action requests;
9.  the policy enforcement layer.

The agent must not be the sole authority deciding whether a tool action
is permitted. Tool authorization must be enforced outside the model.

## 5.5 Safety containment

-   Use only synthetic secrets.
-   Use allowlisted local tools with narrow schemas.
-   Disable arbitrary shell execution.
-   Disable unrestricted filesystem access.
-   Disable outbound network access from the sandbox.
-   Simulate sensitive actions such as sending a report or email by
    recording the attempted action rather than sending anything.
-   Make destructive actions impossible or replace them with inert mock
    operations.
-   Keep test data separate from personal files.
-   Make reset and cleanup operations explicit and testable.

------------------------------------------------------------------------

# 6. Functional requirements

Priority labels: **P0 = required for MVP**, **P1 = important**, **P2 =
deferred/stretch**.

## FR-01: Agent runtime and model adapter

**Priority:** P0

The system shall expose a consistent interface for interacting with the
target agent.

Requirements: - provide a mock/deterministic agent adapter for tests and
early development; - provide a local Qwen model adapter through
Ollama; - keep model invocation separate from orchestration, tools,
storage, and evaluation; - capture model name, model version/tag where
available, runtime configuration, and generation parameters; - support a
configurable system prompt and task prompt; - handle model timeout,
unavailable model, malformed response, and tool-call parsing errors.

Acceptance: - the same test scenario can be run against the mock adapter
and the local model adapter; - the harness does not require an external
API key; - model unavailability produces a clear error and does not
corrupt run records.

## FR-02: Attack library

**Priority:** P0

Attack scenarios shall be stored as data-driven JSON definitions rather
than hard-coded into the runner.

Each attack definition should support fields equivalent to: -
`attack_id` - `name` - `description` - `category` - `surface` -
`objective` - `severity` - `prerequisites` - `attacker_capability` -
`payload` or payload-template reference - `target_task` -
`expected_safe_behavior` - `success_condition` - `canary_id` or
canary-generation rule - `tags` - `version`

The schema may evolve during implementation, but attack content and
execution logic must remain separate.

Requirements: - load and validate attack definitions; - support
enabling/disabling individual scenarios; - support deterministic
scenario selection; - record the exact attack-definition version used in
each run; - include benign control scenarios.

Acceptance: - an invalid attack definition is rejected with a useful
validation error; - adding a new data-only scenario does not require
changing the runner's core logic, unless the scenario introduces a
genuinely new execution primitive.

## FR-03: Attack surfaces

**Priority:** P0

The harness shall represent the following five surfaces.

### A. Direct input

Test whether malicious instructions supplied in the user input channel
can divert the task, induce secret disclosure, or cause unauthorized
tool use.

### B. Retrieval / RAG

Test whether a poisoned document or chunk can be retrieved and influence
the response or tool plan.

Requirements: - document ingestion into ChromaDB; - chunk metadata and
source identity; - query retrieval with configurable top-k; - record
retrieved document/chunk IDs and similarity scores; - distinguish clean
and poisoned documents; - support corpus reset and scenario-specific
corpus setup.

### C. Tool outputs

Test whether malicious instructions embedded in a tool result can
influence subsequent reasoning or actions.

Requirements: - tool results must be represented as untrusted data; -
record tool input, output, and provenance; - provide controlled fixtures
for benign and poisoned tool responses.

### D. Persistent memory

Test whether malicious content can be written into memory and later
influence a new session.

Requirements: - separate current conversation context from persistent
memory; - support memory append, retrieve, update, quarantine, and reset
operations; - store source, timestamp, session/run ID, trust label, and
provenance; - test both same-session and cross-session effects; - log
the content or safe hash/reference of each memory write and retrieval.

### E. Simulated inter-agent messages

Test whether malicious content can pass through a controlled
message/relay boundary and influence a subsequent agent step.

Requirements: - keep the primary target architecture single-agent; -
implement a lightweight simulated relay or second-stage reader only to
exercise the message boundary; - record sender, recipient, message ID,
source provenance, and read/write events; - do not expand this into a
general multi-agent framework in the MVP.

## FR-04: Sandboxed tool registry

**Priority:** P0

The system shall expose a registry of mock tools with explicit schemas
and permission levels.

Initial tool examples: - `search_documents` - `read_document` -
`query_mock_database` - `read_memory` - `write_memory` - `send_report`
(simulated; records intent only) - `update_mock_record` (restricted,
inert test data only)

Requirements: - tools are allowlisted; - each tool declares required
permission/capability; - arguments are schema-validated; - all calls are
logged before and after policy evaluation; - denied calls are recorded
with the reason; - no arbitrary code execution or unrestricted external
side effects.

## FR-05: Defense and policy middleware

**Priority:** P0

Implement defenses as an independent layer between the agent and
sensitive operations. Defense modules must be individually configurable
so baseline, defended, and ablation experiments can be run.

Planned defense families:

1.  **Input/untrusted-content handling:** label untrusted content,
    delimit it, and apply configurable screening. Do not treat prompt
    wording alone as a security boundary.
2.  **Retrieval defense:** attach source/provenance metadata, flag
    suspicious or untrusted documents, and optionally filter or
    quarantine retrieved material.
3.  **Memory defense:** validate memory writes, preserve provenance,
    apply trust-aware retrieval, and support quarantine/removal of
    poisoned entries.
4.  **Tool authorization:** enforce allowlists, argument validation,
    permission checks, and policy constraints outside the LLM.
5.  **Data-flow / capability checks:** track where sensitive values
    originate and constrain where they may flow. A synthetic secret must
    not be sent to an unauthorized destination merely because the model
    requests it.
6.  **Output/egress checks:** inspect simulated outbound actions and
    prevent prohibited disclosure or side effects.

Requirements: - each defense has a stable identifier and
configuration; - every allow/block/quarantine decision is logged; -
defenses can be switched on/off independently; - the system records
which defense caused a block; - the architecture allows a defense to be
replaced without rewriting the attack runner.

The first implementation should favor transparent, explainable policy
checks over complex heuristics. LLM-based classifiers may be optional,
not a hard dependency.

## FR-06: Provenance and capability tracking

**Priority:** P0

Track the origin and permitted use of data as it moves through the
system.

At minimum, provenance metadata should identify: - source type; -
source/document/tool/memory ID; - trust classification; - run/session
ID; - creation or retrieval time; - whether the content contains a
canary or synthetic secret; - relevant transformation or relay steps.

Sensitive synthetic values should carry labels or capabilities so the
policy layer can reject unauthorized flows to tools or destinations.

The project is not required to reproduce CaMeL's formal guarantees.
Implement a practical, understandable prototype of provenance-aware
policy enforcement.

## FR-07: Stage-level propagation logger

**Priority:** P0

A central differentiator is to record how far an attack payload travels,
not only whether the final action succeeded.

Use a unique synthetic canary token per run or attack instance. Never
use a real secret as a canary.

Required conceptual stages:

1.  **Exposed:** the canary or attack marker appears in an untrusted
    source or tool result visible to the agent.
2.  **Persisted:** the canary appears in a persistent memory write or
    other durable store.
3.  **Relayed:** the canary is read or forwarded across the simulated
    inter-agent/message boundary.
4.  **Executed:** the canary or attack objective reaches an outbound
    tool argument or action request.

For surfaces that do not use every stage, mark the stage as not
applicable rather than treating it as a failure.

Requirements: - log each stage transition with timestamp, run ID, attack
ID, source/destination, and evidence reference; - record the furthest
stage reached; - distinguish "content reached a stage" from "the agent
successfully carried out the malicious objective"; - retain intermediate
events even when the final attack fails; - make stage definitions
extensible without changing the metric semantics silently.

## FR-08: Experiment runner

**Priority:** P0

The runner shall orchestrate repeatable experiments.

Required modes: - single attack run; - batch attack run; - baseline
configuration; - defended configuration; - defense ablation; - benign
utility run; - recovery/reset run.

Each run must record: - unique run ID; - timestamp; - model adapter and
model configuration; - attack ID and version, or benign task ID; -
defense configuration; - corpus and memory state identifiers; - random
seed where applicable; - agent response; - tool calls and policy
decisions; - propagation events; - evaluation outcome; - errors and
incomplete stages.

## FR-09: Evaluator and metrics

**Priority:** P0

Compute metrics from structured evidence, not from manually interpreted
dashboard labels.

Required metrics:

  -----------------------------------------------------------------------
  Metric                              Definition
  ----------------------------------- -----------------------------------
  Attack Success Rate (ASR)           Successful malicious objectives
                                      divided by valid attack runs

  Injection Success Rate (ISR)        Runs in which the attack content is
                                      successfully inserted into the
                                      intended target surface/state
                                      divided by eligible injection
                                      attempts

  Secret Leakage Rate                 Runs in which a synthetic secret
                                      reaches an unauthorized
                                      output/destination divided by
                                      eligible runs

  Unauthorized Tool Attempt Rate      Runs in which the agent requests a
                                      prohibited tool/action divided by
                                      eligible runs

  Unauthorized Tool Execution Rate    Runs in which a prohibited action
                                      passes enforcement and executes in
                                      the sandbox divided by eligible
                                      runs; should be zero for correctly
                                      enforced prohibited actions

  Defense Block Rate                  Prohibited attempts blocked by a
                                      defense divided by prohibited
                                      attempts observed

  False Refusal Rate                  Benign tasks incorrectly blocked or
                                      refused divided by benign tasks

  Benign Task Utility                 Fraction of benign tasks completed
                                      according to their expected outcome

  Recovery Success                    Previously compromised scenarios
                                      that return to safe expected
                                      behavior after cleanup/reset
                                      divided by recovery attempts

  Furthest Propagation Stage          Highest canary stage reached for
                                      each attack run
  -----------------------------------------------------------------------

Definitions and denominators must be documented in code and in the
experiment report. Report raw counts alongside percentages. Do not
compare rates when denominators or scenario populations differ without
explaining the difference.

Where useful, report stage transition counts (Exposed → Persisted →
Relayed → Executed) and the point at which propagation stopped.

## FR-10: Dashboard and visualization

**Priority:** P0

The dashboard is the main product differentiator. It must make security
behavior inspectable rather than merely decorative.

Use Streamlit for the application and Plotly/NetworkX for
visualizations.

Required dashboard areas:

1.  **Overview**
    -   total runs;
    -   attack success and injection success;
    -   secret leakage;
    -   unauthorized tool attempts/executions;
    -   false refusal and benign utility;
    -   baseline versus defended summary.
2.  **Attack library**
    -   attack ID, name, surface, objective, severity, and status;
    -   filters by surface/category/severity;
    -   launch or inspect a scenario.
3.  **Run explorer**
    -   select a run;
    -   show timeline of events;
    -   show agent/tool/policy sequence;
    -   show retrieved documents and memory events;
    -   show the furthest canary stage;
    -   expose the evidence behind each conclusion.
4.  **Attack-path visualization**
    -   graph of source → ingestion/retrieval → agent → memory/relay →
        tool/action;
    -   distinguish observed, blocked, and executed transitions;
    -   show provenance and policy decision at relevant edges.
5.  **Baseline-versus-defended comparison**
    -   compare the same attack set under matched conditions;
    -   show metric deltas and raw denominators;
    -   highlight regressions in benign utility.
6.  **Defense/ablation view**
    -   compare defenses enabled individually and in combination;
    -   identify which layer blocked each attempt.
7.  **Evidence/log view**
    -   searchable event table;
    -   filters by run, attack, surface, stage, and event type;
    -   inspect structured event payloads safely.
8.  **Export**
    -   export run summaries and experiment results as JSON and CSV;
    -   generate a concise Markdown report, with PDF optional later.

Visualization requirements: - every chart must be backed by persisted
experiment data; - use clear labels and legends; - never imply that a
blocked attempt was a successful compromise; - allow the user to move
from aggregate metrics to the underlying run evidence; - avoid
presenting a single ASR number without stage and utility context.

## FR-11: Persistence and storage

**Priority:** P0

Use: - **MySQL** as the canonical store for experiment metadata, run
records, event logs, policy decisions, and structured memory records; -
**ChromaDB** for document and retrieval embeddings; - optional local
JSON/JSONL artifacts for attack definitions, fixtures, and portable raw
evidence.

Requirements: - schema migrations or versioned initialization scripts; -
stable IDs and relationships between runs, attacks, events, documents,
and memory entries; - reset/seed scripts for deterministic
experiments; - clear separation between test fixtures and actual
application state; - no credentials committed to source control.

Neo4j is optional and should not be introduced until a concrete
graph-query or visualization need exceeds what NetworkX can provide.

## FR-12: Reporting

**Priority:** P1

Generate a report containing: - project and environment configuration; -
experiment objective and threat model; - attack and defense
configuration; - run counts and exclusions; - security metrics and
benign utility; - stage-level propagation summary; - representative
traces and evidence; - limitations and reproducibility details; -
mitigation recommendations.

------------------------------------------------------------------------

# 7. Non-functional requirements

## NFR-01: Local-first operation

The system should run on a developer workstation. Core testing must work
with the mock adapter even if Ollama or the local model is unavailable.

## NFR-02: Reproducibility

-   deterministic mock mode;
-   fixed seeds where possible;
-   versioned attack definitions;
-   explicit model and configuration metadata;
-   resettable corpora and memory;
-   persisted raw events;
-   repeatable run commands.

LLM outputs may be nondeterministic. Record generation settings and do
not promise identical outputs from a local generative model.

## NFR-03: Modularity

Separate: - agent adapters; - attack definitions and loading; - attack
execution; - tools; - RAG; - memory; - policy/defense middleware; -
provenance/capability tracking; - event logging; - evaluation; -
dashboard; - configuration.

Avoid a monolithic script or tight coupling between Streamlit and the
experiment runner.

## NFR-04: Reliability and error handling

A failed model call, unavailable database, invalid attack, or tool error
must be recorded as an error/incomplete run, not silently counted as a
successful defense.

## NFR-05: Performance

Prioritize correctness and traceability over throughput. Batch execution
should be supported, but the MVP does not require distributed workers or
high concurrency.

## NFR-06: Security

-   no real secrets;
-   no unrestricted execution;
-   no outbound network access from simulated tools;
-   least-privilege tool design;
-   parameterized SQL;
-   local configuration/secrets excluded from version control;
-   safe handling of malicious payloads in the UI and logs.

## NFR-07: Usability

A user should be able to initialize the environment, seed test data, run
an attack, enable a defense, compare results, and inspect a trace using
documented commands and a clear dashboard workflow.

------------------------------------------------------------------------

# 8. Proposed system architecture

The architecture should be modular and event-driven. The following is a
logical architecture, not a requirement to adopt a specific framework.

``` text
                    ┌───────────────────────────┐
                    │       Streamlit UI        │
                    │ Overview / Runs / Graphs  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │ Experiment Orchestrator   │
                    │ run / batch / compare     │
                    └──────┬─────────────┬──────┘
                           │             │
             ┌─────────────▼───┐   ┌─────▼────────────┐
             │ Attack Library  │   │ Evaluator        │
             │ JSON + Validator│   │ Metrics + Report │
             └─────────────┬───┘   └─────▲────────────┘
                           │             │
                    ┌──────▼─────────────┴──────┐
                    │       Target Agent        │
                    │ Mock Adapter / Qwen      │
                    │ Ollama Adapter            │
                    └──────┬───────────────────┘
                           │
              ┌────────────▼─────────────┐
              │ Policy / Defense Layer   │
              │ Provenance + Capabilities│
              │ Tool Authorization       │
              └──────┬──────────┬────────┘
                     │          │
          ┌──────────▼───┐  ┌───▼─────────────────┐
          │ Tool Registry│  │ Context Services    │
          │ Sandboxed    │  │ RAG / Memory / Relay│
          └──────────┬───┘  └───┬─────────────────┘
                     │          │
                     └────┬─────┘
                          │
                ┌─────────▼──────────┐
                │ Event / Canary     │
                │ Propagation Logger │
                └─────────┬──────────┘
                          │
             ┌────────────▼─────────────┐
             │ MySQL + ChromaDB         │
             │ Runs / Events / Memory   │
             │ Documents / Embeddings  │
             └─────────────────────────┘
```

## 8.1 Architectural principles

-   The agent proposes actions; the policy layer authorizes them.
-   Untrusted content must retain source/provenance labels as it moves
    through the pipeline.
-   The logger should observe events at boundaries, not infer them from
    final natural-language responses.
-   The evaluator should consume persisted events and outcomes, not
    dashboard-specific state.
-   The dashboard must not be required for running experiments.
-   The mock adapter should allow all core software components to be
    tested without a model download.
-   A single target agent is the default. The relay is a controlled test
    fixture for inter-agent-message propagation.

## 8.2 Suggested project structure

The coding agent may adjust this after repository inspection, but should
preserve these logical boundaries.

``` text
prompt-injection-red-team-harness/
├── README.md
├── PRD.md
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── experiment-methodology.md
│   ├── metrics.md
│   ├── mitigation-guide.md
│   └── decisions.md
├── config/
│   ├── settings.yaml
│   └── defense_profiles.yaml
├── attacks/
│   ├── schema.json
│   ├── direct/
│   ├── rag/
│   ├── tool_output/
│   ├── memory/
│   └── relay/
├── data/
│   ├── fixtures/
│   ├── clean_documents/
│   ├── poisoned_documents/
│   └── synthetic_secrets/
├── src/
│   └── harness/
│       ├── agents/
│       ├── orchestrator/
│       ├── attacks/
│       ├── tools/
│       ├── retrieval/
│       ├── memory/
│       ├── defenses/
│       ├── provenance/
│       ├── telemetry/
│       ├── evaluation/
│       ├── storage/
│       └── reporting/
├── dashboard/
│   ├── app.py
│   └── pages/
├── scripts/
│   ├── init_db.py
│   ├── seed_data.py
│   ├── reset_environment.py
│   └── run_experiment.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── safety/
│   └── fixtures/
├── migrations/
├── requirements.txt
└── .env.example
```

Do not create every directory mechanically on day one. Add modules as
the vertical slice requires them.

------------------------------------------------------------------------

# 9. Data model and event design

The exact schema is an implementation task, but it must support the
following entities.

## 9.1 Core entities

-   **AttackDefinition:** versioned attack metadata and payload
    reference.
-   **Experiment:** a logical group of runs sharing an objective and
    configuration.
-   **Run:** one execution of an attack or benign task.
-   **AgentConfig:** adapter, model, prompt/configuration identifiers.
-   **DefenseConfig:** enabled defenses and parameters.
-   **Document:** source document and trust/provenance metadata.
-   **RetrievedChunk:** chunk ID, document ID, score, and retrieval
    position.
-   **MemoryEntry:** content/reference, trust label, provenance,
    timestamp, and status.
-   **ToolCall:** requested tool, arguments, permission, decision,
    result, and error.
-   **PolicyDecision:** allow/block/quarantine plus rule/defense and
    reason.
-   **PropagationEvent:** canary stage, source, destination, event time,
    and evidence reference.
-   **MetricResult:** metric name, numerator, denominator, value, and
    scope.
-   **BenignTaskResult:** expected outcome, actual outcome, and utility
    label.

## 9.2 Event log

Use a structured event model. A representative event should contain
fields such as:

``` json
{
  "event_id": "uuid",
  "run_id": "uuid",
  "attack_id": "RAG-001",
  "timestamp": "ISO-8601",
  "event_type": "tool_call_blocked",
  "stage": "tool_execution",
  "source_type": "retrieved_document",
  "source_id": "doc-123",
  "destination": "send_report",
  "canary_id": "synthetic-canary-id",
  "decision": "blocked",
  "defense_id": "capability_policy",
  "reason": "synthetic secret cannot flow to untrusted destination",
  "evidence_ref": "..."
}
```

This is illustrative; use a validated schema and avoid logging sensitive
raw data unnecessarily. Synthetic test payloads may be stored as
evidence.

## 9.3 Event integrity

-   Events should be append-only during a run.
-   A run should have a clear terminal status: completed, failed, or
    incomplete.
-   Metric calculations should be reproducible from stored events.
-   Store enough information to distinguish a model refusal, a defense
    block, a tool failure, and an attack that never reached the relevant
    stage.

------------------------------------------------------------------------

# 10. Attack library plan

The MVP should contain representative, understandable scenarios rather
than attempting to reproduce every paper's attack suite.

## 10.1 Initial scenario families

  -----------------------------------------------------------------------
  ID family               Surface                 Scenario objective
  ----------------------- ----------------------- -----------------------
  DIR                     Direct input            Attempt to override the
                                                  task or request a
                                                  synthetic secret

  RAG                     Retrieval               Poison a document so
                                                  retrieval influences
                                                  the answer or action

  TOOL                    Tool output             Put malicious
                                                  instructions in a
                                                  simulated tool result

  MEM                     Persistent memory       Cause unsafe content to
                                                  be written and
                                                  influence a later
                                                  session

  RELAY                   Simulated inter-agent   Carry malicious content
                          message                 across a controlled
                                                  message boundary
  -----------------------------------------------------------------------

## 10.2 Scenario design requirements

Each scenario must define: - the attacker's assumed access; - the
initial clean state; - the malicious content source; - the intended user
task; - the attack objective; - the expected safe behavior; - the
success predicate; - the relevant canary stages; - cleanup/reset
procedure; - one or more benign control tasks.

Do not equate "the model repeated malicious text" with "the attack
succeeded." Success must be based on a clearly specified harmful
objective, such as unauthorized synthetic-secret disclosure or an
unauthorized simulated tool action.

## 10.3 Adaptive evaluation

The literature review highlighted that static attacks can overstate
defense robustness. The project should therefore support a small number
of controlled variants per scenario, such as: - payload wording
variants; - alternate placement in a document or tool result; -
different retrieval relevance or top-k settings; - different session
orderings for memory tests; - alternate benign task phrasing.

For the MVP, these can be manually authored JSON variants. Automated
optimization, reinforcement learning, and large-scale adaptive attack
generation are deferred.

------------------------------------------------------------------------

# 11. Defense evaluation methodology

Every meaningful attack family should be evaluated under at least:

1.  **Baseline:** defenses disabled, with the same safety sandbox still
    active.
2.  **Defended:** selected defense profile enabled.
3.  **Ablation:** one defense component disabled at a time to understand
    its contribution.
4.  **Benign control:** legitimate tasks run under the same
    configurations.

For fair comparisons: - use the same attack definitions and initial
corpus/memory state; - record model and generation configuration; - use
the same task and tool fixtures; - reset state between independent
runs; - report repeated-run counts; - show raw counts and rates; -
distinguish stochastic model variation from code defects.

A defense should be assessed on both security and utility. A
configuration that blocks every request is not a successful defense.

## 11.1 Recovery testing

Recovery scenarios should test whether the system can: - identify the
relevant poisoned document or memory record; - quarantine or remove the
record; - reset or rebuild the affected retrieval/memory state; - rerun
the original benign task; - verify that the unsafe behavior no longer
occurs.

Recovery success must be measured, not assumed because a cleanup
function returned successfully.

------------------------------------------------------------------------

# 12. Literature basis and project relevance

The current literature survey has **10 core papers** and **2
supplementary papers**. This is the working literature set from the
latest review; it is not a requirement to reproduce the papers' systems.

## 12.1 Core papers retained

1.  **AgentDojo** --- provides an agent-security task/benchmark
    perspective and motivates evaluating realistic tool-using workflows
    rather than isolated prompts.
2.  **Defeating Prompt Injections by Design (CaMeL)** --- motivates
    capability-based tool authorization and explicit data/control-flow
    constraints.
3.  **The Attacker Moves Second: Stronger Adaptive Attacks Bypass
    Defenses Against LLM Jailbreaks and Prompt Injections** ---
    motivates adaptive attack variants and caution against claims based
    only on static payloads.
4.  **Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection
    Across Attack Surfaces and Five Production LLMs** --- strongly
    informs the stage-level canary design: Exposed → Persisted → Relayed
    → Executed.
5.  **Prompt Infection** --- informs propagation of malicious
    instructions across agent interactions and message boundaries.
6.  **Traceback of Poisoning Attacks to Retrieval-Augmented Generation
    (RAGForensics)** --- motivates source attribution and tracing
    poisoned retrieved content rather than relying only on output
    filtering.
7.  **Benchmarking Poisoning Attacks against Retrieval-Augmented
    Generation (RAG Security Bench)** --- motivates attack/defense
    comparisons across poisoning categories and RAG configurations.
8.  **AgentPoison: Red-teaming LLM Agents via Poisoning Memory or
    Knowledge Bases** --- informs retrieval-triggered poisoning of agent
    memory and knowledge stores.
9.  **MemoryGraft: Persistent Compromise of LLM Agents via Poisoned
    Experience Retrieval** --- informs indirect, persistent memory
    poisoning through apparently benign ingestion pathways.
10. **Zombie Agents: Persistent Control of Self-Evolving LLM Agents via
    Self-Reinforcing Injections** --- informs cross-session
    infection/trigger evaluation and the risk of memory evolution.

## 12.2 Supplementary papers

11. **Memory Poisoning Attack and Defense on Memory-Based LLM-Agents**
    --- useful for realistic memory-state conditions, trust scoring,
    memory sanitization, and security/utility trade-offs.
12. **PANDORA** --- retained as supplementary background from the
    literature review; consult the paper's exact findings when a
    specific design decision depends on it.

## 12.3 Excluded from the core survey

The latest literature review excluded: - LLM Agent Honeypot; -
Multi-Agent NLP Framework; - the duplicate AgentDojo copy.

The excluded papers should not be added back to the core set without a
clear gap they fill.

## 12.4 How the literature informs implementation

-   AgentDojo informs task-oriented evaluation, but full benchmark
    reproduction is out of scope.
-   CaMeL informs the independent capability/provenance enforcement
    layer; do not claim CaMeL-equivalent guarantees.
-   Adaptive-attack research informs manually curated attack variants
    and careful robustness claims.
-   Kill-chain canaries inform stage-level instrumentation and
    visualization.
-   RAGForensics and RAG Security Bench inform poisoning scenarios,
    retrieval evidence, and source traceback.
-   AgentPoison, MemoryGraft, and Zombie Agents inform
    retrieval-triggered and persistent cross-session memory tests.
-   Memory-poisoning defense work informs trust-aware memory controls
    and the need to measure false refusals and utility.

------------------------------------------------------------------------

# 13. Acceptance criteria

The MVP is considered complete when all of the following are
demonstrably working.

## 13.1 Core runtime

-   [ ] The project starts locally using documented setup instructions.
-   [ ] The mock agent runs without Ollama.
-   [ ] The local Qwen/Ollama adapter can be selected when available.
-   [ ] The agent can complete a benign task using at least one
    sandboxed tool.

## 13.2 Attack execution

-   [ ] At least one valid attack scenario exists for each of the five
    agreed surfaces.
-   [ ] Attack definitions are loaded from JSON and validated.
-   [ ] The runner supports single and batch runs.
-   [ ] Each run records its attack, model, configuration, and initial
    state.

## 13.3 Safety and defenses

-   [ ] Synthetic secrets are used throughout.
-   [ ] Tools cannot access arbitrary host resources or external
    networks.
-   [ ] Tool permissions are enforced outside the LLM.
-   [ ] At least one defense can block an unauthorized simulated action.
-   [ ] Defense decisions and reasons are logged.
-   [ ] Defenses can be individually enabled/disabled for ablations.

## 13.4 Evidence and metrics

-   [ ] Events are persisted and linked to a run.
-   [ ] Canary propagation is tracked through applicable stages.
-   [ ] The evaluator computes ASR, ISR, secret leakage, unauthorized
    tool rates, defense block rate, false refusal, benign utility, and
    recovery success where applicable.
-   [ ] Metric denominators and raw counts are visible.
-   [ ] Failed/incomplete runs are not silently counted as defended
    runs.

## 13.5 Visualization

-   [ ] The dashboard shows aggregate results.
-   [ ] A user can select a run and inspect its timeline.
-   [ ] An attack path/provenance graph is available.
-   [ ] Baseline and defended runs can be compared.
-   [ ] Aggregate findings can be traced to underlying events.

## 13.6 Reproducibility and documentation

-   [ ] A reset/seed workflow exists.
-   [ ] A repeatable experiment command exists.
-   [ ] Unit and integration tests cover critical boundaries.
-   [ ] README, architecture, threat model, metrics, and mitigation
    guide are present.
-   [ ] The report clearly states limitations and does not claim formal
    security guarantees.

------------------------------------------------------------------------

# 14. Next steps and task backlog

The next tasks are ordered to reduce architectural rework. The coding
agent should update this checklist as work is completed.

## Phase 0 --- Repository and environment reconnaissance

-   [x] Inspect the existing repository and identify current
    implementation, if any.
-   [x] Confirm Python version and package/environment manager.
-   [x] Check availability of Ollama and the intended Qwen model.
-   [x] Check MySQL availability and credentials/configuration approach.
    (Installed but stopped; DB/user creation pending user action.)
-   [x] Check ChromaDB compatibility and persistence location.
-   [x] Identify current UI framework state.
-   [x] Create or update `PRD.md` and `docs/decisions.md`.
-   [x] Report any conflicts or missing prerequisites before coding.

**Deliverable:** repository assessment and implementation plan —
see `docs/phase0-assessment.md` and `docs/decisions.md`.

## Phase 1 --- Architecture and contracts

-   [x] Define core Python interfaces for AgentAdapter, Tool,
    AttackScenario, Defense, EventLogger, and Evaluator.
-   [x] Define JSON attack schema and validation.
-   [x] Define event and propagation-event schemas.
-   [x] Define metric formulas and denominators.
-   [x] Define tool permission levels and synthetic-secret labels.
-   [x] Decide initial MySQL tables and ChromaDB collection strategy.
-   [x] Write architecture and threat-model documents.

**Deliverable:** architecture skeleton, schemas, and design notes —
see `src/harness/`, `attacks/`, `docs/architecture.md`,
`docs/threat-model.md`, `docs/metrics.md`, `docs/decisions.md`
(D-011–D-018).

## Phase 2 --- First end-to-end vertical slice

-   [x] Implement deterministic mock agent.
-   [x] Implement one benign task.
-   [x] Implement one sandboxed read tool and one simulated outbound
    tool.
-   [x] Implement one direct-input or tool-output attack.
-   [x] Implement a minimal policy middleware that blocks an
    unauthorized action.
-   [x] Implement synthetic canary generation and event logging.
-   [x] Implement evaluator for one attack and one benign task.
-   [x] Persist the run and events. (Verified on SQLite; MySQL pending
    service start.)
-   [x] Display the run timeline in a minimal Streamlit page.
-   [x] Add unit and integration tests.

**Deliverable:** a repeatable baseline-versus-defended demo with an
inspectable trace — `scripts/run_experiment.py`, `dashboard/app.py`.

## Phase 3 --- RAG surface

-   [x] Add document ingestion and chunk metadata.
-   [x] Integrate ChromaDB.
-   [x] Implement clean and poisoned document fixtures.
-   [x] Record retrieved chunks, scores, and provenance.
-   [x] Add RAG poisoning scenarios and benign controls.
-   [x] Add retrieval trust/provenance defense options.
-   [x] Add retrieval/source visualization and corpus reset.

**Deliverable:** RAG attack and defense experiments with source
attribution --- `RAG-001`/`BENIGN-002`, `harness/retrieval.py`,
`retrieval_screen` defense, "Retrieved sources" dashboard table.

## Phase 4 --- Persistent memory and relay surfaces

-   [ ] Implement persistent memory records in MySQL.
-   [ ] Implement append/retrieve/quarantine/delete/reset operations.
-   [ ] Add session IDs and cross-session experiments.
-   [ ] Add memory poisoning and recovery scenarios.
-   [ ] Implement simulated inter-agent message relay.
-   [ ] Track Exposed, Persisted, Relayed, and Executed stages.
-   [ ] Add memory provenance and trust-aware retrieval controls.
-   [ ] Visualize memory writes, reads, and relay paths.

**Deliverable:** cross-session and relay attack traces.

## Phase 5 --- Defense suite and comparative evaluation

-   [ ] Add configurable input/untrusted-content handling.
-   [ ] Add retrieval filtering/provenance checks.
-   [ ] Add memory write and retrieval controls.
-   [ ] Add tool permission and capability/data-flow enforcement.
-   [ ] Add simulated egress/output checks.
-   [ ] Implement baseline, defended, and ablation profiles.
-   [ ] Add controlled adaptive variants.
-   [ ] Add benign utility and false-refusal test sets.
-   [ ] Add recovery and reset experiments.

**Deliverable:** comparative security/utility benchmark.

## Phase 6 --- Dashboard and reporting

-   [ ] Build overview metrics page.
-   [ ] Build attack library page.
-   [ ] Build run explorer and event timeline.
-   [ ] Build attack-path graph using NetworkX/Plotly.
-   [ ] Build baseline-versus-defended comparisons.
-   [ ] Build defense ablation view.
-   [ ] Add evidence search/filtering.
-   [ ] Add JSON/CSV export and Markdown report generation.
-   [ ] Improve error states and dashboard usability.

**Deliverable:** demonstrable visualization-led security dashboard.

## Phase 7 --- Final validation and project handoff

-   [ ] Run the full test suite.
-   [ ] Run the full benchmark from a clean seeded state.
-   [ ] Verify all metrics from raw events.
-   [ ] Verify recovery and reset behavior.
-   [ ] Document machine specifications and model configuration.
-   [ ] Document known limitations and untested cases.
-   [ ] Prepare final architecture diagram and demonstration workflow.
-   [ ] Prepare final benchmark and mitigation report.
-   [ ] Tag a reproducible project version.

**Deliverable:** reproducible local project suitable for demonstration
and academic review.

------------------------------------------------------------------------

# 15. Risks and mitigations

  -----------------------------------------------------------------------
  Risk                    Impact                  Mitigation
  ----------------------- ----------------------- -----------------------
  Local model is slow or  Blocks                  Build mock adapter
  unavailable             development/testing     first; keep model
                                                  integration modular

  LLM output variability  Unstable metrics        Use deterministic mock
                                                  tests, repeat model
                                                  trials, record
                                                  configuration

  Scope grows into a full Project becomes         Preserve single-target
  agent platform          infeasible              scope and defer full
                                                  multi-agent features

  Defenses rely too       Weak security           Enforce permissions and
  heavily on prompts      demonstration           data-flow rules outside
                                                  the model

  Logs capture only final Cannot explain failures Instrument boundaries
  outcomes                or defense behavior     and persist stage-level
                                                  events

  Memory/RAG state        Invalid comparisons     Provide deterministic
  contaminates later                              seed/reset routines and
  tests                                           state identifiers

  False positives make    Benign utility degrades Include benign controls
  defenses look strong                            and false-refusal
                                                  metrics

  Dashboard becomes       Weak differentiator     Every visualization
  cosmetic                                        must link to persisted
                                                  evidence

  Dependencies are        Setup friction          Pin dependencies,
  difficult to install                            document service setup,
                                                  keep mock mode
                                                  self-contained

  Security testing        Unacceptable risk       Use allowlisted inert
  escapes the sandbox                             tools, synthetic data,
                                                  and no external
                                                  targets/network
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 16. Open decisions and assumptions

The following are not treated as finalized unless explicitly confirmed
in later project decisions. The coding agent should choose conservative
defaults and record them in `docs/decisions.md`.

1.  Exact Qwen model tag and quantization.
2.  Exact Python version and dependency manager.
3.  MySQL deployment method (local installation or local container).
4.  Exact schema and migration tool.
5.  Embedding model for ChromaDB.
6.  Exact initial attack count and repeat count per scenario.
7.  Final defense profile names and parameter values.
8.  Whether Neo4j adds enough value to justify setup.
9.  Whether the final report needs PDF output.
10. Whether the dashboard needs user authentication (not expected for a
    local single-user MVP).

Do not block the vertical slice on optional Neo4j, PDF reporting, or
authentication.

------------------------------------------------------------------------

# 17. Definition of done

The project is done when a developer can, from a clean local setup:

1.  initialize the databases and seed synthetic data;
2.  start the harness and dashboard;
3.  run a baseline attack against the local target agent;
4.  inspect where the attack content travelled;
5.  enable defenses and rerun the same scenario;
6.  see whether the attack was blocked and by which layer;
7.  compare attack success and benign utility;
8.  inspect the evidence behind the metrics;
9.  reset the environment and reproduce the experiment;
10. export a concise benchmark and mitigation report.

The final demonstration should make one point unmistakable: **the
harness does not only say whether an attack worked; it shows how far the
attack travelled, what the agent attempted, which controls intervened,
and what evidence supports the result.**

------------------------------------------------------------------------

# 18. Final instruction to the implementation agent

Start with Phase 0. Do not immediately implement every module described
here.

After repository inspection, propose the smallest vertical slice that
proves the complete architecture:

**one local/mock agent → one controlled attack → one sandboxed tool →
one independent defense decision → one canary/event trace → one
evaluator result → one dashboard visualization.**

Once this works and is tested, extend the same contracts to RAG,
persistent memory, and the simulated inter-agent relay. Preserve the
single-target architecture, balanced scope, local-first constraint, and
visualization-led differentiator throughout.
