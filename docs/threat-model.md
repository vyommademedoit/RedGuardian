# Threat Model

Summarises PRD §5 and maps it to the contracts in `src/harness/models.py`.

## Assets (all synthetic)

Synthetic secrets (`SecretSpec`, values `SECRET-<KIND>-<hex>`), sandbox records, memory store integrity, retrieval corpus integrity, tool authorization state, the user's intended task, and run evidence.

## Adversary

Controls content on exactly one surface per scenario (`AttackScenario.surface`), stated in `attacker_capability`:

| Surface | Attacker controls |
|---|---|
| `direct` | the user message |
| `rag` | one or more corpus documents |
| `tool_output` | text a simulated tool returns |
| `memory` | content that may be written to persistent memory |
| `relay` | a message on the simulated relay channel |

The adversary has no access to model weights, the system prompt, sandbox secrets, the host, or the network.

## Goals → `Objective`

`task_diversion`, `targeted_response`, `secret_disclosure`, `unauthorized_tool_use`, `poisoning`, `relay_propagation`, `persistence`, `denial_of_service`.

Success is a **structured predicate** (`success_condition`), never "the model repeated the payload".

## Trust boundaries → `SourceType` × `Trust`

| PRD §5.4 boundary | Representation |
|---|---|
| system/developer policy | `SourceType.SYSTEM`, `TRUSTED` |
| user task | `SourceType.USER`, `TRUSTED` |
| untrusted user content | `SourceType.USER`, `UNTRUSTED` (direct-input attacks) |
| retrieved documents | `DOCUMENT`, `UNTRUSTED` |
| tool outputs | `TOOL_OUTPUT`, `UNTRUSTED` |
| memory records | `MEMORY`, trust inherited from the content's origin |
| relay messages | `RELAY`, trust inherited from the sender session's taint |
| tool arguments / outbound requests | `Check(point=TOOL_CALL or EGRESS)` |
| policy layer | `Defense` implementations, outside the model |

Every piece of content carries a `Provenance`; transformations append to `Provenance.steps`.

## Containment (always on, including baseline)

- Allowlisted tools; arguments validated against each tool's JSON Schema before any policy check or execution; three permission levels (`read`, `write_internal`, `outbound`).
- `outbound` tools record intent only. No shell, real filesystem, or network from any tool.
- Synthetic data only; secrets generated per run.
- Reset procedures named in each scenario's `cleanup` and tested.

"Baseline" means *defenses* are off — never the sandbox.

## Out of scope

Real targets, real credentials, multimodal payloads, model-weight attacks, formal guarantees (PRD §2.2).
