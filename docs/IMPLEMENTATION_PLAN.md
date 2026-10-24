# Implementation plan and status

Status reflects what is built and tested, not what is intended. `done` means
the code exists, has tests, and the tests pass on the development host.

Legend: `done` | `partial` | `interface-only` | `not implemented`

## Phase 0 — Audit and architecture

| Item | Status |
| --- | --- |
| Repository and environment audit | done |
| Toolchain capability probes (compilers, fuzzers, solvers, sandbox) | done |
| Verify current Claude Code plugin and skill schemas against the docs | done |
| Architecture, threat model, decision record | done |
| Working build and test workflow | done |

The audit decided the architecture: clang can compile SanitizerCoverage
instrumentation here but no `libclang_rt` archives are installable, and AFL++
has no package candidate, so AETHER provides its own runtime rather than
wrapping an absent engine. See
[DECISIONS.md](DECISIONS.md#d1-own-coverage-runtime-instead-of-wrapping-an-existing-fuzzer).

## Phase 1 — Vertical slice

| Item | Status |
| --- | --- |
| C coverage runtime: edge map, comparison log, fork server | done |
| `aether-cc` build wrapper | done |
| Shared-memory ABI with header validation | done |
| Native executor: fork server with exec fallback | done |
| Resource limits with honest enforcement reporting | done |
| Sanitizer report parsing | done |
| Exit classification | done |
| Test fixtures | done (11 programs) |
| Feedback: coverage novelty, signal aggregation | done |
| Corpus: content-addressed store + SQLite metadata | done |
| Finding detection and reproduction | done |
| Report generation | done (JSON, Markdown, SARIF, bench-JSON) |

Exit condition met: `campaign_e2e` drives a real instrumented target to a
reproduced, minimised finding.

## Phase 2 — Hybrid strategies

| Item | Status |
| --- | --- |
| Strategy trait and registry with requirement filtering | done |
| Random / havoc / boundary mutation | done |
| Dictionary mutation with per-token productivity weighting | done |
| Comparison-guided (input-to-state) substitution | done |
| Grammar-aware generation | done |
| Structure-aware mutation | done |
| Evolutionary search | done |
| Splice | done |
| Stateful sequence generation | done |
| Thompson Sampling and UCB1 schedulers | done |
| Stagnation detection with hysteresis | done |
| Multi-objective corpus scoring | done |

Exit condition met: strategies run concurrently and their measured
effectiveness differs — Experiment E shows comparison-guided substitution
reaching a defect that blind mutation does not at equal budget.

## Phase 3 — Evidence and resilience

| Item | Status |
| --- | --- |
| Finding state machine with checked transitions | done |
| Failure signatures and deduplication | done |
| Delta-debugging minimisation preserving the signature | done |
| Reproduction classification | done |
| Checkpoint and recovery | done |
| Cancellation, including across processes | done |
| SARIF export | done |
| Scope authorization enforced pre-execution | done |

## Phase 4 — Claude Code integration

| Item | Status |
| --- | --- |
| CLI command groups with `--json` and meaningful exit codes | done |
| MCP server (16 typed tools, bounded output, job ids) | done |
| Skills | done (4) |
| Agents | done (3) |
| Plugin manifest, MCP config, hooks | done — passes `claude plugin validate` |
| Installation and health check | done |

Exit condition met: a campaign was designed, started, polled to completion,
and reported through MCP over real JSON-RPC stdio.

## Phase 5 — Advanced exploration

| Item | Status |
| --- | --- |
| Semantic feedback providers | done (exit class, response transitions, invariants) |
| Stateful sequence generation | done |
| Differential oracle | **not implemented** — fixtures exist (`diff_impl_a/b.c`), the oracle does not |
| Metamorphic oracle | **not implemented** |
| Constraint-assisted exploration | **partial** — comparison-guided substitution is the constraint assistance that exists; no symbolic or SMT backend is wired in, and the stagnation detector records that the escalation was requested and not performed |

## Phase 6 — Distributed execution

| Item | Status |
| --- | --- |
| Local worker abstraction, transport, backpressure, priority | done |
| Multi-worker campaign execution | **not implemented** — the controller runs a single loop |
| Remote worker transport | **interface-only** — `WorkerTransport` defines registration, capability negotiation, leasing, heartbeats and result delivery; only `LocalTransport` exists |

`aether doctor` reports distributed execution as unavailable, and benchmark
experiment G refuses to run rather than report a fabricated scaling number.

## Phase 7 — Quantum-inspired optimisation lab

| Item | Status |
| --- | --- |
| Optimizer interface | done |
| QUBO formulation (corpus subset, budget allocation) | done |
| Classical baselines (greedy, exhaustive ground truth) | done |
| Simulated annealing | done |
| Quantum-inspired evolutionary algorithm | done |
| Simulated quantum annealing (Trotter replicas, transverse field) | done |
| Hyperparameter sweeps | done |
| Equal-budget comparison harness | done |
| External quantum-solver adapter | **not implemented** — none available |

Exit condition met: the lab answers its question with evidence. Greedy wins on
both problems; the quantum-inspired evolutionary solver consistently beats
classical simulated annealing. Recorded in
[DECISIONS.md D13](DECISIONS.md#d13-quantum-inspired-optimisation-measured-tuned-and-not-made-the-default).

## Phase 8 — Validation

| Item | Status |
| --- | --- |
| Unit tests | done (418) |
| Integration tests | done (`exec_native`, 18) |
| End-to-end tests | done (`campaign_e2e`, 13) |
| Security tests | done (`security`, 18) |
| Benchmark experiments | A–E implemented, F in the sweep harness, G refused |
| Performance probe | done |
| CI | done (lint, runtime, test, integration, plugin, gcc-only degraded host) |

## Test count

| Suite | Count | Result |
| --- | --- | --- |
| `aether-core` unit | 418 | pass |
| `exec_native` integration | 18 | pass |
| `campaign_e2e` end-to-end | 13 | pass |
| `security` | 18 | pass |
| `optimizer_tuning` | 6 | pass |
| `perf_probe` | 1 | pass |
| **Total** | **474** | **pass** |

`cargo clippy --all-targets` reports no warnings; `cargo fmt --check` is clean.

## What remains, in the order worth doing it

1. **Multi-worker campaigns.** The largest gap. The abstraction is in place;
   the controller needs to drive several executors and merge their coverage.
   Would make experiment G meaningful.
2. **Differential and metamorphic oracles.** The fixtures and the design
   (oracles, not strategies — see
   [D11](DECISIONS.md#d11-differential-and-metamorphic-testing-are-oracles-not-generators))
   exist; the implementations do not.
3. **Isolate the residual replay variance.** Campaigns agree in roughly five
   runs out of six under `research-benchmark` and otherwise differ by a single
   edge. The execution layer is deterministic, so the cause is in scheduling.
4. **A constraint-solving backend.** The escalation path exists and reports
   that it cannot act.
5. **Verify the libFuzzer and AFL++ adapters** on a host where those engines can
   actually be installed.
6. **FuzzBench or Magma**, for comparison against established fuzzers on real
   targets rather than on fixtures with planted defects.
