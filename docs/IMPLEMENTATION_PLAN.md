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
| Differential oracle | done — compares exit class, exit code and standard output against a second implementation; stderr and timing deliberately excluded (D18) |
| Metamorphic oracle | done — five declared relations, none enabled by default, because a relation is a claim about the target AETHER cannot verify (D17) |
| Oracle execution budget | done — a hard cap as a share of the campaign, with refusals counted so partial coverage is reported |
| Constraint-assisted exploration | **partial** — comparison-guided substitution is the constraint assistance that exists; no symbolic or SMT backend is wired in, and the stagnation detector records that the escalation was requested and not performed |

## Phase 6 — Distributed execution

| Item | Status |
| --- | --- |
| Local worker abstraction, transport, backpressure, priority | done |
| Multi-worker campaign execution | done — a real thread pool over one shared corpus and coverage map, with a two-tier novelty check so the common path takes no lock (D14) |
| Shared scheduler statistics | done — one lock per round, measured at 0.26 s of 100 worker-seconds (D20) |
| Pool instrumentation | done — redundant discoveries, lock wait, per-worker load and worker failures are all reported |
| Stagnation escalation in a pool | **not applied, by decision** — the detector reads one sequential stream of rounds, and advice from several workers' interleaved rounds would not mean what it says. The report records it as a limitation |
| Remote worker transport | **interface-only** — `WorkerTransport` defines registration, capability negotiation, leasing, heartbeats and result delivery; only `LocalTransport` exists |

`aether doctor` reports distributed execution as unavailable and the local pool
as available with the host's core count. Benchmark experiment G measures
scaling across 1, 2 and 4 workers: throughput scaled 2.21× and 4.15× on a
four-core host, and coverage did not move on a fixture that saturates
immediately (D16).

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
| Unit tests | done (457) |
| Integration tests | done (`exec_native`, 21, including the C++ build path, virtual-call coverage and the `--opt` regression) |
| End-to-end tests | done (`campaign_e2e`, 19, including three pooled and three oracle) |
| Security tests | done (`security`, 23, including five for the oracle and worker surfaces) |
| Benchmark experiments | A–E and G implemented, F in the sweep harness |
| Performance probe | done |
| CI | done (lint, runtime, test, integration, pooled campaign, differential oracle, plugin, gcc-only degraded host) |

## Test count

| Suite | Count | Result |
| --- | --- | --- |
| `aether-core` unit | 457 | pass |
| `exec_native` integration | 21 | pass |
| `campaign_e2e` end-to-end | 19 | pass |
| `security` | 23 | pass |
| `optimizer_tuning` | 6 | pass |
| `perf_probe` | 1 | pass |
| **Total** | **527** | **pass** |

`cargo clippy --all-targets` reports no warnings; `cargo fmt --check` is clean.

## What remains, in the order worth doing it

Ordered by what the measurements say is worth doing, not by what sounds
impressive.

1. **Isolate the residual replay variance.** Campaigns agree in roughly five
   runs out of six under `research-benchmark` and otherwise differ by a single
   edge. The execution layer is proven deterministic in isolation, so the cause
   is in scheduling. This is first because every benchmark number above rests
   on it.
2. **Find out why a pooled worker costs less CPU per execution than the
   sequential loop** — 336–366 µs against 418 µs (D16). One candidate was
   tested and ruled out (D15). Whatever the sequential loop is paying for, a
   single-worker campaign is paying it too.
3. **Context fragmentation in the scheduler.** 36 contexts over a short
   campaign leaves each cell with too few rounds; the shrinkage prior (D19)
   mitigates it but does not solve it. Fewer, better-chosen context dimensions
   would likely beat a better estimator.
4. **A constraint-solving backend.** The escalation path exists and reports
   that it cannot act.
5. **Remote workers.** `WorkerTransport` is ready. Lower priority than it
   looks: throughput already scales to the core count, and throughput is not
   the objective.
6. **Verify the libFuzzer and AFL++ adapters** against the real engines on a
   host where they install.
5. **Verify the libFuzzer and AFL++ adapters** on a host where those engines can
   actually be installed.
6. **FuzzBench or Magma**, for comparison against established fuzzers on real
   targets rather than on fixtures with planted defects.
