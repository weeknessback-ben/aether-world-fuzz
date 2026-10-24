# Implementation plan and status

Status is recorded against what is actually built and tested, not against what
is intended. `done` means the code exists, has tests, and the tests pass on the
development host.

Legend: `done` | `partial` | `interface-only` | `not started`

## Phase 0 - Audit and architecture

| Item | Status |
| --- | --- |
| Repository and environment audit | done |
| Toolchain capability probes (clang/gcc/fuzzers/solvers/sandbox) | done |
| Verify current Claude Code plugin + skill schemas against the docs | done |
| Architecture, threat model, decision record | done |
| Working build and test workflow | done |

Findings that shaped the design are recorded in
[DECISIONS.md](DECISIONS.md#d1-own-coverage-runtime-instead-of-wrapping-an-existing-fuzzer).

## Phase 1 - Vertical slice

| Item | Status |
| --- | --- |
| C coverage runtime: edge map, comparison log, fork server | done |
| `aether-cc` target build wrapper | done |
| Shared-memory ABI with header validation | done |
| Native executor: fork server + exec fallback | done |
| Resource limits with honest enforcement reporting | done |
| Sanitizer report parsing | done |
| Exit classification | done |
| Test fixtures (10 programs) | done |
| Feedback: coverage novelty, signal aggregation | in progress |
| Corpus: content-addressed store + SQLite metadata | not started |
| Finding detection and reproduction | not started |
| Report generation | not started |

## Phase 2 - Hybrid strategies

| Item | Status |
| --- | --- |
| Strategy trait and registry | not started |
| Random / havoc / boundary mutation | not started |
| Dictionary mutation | not started |
| Comparison-guided (input-to-state) mutation | not started |
| Grammar-aware generation | not started |
| Structure-aware mutation | not started |
| Evolutionary search | not started |
| Splice | not started |
| Thompson Sampling / UCB1 scheduler | not started |
| Stagnation detection with hysteresis | not started |
| Multi-objective corpus scoring | not started |

## Phase 3 - Evidence and resilience

| Item | Status |
| --- | --- |
| Finding state machine | not started |
| Failure signatures and deduplication | not started |
| Delta-debugging minimisation | not started |
| Reproduction classification | not started |
| Checkpoint and recovery | not started |
| Cancellation | not started |
| SARIF export | not started |

## Phase 4 - Claude Code integration

| Item | Status |
| --- | --- |
| CLI command groups | not started |
| MCP server | not started |
| Skills | not started |
| Agents | not started |
| Plugin manifest and hooks | not started |
| Installation and health check | not started |

## Phase 5 - Advanced exploration

| Item | Status |
| --- | --- |
| Semantic feedback providers | not started |
| Stateful sequence generation | not started |
| Differential oracle | not started |
| Metamorphic oracle | not started |
| Constraint-assisted exploration | not started |

## Phase 6 - Distributed execution

| Item | Status |
| --- | --- |
| Local multi-worker pool | not started |
| Result aggregation and backpressure | not started |
| Remote worker interfaces | not started |

## Phase 7 - Quantum-inspired optimisation lab

| Item | Status |
| --- | --- |
| Optimizer interface | not started |
| Classical baselines | not started |
| Simulated annealing | not started |
| Quantum-inspired evolutionary solver | not started |
| Equal-budget comparison harness | not started |

## Phase 8 - Validation

| Item | Status |
| --- | --- |
| Unit tests | in progress |
| Integration tests | in progress |
| Security tests | not started |
| Benchmark experiments A-G | not started |
| CI | not started |

## Test counts

Updated as work lands:

| Suite | Count | Result |
| --- | --- | --- |
| `aether-core` unit | 85 | pass |
| `exec_native` integration | 18 | pass |
| `perf_probe` | 1 | pass |
