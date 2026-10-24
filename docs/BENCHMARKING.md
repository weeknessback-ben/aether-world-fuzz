# Benchmarking

Fuzzing is stochastic. A single run is an anecdote, two runs of different
lengths are not a comparison, and a difference smaller than the noise is not a
result. This document records the method and the numbers it produced.

## Method

**Equal budgets.** Configurations differ in the variable under test and nothing
else.

**Several trials, distributions reported.** Minimum, median and maximum — never
a mean alone.

**Fixed seeds, derived and recorded.** Each trial's seed comes from the
experiment id and trial index, so an experiment replays.

**The `research-benchmark` profile.** It turns off the two things that make a
campaign depend on machine load: the cost-aware scheduler and the corpus cost
term. It explores less efficiently and replays from its seed, which is the
right trade for an experiment and the wrong one for real use.

**A difference is reported only when it exceeds the within-arm spread.** The
harness computes the spread between trials of a single arm and stays silent
when the between-arm difference does not clear it. Without that rule, noise
reads as a finding.

## The host these numbers come from

| | |
| --- | --- |
| CPU | Intel Xeon @ 2.10GHz, 4 cores (shared virtual machine) |
| Memory | 16 GB |
| OS | Ubuntu 24.04, kernel 6.18 |
| Compilers | clang 18.1.3, gcc 13.3.0 |
| Rust | 1.97.0 |
| Absent | AFL++, clang's `libclang_rt` (so no libFuzzer, no clang ASan), z3 |

A shared VM has noticeable run-to-run variance — ±7% on throughput — which is
why the protocol uses five repetitions and reports medians. Nothing here
generalises to other hardware or other targets.

## Execution throughput

1,200 executions per repetition, five repetitions, median reported.
Reproduce with `cargo test --release -p aether-core --test perf_probe -- --nocapture`.

| Configuration | Throughput | Per execution | Spread |
| --- | --- | --- | --- |
| Fork server, coverage + comparison log | **3,249 exec/s** | 308 µs | ±7% |
| Fork server, coverage only | 3,285 exec/s | 304 µs | ±12% |
| `execve` per run, coverage | 623 exec/s | 1,605 µs | ±4% |
| `execve` per run, uninstrumented | 634 exec/s | 1,577 µs | ±4% |

**Fork server: 5.21x.** This is the single largest engineering win in the
engine, and the reason it is the default.

**Comparison log: 1.1%** — inside the run-to-run spread, so the honest
statement is that its cost cannot be distinguished from noise at this
measurement precision. Against that, it changes the search complexity of a
magic-value gate from 2³² to one substitution. It is on by default.

**Instrumentation on the exec path: 1.8%.** Negligible next to the cost of
`execve` itself.

### A negative result worth keeping

Relocating per-execution scratch files to `/dev/shm` gave **3,099 exec/s against
3,249** — no improvement, within the ±12% spread. The test case and log files
are small and already absorbed by the page cache, so where they live is not on
the critical path. Recorded so it is not re-litigated.

## Coverage granularity

Measured on `fixtures/coverage_ladder.c`, which unlocks one more basic block
per correct prefix byte. Edge counts for inputs `""`, `"AE"`, `"AETH"`,
`"AETHER"`:

| Build | Guards | Edge counts |
| --- | --- | --- |
| `-O1`, default pruning | 5 | 2, 3, 3, 4 |
| `-O1`, `no-prune` | 10 | 7, 7, 7, 8 |
| `-O0`, `no-prune` | 19 | 10, 11, 13, 15 |

LLVM prunes guards in dominated blocks, which flattens exactly the gradient
corpus ranking depends on. `no-prune` is therefore always passed; `-O0` gives
the most sensitive signal and `-O1` is the default compromise.

## Comparison-guided substitution

`fixtures/crash_magic.c` gates an `abort()` behind four nested constant
comparisons. Equal budget, equal seed, single strategy each:

| Strategy | Executions | Edges reached | Reached the defect |
| --- | --- | --- | --- |
| `cmplog-guided` | 17,374 | **12** | **yes** |
| `random-mutation` | 19,304 | 6 | no |

Blind mutation ran *more* executions and got nowhere: it never passed the first
32-bit gate, which is the expected outcome of searching 2³² blindly. This is
the clearest demonstration in the suite that the comparison log earns its 1%.

Asserted as a test, not just measured:
`comparison_guided_substitution_beats_blind_mutation_on_a_magic_ladder` in
`crates/aether-core/tests/campaign_e2e.rs`, which also asserts that blind
mutation does *not* succeed — if it ever did, the comparison would be
meaningless and the test should fail.

## Experiments

`aether benchmark list` gives the catalogue with each experiment's status.

| | Comparison | Status |
| --- | --- | --- |
| A | Black-box against coverage-guided | Implemented |
| B | Static allocation against adaptive scheduling | Implemented |
| C | Mutation only against hybrid mutation and generation | Implemented |
| D | Coverage-only against coverage plus semantic signals | Implemented |
| E | Blind mutation against comparison-guided substitution | Implemented |
| F | Classical against quantum-inspired optimisers | In `tests/optimizer_tuning.rs` |
| G | Worker scaling, 1 / 2 / 4 workers | Implemented |

```bash
aether benchmark run --experiment e --config aether.toml --trials 5 --duration 60
aether benchmark run --experiment g --config aether.toml --trials 3 --duration 20
```

**G measures equal wall clock, not equal executions.** The question is how much
throughput and coverage an extra worker buys, which equal wall clock answers
directly. A worker count above the host's core count measures oversubscription
rather than scaling, and the observations say so when it happens.

**F benchmarks solvers rather than campaigns**, so it lives with the
hyperparameter sweeps:

```bash
cargo test --release -p aether-core --test optimizer_tuning -- --nocapture
```

## Experiment F: the quantum-inspired optimisers

Full numbers and the derivation are in
[DECISIONS.md](DECISIONS.md#d13-quantum-inspired-optimisation-measured-tuned-and-not-made-the-default).
In summary, against exhaustive ground truth (n=16, k=5, 24 instances):

| Solver | Mean fraction of optimum | Reached optimum |
| --- | --- | --- |
| greedy | **0.9985** | 21/24 |
| quantum-inspired evolutionary | 0.9792 | 14/24 |
| simulated annealing | 0.9743 | 10/24 |
| simulated quantum annealing | 0.9461 | 0/24 |

**Greedy wins.** Max-coverage is submodular, so greedy carries a proven
`1 − 1/e` bound, and in practice it reached 99.85% of optimal. Nothing in the
lab displaces it as the default.

**The one positive result:** the quantum-inspired evolutionary solver
consistently beats classical simulated annealing — its direct classical
analogue — by about four percentage points at every budget tested (5 ms, 25 ms,
100 ms) and on both problem shapes. That is a comparison between two classical
algorithms, and it is stated as such.

No quantum speedup is claimed. Every solver here runs on a classical CPU.

## Reproducibility, precisely

What holds:

- **The execution budget is exact.** Verified repeatedly: 800 means 800.
- **The execution layer is deterministic.** Replaying a fixed input sequence
  through a fresh executor gives identical coverage every time (4/4 runs).
- **Strategy proposals and RNG streams replay** under a fixed seed, asserted
  per strategy.

What does not hold, and why:

- **A whole campaign does not replay byte-for-byte.** The adaptive schedulers
  reward discovery per unit of *measured* compute, and the corpus ranks cheaper
  inputs higher. Both read a wall-clock duration, so machine load changes what
  gets explored. That is deliberate in a real campaign and fatal to an
  experiment, which is what `research-benchmark` exists for.
- **Even with cost awareness off, a residual variance remains.** Repeated runs
  agree in roughly five cases out of six and otherwise differ by a single edge.
  The source has not been isolated. It is recorded as a known limitation rather
  than papered over, and the end-to-end test asserts the observed tolerance
  rather than a determinism the engine does not currently provide.

## Experiment G: what worker scaling measured

Run on `coverage_ladder`, 3 trials per arm, 20 seconds per campaign, on a
four-core host:

| Arm | exec/s median | Edges min/med/max | Findings |
| --- | --- | --- | --- |
| 1 worker | 2 540 | 9 / 9 / 9 | 0 |
| 2 workers | 5 619 | 9 / 9 / 9 | 0 |
| 4 workers | 10 549 | 9 / 9 / 9 | 0 |

**Throughput scaled roughly linearly** — 2.21× and 4.15× — up to the core
count.

**Coverage did not move at all.** `coverage_ladder` saturates its reachable
coverage almost immediately, so every arm reached 9 edges with zero spread
between trials. The extra workers bought throughput and, on this target at this
budget, nothing else. Throughput is not the objective; no arm produced a
reproducible finding.

**A per-worker efficiency above 1.0 is a property of the baseline, not a
speedup.** The single-worker arm runs the *sequential* campaign loop, which is
a different and more expensive code path than a pooled worker. Measured
directly with `time` on 10-second campaigns:

| workers | exec/s | cores used | CPU per execution |
| --- | --- | --- | --- |
| 1 | 2 433 | 1.02 | 418 µs |
| 2 | 5 651 | 2.08 | 366 µs |
| 3 | 7 795 | 2.85 | 365 µs |
| 4 | 9 869 | 3.32 | 336 µs |

The per-execution CPU cost drops at the *first* pooled arm, so it is the code
path and not the parallelism. One candidate cause was tested and ruled out
(DECISIONS.md D15); the remainder is not isolated, and the experiment's own
output says so next to the number rather than letting it read as super-linear
scaling. Core utilisation never reached 4.0, so the pool leaves headroom on
this host.

## Caveats on every number here

- Single host, short campaigns. Every number above is from one four-core
  container and describes these fixtures on this machine.
- Coverage is a proxy. The objective is reproducible findings, and a
  configuration that reaches more edges while finding nothing has not been shown
  better at what matters.
- Short campaigns favour fast strategies; one that needs time to build a corpus
  looks bad at 30 seconds and may win at an hour.
- Fuzzing results generalise poorly between targets. A result on one parser
  says little about another.
- The fixtures have *planted* defects. Finding a planted abort behind four
  constant gates demonstrates that substitution works; it says nothing about
  how the engine performs on a real codebase.

## External suites

FuzzBench and Magma would give comparisons against established fuzzers on real
targets. Neither is integrated: both need substantial infrastructure, and
neither is installable on this host. No comparison against AFL++ or libFuzzer
appears anywhere in this document, because neither could be run — and quoting
their published numbers against measurements from this machine would not be a
comparison.
