# Design decisions

Each entry records what was decided, what the alternatives were, and - where
the decision was driven by measurement - the numbers it came from. Numbers were
produced on the development host described in
[BENCHMARKING.md](BENCHMARKING.md); they are not claims about other hardware.

---

## D1. Own coverage runtime instead of wrapping an existing fuzzer

**Decision.** AETHER ships `runtime/aether_rt.c`, a dependency-free C runtime
that implements the SanitizerCoverage callbacks, and drives targets itself.

**Why.** The host audit found clang 18 able to *compile* `trace-pc-guard` and
`trace-cmp` instrumentation, but with no `libclang_rt.*` archives present and
no installation candidate, so `-fsanitize=fuzzer` cannot link and clang's
AddressSanitizer is unavailable. AFL++ has no package candidate either.
Wrapping an absent engine would have produced a tool that cannot run.

Linking compiler-emitted instrumentation against our own runtime was verified
to work before any engine code was written, including recovery of comparison
operands (`const=0xdeadbeef got=0x41414141` on the first probe).

**Consequence.** The native backend is the only one exercised end to end. The
libFuzzer and AFL++ adapters are interface-complete and report
`verified: false`, which `aether doctor` surfaces. See
[D9](#d9-third-party-adapters-ship-unverified).

---

## D2. Fork server as the default execution mode

**Decision.** Exec the target once and have its runtime fork a child per test
case, falling back to `execve`-per-run automatically if the handshake fails.

**Measured.** 1,200 executions per repetition, 5 repetitions, median reported:

| Configuration | Throughput | Per execution |
| --- | --- | --- |
| Fork server, coverage + comparison log | **3,249 exec/s** | 308 us |
| `execve` per run, coverage | 623 exec/s | 1,605 us |

**5.21x** speedup. The fallback matters: a binary with no AETHER runtime linked
in has no fork server to offer, and must still run.

**Rejected.** An in-process persistent mode (libFuzzer-style) would be faster
again, but a crash then takes down the engine along with the target, and the
harness has to be written against AETHER's API. Fork-per-input keeps any
executable usable and keeps a crash contained.

---

## D3. Comparison log on by default

**Decision.** Enable `trace-cmp` recording whenever the compiler supports it.

**Measured.** 1.1% throughput cost (3,249 vs 3,285 exec/s), which is inside the
+/-7% run-to-run spread on this host. Against that, the comparison log turns the
four nested constant gates in `fixtures/crash_magic.c` from a ~2^64 blind search
into four substitutions.

A cost that cannot be distinguished from noise, against a change in search
complexity, is not a trade-off worth making configurable-off by default.

---

## D4. Scratch files stay on the default temp directory

**Decision.** Do not relocate per-execution scratch files to `/dev/shm`.

**Measured.** tmpfs scratch came out at 3,099 exec/s against 3,249 for the
default location: **-4.6%**, i.e. no improvement, and within the +/-12% spread.
A negative result, recorded so it is not re-litigated: the test case and log
files are small and already absorbed by the page cache, so where they live is
not on the critical path.

---

## D5. Fused snapshot-and-bucket pass over the coverage map

**Decision.** `CoverageShm::snapshot_classified` copies and buckets the 65,536
slot map in one pass, reading 8 bytes at a time and skipping zero words.

**Why.** This runs once per execution. A copy followed by a separate classify
pass walks the whole map twice, and a real target touches a small fraction of
it. Combined with dropping a per-run `dup`/`close` pair on the log handles and
short-circuiting empty logs, this took throughput from 3,246 to ~3,461 exec/s in
the single-repetition measurement (+6.6%); under the 5-repetition protocol the
two sit within each other's spread, so the honest claim is "no measurable
regression, less work per execution".

---

## D6. Coverage granularity: `no-prune`, and a selectable optimisation level

**Decision.** Pass `-fsanitize-coverage=trace-pc-guard,trace-cmp,no-prune`, and
expose `--opt` on `aether-cc`, defaulting to `-O1`.

**Measured** on `fixtures/coverage_ladder.c`, which unlocks one more block per
correct prefix byte. Edge counts for inputs `""`, `"AE"`, `"AETH"`, `"AETHER"`:

| Build | Guards | Edge counts |
| --- | --- | --- |
| `-O1`, default pruning | 5 | 2, 3, 3, 4 |
| `-O1`, `no-prune` | 10 | 7, 7, 7, 8 |
| `-O0`, `no-prune` | 19 | 10, 11, 13, 15 |

Pruning removes guards in dominated blocks, which flattens exactly the gradient
corpus ranking depends on. `-O0` gives the most sensitive signal and is what the
fixtures' coverage tests use; `-O1` is the default because throughput matters
too.

---

## D7. Address-space limit is dropped for sanitizer builds, and the swap is reported

**Decision.** Do not apply `RLIMIT_AS` to a target that links a sanitizer
runtime. Bound memory with the sanitizer's own `hard_rss_limit_mb` instead, and
record the substitution in `LimitReport::memory_limit_substituted`.

**Why.** Found by a failing test, not by reading documentation: the ASan build
of `fixtures/heap_oob.c` died with

```
AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes
ReserveShadowMemoryRange failed while trying to map 0xdfff0001000 bytes
```

ASan reserves roughly 20 TiB of shadow address space at startup, so any memory
budget a campaign would plausibly set stops the target from starting rather than
bounding it.

The engine sets `ASAN_OPTIONS` itself while `target.env` *refuses* those
variables ([D8](#d8-configuration-may-not-set-loader-or-sanitizer-variables)).
That asymmetry is deliberate: the engine turns the oracle up and adds the RSS
bound, and configuration is not allowed to turn it down.

---

## D8. Configuration may not set loader or sanitizer variables

**Decision.** `target.env` rejects `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
the `DYLD_*` pair, `*SAN_OPTIONS`, and the `AETHER_*` control variables.

**Why.** Those names change which code runs, or suppress the crash oracle. A
config file that can set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0` can make
a campaign silently stop finding things. Targets are also launched with
`env_clear()`, so a variable in the operator's shell cannot change what is
tested either.

---

## D9. Third-party adapters ship unverified

**Decision.** The libFuzzer and AFL++ adapters declare their full contract and
carry `verified: false`.

**Why.** Neither engine is installable on this host, so their drive paths have
never run against the real thing. Detection probes for the *runtime archive*,
not just for clang, because this host is precisely the case that would otherwise
report libFuzzer as available and then fail at link time.

---

## D10. Threads, not async, for the worker pool

**Decision.** `std::thread` plus `crossbeam-channel`. No async runtime.

**Why.** The work is CPU-bound process supervision, a few workers deep. An async
runtime would add a large dependency and a scheduler for concurrency that
`fork`/`waitpid` do not benefit from. Blocking a thread on `waitpid` is the
natural shape.

---

## D11. Differential and metamorphic testing are oracles, not generators

**Decision.** Implement them as `Oracle` implementations rather than as
`Strategy` implementations, even though the specification groups them under
input generation.

**Why.** Neither produces inputs. Both take an input some other strategy
produced and decide whether the behaviour it caused is acceptable - a
disagreement between two implementations, or a violated relation. Modelling them
as strategies would have required a strategy that returns no candidates, and
would have put the comparison logic on the wrong side of the interface.

---

## D12. 128-bit content hashes

**Decision.** BLAKE3 truncated to 128 bits, as 32 lowercase hex characters.

**Why.** At any corpus size AETHER will see, 128 bits is far below practical
collision risk, and it halves the index and path length against a full 256-bit
digest. Hashes that arrive from outside the process are validated as plain
lowercase hex before they are used to build a path.

---

## D13. Quantum-inspired optimisation: measured, tuned, and not made the default

**Decision.** The optimisation lab ships with three stochastic solvers beside a
classical greedy baseline. Greedy remains the default. The quantum-inspired
solvers are retained as a research capability with their measurements attached,
and the module stays off unless explicitly enabled.

**What was built.** Corpus subset selection and strategy budget allocation are
reduced to QUBO (derivation in `intel::qubo`'s module documentation). Four
solvers run against it: greedy, simulated annealing, a quantum-inspired
evolutionary algorithm (QIEA, probability-amplitude registers with rotation
gates, after Han and Kim 2002), and discrete-time simulated quantum annealing
(SQA, Trotter replicas coupled through a transverse field).

**Hyperparameters were swept, not guessed** (`tests/optimizer_tuning.rs`, 25 ms
budget, three instance families, objective relative to greedy):

| Solver | Best configuration found | Mean ratio |
| --- | --- | --- |
| Simulated annealing | 800 sweeps, 16 restarts, T0 = 50 | 0.921 |
| QIEA | population 8, theta = 0.05 pi, catastrophe 0.05 | **0.973** |
| SQA | 32 Trotter slices, gamma0 = 3, T = 2 | 0.917 |

Two findings worth keeping from the sweeps:

* **QIEA's catastrophe operator is decisive.** Without it, a large rotation
  angle collapses the population into one basin and quality falls to 0.78 of
  greedy; with it, every angle tested stays near 0.96.
* **SQA improves monotonically with Trotter count** (0.80 at P = 2 up to 0.92
  at P = 32), which is the expected tunnelling behaviour - but a sweep costs P
  times as much, so at a fixed budget it is a trade-off rather than a gain.

**Experiment F, against exhaustive ground truth** (n = 16, k = 5, 24 instances):

| Solver | Mean fraction of optimum | Worst | Reached optimum |
| --- | --- | --- | --- |
| greedy | **0.9985** | 0.9881 | 21/24 |
| QIEA | 0.9792 | 0.8876 | 14/24 |
| simulated annealing | 0.9743 | 0.8941 | 10/24 |
| SQA | 0.9461 | 0.8764 | 0/24 |

**At equal wall-clock budget** (n = 60, k = 15, objective relative to greedy):

| Budget | Simulated annealing | QIEA | SQA |
| --- | --- | --- | --- |
| 5 ms | 0.906 | **0.955** | 0.890 |
| 25 ms | 0.919 | **0.956** | 0.907 |
| 100 ms | 0.922 | **0.958** | 0.920 |

And on budget allocation, a differently shaped objective with no submodularity
for greedy to exploit: QIEA 0.984, simulated annealing 0.968, SQA 0.932 - still
below greedy.

**Conclusions, stated as the evidence supports them.**

1. **Greedy wins on both problems.** Max-coverage is submodular, so greedy
   carries a proven `1 - 1/e` approximation bound, and in practice it reached
   99.85% of the optimum. Nothing here beats it, so nothing here displaces it.
2. **QIEA consistently beats classical simulated annealing** - its direct
   classical analogue, both being stochastic search over the same QUBO - by
   roughly four percentage points at every budget tested, and on both problem
   shapes. That is the one positive result in this module, and it is a
   comparison between two classical algorithms.
3. **SQA is the weakest of the three** and never reached the optimum on any
   ground-truth instance. The cost of replication is not repaid at these sizes.
4. **More budget barely helps.** All three are within a few points of their
   asymptote by 25 ms, so the gap to greedy is not a budget artefact.

**What is deliberately not claimed.** No quantum speedup, and no quantum
computation: every solver here runs on a classical CPU, and "quantum-inspired"
describes where the algorithm's structure was borrowed from, nothing more. A
real quantum annealer would implement the same `Solver` trait, but none is
available on this host, so no such adapter is claimed to work.

**Why it is kept.** The lab answers its research question with evidence, the
QIEA-versus-annealing result is a genuine finding, and the interface is the
right place for a hardware adapter should one become available. It costs
nothing when disabled, which is its default state.

## D14 — Multi-worker campaigns use a two-tier coverage check, not a shared lock per execution

**Decision.** A pooled campaign runs each worker as an OS thread with its own
executor, coverage region, scratch directory, strategy instances and RNG
stream derived from `(campaign_seed, worker_index)`. Workers coordinate through
one lock around the store, the corpus and a campaign-wide coverage map.

Novelty is judged in two tiers. A worker checks its **own** coverage map first,
with no lock. Only a locally-interesting run — a small fraction of executions —
takes the shared lock to confirm against the campaign-wide map. Workers merge
the global map back into their local one whenever another worker has
discovered something, tracked by a generation counter so a worker can tell its
map is stale without comparing 64 KiB.

**Why not a lock per execution.** The campaign loop runs thousands of times a
second per worker. Taking a global lock on every execution would serialise
exactly the work the pool exists to parallelise.

**Why not per-worker novelty alone.** Four workers judging novelty privately
would each "discover" the same edge, and the corpus would fill with four
equivalent inputs.

**What it costs, measured.** A run that is novel locally but not globally still
pays one lock acquisition, and two workers can briefly both believe they found
the same edge. `ParallelStats::redundant_discoveries` counts how often that
happens and `lock_wait_micros` records the contention, so the cost is a number
in the report rather than an assumption.

**A bug this design caused, and the fix.** The first implementation retained an
input only when coverage was novel *globally*. That discarded every
semantically-novel input — a new comparison constant, a new output shape —
which is what the comparison-guided ladder is built from: a constant is
observed first, and the edge behind it is only reached once that input has been
mutated as a base. Retention now mirrors the sequential loop: globally-novel
coverage **or** local semantic novelty. Corpus retention on `crash_magic` rose
from 3 entries to 4–6 over the same budget.

**What is deliberately not claimed.** Remote workers are not implemented.
`WorkerTransport` defines registration, capability negotiation, leasing,
heartbeats and result delivery, and `LocalTransport` is the only
implementation. `aether doctor` reports distributed execution as unavailable.

Stagnation escalation is **not** applied on the pooled path. The detector reads
one sequential stream of rounds; advice derived from several workers'
interleaved rounds would not mean what it says. A pooled campaign therefore
stops on its budget, not on no-progress, and the report records that as a
limitation.

## D15 — Strategy statistics are persisted on a timer, and that bought nothing measurable

**Decision.** `strategy_stats` rows are written on the same 1.5-second timer as
the status file, and once more when the campaign stops, instead of once per
scheduling round.

**The hypothesis.** Experiment G showed per-worker throughput slightly above
the single-worker rate, which cannot be true scaling. A SQLite upsert per round
looked like the obvious per-round cost in the sequential loop that a pooled
worker does not pay.

**The measurement, which did not support it.** Three 15-second campaigns on
`coverage_ladder` per side, median executions per second:

| | median exec/s |
|---|---|
| upsert per round | 2497 |
| upsert on the status timer | 2499 |

No difference. The hypothesis was wrong.

**Why the change is kept anyway.** Nothing reads the table between rounds, so
the per-round write is I/O for no reader, and fewer writes cannot be worse —
the saving is real on storage slower than this container's. It is kept as a
simplification, **not** as a measured speedup, and the code comment says so.

## D16 — What worker scaling actually measures on this host

**The measurement.** `coverage_ladder`, 10-second campaigns, one run per worker
count, CPU time from `time` (which includes reaped children):

| workers | exec/s | cores used | CPU per execution |
|---|---|---|---|
| 1 | 2 433 | 1.02 | 418 µs |
| 2 | 5 651 | 2.08 | 366 µs |
| 3 | 7 795 | 2.85 | 365 µs |
| 4 | 9 869 | 3.32 | 336 µs |

Experiment G, three 20-second trials per arm, median: 2540, 5619 and 10 549
executions per second for 1, 2 and 4 workers.

**Throughput scales roughly linearly to four workers on this four-core host**:
2.32×, 3.20× and 4.06× relative to one worker.

**Why the efficiency figure exceeds 1.0, stated rather than left implied.** A
per-worker efficiency above 1.0 cannot mean better than perfect scaling. The
single-worker arm runs the *sequential* campaign loop, which is a different and
more expensive code path than a pooled worker: 418 µs of CPU per execution
against 336–366 µs. The drop appears at the first pooled arm, so it is the code
path and not the parallelism. The baseline is therefore not a clean reference,
and the report says so next to the number. D15 records the one candidate cause
that was tested and ruled out; the remainder is not isolated.

**Core utilisation never reached 4.0** — 3.32 at four workers — so the pool
leaves headroom on this host, consistent with time spent blocked in `waitpid`.

**Coverage bought no measurable gain.** Median coverage was 9 edges for every
worker count on `coverage_ladder`, whose reachable coverage saturates almost
immediately. The extra workers bought throughput, and at this budget on this
target that is all the evidence shows. Throughput is not the objective;
reproducible findings are, and none of these arms produced one.

## D17 — Metamorphic relations are declared, never inferred

**Decision.** No metamorphic relation is enabled by default. Each is named in
`oracles.metamorphic_relations`, and each documents the conditions under which
it holds. Declaring a relation without enabling the oracle is a configuration
error, not a silently skipped check.

**Why.** A metamorphic relation is a claim about the target — "appending a
newline must not change what this program does." Whether it is true depends
entirely on what the program is, and AETHER cannot find out by inspection.
Enabling one by default would be asserting something about a target it has
never seen.

**What this means for a violation.** When a declared relation fails there are
two readings of equal standing: the target is wrong, or the relation does not
hold for this target and declaring it was a configuration mistake. The verdict
reports both and chooses neither, and the finding's notes label them as
possible readings rather than conclusions.

**Equivalence is on exit class, not output.** A transformed input legitimately
produces different output — append a record and a well-behaved parser prints
one more line. What these relations assert is narrower and defensible: a
transformation that preserves validity must not turn a clean run into a crash
or a hang. A move between clean exit and non-zero exit is also not a violation:
both mean the target handled the input without failing.

**Deliberate exclusions.** A timeout after a length-increasing transformation
is not counted — that is a longer input against a fixed deadline, not a
relation failure. The exception is `determinism`, where the bytes are
identical, so a timeout really is the target behaving differently.

## D18 — Oracle violations do not go through reproduction, and are not confirmed

**Decision.** An oracle violation becomes a finding with status `candidate`,
severity from the evidence, and notes separating observed facts from possible
readings. It does **not** go through `handle_candidate_failure`.

**Why.** Reproduction means re-running an input and watching for the same
crash. An oracle violation may involve no crash at all — two implementations
printing different text is a real disagreement with nothing to reproduce by
that method. Running the reproduction pipeline over it would produce a
confirmation record about a question it did not ask.

**What is claimed.** That the oracle observed a disagreement, with both sides
recorded. The triggering input is stored and marked as the finding's input, so
the evidence is never lost. The finding's notes state explicitly that no
reproduction run was made and that it is a candidate for investigation rather
than a confirmed defect.

**Severity follows the evidence.** A disagreement where neither side crashed is
`BehaviouralDifference`. A sanitizer report on either side makes it
`MemorySafety`. A crash on either side is a crash first and a disagreement
second. Nothing is escalated to a security claim: the engine does not assign
exploitability or impact.

**Oracles are budgeted.** Every check re-runs the target, so
`oracles.budget_fraction` caps oracle spend as a share of the campaign's
execution budget, reservations are refunded for what a check did not use, and
checks refused for want of allowance are counted — so a report can say oracle
coverage was partial rather than complete. By default only retained inputs are
checked: those are the inputs that showed the campaign something, which is
where an execution spent on a second opinion is worth it.

## D19 — Two measured defects in the bandit scheduler, found by reading its own report

Running a real four-worker campaign on `toy_parser` and reading the per-strategy
numbers showed something that should not have been true: `cmplog-guided` found
40 of the campaign's 44 new edges and received the **smallest** allocation
share of the four strategies. That is the scheduler failing at its one job.
Two separate defects were behind it.

### Defect 1: the reward scale never adapted

`Scheduler::value_scale` normalises an arm's value-per-millisecond into `[0, 1]`
so it can be multiplied against the Beta posterior. It was initialised to
**1.0** and only ever raised.

Value per millisecond is entirely target-dependent. On `toy_parser` the best
arm managed 0.027, so nothing ever exceeded 1.0, the scale never moved, and
every arm's normalised magnitude sat near zero. With the score being
`p * (0.25 + 0.75 * magnitude)`, the `0.25` floor then flattened a real 4.6×
difference in value rate into **1.06×**. Selection was driven almost entirely
by the binary productive-or-not posterior, which barely separates the arms.

The scale now starts at zero — "nothing measured yet" — and is set by the first
observation. A pooled campaign also shares the best rate any worker has seen,
so one worker finding a high-value arm fixes the normalisation for all of them.

### Defect 2: the context-specific estimate discarded the prior far too early

`effective_stats` switched behaviour: once a `(context, arm)` cell had
`min_rounds` rounds (default 3) it was used **alone** and the global prior was
discarded entirely.

There are 36 possible contexts. Measured on `toy_parser`, a worker's cells held
about 25 rounds each at a roughly 2% rate of productive rounds — so a cell saw
zero or one productive round. That is noise, and on the strength of it every
other context's evidence, and every peer worker's, was thrown away.

Context-specific evidence and the discounted prior are now **always** blended.
The prior is a shrinkage term, which is what a contextual bandit with sparse
per-context data needs.

### What the fixes bought, measured

Simulation driven by the arm statistics from the real campaign, mean of 7
seeds. The figure is the share of rounds given to the arm that is ten times
better per unit of compute; uniform allocation would be 0.25.

| scenario | before | after |
|---|---|---|
| 1000 rounds, one context | 0.31 | 0.34 |
| 1000 rounds, 9 contexts | 0.26 | **0.38** |
| 4000 rounds, one context | 0.44 | **0.59** |
| 4000 rounds, 9 contexts | 0.32 | **0.55** |

Before the fixes, in the realistic multi-context case the scheduler was barely
distinguishable from uniform allocation.

On real four-worker 25-second campaigns against `toy_parser`:

| | cmplog-guided share | new edges credited to it | exec/s |
|---|---|---|---|
| before | 0.19 | 61 | 9 958 |
| after | 0.34 – 0.36 | 71 | 9 604 – 9 733 |

**What this did not buy.** Total coverage stayed at 32 edges in every run:
`toy_parser` saturates its reachable coverage with these strategies well inside
25 seconds, so a better allocation had nothing further to reach. The
improvement is in where the compute went and in the edges credited to the
strategy that earned them — not in final coverage on this target. Throughput is
unchanged within run-to-run variance.

A regression test (`thompson_exploits_the_better_arm_at_realistic_value_rates`)
now drives the scheduler at the small absolute value rates a real target
produces and fails if the better arm's share falls below half. The original
code would have failed it at 0.05.

## D20 — Pooled workers share round statistics, not per-execution state

**Decision.** In a pooled campaign each worker publishes its per-arm round
totals to the shared state once per round and takes the pool's totals back as a
peer prior, subtracting its own contribution so nothing is counted twice.

**Why it is affordable.** There is one round outcome per round, not per
execution — roughly one lock acquisition per sixty executions. Measured lock
wait across a four-worker 25-second campaign was 0.26 s of 100 worker-seconds,
and throughput was unchanged.

**Why it is needed.** A worker scheduling on its own slice of the rounds cannot
tell a much-better strategy from an average one; see D19 for the measurement.
Sharing gives each worker four times the evidence at no measurable cost.

**What is deliberately not shared.** Per-execution feedback, the semantic
providers' state, and the comparison-token store all stay worker-local. Sharing
those would mean a lock on the hot path, which is exactly what D14 avoids.
