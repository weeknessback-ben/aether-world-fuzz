# Architecture

## The shape of it

AETHER is three engines over one campaign runtime. The split is not
decorative: each answers a different question, and each can be changed without
touching the others.

```
                        ┌─────────────────────────┐
                        │   Campaign runtime      │
                        │  observe → analyse →    │
                        │  plan → execute →       │
                        │  measure → update       │
                        └───────────┬─────────────┘
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼────────┐  ┌─────────▼────────┐  ┌────────▼─────────┐
    │   Exploration    │  │  Intelligence    │  │    Evidence      │
    │                  │  │                  │  │                  │
    │ strategy  (10)   │  │ intel::bandit    │  │ signature        │
    │ exec             │  │ intel::stagnation│  │ validate         │
    │ feedback         │  │ corpus::score    │  │ report           │
    │                  │  │ intel::qubo (exp)│  │                  │
    └──────────────────┘  └──────────────────┘  └──────────────────┘
              │                     │                     │
    ┌─────────▼─────────────────────▼─────────────────────▼─────────┐
    │  corpus (content-addressed store)   persist (SQLite)          │
    └───────────────────────────────────────────────────────────────┘
```

**Exploration** runs candidates and observes what they did.
**Intelligence** decides what to try next, from measurements rather than fixed
rules. **Evidence** turns a suspected failure into something defensible.

## The layer that makes the rest possible

Everything rests on getting real feedback out of a real process.

`runtime/aether_rt.c` is a dependency-free C runtime linked into the target. It
implements the SanitizerCoverage callbacks the compiler emits calls to, and
writes into a shared memory region:

| Region | Contents |
| --- | --- |
| Header | magic, ABI version, geometry, guard count, execution counter |
| Edge map | 65,536 slots, AFL-style `(prev_loc ^ cur)` hashing, saturating 8-bit counters |
| Comparison log | 4,096 entries of `(v0, v1, pc_hash, width, is_const)` |

Two properties are worth calling out.

**The comparison log is where the advantage comes from.** When a target runs
`if (magic != 0xDEADBEEF)`, the instrumentation reports both operands. Finding
the input-side operand's bytes in the input and overwriting them with the
constant turns a 2³² search into one execution. Measured on a four-gate
ladder: comparison-guided substitution reaches the defect where blind byte
mutation does not, at equal budget.

**The fork server removes `execve` from the hot path.** The target is exec'd
once; its runtime then forks a child per test case on request. Measured 5.21x
faster than exec-per-run. It falls back automatically when the handshake does
not complete, because a binary without the runtime linked in has no fork server
to offer and must still run.

The region is addressed by explicit byte offsets through volatile reads and
writes, not through a `#[repr(C)]` mirror struct: another process writes it, so
holding a Rust reference into it would claim an aliasing guarantee that does not
hold.

## Module map

| Module | Responsibility |
| --- | --- |
| `config` | Versioned schema, seven profiles, full validation before any allocation |
| `scope` | Authorization policy. Enforced, not advisory |
| `exec::shm` | The shared-memory ABI |
| `exec::native` | Fork-server executor with exec fallback |
| `exec::limits` | rlimits, and honest reporting of what the host actually enforces |
| `exec::sanitizer` | Report parsing with volatile detail stripped |
| `exec::adapters` | Backend capability declarations and detection |
| `feedback::coverage` | Campaign-wide reach as a virgin map |
| `feedback::cmplog` | Constant recovery and input-to-state substitution |
| `feedback::semantic` | Exit class, response transitions, declared invariants |
| `strategy` | Ten strategies behind one trait, plus the registry |
| `intel::bandit` | Contextual multi-armed bandit over strategies |
| `intel::stagnation` | Phase detection with hysteresis and an escalation ladder |
| `intel::qubo` | Experimental optimisation lab, off by default |
| `corpus` | Content-addressed storage, ranking, retention, minimisation |
| `evidence` | Finding lifecycle, signatures, validation, reports |
| `oracle` | Differential and metamorphic checks, with an execution budget |
| `runtime` | The campaign loop, checkpoints, worker pool |
| `runtime::parallel` | Multi-worker execution and its two-tier coverage check |
| `persist` / `query` | SQLite schema and typed read-only access |
| `bench` | Benchmark experiments |

## Decisions that shaped it

### Reward is value per unit of compute, not coverage

The bandit's reward divides exploration value by *measured* execution cost. A
strategy that finds twice as much at five times the cost is a worse use of a
fixed budget, and a scheduler maximising raw coverage would pick it.

This has a consequence worth stating: a campaign's outcome depends on machine
load, because cost is measured. The `research-benchmark` profile turns cost
awareness off — in the scheduler and in corpus ranking — so controlled
experiments replay from their seed.

### Estimates are kept per context

Which strategy pays off changes over a campaign: byte mutation while the corpus
is thin, comparison-guided substitution once gates are being hit,
structure-aware once a format is established. Estimates are therefore kept per
discretised context (progress, corpus size, saturation), with the global record
as a prior for a context not yet seen.

### No arm is ever starved

A minimum trial count plus a selection floor. Without them, an arm that started
badly on noise would be eliminated before there was evidence to eliminate it
on.

### Reproducibility must be established

The finding state machine has no edge from `candidate` to `reproducible`.
Reaching `reproducible` requires passing through `Reproducing`, and the status
follows from the counts in one place — `ReproductionRecord::implied_status` — so
the threshold cannot be applied inconsistently.

### Minimisation preserves the signature

The minimiser's predicate is "the same signature still occurs", not "something
still crashes". Shrinking one defect into a different one would attach the
wrong evidence to the finding, which is worse than not minimising.

### Signatures exclude volatile detail

Addresses, load offsets, PIDs and build paths are stripped, and only the
innermost few frames contribute. A signature that included them would report
the same defect as new after every rebuild; one that included the whole stack
would split one defect across every path that reaches it.

### Differential and metamorphic testing are oracles

Neither generates input. Both take an input some other strategy produced and
decide whether the resulting behaviour is acceptable. Modelling them as
strategies would have required a strategy that returns no candidates.

### Threads, not async

The work is CPU-bound process supervision a few workers deep. Blocking a thread
on `waitpid` is the natural shape; an async runtime would add a large
dependency and a scheduler for concurrency that `fork` does not benefit from.

## Multi-worker campaigns

Set `campaign.workers` above one and the campaign takes a different path. The
controller stops fuzzing: it hands the store and the corpus to a pool of worker
threads, waits, then validates what came back.

Each worker owns an executor, a coverage region, a scratch directory, its own
strategy instances and an RNG stream derived from `(campaign_seed,
worker_index)` — so a fixed seed still replays, and adding a worker does not
perturb the streams the existing workers draw from. They share one lock around
the store, the corpus and a campaign-wide coverage map.

Novelty is decided in two tiers, because deciding it either way alone fails.
Judged privately, four workers each "discover" the same edge and the corpus
fills with four equivalent inputs. Judged under a global lock on every
execution, the lock serialises exactly what the pool exists to parallelise. So
a worker checks its own map first with no lock, and only a locally-interesting
run — a small fraction of executions — takes the lock to confirm against the
campaign-wide map. A generation counter tells a worker its local map is stale
without comparing 64 KiB.

What that design costs is measured rather than assumed:
`ParallelStats::redundant_discoveries` counts how often two workers reached the
same coverage before either published it, `lock_wait_micros` records
contention, and `imbalance` shows whether one worker did most of the work. All
three land in the report's `parallel` section.

Workers do not validate failures. Reproduction re-runs an input several times,
which would stall a worker's loop, and two workers hitting one defect would
validate it twice. Workers report candidate failures; the controller
deduplicates and validates each once.

Two things a pooled campaign does **not** do, stated here rather than left to
be discovered: stagnation escalation is not applied, because the detector reads
one sequential stream of rounds and advice derived from several workers'
interleaved rounds would not mean what it says; and remote workers do not
exist — `WorkerTransport` defines the interface and `LocalTransport` is the
only implementation, which `aether doctor` reports.

Measured scaling on a four-core host is in [DECISIONS.md](DECISIONS.md) D16.

## Oracles

An oracle is not a strategy. A strategy proposes inputs; an oracle decides
whether what happened to one is wrong. Both differential and metamorphic
testing live here because neither generates input.

Every oracle check re-runs the target, so that compute comes out of the
campaign's budget. `oracles.budget_fraction` caps the spend, reservations are
refunded for what a check did not use, and checks refused for want of allowance
are counted — so a report says oracle coverage was partial rather than
complete. By default only retained inputs are checked.

**Differential** runs a second implementation and compares exit class, exit
code and standard output. Standard error and timing are deliberately not
compared: diagnostics differ legitimately between implementations, and a build
flag can change them with no behavioural difference at all.

**Metamorphic** applies a declared transformation and requires the exit class
to be preserved. No relation is enabled by default — a relation is a claim
about the target that AETHER cannot verify by inspection. See
[DECISIONS.md](DECISIONS.md) D17 and D18 for what a violation does and does not
claim.

## Data flow, one round

```
corpus.sample ──► bases (+ cached comparison operands)
                    │
scheduler.select ──►│──► strategy.propose(budget) ──► candidates
                    │
                    └──► for each candidate:
                           executor.run                 (fork server)
                           feedback.observe             (coverage + semantic)
                           corpus.add if interesting
                           evidence pipeline if it failed
                           intel.record_execution
                    │
strategy.observe ◄──┘
intel.finish_round ──► scheduler.update + stagnation advice
```

The comparison-operand cache in that first line is load-bearing. An earlier
version built bases with an empty operand list, which starved the one strategy
that exists to use them — it proposed nothing for 9,000 consecutive rounds while
executing once in total. Operands are now carried with the base, collected on
first use.

## Storage

Content in a content-addressed store, metadata in SQLite, referenced by hash.
That split keeps the database small enough to stay fast while a campaign
accumulates gigabytes of test cases.

Two invariants are enforced by the schema rather than by caller discipline:

- Deduplication is a `UNIQUE(campaign_id, content_hash)` index, so a bug
  elsewhere cannot create a duplicate.
- An input tied to a finding is excluded from retention by the query that
  selects eviction candidates, so trimming cannot lose evidence.

Writes that must not be seen half-applied go through transactions, and objects
are written to a temporary name and renamed into place, so a crash mid-write
cannot leave a truncated object a later read would treat as valid.

## Extending it

**A strategy** implements `Strategy` and declares its requirements in
`StrategyCapabilities`. The registry drops one whose requirements the target
cannot meet, and reports why.

**A feedback provider** implements `SemanticProvider` and must declare how its
measurement is obtained, what it cannot see, and what it costs. That is not
decoration: these signals are weaker than edge coverage, and a campaign that
treats them as equally authoritative chases noise.

**An execution backend** implements `Executor` and an `AdapterDeclaration`.
Detection probes for what is actually needed — the libFuzzer probe looks for the
runtime archive, not just for clang, because a host with clang and no
`libclang_rt` is exactly the case that would otherwise report available and
fail at link time.

**An optimiser** implements `Solver`. Every solution is repaired, checked
against the real constraints, and scored on the true objective rather than on
QUBO energy.
