# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is [semantic](https://semver.org/).

## [Unreleased]

### Added

- **Multi-worker campaigns.** `campaign.workers` above one now runs a real pool
  of worker threads sharing one corpus and one coverage map, instead of being
  accepted and ignored. Novelty is judged in two tiers so the common path takes
  no lock; redundancy, lock wait and per-worker load are measured and reported.
  Remote workers remain unimplemented and `aether doctor` says so.
  (docs/DECISIONS.md D14)
- **Benchmark experiment G**, worker scaling across 1, 2 and 4 workers. On a
  four-core host throughput scaled 2.21× and 4.15×; coverage did not move on a
  fixture that saturates immediately. The experiment explains why a per-worker
  efficiency above 1.0 is a property of the baseline rather than a speedup.
  (D16)
- **Oracles** as a first-class module. A differential oracle comparing two
  implementations on exit class, exit code and standard output; a metamorphic
  oracle checking declared input transformations. Both are budgeted as a share
  of the campaign's executions, and oracle violations are recorded as
  candidates with observed facts separated from possible readings — never as
  confirmed defects or security claims. (D17, D18)
- `aether doctor` now reports the local worker pool, the host's core count and
  both oracles with their requirements.
- `aether_campaign_start` (MCP) accepts `workers`.

### Fixed

- **The bandit scheduler was barely better than uniform allocation.** Two
  defects, both found by reading a real campaign's own report, where the
  strategy that found 40 of 44 new edges received the smallest share of the
  budget:
  - `value_scale` was initialised to 1.0 and only ever raised, so on any target
    whose value-per-millisecond sits below 1 the reward normalisation never
    adapted and a 4.6× difference in value rate was flattened to 1.06×.
  - `effective_stats` discarded the global prior once a `(context, arm)` cell
    had three rounds, leaving selection to run on ~25 noisy rounds per cell and
    throwing away every other context's and every peer worker's evidence.

  Share given to a ten-times-better arm, mean of 7 seeds, 4000 rounds across 9
  contexts: **0.32 → 0.55** (uniform is 0.25). On real campaigns the
  comparison-guided strategy's share went from 0.19 to 0.34–0.36 with
  throughput unchanged. Total coverage did not improve on the fixture tested,
  which saturates its reachable coverage — stated rather than implied. (D19)
- Pooled workers share per-arm round statistics, so each schedules on all the
  workers' evidence rather than its own slice. One lock per round, measured at
  0.26 s of 100 worker-seconds. (D20)
- Strategy statistics are persisted on the status timer rather than once per
  round. Measured no throughput difference; kept as a simplification, not as a
  speedup. (D15)

## [0.1.0] — 2026-10-24

First working version. The engine runs campaigns end to end against real
instrumented targets and turns what it finds into reproducible evidence.

### Engine

- **Coverage runtime** (`runtime/aether_rt.c`): SanitizerCoverage callbacks
  writing an AFL-style edge map and a comparison-operand log into shared
  memory, plus a fork server. Dependency-free, and safe to run standalone.
- **`aether-cc`**: build wrapper. Compiles and links as separate steps, because
  passing `-fsanitize-coverage` to the link line makes clang demand runtime
  archives that are not always present.
- **Fork-server executor** with automatic exec-per-run fallback, per-run
  deadlines enforced by signalling the process group, bounded output capture,
  and rlimits with honest reporting of what the host actually enforces.
- **Ten strategies**: random mutation, havoc with an adaptive stack size,
  boundary values, splice, dictionary, comparison-guided substitution, grammar
  generation, structure-aware mutation, evolutionary search, stateful sequences.
- **Contextual multi-armed bandit** (Thompson Sampling and UCB1) allocating
  budget from measured value per unit of compute, with static and round-robin
  as experiment controls.
- **Stagnation detection** with a hysteresis band and an escalation ladder from
  cheap responses to expensive ones.
- **Multi-objective corpus ranking** over coverage, novelty, diversity,
  mutation productivity, cost and redundancy, every component normalised before
  weighting.
- **Evidence engine**: failure signatures that survive a rebuild, a finding
  lifecycle where reproducibility must be established rather than asserted,
  delta-debugging minimisation that preserves the signature, and deduplication.
- **Reports** in JSON, Markdown, SARIF 2.1.0 and flat benchmark JSON.
- **Experimental optimisation lab**: corpus subset selection and budget
  allocation as QUBO, with greedy, simulated annealing, a quantum-inspired
  evolutionary algorithm and simulated quantum annealing. Off by default.

### Interfaces

- **`aether` CLI** with `--json` throughout and meaningful exit codes,
  including 3 for "findings confirmed".
- **Claude Code plugin**: MCP server with 16 typed tools, four skills, three
  agents, and a health-check hook. Passes `claude plugin validate`.

### Measured on the development host

- Fork server **3,249 exec/s** against 623 for exec-per-run — **5.21x**.
- Comparison log costs **1.1%**, inside the ±7% run-to-run spread.
- On a four-gate magic ladder, comparison-guided substitution reached the defect
  and 12 edges; blind byte mutation reached 6 edges and never passed the first
  gate, at equal budget.
- Experiment F: greedy reaches **0.9985** of the optimum against exhaustive
  ground truth. The quantum-inspired evolutionary solver beats classical
  simulated annealing at every budget tested, and neither beats greedy.

### Known limitations

- Multi-worker campaigns are not implemented. The worker abstraction and
  transport interface exist; the controller runs a single loop. Benchmark
  experiment G refuses rather than reporting a fabricated scaling number.
- The libFuzzer and AFL++ adapters are interface-complete but unverified:
  neither engine is installable on the development host.
- No constraint solver is wired in. The stagnation detector can request the
  escalation, and the campaign records that it was requested and not performed.
- Whole campaigns do not replay byte-for-byte. The execution budget is exact and
  the execution layer is deterministic, but the cost-aware scheduler and corpus
  ranking read wall-clock durations. The `research-benchmark` profile turns both
  off; a residual single-edge variance remains and is documented.
- No comparison against AFL++ or libFuzzer, because neither could be run here.
- No FuzzBench or Magma integration.

### Tests

437 tests. The integration suite drives real compiled fixtures and covers
coverage responding monotonically to input quality, the comparison log
surfacing the constants a target gates on, crash and timeout detection,
process-group reaping, bounded output capture, and a target being unable to
fake a sanitizer finding or reach a shell through its input.
