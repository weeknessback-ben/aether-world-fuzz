# AETHER

**A**daptive **E**volutionary **T**esting & **H**ybrid **E**xploration
**R**untime — a coverage-guided fuzzing engine with adaptive strategy
selection and an evidence pipeline that reproduces and minimises what it
finds, or explicitly declines to.

AETHER provides its own coverage runtime and drives targets directly. It is not
a wrapper around another fuzzer: the host it was built on has clang able to
*compile* SanitizerCoverage instrumentation but no `libclang_rt` archives and
no AFL++ package, so wrapping an absent engine would not have run at all. What
it does instead is linked compiler-emitted instrumentation against a runtime of
its own — including comparison-operand recovery, which is where most of its
advantage comes from.

## What it does

```
$ aether target inspect ./build/parser
Target: ./build/parser
  Instrumented: yes (12 guards)
  Fork server:  yes
  Edge coverage: yes
  Comparison log: yes (6 comparisons seen)
  Suggested strategies: cmplog-guided, havoc, random-mutation, boundary, ...

$ aether campaign run --config aether.toml
Campaign cmp-a16c3e717b0001ff4b starting.

Campaign cmp-a16c3e717b0001ff4b finished: duration-elapsed
  32900 executions (2741/s), 12 edges, 7 corpus entries
  findings: 1 reproducible, 0 intermittent, 0 unconfirmed
    [reproducible] crash: SIGABRT (6) (5/5 reproduced, confidence High)
```

Exit code 3 means findings were confirmed, so CI can fail a build without
parsing output.

## Design

Three engines over one campaign runtime:

**Exploration** — ten input-generation strategies behind one trait, a fork
server that skips `execve` per run, and an AFL-style edge map with
comparison-operand logging.

**Intelligence** — a contextual multi-armed bandit that allocates execution
budget from *measured* value per unit of compute, multi-objective corpus
ranking, and stagnation detection with hysteresis.

**Evidence** — a finding lifecycle where reproducibility has to be established
rather than asserted. There is no transition from `candidate` straight to
`reproducible`.

## Measured on the development host

| | |
| --- | --- |
| Fork server throughput | **3,249 exec/s** against 623 for `execve`-per-run — a **5.21x** speedup |
| Comparison log overhead | 1.1%, inside the ±7% run-to-run spread |
| Comparison-guided vs blind mutation | On a four-gate magic ladder: reached the defect and 12 edges, against 6 edges and no defect for blind byte mutation at equal budget |

Protocol: 1,200 executions per repetition, five repetitions, median reported.
[docs/BENCHMARKING.md](docs/BENCHMARKING.md) has the method;
[docs/DECISIONS.md](docs/DECISIONS.md) records which numbers drove which
decision, including the negative results.

## Getting started

```bash
cargo build --release
./target/release/aether doctor          # what this host supports, and what it does not
```

Build a target with instrumentation, then fuzz it:

```bash
./runtime/aether-cc -o build/parser src/parser_harness.c
./target/release/aether init --binary build/parser --output aether.toml
./target/release/aether campaign run --config aether.toml
```

[docs/USAGE.md](docs/USAGE.md) covers the command surface.
[docs/INSTALLATION.md](docs/INSTALLATION.md) covers prerequisites and the
Claude Code plugin.

## Claude Code integration

`integrations/claude-code/` packages an MCP server with 16 typed tools, four
skills, three agents and a health-check hook, so a campaign can be designed,
run and interpreted from a conversation. See
[docs/CLAUDE_CODE_INTEGRATION.md](docs/CLAUDE_CODE_INTEGRATION.md).

## What it can fuzz

Every row below was established by building the target and running a campaign
against it, not inferred from the design.

| Language | How | Coverage guidance | Verified |
|---|---|---|---|
| C | `aether-cc` | edges + comparison log | campaign, finding reproduced 5/5 |
| C++ | `aether-cc --cc clang++` | edges + comparison log, virtual calls included | campaign, finding reproduced 5/5 |
| Rust | `rustc -C passes=sancov-module -C link-arg=aether_rt.o -C panic=abort` | edges + comparison log | campaign, finding reproduced 5/5 |
| Objective-C, and other clang front ends | `aether-cc --cc clang` | same as C | not tried |
| Python, Node, Ruby, Java, Go, any executable | `instrumentation = "none"` | **none** — exit status, output and oracles only | Python campaign, finding reproduced 5/5 |

The target must be a **local executable** that takes one input per run on stdin
or as a file path argument. Three target shapes are accepted: a plain
executable, a newline-delimited command sequence (`stateful-stdio`), and a pair
of executables compared against each other (`differential`).

**A managed language's uncaught exception is not a crash.** Python exits 1,
Rust panics with 101 — and a non-zero exit is how a correct parser rejects
malformed input, so AETHER does not treat it as a defect. An interpreted target
needs a harness that turns an *unexpected* exception into `SIGABRT` while
letting intended rejections exit non-zero; that distinction is the harness's
job and cannot be inferred. Recipes are in
[docs/USAGE.md](docs/USAGE.md#targets-that-are-not-c), and the measurement is in
[DECISIONS.md D21](docs/DECISIONS.md).

Out of reach: network services (the scope policy validates authorisation but no
network backend exists), libraries without an executable harness, JVM and .NET
bytecode coverage, and Go coverage.

## What it does not do

Stated here rather than left to be discovered:

- **No remote workers.** Multi-worker campaigns run as threads in one process,
  and scale roughly linearly to the host's core count (2.21× and 4.15× for two
  and four workers on a four-core host — experiment G). `WorkerTransport`
  defines what a remote implementation would satisfy; `LocalTransport` is the
  only one, and `aether doctor` reports distributed execution as unavailable.
  A pooled campaign also does not apply stagnation escalation, because the
  detector reads one sequential stream of rounds.
- **Metamorphic relations are yours to declare.** The oracle checks the
  relations you name and assumes none, because whether a relation holds depends
  on what your target is. A violation is reported as a candidate with both
  readings — the target is wrong, or the relation does not hold here — and never
  as a confirmed defect.
- **The libFuzzer and AFL++ adapters are unverified.** Interface-complete, with
  full capability declarations, but never exercised against the real engines
  because neither is installable on this host. They report
  `verified: false`.
- **No constraint solver.** The stagnation detector can escalate to constraint
  solving; no solver is wired in, and the campaign records that the escalation
  was requested and not performed.
- **No claim of exploitability.** A crash is a crash. Every finding records that
  exploitability was not assessed.
- **Campaigns do not replay byte-for-byte.** The execution budget is exact and
  the execution layer is deterministic, but the cost-aware scheduler and corpus
  ranking read wall-clock durations. The `research-benchmark` profile turns both
  off; a residual single-edge variance remains and is documented rather than
  hidden.

## Repository layout

```
runtime/              C coverage runtime and the aether-cc build wrapper
crates/aether-core/   engine: exec, feedback, corpus, strategy, intel, evidence, runtime
crates/aether-cli/    the aether command
fixtures/             11 C and 1 C++ self-contained targets with known behaviour
integrations/         Claude Code plugin and MCP server
docs/                 architecture, decisions, threat model, usage, benchmarking
```

## Tests

```bash
cargo test                                            # 527 tests
cargo test --release --test optimizer_tuning -- --nocapture   # solver sweeps
```

The integration suite drives real compiled fixtures: coverage responding
monotonically to input quality, the comparison log surfacing the constants a
target gates on, crash and timeout detection, process-group reaping, bounded
output capture, and a target being unable to fake a sanitizer finding or reach
a shell through its input.

## Licence

Apache-2.0.
