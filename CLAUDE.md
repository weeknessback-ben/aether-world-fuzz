# Working on AETHER

Notes for anyone — person or model — changing this codebase.

## What this project is

A fuzzing engine with its own coverage runtime. Not a wrapper: the host it was
built on has clang able to compile SanitizerCoverage instrumentation but no
`libclang_rt` archives and no AFL++ package, so wrapping an absent engine would
not have run. Read
[docs/DECISIONS.md](docs/DECISIONS.md#d1-own-coverage-runtime-instead-of-wrapping-an-existing-fuzzer)
before proposing that it should be one.

## Build and test

```bash
cargo build --release
cargo test                                                     # 524 tests
cargo test --release --test optimizer_tuning -- --nocapture     # solver sweeps
cargo clippy --all-targets -- -D warnings
cargo fmt --check
./target/release/aether doctor
```

Integration tests compile the C fixtures through `runtime/aether-cc` on demand
and cache them under `target/fixture-bin`. They need a working clang or gcc.

## House rules

### Never report a metric that was not measured

`Option<T>` for anything that may be unmeasurable, and `None` must render as
"not measured", never as `0`. An uninstrumented target has no coverage; saying
it has zero coverage is a different and false claim.

### Never claim exploitability

A crash is a crash. Severity reflects the fault class and nothing more. Every
finding records `exploitabilityAssessed: false`, and the tests check that no
report contains an affirmative exploitability claim. If you add a severity
level, add it to those tests.

### A capability that is unavailable says so, with a remedy

Detection probes for what is actually needed, not for a proxy. The libFuzzer
probe looks for the runtime archive rather than just for clang, because a host
with clang and no `libclang_rt` is exactly the case that would otherwise report
available and fail at link time.

An unimplemented feature refuses rather than substituting something else.
Benchmark experiment F returns an error pointing at `tests/optimizer_tuning.rs`
instead of running a campaign comparison and labelling it a solver result.

### Reproducibility must be established, not asserted

The finding state machine has no edge from `candidate` to `reproducible`. If you
touch `evidence::FindingStatus::can_transition_to`, the test that asserts this
should fail — if it does not, the change removed the guarantee.

### No shell, ever

Targets launch from an explicit path and an argument vector. No string reaches a
shell, anywhere, in Rust or TypeScript. There are tests that feed
`; rm -rf /` and `$(touch ...)` as *input* and assert nothing happened.

### Validate identifiers before they reach a path or a statement

Every id from outside goes through `validate()` first. There are tests with
`../../etc/passwd` and `' OR 1=1 --`.

### Tests assert the guarantee, not the current behaviour

If a test is flaky, find out why before weakening it. Two examples in this
repository:

- A campaign-replay test was flaky because the scheduler reads *measured*
  execution cost, so machine load changes what gets explored. The fix was to
  test what actually holds — the exact execution budget, and determinism of the
  execution layer in isolation — and to document the residual variance, not to
  widen a tolerance until it passed.
- A corpus-ranking test failed because scores were normalised against a running
  maximum, so insert order changed the ranking. That was a real bug; the fix was
  to rescore when a maximum moves.

### Comments explain why, not what

The code says what it does. A comment should say why it is that way, and
especially why the obvious alternative is wrong. Several here record a measured
result or a bug that a change would reintroduce.

## Layout

| Path | Contents |
| --- | --- |
| `runtime/` | C coverage runtime and `aether-cc` |
| `crates/aether-core/src/exec/` | Execution, shared memory, limits, sanitizer parsing |
| `crates/aether-core/src/feedback/` | Coverage, comparison log, semantic providers |
| `crates/aether-core/src/strategy/` | Ten strategies behind one trait |
| `crates/aether-core/src/intel/` | Bandit, stagnation, optimisation lab |
| `crates/aether-core/src/corpus/` | Content store, ranking, minimisation |
| `crates/aether-core/src/evidence/` | Finding lifecycle, signatures, reports |
| `crates/aether-core/src/oracle/` | Differential and metamorphic checks, budgeted |
| `crates/aether-core/src/runtime/` | Campaign loop, checkpoints, worker pool |
| `crates/aether-cli/` | The `aether` command. No SQL — use `query` |
| `fixtures/` | 11 C and 1 C++ target with known behaviour |
| `integrations/claude-code/` | Plugin and MCP server. No fuzzing logic |

## Adding things

**A strategy:** implement `Strategy`, declare requirements in
`StrategyCapabilities`, register in `strategy::build`, add to
`ALL_STRATEGY_IDS`. It must propose nothing rather than panic when its inputs
are missing — and the registry test checks that.

**A feedback provider:** implement `SemanticProvider`, including
`describe()` with method, limitations and cost. That is enforced by a test, not
by convention.

**An execution backend:** implement `Executor`, add an `AdapterDeclaration`
with its full contract, and a detection probe. Mark `verified: false` unless it
has actually been driven against the real engine.

**A language:** the engine drives processes, so what matters is the build. C,
C++ and Rust are verified end to end and the recipes are in
[docs/USAGE.md](docs/USAGE.md#targets-that-are-not-c). Two things bite:
`aether_rt.c` must be compiled by a **C** compiler even when the target links
with a C++ driver, or its callback symbols mangle and nothing links; and a
managed language's uncaught exception exits non-zero, which is *not* a
candidate failure, so the harness has to turn an unexpected one into `SIGABRT`.
See [D21](docs/DECISIONS.md).

**A CLI command:** add it to `main.rs`, implement in `commands.rs`, support
`--json`. No SQL — extend `aether_core::query` instead.

**An oracle:** implement `Oracle`, including `describe()` and
`cost_per_check()` — every check re-runs the target, so the cost is budgeted
before it is spent. `unavailable()` must explain what is missing rather than
letting the oracle be built and silently skip. A verdict separates `observed`
facts from `interpretations`, and the interpretations are alternatives, never a
conclusion.

**A metamorphic relation:** add it to `Relation`, give it a `validity()` string
saying when believing it is justified, and add the name to **both**
`Relation::parse` and `OracleConfig::validate` — a typo must be a configuration
error, not a check that never runs. A test asserts every relation states its
validity.

**An MCP tool:** add the Zod schema, the tool definition with a description
that says what the result means, and the dispatch arm. Bound the output.

## Known gaps

Documented in the README and the relevant modules. The substantial ones:
remote workers are not implemented (local thread pools are — see
[D14](docs/DECISIONS.md)); a pooled campaign does not apply stagnation
escalation, by decision; the libFuzzer and AFL++ adapters are interface-only
and unverified; no constraint solver is wired in; and whole campaigns do not
replay byte-for-byte.

Two measured facts worth knowing before optimising anything: a pooled worker
costs 336-366 microseconds of CPU per execution against the sequential loop's
418, and nobody knows why yet
([D16](docs/DECISIONS.md)); and the bandit's 36 contexts leave each cell with
too few rounds in a short campaign, which a shrinkage prior mitigates rather
than solves ([D19](docs/DECISIONS.md)).

If you fix one, update the README's "What it does not do", `docs/DECISIONS.md`,
and the honesty tests that currently assert the gap.
