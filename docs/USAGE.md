# Usage

Every command takes `--json` for machine-readable output and `--quiet` to
suppress progress. `--help` works on every group.

Exit codes are meaningful, so scripts need not parse output:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Usage or configuration problem |
| 2 | Engine failure |
| 3 | **Findings were confirmed** — a CI gate can fail on this alone |

## Start here

```bash
aether doctor
```

Reports what this host supports and what it does not, with a remedy for each
gap. Everything else assumes you have read it.

## Inspecting a target

```bash
aether target inspect ./build/parser
aether target inspect ./build/parser --input-mode file-arg --args @@
```

Probes with several representative inputs and reports instrumentation, guard
count, fork server, comparison log, and what each probe did. Run this before
designing a campaign: `Instrumented: no` means there is no coverage signal, and
a campaign planned as though there were would be planned wrongly.

## Configuration

```bash
aether init --binary ./build/parser --output aether.toml
aether init --profile structured-parser --output aether.toml
```

The file is versioned and validated in full before a campaign allocates
anything. The sections:

```toml
schema_version = 1

[target]
name = "parser"
kind = "executable"              # executable | stateful-stdio | differential
binary = "build/parser"
input_mode = "stdin"             # stdin | file-arg (with @@ in args)
timeout_ms = 1000
memory_limit_mb = 512
instrumentation = "aether-native"
oracle_binary = "build/parser-asan"   # optional sanitizer build
# differential_binary = "build/parser-v2"  # second implementation, for the
#                                          # differential oracle

[campaign]
duration_secs = 300
max_execs = 0                    # 0 = unbounded; set one of these
workers = 1                      # above 1 runs a worker pool; see below
seed = 20260124                  # recorded in every report
max_input_bytes = 65536
stop_after_findings = 0          # 0 = run the full budget

[scope]
allow_local_execution = true
allow_network_targets = false
# A network target needs all three:
# authorized_hosts = ["127.0.0.1:8080"]
# authorization_note = "engagement ticket SEC-1234"
# max_requests_per_second = 25

[oracles]
# Nothing is enabled implicitly: every oracle check re-runs the target and
# spends budget that would otherwise go to exploration.
enabled = []                     # "differential" and/or "metamorphic"
# A metamorphic relation is a claim about *your* target that AETHER cannot
# verify by inspection, so none is assumed. Each relation's validity
# conditions are in docs/DECISIONS.md D17.
metamorphic_relations = []       # determinism | trailing-newline |
                                 # trailing-whitespace | self-concatenation |
                                 # nul-padding
budget_fraction = 0.05           # share of the execution budget oracles may use
check_retained_only = true       # only inputs that showed the campaign something

[strategies]
enabled = []                     # empty = every strategy the target supports
dictionary = ["TLV1", "BEGIN"]
# dictionary_file = "tokens.dict"   # AFL format
# grammar_file = "format.bnf"

[feedback]
providers = ["edge-coverage", "exit-class", "cmplog", "sanitizer"]

[intel]
scheduler = "thompson"           # thompson | ucb1 | static | round-robin
round_budget = 64

[reproduction]
attempts = 5
required_successes = 3           # below this is "intermittent", never "reproducible"
minimize = true

[output]
dir = ".aether"
report_formats = ["json", "markdown", "sarif"]
```

### Profiles

```bash
aether campaign run --config aether.toml --profile deep-exploration
```

| Profile | For |
| --- | --- |
| `quick-local` | 30s, is this target worth fuzzing at all |
| `deep-exploration` | 1h, every eligible strategy |
| `structured-parser` | Grammar, structure-aware and dictionary strategies |
| `stateful-api` | Command sequences with transition feedback |
| `low-resource` | Constrained machines: 1 worker, small inputs, minimal telemetry |
| `research-benchmark` | **Replays from its seed.** Use whenever comparing configurations |
| `distributed` | Larger budgets — note that multi-worker is not implemented |

`research-benchmark` turns off the two things that make a campaign depend on
machine load: the cost-aware scheduler and the corpus cost term. It explores
less efficiently and replays exactly, which is the right trade for an
experiment.

## Campaigns

```bash
aether campaign create --config aether.toml      # validate without running
aether campaign run --config aether.toml
aether campaign run --config aether.toml --duration 600 --seeds ./corpus
aether campaign run --config aether.toml --strategies cmplog-guided,havoc
aether campaign run --config aether.toml --resume cmp-...     # reuse learned state

aether campaign list
aether campaign status                            # most recent campaign
aether campaign status cmp-...
aether campaign cancel cmp-...
```

`create` first when iterating on a configuration: it reports exactly which
field is wrong before any CPU is spent.

`cancel` works across processes — it writes a sentinel the campaign watches, so
it stops at its next execution boundary. Stored corpus and findings are kept.

Status output distinguishes **not measured** from zero. `edges: not measured`
means the target is uninstrumented; it does not mean no code was reached.

## Several workers

```bash
aether campaign run --config aether.toml --workers 4
```

A pooled campaign shares one corpus and one coverage map across worker threads.
Throughput scales roughly linearly up to the host's core count; measured
figures for a four-core host are in [DECISIONS.md](DECISIONS.md) D16. What that
buys in *coverage* depends entirely on the target — on a fixture whose
reachable coverage saturates immediately, four workers bought throughput and no
additional coverage at all.

The report's `parallel` section records how the pool actually behaved:

```bash
jq '.parallel' .aether/<campaign-id>/report.json
```

| Field | What it tells you |
| --- | --- |
| `per_worker_executions` | Whether the load was shared. One busy worker means a problem |
| `redundant_discoveries` | Two workers reaching the same coverage before either published it |
| `lock_wait_micros` | Contention on the shared corpus |
| `worker_failures` | A worker that stopped early, with the reason |

Two limits a pooled campaign carries, which the report also states: stagnation
escalation is not applied, and strategy allocation is per-worker rather than
campaign-wide. Workers are threads in one process — remote workers are not
implemented, which `aether doctor` reports.

## Oracles

An oracle asks a further question about an input that already ran. Both cost
executions, so both are budgeted.

**Differential testing** needs a second implementation:

```toml
[target]
kind = "differential"
binary = "build/parser-v1"
differential_binary = "build/parser-v2"

[feedback]
providers = ["edge-coverage", "exit-class", "differential"]

[oracles]
enabled = ["differential"]
```

It compares exit class, exit code and standard output. It does **not** compare
standard error or timing: diagnostics differ legitimately between
implementations.

**Metamorphic testing** needs you to declare which relations hold for your
target:

```toml
[oracles]
enabled = ["metamorphic"]
metamorphic_relations = ["determinism", "trailing-newline"]
```

Declaring a relation without enabling the oracle is refused, rather than
silently ignored. Pick only relations you know hold — `self-concatenation` is
valid for a stream of self-delimiting records and wrong for a format with a
single header.

An oracle violation is recorded as a **candidate**, never as a confirmed
defect: there is no crash to reproduce, so no reproduction run is made. The
finding separates what was observed from what it might mean, and offers the
readings as alternatives — including that the relation you declared may not
hold for this target. Nothing is escalated to a security claim.

## Findings

```bash
aether findings list
aether findings list --status reproducible
aether findings show fnd-...
aether findings validate fnd-... --config aether.toml --attempts 50
aether findings minimize fnd-... --config aether.toml
```

**The statuses are not interchangeable:**

| Status | Meaning |
| --- | --- |
| `reproducible` | Reproduced at or above the threshold. A defect |
| `intermittent` | Reproduced sometimes, below the threshold. A defect — say so, with the rate |
| `unconfirmed` | Seen once, never reproduced. **Not a defect** |
| `duplicate` | Same signature as an existing finding |
| `environmental` | Attributable to the environment, not the target |

`validate` re-runs the input and reports whether the failure now is the *same
defect*. A different signature usually means memory corruption whose symptom
varies between runs — more serious, not less. Raise `--attempts` when the rate
matters.

`minimize` only accepts a candidate reproducing the same signature, and reports
whether the result re-validated. If it did not, use the original input and say
the minimisation is unconfirmed.

## Corpus

```bash
aether corpus stats
aether corpus export cmp-... --output ./exported-corpus
```

Reading it: a corpus barely above the seed count means almost nothing was
interesting, which usually points at the harness. Saturation near 1.0 means
more time will not help but a better harness would. `distinct_behaviours` well
below the corpus size means many inputs drive the target the same way.

## Reports

```bash
aether report generate --format markdown
aether report generate --format sarif --output findings.sarif
aether report generate --format bench-json --output metrics.json
```

Reports put established findings first, list unconfirmed observations as
explicitly not defects, and name the capabilities that were unavailable. Only
confirmed findings become SARIF results, since a SARIF consumer treats every
result as an issue.

## Benchmarks

```bash
aether benchmark list
aether benchmark run --experiment e --config aether.toml --trials 5 --duration 60
```

A difference is reported only when it exceeds the spread between trials of a
single arm. When the output says the arms are not distinguishable, that is the
finding. See [BENCHMARKING.md](BENCHMARKING.md).

## In CI

```bash
aether campaign run --config ci.toml --max-execs 200000
# exit 3 = findings confirmed
```

Use `max_execs` rather than a duration so the run does the same work on every
machine, and `research-benchmark` if you want byte-comparable results between
commits.

```bash
aether campaign run --config ci.toml --max-execs 200000 --no-fail-on-findings
aether report generate --format sarif --output findings.sarif
```

## Scope and authorization

Local executables are allowed by default. A network target is refused unless
the configuration names the host explicitly, records an authorization note, and
sets a rate limit — all three. Loopback is not special-cased, and
`example.com` does not authorize `admin.example.com`.

This is enforced in the engine before any execution. Supplying an address is
not authorization to test it.
