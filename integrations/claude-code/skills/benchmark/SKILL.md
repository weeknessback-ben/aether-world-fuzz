---
name: benchmark
description: Run and interpret an AETHER benchmark experiment comparing fuzzing configurations. Use when asked whether a strategy or setting actually helps, to compare fuzzing approaches, or to measure the effect of a change with evidence.
---

# Benchmarking fuzzing configurations

Fuzzing is stochastic. A single run proves nothing, and two runs of different
lengths are not a comparison. This skill is about producing a result that holds
up.

## What can be compared

`aether_benchmark_list` gives the catalogue and says which experiments this
build can run and which it cannot. Experiments that are not implemented say so
rather than returning a substitute:

- **A** black-box against coverage-guided
- **B** static allocation against adaptive scheduling
- **C** mutation only against hybrid mutation and generation
- **D** coverage-only feedback against coverage plus semantic signals
- **E** blind mutation against comparison-guided substitution
- **F** classical against quantum-inspired optimisers — runs through
  `cargo test --release --test optimizer_tuning`, which carries the
  hyperparameter sweeps too; results are in `docs/DECISIONS.md` D13
- **G** worker scaling — **not implemented**, because multi-worker campaigns
  are not. Reporting a scaling number would be fabricating one.

## Running one

Via the CLI, since a benchmark runs many campaigns:

```
aether benchmark run --experiment e --config aether.toml --trials 5 --duration 60
```

Every arm gets the same budget, the same target and the same seeds. The
`research-benchmark` profile is applied automatically, which turns off the two
things that make a campaign depend on machine load — the cost-aware scheduler
and the corpus cost term — so a run replays from its seed.

Use at least 3 trials, 5 or more when the effect looks small.

## Interpreting the result

The harness reports min/median/max per arm, and states a difference **only when
it exceeds the spread between trials of a single arm**. That rule matters:
without it, noise reads as a result.

When the output says the arms are not distinguishable, that is the finding.
Report it as such. "No measurable difference at this budget on this target" is
a real and useful answer, and much better than picking the higher median and
calling it a win.

When a difference does exceed the spread, state it with its numbers and its
scope: this target, this budget, this host. Fuzzing results generalise poorly
between targets, and a result on one parser says little about another.

## Caveats to carry into any summary

- **Coverage is a proxy.** The objective is reproducible findings. A
  configuration that reaches more edges and finds nothing has not been shown to
  be better at the thing that matters.
- **Short campaigns favour fast strategies.** A strategy that needs time to
  build a corpus looks bad at 30 seconds and may win at an hour.
- **Single host, single worker.** No conclusion here is about scaling.
- **A target with no defects cannot distinguish bug-finding ability.** If
  neither arm finds anything, the experiment compared coverage only, and the
  output says so.

## What not to do

Do not report a speedup, a coverage improvement or a bug-count difference that
the trial spread does not support. Do not combine results from runs of
different lengths. Do not describe the quantum-inspired optimisers as a quantum
speedup — they are classical algorithms, and `docs/DECISIONS.md` D13 records
exactly where they do and do not beat the classical baseline.
