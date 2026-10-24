---
name: campaign
description: Design, run and interpret an AETHER fuzzing campaign against a target. Use when asked to fuzz something, test a parser with malformed input, look for crashes or memory-safety bugs, or set up a fuzzing campaign.
---

# Running a fuzzing campaign

This skill drives the `aether_*` MCP tools. It does not reimplement anything
they do — the engine owns execution, scheduling and validation.

## Before anything else

Call `aether_environment_check` once. It reports which execution backends work
on this host and which do not, and why. Plan around what it says rather than
around what the engine supports in principle: on a host without clang's
sanitizer runtimes, for example, libFuzzer targets simply cannot be built.

## 1. Inspect the target

Call `aether_target_inspect` with the binary path. The answer decides the plan:

| What it reports | What it means |
| --- | --- |
| `instrumented: true`, guards > 0 | Coverage feedback works. Full strategy set available. |
| `comparison_log: true` with comparisons seen | `cmplog-guided` is available, and on a target gated by magic values it is usually the single most effective strategy. |
| `instrumented: false` | **Stop and say so.** Only exit status is observable. Recommend rebuilding with `runtime/aether-cc` before continuing, and explain that a campaign without coverage is far weaker. |
| `fork_server: false` | Roughly 5x slower. Usually means the binary was not linked against the AETHER runtime. |

If the target is uninstrumented, say that plainly before running anything. A
campaign will still run, but reporting its coverage numbers as meaningful
would be wrong.

## 2. Check scope

Local executables are allowed by default. A **network target is refused**
unless the configuration names the host explicitly, records an authorization
note, and sets a rate limit. This is enforced in the engine, so a tool call
cannot widen it.

If the user asks to fuzz something reachable over the network, do not try to
work around the refusal. Ask who authorized the testing and record it in
`scope.authorization_note`. Supplying an address is not authorization to test
it.

## 3. Choose a budget and strategies

Call `aether_strategy_recommend` — it only suggests strategies whose required
signals the target actually produces.

Budget guidance:

- **Exploring an unfamiliar target:** 60–300 seconds. Enough to see whether
  coverage grows at all.
- **Looking for a specific defect class:** 600+ seconds with the matching
  strategy set (`structure-aware` and `dictionary` for a format parser,
  `stateful-sequence` for a protocol).
- **CI gate:** a fixed `max_execs` rather than a duration, so the run takes the
  same work on every machine.

Pick a profile where one fits: `quick-local`, `structured-parser`,
`stateful-api`, `low-resource`, `deep-exploration`, `research-benchmark`.
Use `research-benchmark` whenever two configurations are being compared, since
it makes a campaign replay from its seed.

## 4. Run it

`aether_campaign_create` first — it validates everything and reports exactly
which field is wrong, before any CPU is spent.

Then `aether_campaign_start` with `acknowledge_resource_use: true`. It returns a
job id immediately; the campaign runs in the background and will saturate a
core for its whole budget.

Poll `aether_campaign_status` every few seconds. What to watch:

- `total_executions` not rising → the target is failing to start, or every
  input is timing out. Check the job log path from the start result.
- `total_edges` flat from the beginning → coverage feedback is not working, or
  the seeds never get past a first check.
- `stagnation_phase: Stagnant` → discovery has stopped. The scheduler is
  already responding; mention it, do not restart the campaign reflexively.
- `coverage_saturation` near 1.0 → most of the instrumented code is reached.
  More time on this target and harness is unlikely to help; a better harness
  would.

Use `aether_campaign_cancel` when the user asks to stop, or when status shows
the campaign is clearly not working.

## 5. Report what was actually found

Call `aether_findings_list`, then `aether_finding_detail` for each one.

**The statuses are not interchangeable:**

- `reproducible` — reproduced at or above the configured threshold. A defect.
- `intermittent` — reproduced sometimes, below the threshold. A defect, but say
  it is intermittent and give the rate.
- `unconfirmed` — observed once, never reproduced. **Not a defect.** Mention it
  as an observation if relevant, never in a count of bugs found.
- `duplicate`, `environmental` — not separate defects.

When reporting a finding:

- Give the reproduction command and the input hash from the evidence.
- Give the reproduction rate as a fraction, not as "reproducible" alone.
- **Do not claim exploitability.** A crash is a crash. The engine records that
  exploitability was not assessed, and that caveat belongs in the summary.
- Pass on the caveats in the evidence, especially `unenforced_limits`.

When nothing was found, say what that does and does not mean: this target, this
budget, this configuration. It is not a clean bill of health.

## Common situations

**"It found nothing."** Check `total_edges` and `coverage_saturation` first. Flat
coverage usually means a harness problem, not an absence of bugs. Suggest
seeds, a dictionary, or a grammar before suggesting more time.

**"It found hundreds of crashes."** It did not — look again. The engine
deduplicates by failure signature, so a large candidate count with few findings
means one defect reached many ways. Report the findings.

**"Which strategy found it?"** `discovered_by` on the finding, and the report's
strategy table shows what each was allocated and returned.
