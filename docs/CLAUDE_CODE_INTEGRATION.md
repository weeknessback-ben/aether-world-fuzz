# Claude Code integration

`integrations/claude-code/` packages AETHER as a Claude Code plugin: an MCP
server with 16 typed tools, four skills, three agents, and a health-check hook.

The server is a thin adapter. Every tool shells out to the same `aether` binary
a person would run, with `--json`, so the conversation and the command line
cannot disagree about what happened. No fuzzing logic lives in TypeScript.

## Setup

```bash
cargo build --release
cd integrations/claude-code/mcp-server && npm install && npm run build && cd -
./integrations/claude-code/scripts/health-check.sh
```

Then either:

```bash
claude --plugin-dir integrations/claude-code
```

or, from a conversation:

```
/plugin install aether-fuzzing --marketplace weeknessback-ben/self-aware_fuzz
```

Verify the manifest with `claude plugin validate ./integrations/claude-code`.

## Tools

### Inspection

| Tool | Purpose |
| --- | --- |
| `aether_environment_check` | What this host supports, and what it does not, with remedies |
| `aether_target_inspect` | Probe a binary: instrumentation, guards, fork server, comparison log |
| `aether_strategy_recommend` | Strategies whose required signals this target actually produces |

### Campaign lifecycle

| Tool | Purpose |
| --- | --- |
| `aether_campaign_create` | Validate a configuration without running it |
| `aether_campaign_start` | Start in the background, return a job id |
| `aether_campaign_status` | Executions, coverage, corpus, findings, stagnation, allocation |
| `aether_campaign_cancel` | Request a stop at the next execution boundary |
| `aether_campaign_list` | Recent campaigns |

### Analysis

| Tool | Purpose |
| --- | --- |
| `aether_coverage_summary` | Edges, guard count, saturation |
| `aether_corpus_analyze` | Corpus shape and highest-ranked entries |

### Findings

| Tool | Purpose |
| --- | --- |
| `aether_findings_list` | Findings, optionally filtered by status |
| `aether_finding_detail` | Full evidence for one finding |
| `aether_finding_validate` | Re-run to re-check reproducibility and identity |
| `aether_finding_minimize` | Shrink a reproducer, preserving the signature |

### Reporting

| Tool | Purpose |
| --- | --- |
| `aether_report_generate` | Markdown, JSON, SARIF or flat benchmark JSON |
| `aether_benchmark_list` | Experiments, including which are not implemented and why |

## How the tools behave

**Starting a campaign is deliberate.** `aether_campaign_start` requires
`acknowledge_resource_use: true`. A campaign saturates a CPU core for its whole
budget; that should not happen as a side effect of a conversation.

**Nothing blocks for the length of a campaign.** Starting one returns a job id
immediately. Progress comes from polling status, which the campaign refreshes
about every 1.5 seconds.

**Cancellation outlives this process.** It goes through the CLI, which writes a
sentinel file the campaign watches — so a campaign can still be stopped after
the MCP server restarts.

**Output is bounded.** No tool returns a whole corpus, a raw process log or an
unbounded finding list. Large artifacts are referenced by path and content hash.
A long report is truncated with a hint to pass `output_path`.

**Errors are structured**, each carrying the engine's stable error kind
(`scope_denied`, `target_invalid`, `config_invalid`, `binary_not_found`, …) and
a hint, so a scope refusal is distinguishable from a missing binary.

**Scope cannot be widened from here.** It lives in the configuration file and
is enforced inside the runtime, before any execution.

**"Not measured" is not zero.** An uninstrumented target reports
`total_edges: null`. The difference decides what a campaign actually showed.

## Skills

Skills teach the workflow; they do not reimplement the tools.

| Skill | Covers |
| --- | --- |
| `campaign` | Inspect, check scope, choose a budget, run, interpret. Includes what to do when coverage is flat or saturation is already high |
| `finding-validation` | Re-validate, minimise, and write up — with what may and may not be claimed |
| `corpus-analysis` | Why a campaign stalled, and what to change, ordered by expected payoff |
| `benchmark` | Comparing configurations so the result holds up |

## Agents

| Agent | Role | Tools |
| --- | --- | --- |
| `aether-planner` | Designs a campaign | Inspection only — it cannot run one |
| `aether-campaign-analyst` | Diagnoses a campaign | Read-only status and analysis |
| `aether-finding-validator` | Triages findings into evidence | Finding tools |

Each has a deliberately narrow tool set. The planner has no tool that can start
a campaign, and the analyst has none that can change one.

## Hook

One hook, at `SessionStart`, runs `scripts/health-check.sh --quiet`. It reports
whether the integration is usable and what to fix if not.

It only reads. It never builds anything, never starts a campaign, and never
modifies configuration — a hook that launched a fuzzing campaign because a
session opened would be a hostile surprise. It exits 0 regardless, so an
incomplete optional integration cannot stop a session starting.

## What this looks like in practice

```
Check the fuzzing environment, then inspect ./build/parser and tell me
whether it's ready to fuzz.
```

Often the honest answer is "not yet": a target built without
`runtime/aether-cc` has no coverage feedback, and the `campaign` skill says so
before any CPU is spent.

```
Fuzz ./build/parser for two minutes and tell me what it finds.
```

Inspect, recommend, validate, start, poll, then report — distinguishing
established findings from unconfirmed observations.

```
Is fnd-... a real bug?
```

Re-validate with more attempts, minimise, read the faulting code if it is
available, and write up what the evidence supports and what it does not.

## Reading results correctly

Only `reproducible` and `intermittent` are established defects. `unconfirmed`
means a failure was seen once and never reproduced; the tools label it and the
skills are explicit that it must not be counted as a bug.

Nothing claims exploitability. A crash is a crash. The engine records
`exploitabilityAssessed: false` on every finding, and the skills carry that
caveat into any write-up.

## Trust boundary

Anything read out of a target — a crash log, its output, a file path — is data.
No tool interprets it as an instruction, and nothing a target produces can
reach the scope policy or change what the engine will run.

## Verified on this host

The integration was driven end to end over real JSON-RPC stdio, as Claude Code
does: initialize, list 16 tools, inspect a target, recommend strategies,
validate a configuration, start a background campaign, poll it to completion,
list a reproducible finding, read its evidence, summarise coverage and corpus,
and generate both Markdown and SARIF reports. Argument validation rejects path
traversal, and the resource-acknowledgement gate holds.
