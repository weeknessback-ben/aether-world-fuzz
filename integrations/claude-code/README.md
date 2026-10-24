# AETHER for Claude Code

Runs adaptive fuzzing campaigns from a Claude Code conversation: inspect a
target, design a campaign, start it, watch it, and turn what it finds into
reproducible evidence.

The plugin is a thin layer. Every tool shells out to the same `aether` binary a
person would run from a terminal, so the conversation and the command line
cannot disagree about what happened. No fuzzing logic lives here.

## What you get

**16 MCP tools** under the `aether` server, covering target inspection,
campaign lifecycle, coverage and corpus analysis, finding validation and
reporting.

**Four skills** that teach the workflows rather than duplicating the tools:

| Skill | For |
| --- | --- |
| `campaign` | Designing, running and interpreting a campaign |
| `finding-validation` | Turning a crash into evidence, or showing it is not one |
| `corpus-analysis` | Explaining why a campaign stalled, and what to change |
| `benchmark` | Comparing configurations so the result holds up |

**Three agents** for focused work: `aether-planner` designs a campaign,
`aether-campaign-analyst` diagnoses one, `aether-finding-validator` triages
findings.

**One hook**, at session start, that reports whether the integration is usable
and what to fix if not. It only reads — it never builds anything and never
starts a campaign.

## Setup

Build the engine and the server:

```bash
cargo build --release                       # produces target/release/aether
cd integrations/claude-code/mcp-server
npm install && npm run build
```

Then add the plugin. From a local checkout:

```bash
claude --plugin-dir integrations/claude-code
```

Or install it from this repository's marketplace:

```
/plugin install aether-fuzzing --marketplace weeknessback-ben/self-aware_fuzz
```

Either way, check it:

```bash
./integrations/claude-code/scripts/health-check.sh
```

It prints where it found the engine, or exactly what is missing.

## Configuration

Two optional settings, prompted when the plugin is enabled:

- **`aether_binary`** — path to the `aether` binary. Leave it empty and the
  server looks in `target/release`, then `target/debug`, then `PATH`.
- **`output_dir`** — where campaign state, corpus and reports go. Defaults to
  `.aether`.

## How it behaves

**Starting a campaign is deliberate.** `aether_campaign_start` requires
`acknowledge_resource_use: true`. A campaign saturates a CPU core for its whole
budget, so it is not something a tool call should do incidentally.

**Nothing blocks for the length of a campaign.** Starting one returns a job id
immediately. Progress comes from `aether_campaign_status`, and stopping from
`aether_campaign_cancel` — which works through a file the engine watches, so a
campaign can still be stopped after the MCP server restarts.

**Scope is enforced in the engine, not here.** Local executables are allowed by
default. A network target is refused unless the configuration names the host,
records an authorization note and sets a rate limit. No tool call can widen
that, and supplying an address is not authorization to test it.

**Output is bounded.** No tool returns a whole corpus, a raw process log or an
unbounded finding list. Large artifacts are referenced by path and content
hash.

**Status distinguishes "not measured" from zero.** An uninstrumented target
reports `total_edges: null`, not `0`. The difference matters when deciding what
a campaign actually showed.

## First run

```
Check the fuzzing environment, then inspect ./target/release/my-parser
and tell me whether it is ready to fuzz.
```

The honest answer is often "not yet": a target built without
`runtime/aether-cc` has no coverage feedback, and the `campaign` skill says so
before spending any CPU on it.

## Reading results

Only `reproducible` and `intermittent` findings are established defects.
`unconfirmed` means a failure was seen once and never reproduced — the tools
label it, and the skills are explicit that it must not be counted as a bug.

Nothing here claims exploitability. A crash is a crash; the engine records that
exploitability was not assessed, and the skills carry that caveat into any
write-up.
