# Threat model

AETHER runs arbitrary programs on deliberately malformed input. That makes the
engine itself security-sensitive software, in two directions: the target is
hostile to the engine, and the engine is dangerous to whatever the target can
reach.

Everything below distinguishes what is **enforced in code** from what is
**documented but not enforced**. Treating the second kind as the first is the
mistake this document exists to prevent.

## Assets

| Asset | Why it matters |
| --- | --- |
| The host running AETHER | A target can fork, write files, open sockets |
| Findings and corpus | Evidence; losing it loses the work |
| Campaign metadata | Decides what counts as novel; corruption silently degrades a campaign |
| Target scope | Testing something unauthorized is the worst outcome here |

## Adversaries

**The target.** Not malicious, but under attacker-controlled input and
therefore capable of anything its code permits: crashing, hanging, forking
without bound, writing endlessly, printing text designed to look like
something else.

**Target-controlled content.** Crash logs, stdout, protocol responses, file
paths. All of it is data. None of it is ever interpreted as instruction, and
none of it can reach the scope policy.

**A malformed configuration**, hand-written or generated, that would widen what
the engine does.

**Not in scope:** a compromised host, a malicious compiler, an attacker with
local code execution. AETHER offers nothing against those.

## What is enforced in code

### Target scope

`scope::ScopePolicy::authorize_target` is called before any execution, and
`TargetSpec::from_config` is the only constructor for an executor, so there is
no path to a running target that skipped the check.

- Local execution allowed by default — the laboratory case the tool exists for.
- A network target is refused unless **all three** hold: the host is listed
  explicitly, `authorization_note` is non-empty, and
  `max_requests_per_second` is set.
- **Loopback is not special-cased.** `127.0.0.1:8080` may be someone's
  production admin panel forwarded over SSH.
- **No wildcards, no subdomain inheritance.** `example.com` does not authorize
  `admin.example.com`. Refused at validation time.
- Nothing a target produces can reach this module.

Tested in `scope::tests`, including that a URL alone is not authorization.

### No shell, ever

Targets are launched from an explicit program path and an argument vector, with
`shell: false` in the MCP adapter and `Command` with argument arrays in the
engine. A mutated input cannot become a shell metacharacter, because no string
is ever handed to a shell.

Tested with inputs containing `; rm -rf /`, `$(touch ...)`, backticks, NUL
bytes and path traversal, asserting the side effect did not happen.

### Configuration cannot redirect the loader or disable the oracle

`target.env` refuses `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, the `DYLD_*`
pair, every `*SAN_OPTIONS`, and the `AETHER_*` control variables. Those names
change which code runs or suppress crash detection.

Targets are launched with `env_clear()`, so a variable in the operator's shell
cannot change what is tested either.

The engine sets `ASAN_OPTIONS` itself while configuration may not. That
asymmetry is deliberate: the engine turns the oracle *up* and adds an RSS
bound, and configuration is not allowed to turn it down.

### Identifiers and hashes cannot escape a directory

Every identifier arriving from outside — a CLI argument, an MCP request, a
database row — is validated against `[A-Za-z0-9_-]` with a required prefix, and
content hashes against 32 lowercase hex characters, *before* either is used to
build a path or reach a SQL statement.

Tested with `../../../../etc/passwd`, `cmp-a;DROP TABLE campaigns`,
`' OR 1=1 --` and uppercase hex.

### Resource limits, with honest reporting

Applied post-fork: `RLIMIT_AS` from the configured memory budget,
`RLIMIT_FSIZE` at 64 MiB, `RLIMIT_NPROC` at 256, `RLIMIT_CORE` at 0, and
`setpgid` so a timeout signals the whole group and reaps grandchildren.

`ProcessLimits::probe` reports what the host will actually accept, and
`LimitReport::unenforced` names anything it would not. A report never implies a
containment guarantee the host did not provide.

**One substitution is made and reported.** A sanitizer build reserves roughly
20 TiB of shadow address space, so `RLIMIT_AS` stops it starting rather than
bounding it. For such builds the address-space limit is dropped and memory is
bounded by the sanitizer's own `hard_rss_limit_mb` instead, recorded in
`memory_limit_substituted` and carried into every finding's evidence.

### Deadlines and child cleanup

Every run has a deadline. On expiry the process *group* is SIGKILLed, so a
target that forked children cannot leak them. The fork-server protocol stays in
lockstep across a timeout: the engine kills the reported pid and still reads the
pending status word.

Tested with a spinning target, asserting the deadline fires and the executor
remains usable afterwards.

### Output capture is bounded as it streams

stdout and stderr are capped while being read, not truncated afterwards, and
truncation is reported rather than silent. A target that prints without end
cannot exhaust memory or fill a report.

Tested against a fixture that prints 20,000 lines with embedded NUL bytes.

### A target cannot manufacture a finding

A sanitizer report is believed only when it arrives **on stderr** from a
process that terminated **abnormally**. `fixtures/noisy_output.c` prints a
convincing AddressSanitizer banner on stdout and exits 0 precisely to test
this; it must not produce a finding.

### Evidence cannot be lost to retention

An input tied to a finding is excluded by the query that selects eviction
candidates, so a trimming bug cannot discard a reproducer. The original input
and its hash are retained even after minimisation.

### Storage integrity

Objects are written to a temporary name and renamed into place — `rename(2)`
within a directory is atomic — so an interrupted write cannot leave a truncated
object that a later read treats as valid. `ContentStore::verify` re-hashes
stored content, and directory traversal does not follow symlinks, so a link
planted in the store cannot walk out of it.

### MCP surface

- Starting a campaign requires `acknowledge_resource_use: true`. It saturates a
  core for its whole budget; that should not happen as a side effect.
- Every argument is schema-validated, with bounded lengths and regex-checked
  identifiers.
- No tool returns an unbounded list; large artifacts are referenced by hash.
- Nothing blocks for the length of a campaign.
- **No tool can change the scope policy.** It lives in the configuration file
  and is enforced in the runtime.

## What is documented but not enforced

Stated plainly, because the distinction is the point of this document.

**Process isolation is partial.** rlimits and process groups are not a security
boundary. A target can still read any file the invoking user can, open outbound
sockets, and consume CPU up to its deadline. AETHER does not claim containment.

**No sandbox is applied by default.** `unshare --user --net` is available on
Linux hosts and would give network isolation; the engine does not currently use
it. Running untrusted targets in a container or VM is the operator's
responsibility, and a container is not a complete boundary in every
configuration either.

**Rate limiting for network targets is validated, not applied.** The policy
requires `max_requests_per_second` to be set before a network target is
accepted, and the value is recorded — but no network execution backend exists,
so nothing enforces it at request time. When one is added, it must.

**Corpus content is attacker-influenced.** Inputs in the store were shaped by a
fuzzer against a possibly-buggy target. Treat exported corpus files as
untrusted input to whatever consumes them next.

**Findings are not sanitized for downstream display.** A finding's stderr
excerpt is target-controlled text, bounded but not escaped. A system rendering
it as HTML must escape it.

## Residual risks

| Risk | Mitigation | Residual |
| --- | --- | --- |
| Target escapes resource limits | rlimits, process groups, deadlines | Not a security boundary; use a container for untrusted targets |
| Target exhausts disk | `RLIMIT_FSIZE`, bounded capture, retention | A target writing many small files within its limit can still fill a volume |
| Unauthorized target tested | Scope policy enforced pre-execution | An operator who writes a host into `authorized_hosts` has authorized it; the engine cannot verify they were entitled to |
| Evidence lost | Retention exemption, atomic writes, transactions | A disk failure mid-campaign loses the uncheckpointed tail |
| Misleading report | Status separation, exploitability disclaimers, null-not-zero | A reader who ignores the status field can still misread a report |

## Reporting a vulnerability in AETHER

Open an issue describing the behaviour and how to reproduce it. If it concerns
a way the engine can be made to run something out of scope, or to lose
evidence, say so prominently — those are the two failures that matter most here.
