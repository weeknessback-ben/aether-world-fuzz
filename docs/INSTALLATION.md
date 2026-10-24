# Installation

## Prerequisites

| Requirement | Why | Notes |
| --- | --- | --- |
| Rust 1.76+ | The engine | `rustup` or your distribution's package |
| **clang** or gcc | Instruments targets | clang strongly preferred — see below |
| Linux | `/dev/shm`, `setpgid`, `prctl` | macOS and Windows are not supported |
| Node 18+ | Claude Code integration only | Not needed for the CLI |

**clang matters more than it looks.** Only clang emits `trace-cmp`, which is
what produces the comparison log — and comparison-guided substitution is where
most of AETHER's advantage over blind mutation comes from. gcc works, but gives
coarser coverage (derived from return addresses) and no comparison log at all.

A sanitizer build needs a compiler whose sanitizer runtime is present. gcc
ships `libasan` with the compiler package; a clang install may lack
`libclang_rt`, in which case `aether-cc --sanitizer address --cc clang` fails
at link time and you should use `--cc gcc` for the oracle build.

## Build

```bash
git clone https://github.com/weeknessback-ben/self-aware_fuzz
cd self-aware_fuzz
cargo build --release
./target/release/aether doctor
```

`doctor` is the real check. It reports which execution backends work here,
which resource limits this host actually enforces, and what is missing — with
the remedy for each. Read it before anything else; it will tell you, for
instance, that libFuzzer is unavailable because the runtime archive is absent,
rather than letting you discover that at link time.

Optionally put it on `PATH`:

```bash
install -m755 target/release/aether ~/.local/bin/aether
```

## Build a target

Instrumentation is not optional in any meaningful sense: without it there is no
coverage feedback, no comparison log, and corpus ranking loses its strongest
signal.

```bash
./runtime/aether-cc -o build/parser harness.c parser.c
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--cc gcc` | Use gcc. Coarser coverage, no comparison log |
| `--sanitizer address` | AddressSanitizer build. Use `--cc gcc` if clang lacks its runtime |
| `--opt -O0` | Most sensitive coverage gradient; slower |
| `--no-cmplog` | Drop comparison tracing. Rarely worth it — it costs about 1% |
| `--no-instrument` | No instrumentation. For an oracle-only build |

An instrumented binary still runs normally by hand: with no `AETHER_SHM_PATH`
in the environment, the runtime callbacks fall back to a private map and the
program behaves as usual.

### Two builds are better than one

A sanitizer sees faults that do not crash on their own — a heap overflow that
happens to land in unused memory, for example. But a clang sanitizer build may
be impossible where its runtime is missing, and gcc cannot produce a comparison
log. So build both and let the engine use each for what it is good at:

```bash
./runtime/aether-cc -o build/parser harness.c parser.c                       # fast, cmplog
./runtime/aether-cc --cc gcc --sanitizer address -o build/parser-asan harness.c parser.c
```

```toml
[target]
binary = "build/parser"              # the campaign loop runs this
oracle_binary = "build/parser-asan"  # candidates are re-run here
```

The campaign uses the fast build; the evidence engine re-runs candidates
against the oracle. Without an `oracle_binary` the report says so, under
limitations.

## First campaign

```bash
./target/release/aether target inspect build/parser
./target/release/aether init --binary build/parser --output aether.toml
./target/release/aether campaign run --config aether.toml
```

`target inspect` first. If it reports `Instrumented: no`, stop and fix the
build — a campaign will run, but its coverage numbers will be meaningless.

## Claude Code plugin

```bash
cd integrations/claude-code/mcp-server
npm install && npm run build
cd -
./integrations/claude-code/scripts/health-check.sh
```

Then either:

```bash
claude --plugin-dir integrations/claude-code        # local checkout
```

or, from a conversation:

```
/plugin install aether-fuzzing --marketplace weeknessback-ben/self-aware_fuzz
```

Verify with `claude plugin validate ./integrations/claude-code`.

See [CLAUDE_CODE_INTEGRATION.md](CLAUDE_CODE_INTEGRATION.md) for the tools and
how to use them.

## Removal

```bash
rm -rf target/ .aether/                              # build output and campaign state
rm -rf integrations/claude-code/mcp-server/{node_modules,dist}
```

Remove the plugin with `/plugin uninstall aether-fuzzing`, or by dropping the
`--plugin-dir` flag. Nothing is written outside the repository and `.aether/`
unless you configured `output.dir` elsewhere; no global Claude Code settings
are modified.

## Troubleshooting

**`doctor` reports no usable backend.** Install clang or gcc. Nothing works
without one.

**`aether-cc` fails with `cannot find libclang_rt...`.** clang's sanitizer
runtime is absent. Use `--cc gcc` for sanitizer builds, or install the
compiler-rt package (`libclang-rt-<version>-dev` on Debian and Ubuntu).

**`target inspect` reports `Instrumented: no`** for a binary you built with
`aether-cc`. Check that `aether_rt.c` was linked — `nm binary | grep
__sanitizer_cov` should show symbols.

**`Fork server: no`.** The binary has no AETHER runtime linked, so there is no
fork server to offer. The campaign falls back to exec-per-run, roughly 5x
slower, and says so in its limitations.

**Campaign runs but coverage stays at zero.** Usually the harness rejects every
input at a first check. Supply seeds, a dictionary, or a grammar before
reaching for more time.

**MCP tools report `binary_not_found`.** Build with `cargo build --release`, or
set the plugin's `aether_binary` option to the binary's path.
