# Design decisions

Each entry records what was decided, what the alternatives were, and - where
the decision was driven by measurement - the numbers it came from. Numbers were
produced on the development host described in
[BENCHMARKING.md](BENCHMARKING.md); they are not claims about other hardware.

---

## D1. Own coverage runtime instead of wrapping an existing fuzzer

**Decision.** AETHER ships `runtime/aether_rt.c`, a dependency-free C runtime
that implements the SanitizerCoverage callbacks, and drives targets itself.

**Why.** The host audit found clang 18 able to *compile* `trace-pc-guard` and
`trace-cmp` instrumentation, but with no `libclang_rt.*` archives present and
no installation candidate, so `-fsanitize=fuzzer` cannot link and clang's
AddressSanitizer is unavailable. AFL++ has no package candidate either.
Wrapping an absent engine would have produced a tool that cannot run.

Linking compiler-emitted instrumentation against our own runtime was verified
to work before any engine code was written, including recovery of comparison
operands (`const=0xdeadbeef got=0x41414141` on the first probe).

**Consequence.** The native backend is the only one exercised end to end. The
libFuzzer and AFL++ adapters are interface-complete and report
`verified: false`, which `aether doctor` surfaces. See
[D9](#d9-third-party-adapters-ship-unverified).

---

## D2. Fork server as the default execution mode

**Decision.** Exec the target once and have its runtime fork a child per test
case, falling back to `execve`-per-run automatically if the handshake fails.

**Measured.** 1,200 executions per repetition, 5 repetitions, median reported:

| Configuration | Throughput | Per execution |
| --- | --- | --- |
| Fork server, coverage + comparison log | **3,249 exec/s** | 308 us |
| `execve` per run, coverage | 623 exec/s | 1,605 us |

**5.21x** speedup. The fallback matters: a binary with no AETHER runtime linked
in has no fork server to offer, and must still run.

**Rejected.** An in-process persistent mode (libFuzzer-style) would be faster
again, but a crash then takes down the engine along with the target, and the
harness has to be written against AETHER's API. Fork-per-input keeps any
executable usable and keeps a crash contained.

---

## D3. Comparison log on by default

**Decision.** Enable `trace-cmp` recording whenever the compiler supports it.

**Measured.** 1.1% throughput cost (3,249 vs 3,285 exec/s), which is inside the
+/-7% run-to-run spread on this host. Against that, the comparison log turns the
four nested constant gates in `fixtures/crash_magic.c` from a ~2^64 blind search
into four substitutions.

A cost that cannot be distinguished from noise, against a change in search
complexity, is not a trade-off worth making configurable-off by default.

---

## D4. Scratch files stay on the default temp directory

**Decision.** Do not relocate per-execution scratch files to `/dev/shm`.

**Measured.** tmpfs scratch came out at 3,099 exec/s against 3,249 for the
default location: **-4.6%**, i.e. no improvement, and within the +/-12% spread.
A negative result, recorded so it is not re-litigated: the test case and log
files are small and already absorbed by the page cache, so where they live is
not on the critical path.

---

## D5. Fused snapshot-and-bucket pass over the coverage map

**Decision.** `CoverageShm::snapshot_classified` copies and buckets the 65,536
slot map in one pass, reading 8 bytes at a time and skipping zero words.

**Why.** This runs once per execution. A copy followed by a separate classify
pass walks the whole map twice, and a real target touches a small fraction of
it. Combined with dropping a per-run `dup`/`close` pair on the log handles and
short-circuiting empty logs, this took throughput from 3,246 to ~3,461 exec/s in
the single-repetition measurement (+6.6%); under the 5-repetition protocol the
two sit within each other's spread, so the honest claim is "no measurable
regression, less work per execution".

---

## D6. Coverage granularity: `no-prune`, and a selectable optimisation level

**Decision.** Pass `-fsanitize-coverage=trace-pc-guard,trace-cmp,no-prune`, and
expose `--opt` on `aether-cc`, defaulting to `-O1`.

**Measured** on `fixtures/coverage_ladder.c`, which unlocks one more block per
correct prefix byte. Edge counts for inputs `""`, `"AE"`, `"AETH"`, `"AETHER"`:

| Build | Guards | Edge counts |
| --- | --- | --- |
| `-O1`, default pruning | 5 | 2, 3, 3, 4 |
| `-O1`, `no-prune` | 10 | 7, 7, 7, 8 |
| `-O0`, `no-prune` | 19 | 10, 11, 13, 15 |

Pruning removes guards in dominated blocks, which flattens exactly the gradient
corpus ranking depends on. `-O0` gives the most sensitive signal and is what the
fixtures' coverage tests use; `-O1` is the default because throughput matters
too.

---

## D7. Address-space limit is dropped for sanitizer builds, and the swap is reported

**Decision.** Do not apply `RLIMIT_AS` to a target that links a sanitizer
runtime. Bound memory with the sanitizer's own `hard_rss_limit_mb` instead, and
record the substitution in `LimitReport::memory_limit_substituted`.

**Why.** Found by a failing test, not by reading documentation: the ASan build
of `fixtures/heap_oob.c` died with

```
AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes
ReserveShadowMemoryRange failed while trying to map 0xdfff0001000 bytes
```

ASan reserves roughly 20 TiB of shadow address space at startup, so any memory
budget a campaign would plausibly set stops the target from starting rather than
bounding it.

The engine sets `ASAN_OPTIONS` itself while `target.env` *refuses* those
variables ([D8](#d8-configuration-may-not-set-loader-or-sanitizer-variables)).
That asymmetry is deliberate: the engine turns the oracle up and adds the RSS
bound, and configuration is not allowed to turn it down.

---

## D8. Configuration may not set loader or sanitizer variables

**Decision.** `target.env` rejects `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
the `DYLD_*` pair, `*SAN_OPTIONS`, and the `AETHER_*` control variables.

**Why.** Those names change which code runs, or suppress the crash oracle. A
config file that can set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0` can make
a campaign silently stop finding things. Targets are also launched with
`env_clear()`, so a variable in the operator's shell cannot change what is
tested either.

---

## D9. Third-party adapters ship unverified

**Decision.** The libFuzzer and AFL++ adapters declare their full contract and
carry `verified: false`.

**Why.** Neither engine is installable on this host, so their drive paths have
never run against the real thing. Detection probes for the *runtime archive*,
not just for clang, because this host is precisely the case that would otherwise
report libFuzzer as available and then fail at link time.

---

## D10. Threads, not async, for the worker pool

**Decision.** `std::thread` plus `crossbeam-channel`. No async runtime.

**Why.** The work is CPU-bound process supervision, a few workers deep. An async
runtime would add a large dependency and a scheduler for concurrency that
`fork`/`waitpid` do not benefit from. Blocking a thread on `waitpid` is the
natural shape.

---

## D11. Differential and metamorphic testing are oracles, not generators

**Decision.** Implement them as `Oracle` implementations rather than as
`Strategy` implementations, even though the specification groups them under
input generation.

**Why.** Neither produces inputs. Both take an input some other strategy
produced and decide whether the behaviour it caused is acceptable - a
disagreement between two implementations, or a violated relation. Modelling them
as strategies would have required a strategy that returns no candidates, and
would have put the comparison logic on the wrong side of the interface.

---

## D12. 128-bit content hashes

**Decision.** BLAKE3 truncated to 128 bits, as 32 lowercase hex characters.

**Why.** At any corpus size AETHER will see, 128 bits is far below practical
collision risk, and it halves the index and path length against a full 256-bit
digest. Hashes that arrive from outside the process are validated as plain
lowercase hex before they are used to build a path.
