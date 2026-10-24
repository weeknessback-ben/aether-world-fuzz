# Example configurations

Each one is a complete, valid campaign configuration. Paths assume targets
built into `build/` with `runtime/aether-cc`:

```bash
./runtime/aether-cc -o build/crash_magic fixtures/crash_magic.c
./target/release/aether campaign run --config examples/quick-local.toml
```

| File | For |
| --- | --- |
| `quick-local.toml` | Is this target worth fuzzing at all |
| `structured-parser.toml` | A format parser, with a dictionary and a grammar |
| `stateful-api.toml` | A protocol where the *order* of operations matters |
| `sanitizer-oracle.toml` | Two builds: fast coverage, plus a sanitizer oracle |
| `low-resource.toml` | A constrained machine |
| `research-benchmark.toml` | Comparing configurations; replays from its seed |
| `ci-gate.toml` | A fixed work budget for CI |
| `network-target.toml` | What authorizing a network target actually requires |

`tlv.bnf` is a grammar for the format `fixtures/toy_parser.c` accepts, and
`tlv.dict` the matching dictionary.
