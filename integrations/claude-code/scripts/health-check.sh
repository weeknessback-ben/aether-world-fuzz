#!/usr/bin/env bash
# Report whether this plugin's integration is usable, and say what to fix if not.
#
# Runs at session start as a hook, and is also the documented health check a
# person can run by hand. It only reads: it never builds anything, never starts
# a campaign, and never changes configuration. A hook that launched a fuzzing
# campaign because a session opened would be a hostile surprise.
set -uo pipefail

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

say() { [[ "$QUIET" == "1" ]] || echo "$@"; }
warn() { echo "aether: $*" >&2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${CLAUDE_PROJECT_DIR:-$PWD}"

problems=0

# 1. The MCP server has to be built.
SERVER="$HERE/mcp-server/dist/index.js"
if [[ ! -f "$SERVER" ]]; then
  warn "the MCP server is not built. Run: (cd '$HERE/mcp-server' && npm install && npm run build)"
  problems=$((problems + 1))
else
  say "aether: MCP server present"
fi

# 2. The engine binary has to be findable.
BIN="${AETHER_BINARY:-}"
if [[ -z "$BIN" ]]; then
  for c in "$PROJECT/target/release/aether" "$PROJECT/target/debug/aether"; do
    [[ -x "$c" ]] && BIN="$c" && break
  done
fi
if [[ -z "$BIN" ]]; then
  BIN="$(command -v aether 2>/dev/null || true)"
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  warn "the aether binary was not found. Build it with: (cd '$PROJECT' && cargo build --release), or set the plugin's aether_binary option."
  problems=$((problems + 1))
else
  say "aether: engine at $BIN"
  # 3. A compiler able to emit the instrumentation is the one hard requirement.
  if ! "$BIN" doctor --json >/dev/null 2>&1; then
    warn "'$BIN doctor' reported no usable execution backend. Install clang (preferred) or gcc."
    problems=$((problems + 1))
  else
    say "aether: at least one execution backend is usable"
  fi
fi

if [[ "$problems" -gt 0 ]]; then
  warn "$problems problem(s) found; the aether tools will report the same when called."
  # Exit 0 regardless: a session must not fail to start because an optional
  # integration is incomplete.
fi
exit 0
