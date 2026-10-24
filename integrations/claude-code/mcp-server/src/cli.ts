/**
 * Adapter over the `aether` binary.
 *
 * The MCP server implements no fuzzing logic. Every tool shells out to the
 * same CLI a human would use, with `--json`, so the two interfaces cannot
 * drift apart in behaviour. If a tool here produces a result the CLI would
 * not, that is a bug in this file.
 *
 * Two properties this module is responsible for:
 *
 *  - **No shell.** The binary is spawned with an argument array and
 *    `shell: false`, so nothing arriving from an MCP request - a campaign id,
 *    a path, a status filter - can become a shell metacharacter.
 *  - **Bounded output.** stdout and stderr are capped as they stream. A
 *    campaign can print a great deal, and an MCP response must stay small
 *    enough to be useful in a conversation.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

/** Hard cap on captured output per stream. */
const MAX_CAPTURE_BYTES = 1_000_000;

/** Default ceiling on how long a single CLI invocation may take. */
const DEFAULT_TIMEOUT_MS = 120_000;

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

export class AetherError extends Error {
  constructor(
    message: string,
    readonly kind: string,
    readonly exitCode: number,
    readonly stderr: string,
  ) {
    super(message);
    this.name = "AetherError";
  }
}

/**
 * Locate the `aether` binary.
 *
 * Checked in order: an explicit override, the plugin's own bundled build, a
 * release build in the repository, a debug build, then `PATH`. Resolving it
 * once at startup means a tool call fails with a clear message rather than a
 * spawn error buried in a tool result.
 */
export function resolveBinary(explicit?: string): string {
  if (explicit) return explicit;
  const fromEnv = process.env.AETHER_BINARY;
  if (fromEnv) return fromEnv;

  const root = process.env.AETHER_REPO_ROOT ?? process.env.CLAUDE_PLUGIN_ROOT ?? process.cwd();
  const candidates = [
    join(root, "target", "release", "aether"),
    join(root, "target", "debug", "aether"),
    join(root, "..", "..", "..", "target", "release", "aether"),
    join(root, "..", "..", "..", "target", "debug", "aether"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  // Fall back to PATH; spawn reports a usable error if it is not there.
  return "aether";
}

export interface RunOptions {
  cwd?: string;
  timeoutMs?: number;
  /** Extra environment. The child otherwise inherits this process's. */
  env?: Record<string, string>;
}

/**
 * Run the CLI with an argument array.
 *
 * `shell` is left false deliberately: arguments reach the binary as a vector,
 * so a campaign id containing `;` is an invalid identifier rather than a
 * command separator.
 */
export function runCli(
  binary: string,
  args: string[],
  options: RunOptions = {},
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let truncated = false;
    let timedOut = false;

    const cap = (current: string, chunk: string): string => {
      if (current.length >= MAX_CAPTURE_BYTES) {
        truncated = true;
        return current;
      }
      const room = MAX_CAPTURE_BYTES - current.length;
      if (chunk.length > room) {
        truncated = true;
        return current + chunk.slice(0, room);
      }
      return current + chunk;
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c: string) => {
      stdout = cap(stdout, c);
    });
    child.stderr.on("data", (c: string) => {
      stderr = cap(stderr, c);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      // The whole group, so a campaign's children go too.
      child.kill("SIGKILL");
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    child.on("error", (e) => {
      clearTimeout(timer);
      reject(
        new AetherError(
          `could not run the aether binary at ${binary}: ${e.message}. Set AETHER_BINARY ` +
            `to its path, or build it with \`cargo build --release\`.`,
          "binary_not_found",
          -1,
          "",
        ),
      );
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, truncated, timedOut });
    });
  });
}

/**
 * Run a CLI command expected to emit JSON, and parse it.
 *
 * Exit code 3 means "findings were confirmed", which is a successful run, not
 * an error; it is reported in the payload rather than thrown.
 */
export async function runJson<T = unknown>(
  binary: string,
  args: string[],
  options: RunOptions = {},
): Promise<T> {
  const result = await runCli(binary, ["--json", ...args], options);

  if (result.timedOut) {
    throw new AetherError(
      `the command exceeded its ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms limit and was ` +
        `stopped. For a long campaign, start it in the background and poll ` +
        `aether_campaign_status instead.`,
      "timeout",
      result.code,
      result.stderr,
    );
  }

  // Both success and the findings-confirmed code carry a JSON payload.
  const ok = result.code === 0 || result.code === 3;
  const source = result.stdout.trim() || result.stderr.trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    if (!ok) {
      throw new AetherError(
        result.stderr.trim() || `the command failed with exit code ${result.code}`,
        "engine_error",
        result.code,
        result.stderr,
      );
    }
    throw new AetherError(
      `the command produced output that is not JSON: ${source.slice(0, 400)}`,
      "unparseable_output",
      result.code,
      result.stderr,
    );
  }

  if (!ok) {
    // The CLI's own structured error, with its stable kind.
    const err = parsed as { error?: { kind?: string; message?: string } };
    throw new AetherError(
      err.error?.message ?? `the command failed with exit code ${result.code}`,
      err.error?.kind ?? "engine_error",
      result.code,
      result.stderr,
    );
  }
  return parsed as T;
}
