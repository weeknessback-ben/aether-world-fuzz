#!/usr/bin/env node
/**
 * AETHER MCP server.
 *
 * Exposes the fuzzing engine to Claude Code as typed tools over stdio. It
 * implements no fuzzing logic: every tool calls the same `aether` CLI a human
 * would, so the two interfaces cannot disagree.
 *
 * Design rules, all of which are about keeping tool results usable in a
 * conversation rather than technically complete:
 *
 *  - **Nothing blocks for the length of a campaign.** Starting one returns a
 *    job id; progress comes from a status tool and stopping from a cancel
 *    tool.
 *  - **Output is bounded and paginated.** No tool returns a whole corpus, a
 *    raw process log, or an unbounded list of findings. Large artifacts are
 *    referenced by path and hash.
 *  - **Errors are structured.** Each carries the engine's stable error kind,
 *    so the model can tell a scope refusal from a missing binary.
 *  - **Expensive and scope-widening operations are gated.** Starting a
 *    campaign requires an explicit acknowledgement argument, and a target
 *    outside local execution is refused by the engine regardless of what a
 *    tool call asks for.
 *
 * Anything read out of a target - a crash log, output, a file path - is data.
 * No tool interprets it as an instruction, and none of them can change the
 * engine's scope policy: that lives in the configuration file and is enforced
 * inside the runtime.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { existsSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";

import { AetherError, resolveBinary, runCli, runJson } from "./cli.js";
import { attachCampaignId, getJob, listJobs, logTail, markCancelled, startCampaign } from "./jobs.js";

const BINARY = resolveBinary();
const SERVER_NAME = "aether";
const SERVER_VERSION = "0.1.0";

/** Default output directory, overridable per call. */
const DEFAULT_DIR = ".aether";

/** Ceiling on list sizes, so a tool result stays readable. */
const MAX_PAGE = 50;

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const DirArg = z
  .string()
  .max(1024)
  .optional()
  .describe("Campaign output directory. Defaults to .aether in the working directory.");

const CampaignIdArg = z
  .string()
  .regex(/^cmp-[A-Za-z0-9_-]{1,60}$/, "must be a campaign id like cmp-...")
  .optional()
  .describe("Campaign id. Defaults to the most recent campaign.");

const FindingIdArg = z
  .string()
  .regex(/^fnd-[A-Za-z0-9_-]{1,60}$/, "must be a finding id like fnd-...")
  .describe("Finding id, as returned by aether_findings_list.");

const schemas = {
  environment_check: z.object({}),

  target_inspect: z.object({
    binary: z.string().min(1).max(4096).describe("Path to the target executable."),
    input_mode: z
      .enum(["stdin", "file-arg"])
      .optional()
      .describe("How the target receives one test case. Defaults to stdin."),
    args: z
      .array(z.string().max(4096))
      .max(64)
      .optional()
      .describe("Arguments for the target; @@ is replaced by the test case path."),
    timeout_ms: z.number().int().min(1).max(600_000).optional(),
  }),

  campaign_create: z.object({
    config_path: z
      .string()
      .min(1)
      .max(4096)
      .optional()
      .describe("Path to an existing configuration file."),
    config_toml: z
      .string()
      .max(200_000)
      .optional()
      .describe(
        "Configuration as TOML, written to a file under the output directory. Use this " +
          "or config_path, not both.",
      ),
    dir: DirArg,
  }),

  campaign_start: z.object({
    config_path: z.string().min(1).max(4096).optional(),
    config_toml: z.string().max(200_000).optional(),
    dir: DirArg,
    duration_secs: z
      .number()
      .int()
      .min(1)
      .max(86_400)
      .optional()
      .describe("Overrides the configured wall-clock budget."),
    max_execs: z.number().int().min(1).optional(),
    seed: z.number().int().min(0).optional(),
    strategies: z.array(z.string().max(64)).max(32).optional(),
    seeds_dir: z.string().max(4096).optional().describe("Directory of seed inputs."),
    workers: z
      .number()
      .int()
      .min(1)
      .max(64)
      .optional()
      .describe(
        "Worker threads. Each one saturates a core, so more workers than the host has " +
          "cores measures oversubscription rather than scaling; aether_environment_check " +
          "reports the core count. A pooled campaign does not apply stagnation " +
          "escalation and reports strategy allocation per worker rather than " +
          "campaign-wide.",
      ),
    acknowledge_resource_use: z
      .boolean()
      .describe(
        "Must be true. A campaign runs the target continuously and consumes CPU for its " +
          "whole budget, so starting one is an explicit decision rather than a side effect.",
      ),
  }),

  campaign_status: z.object({
    campaign_id: CampaignIdArg,
    job_id: z.string().max(128).optional().describe("Job id from aether_campaign_start."),
    dir: DirArg,
  }),

  campaign_cancel: z.object({
    campaign_id: z.string().regex(/^cmp-[A-Za-z0-9_-]{1,60}$/),
    dir: DirArg,
  }),

  campaign_list: z.object({
    dir: DirArg,
    limit: z.number().int().min(1).max(MAX_PAGE).optional(),
  }),

  strategy_recommend: z.object({
    binary: z.string().min(1).max(4096),
    input_mode: z.enum(["stdin", "file-arg"]).optional(),
  }),

  coverage_summary: z.object({ campaign_id: CampaignIdArg, dir: DirArg }),

  corpus_analyze: z.object({
    campaign_id: CampaignIdArg,
    dir: DirArg,
    limit: z.number().int().min(1).max(MAX_PAGE).optional(),
  }),

  findings_list: z.object({
    campaign_id: CampaignIdArg,
    dir: DirArg,
    status: z
      .enum([
        "candidate",
        "reproducing",
        "reproducible",
        "intermittent",
        "unconfirmed",
        "environmental",
        "duplicate",
        "closed",
      ])
      .optional(),
    limit: z.number().int().min(1).max(MAX_PAGE).optional(),
  }),

  finding_detail: z.object({ finding_id: FindingIdArg, dir: DirArg }),

  finding_validate: z.object({
    finding_id: FindingIdArg,
    config_path: z.string().min(1).max(4096),
    dir: DirArg,
    attempts: z.number().int().min(1).max(200).optional(),
  }),

  finding_minimize: z.object({
    finding_id: FindingIdArg,
    config_path: z.string().min(1).max(4096),
    dir: DirArg,
  }),

  report_generate: z.object({
    campaign_id: CampaignIdArg,
    dir: DirArg,
    format: z.enum(["markdown", "json", "sarif", "bench-json"]).optional(),
    output_path: z
      .string()
      .max(4096)
      .optional()
      .describe("Write the report here instead of returning its body."),
  }),

  benchmark_list: z.object({}),
} as const;

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

function jsonSchema(schema: z.ZodType): Record<string, unknown> {
  // Hand-built rather than generated: the MCP schema has to be plain JSON
  // Schema, and keeping it explicit keeps the descriptions the model reads
  // under this file's control.
  return zodToJsonSchema(schema);
}

/** Minimal Zod-to-JSON-Schema conversion covering the shapes used here. */
function zodToJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const def = (schema as unknown as { _def: Record<string, unknown> })._def;
  const typeName = def.typeName as string;

  switch (typeName) {
    case "ZodObject": {
      const shape = (schema as unknown as z.ZodObject<z.ZodRawShape>).shape;
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        const field = value as z.ZodTypeAny;
        properties[key] = zodToJsonSchema(field);
        if (!field.isOptional()) required.push(key);
      }
      return {
        type: "object",
        properties,
        ...(required.length ? { required } : {}),
        additionalProperties: false,
      };
    }
    case "ZodOptional":
      return zodToJsonSchema((def.innerType as z.ZodTypeAny));
    case "ZodDefault":
      return zodToJsonSchema((def.innerType as z.ZodTypeAny));
    case "ZodString": {
      const out: Record<string, unknown> = { type: "string" };
      const checks = (def.checks ?? []) as Array<{ kind: string; value?: number }>;
      for (const c of checks) {
        if (c.kind === "min" && typeof c.value === "number") out.minLength = c.value;
        if (c.kind === "max" && typeof c.value === "number") out.maxLength = c.value;
      }
      const desc = (schema as z.ZodTypeAny).description;
      if (desc) out.description = desc;
      return out;
    }
    case "ZodNumber": {
      const out: Record<string, unknown> = { type: "integer" };
      const checks = (def.checks ?? []) as Array<{ kind: string; value?: number }>;
      for (const c of checks) {
        if (c.kind === "min" && typeof c.value === "number") out.minimum = c.value;
        if (c.kind === "max" && typeof c.value === "number") out.maximum = c.value;
      }
      const desc = (schema as z.ZodTypeAny).description;
      if (desc) out.description = desc;
      return out;
    }
    case "ZodBoolean": {
      const out: Record<string, unknown> = { type: "boolean" };
      const desc = (schema as z.ZodTypeAny).description;
      if (desc) out.description = desc;
      return out;
    }
    case "ZodEnum": {
      const out: Record<string, unknown> = {
        type: "string",
        enum: def.values as string[],
      };
      const desc = (schema as z.ZodTypeAny).description;
      if (desc) out.description = desc;
      return out;
    }
    case "ZodArray": {
      const out: Record<string, unknown> = {
        type: "array",
        items: zodToJsonSchema(def.type as z.ZodTypeAny),
      };
      if (def.maxLength) out.maxItems = (def.maxLength as { value: number }).value;
      const desc = (schema as z.ZodTypeAny).description;
      if (desc) out.description = desc;
      return out;
    }
    case "ZodEffects":
      return zodToJsonSchema(def.schema as z.ZodTypeAny);
    default:
      return { type: "string" };
  }
}

const TOOLS: Tool[] = [
  {
    name: "aether_environment_check",
    description:
      "Report what this host supports: execution backends, which resource limits are " +
      "actually enforced, available strategies and profiles. Run this first - it says " +
      "plainly which capabilities are unavailable and why, so a campaign is not planned " +
      "around something that cannot work here.",
    inputSchema: jsonSchema(schemas.environment_check) as Tool["inputSchema"],
  },
  {
    name: "aether_target_inspect",
    description:
      "Probe a target binary with several representative inputs and report whether it " +
      "carries instrumentation, how many guards it registered, whether the fork server " +
      "and comparison log work, and what each probe did. Use this before designing a " +
      "campaign: an uninstrumented target has no coverage signal and needs a different " +
      "plan.",
    inputSchema: jsonSchema(schemas.target_inspect) as Tool["inputSchema"],
  },
  {
    name: "aether_campaign_create",
    description:
      "Validate a campaign configuration and register the campaign without running it. " +
      "Every check happens here - scope authorization, the target binary, strategy " +
      "requirements, storage - so a problem is reported before any execution.",
    inputSchema: jsonSchema(schemas.campaign_create) as Tool["inputSchema"],
  },
  {
    name: "aether_campaign_start",
    description:
      "Start a campaign in the background and return a job id immediately. The campaign " +
      "runs the target continuously for its whole budget, so acknowledge_resource_use " +
      "must be set true. Poll aether_campaign_status for progress and use " +
      "aether_campaign_cancel to stop it early.",
    inputSchema: jsonSchema(schemas.campaign_start) as Tool["inputSchema"],
  },
  {
    name: "aether_campaign_status",
    description:
      "Current state of a campaign: executions and rate, coverage, corpus size, finding " +
      "counts, stagnation phase and how budget is being allocated across strategies. " +
      "Metrics that are not measurable for this target are reported as null rather than " +
      "zero.",
    inputSchema: jsonSchema(schemas.campaign_status) as Tool["inputSchema"],
  },
  {
    name: "aether_campaign_cancel",
    description:
      "Request cancellation of a running campaign. It stops at its next execution " +
      "boundary, so this returns promptly rather than waiting. Already-stored corpus " +
      "entries and findings are kept.",
    inputSchema: jsonSchema(schemas.campaign_cancel) as Tool["inputSchema"],
  },
  {
    name: "aether_campaign_list",
    description: "List recent campaigns with their status, executions and coverage.",
    inputSchema: jsonSchema(schemas.campaign_list) as Tool["inputSchema"],
  },
  {
    name: "aether_strategy_recommend",
    description:
      "Recommend strategies for a target, based on probing it rather than on guesswork. " +
      "Only strategies whose requirements the target actually meets are suggested: a " +
      "comparison-guided strategy is not recommended for a binary with no comparison log.",
    inputSchema: jsonSchema(schemas.strategy_recommend) as Tool["inputSchema"],
  },
  {
    name: "aether_coverage_summary",
    description:
      "Coverage for a campaign: edges reached, instrumented guard count and saturation. " +
      "Saturation is null when the target did not report a guard count, which is not the " +
      "same as zero coverage.",
    inputSchema: jsonSchema(schemas.coverage_summary) as Tool["inputSchema"],
  },
  {
    name: "aether_corpus_analyze",
    description:
      "Corpus shape and its highest-ranked entries: size, distinct behaviours, mean " +
      "score, and per-entry coverage contribution and originating strategy. Returns a " +
      "bounded sample, never the whole corpus.",
    inputSchema: jsonSchema(schemas.corpus_analyze) as Tool["inputSchema"],
  },
  {
    name: "aether_findings_list",
    description:
      "List findings, optionally filtered by status. Note the statuses: only " +
      "'reproducible' and 'intermittent' are established defects. 'unconfirmed' means " +
      "it was observed once and never reproduced, and must not be reported as a defect.",
    inputSchema: jsonSchema(schemas.findings_list) as Tool["inputSchema"],
  },
  {
    name: "aether_finding_detail",
    description:
      "Full evidence for one finding: reproduction counts, the command that reproduces " +
      "it, input hashes, sanitizer report, and the caveats recorded against it. Large " +
      "artifacts are referenced by hash rather than inlined.",
    inputSchema: jsonSchema(schemas.finding_detail) as Tool["inputSchema"],
  },
  {
    name: "aether_finding_validate",
    description:
      "Re-run a finding's input to re-check reproducibility, and report whether the " +
      "failure observed now is the same defect as the one recorded. A different failure " +
      "is reported as such rather than counted as reproduction.",
    inputSchema: jsonSchema(schemas.finding_validate) as Tool["inputSchema"],
  },
  {
    name: "aether_finding_minimize",
    description:
      "Shrink a finding's triggering input while the same failure signature keeps " +
      "occurring, and report whether the minimised input re-validated. Minimisation " +
      "that cannot be confirmed is reported, not assumed.",
    inputSchema: jsonSchema(schemas.finding_minimize) as Tool["inputSchema"],
  },
  {
    name: "aether_report_generate",
    description:
      "Generate a campaign report as Markdown, JSON, SARIF or flat benchmark JSON. " +
      "Reports separate established findings from unconfirmed observations and list the " +
      "capabilities that were unavailable. Pass output_path for a large report rather " +
      "than returning its body.",
    inputSchema: jsonSchema(schemas.report_generate) as Tool["inputSchema"],
  },
  {
    name: "aether_benchmark_list",
    description:
      "List the benchmark experiments, including which are not implemented and why.",
    inputSchema: jsonSchema(schemas.benchmark_list) as Tool["inputSchema"],
  },
];

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

function ok(payload: unknown, note?: string): CallToolResult {
  const body = note ? { ...(payload as object), note } : payload;
  return {
    content: [{ type: "text", text: JSON.stringify(body, null, 2) }],
  };
}

function fail(kind: string, message: string, hint?: string): CallToolResult {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify({ ok: false, error: { kind, message, hint } }, null, 2),
      },
    ],
  };
}

/** Write inline TOML to a file under the output directory. */
function materializeConfig(dir: string, toml: string): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `campaign-${Date.now().toString(36)}.toml`);
  writeFileSync(path, toml, "utf8");
  return path;
}

function resolveConfig(
  args: { config_path?: string; config_toml?: string },
  dir: string,
): string {
  if (args.config_path && args.config_toml) {
    throw new AetherError(
      "give either config_path or config_toml, not both",
      "config_invalid",
      1,
      "",
    );
  }
  if (args.config_path) {
    const p = resolvePath(args.config_path);
    if (!existsSync(p)) {
      throw new AetherError(`no configuration file at ${p}`, "not_found", 1, "");
    }
    return p;
  }
  if (args.config_toml) return materializeConfig(dir, args.config_toml);
  throw new AetherError(
    "a campaign needs either config_path or config_toml",
    "config_invalid",
    1,
    "",
  );
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async function dispatch(name: string, rawArgs: unknown): Promise<CallToolResult> {
  const dirOf = (a: { dir?: string }) => a.dir ?? DEFAULT_DIR;

  switch (name) {
    case "aether_environment_check": {
      const r = await runJson<Record<string, unknown>>(BINARY, ["doctor"]);
      return ok(r);
    }

    case "aether_target_inspect":
    case "aether_strategy_recommend": {
      const a =
        name === "aether_target_inspect"
          ? schemas.target_inspect.parse(rawArgs)
          : { ...schemas.strategy_recommend.parse(rawArgs), args: undefined, timeout_ms: undefined };
      const argv = ["target", "inspect", a.binary];
      if (a.input_mode) argv.push("--input-mode", a.input_mode);
      if ("timeout_ms" in a && a.timeout_ms) argv.push("--timeout-ms", String(a.timeout_ms));
      if ("args" in a && a.args?.length) argv.push("--args", ...a.args);
      const r = await runJson<Record<string, unknown>>(BINARY, argv);
      if (name === "aether_strategy_recommend") {
        return ok({
          ok: true,
          binary: r.binary,
          instrumented: r.instrumented,
          recommended_strategies: r.recommended_strategies,
          rationale:
            "Recommendations come from probing this binary. A strategy is only listed " +
            "when the signals it needs are actually present: comparison-guided " +
            "substitution appears only if the comparison log produced entries, and " +
            "coverage-dependent strategies only if instrumentation reported guards.",
          limitations: r.limitations,
        });
      }
      return ok(r);
    }

    case "aether_campaign_create": {
      const a = schemas.campaign_create.parse(rawArgs);
      const dir = dirOf(a);
      const config = resolveConfig(a, dir);
      const r = await runJson<Record<string, unknown>>(BINARY, [
        "campaign",
        "create",
        "--config",
        config,
      ]);
      return ok({ ...r, config_path: config });
    }

    case "aether_campaign_start": {
      const a = schemas.campaign_start.parse(rawArgs);
      if (!a.acknowledge_resource_use) {
        return fail(
          "acknowledgement_required",
          "acknowledge_resource_use must be true to start a campaign.",
          "A campaign executes the target continuously for its whole budget and will " +
            "saturate a CPU core. Set acknowledge_resource_use: true once that is intended.",
        );
      }
      const dir = dirOf(a);
      const config = resolveConfig(a, dir);

      // Validate before spawning, so a bad configuration is a clear error
      // rather than a job that fails in the background.
      await runJson<Record<string, unknown>>(BINARY, ["campaign", "create", "--config", config]);

      const extra: string[] = [];
      if (a.duration_secs) extra.push("--duration", String(a.duration_secs));
      if (a.max_execs) extra.push("--max-execs", String(a.max_execs));
      if (a.seed !== undefined) extra.push("--seed", String(a.seed));
      if (a.strategies?.length) extra.push("--strategies", a.strategies.join(","));
      if (a.seeds_dir) extra.push("--seeds", a.seeds_dir);
      if (a.workers) extra.push("--workers", String(a.workers));

      const job = startCampaign(BINARY, config, dir, extra);
      if (job.state === "failed") {
        return fail("start_failed", job.error ?? "the campaign could not be started", logTail(job));
      }
      return ok(
        {
          ok: true,
          job_id: job.jobId,
          state: job.state,
          pid: job.pid,
          output_dir: dir,
          config_path: config,
          log_path: job.logPath,
        },
        "The campaign is running in the background. Poll aether_campaign_status with this " +
          "job_id for progress; it will carry the campaign id once the campaign has " +
          "registered itself.",
      );
    }

    case "aether_campaign_status": {
      const a = schemas.campaign_status.parse(rawArgs);
      const dir = dirOf(a);

      let campaignId = a.campaign_id;
      let job = a.job_id ? getJob(a.job_id) : undefined;
      if (a.job_id && !job) {
        return fail(
          "not_found",
          `no job ${a.job_id} in this server's memory`,
          "Job state is kept in this process only. If the server restarted, query by " +
            "campaign_id instead, or use aether_campaign_list to find it.",
        );
      }
      if (job && !campaignId) {
        // Tie the job to its campaign by looking at what has registered.
        const list = await runJson<{ campaigns: Array<{ campaign_id: string }> }>(BINARY, [
          "campaign",
          "list",
          "--dir",
          dir,
          "--limit",
          "10",
        ]);
        attachCampaignId(job, list.campaigns.map((c) => c.campaign_id));
        campaignId = job.campaignId;
      }

      if (!campaignId) {
        return ok({
          ok: true,
          job: job
            ? { job_id: job.jobId, state: job.state, log_tail: logTail(job, 1500) }
            : undefined,
          campaign: null,
          note: "The campaign has not published a status file yet. Poll again shortly.",
        });
      }

      const argv = ["campaign", "status", campaignId, "--dir", dir];
      const r = await runJson<Record<string, unknown>>(BINARY, argv);
      return ok({
        ok: true,
        job: job ? { job_id: job.jobId, state: job.state, exit_code: job.exitCode } : undefined,
        campaign: r,
      });
    }

    case "aether_campaign_cancel": {
      const a = schemas.campaign_cancel.parse(rawArgs);
      const r = await runJson<Record<string, unknown>>(BINARY, [
        "campaign",
        "cancel",
        a.campaign_id,
        "--dir",
        dirOf(a),
      ]);
      for (const j of listJobs()) {
        if (j.campaignId === a.campaign_id) markCancelled(j.jobId);
      }
      return ok(r);
    }

    case "aether_campaign_list": {
      const a = schemas.campaign_list.parse(rawArgs);
      const r = await runJson<Record<string, unknown>>(BINARY, [
        "campaign",
        "list",
        "--dir",
        dirOf(a),
        "--limit",
        String(a.limit ?? 20),
      ]);
      return ok({ ...r, jobs: listJobs().slice(0, 10) });
    }

    case "aether_coverage_summary": {
      const a = schemas.coverage_summary.parse(rawArgs);
      const argv = ["campaign", "status", ...(a.campaign_id ? [a.campaign_id] : []), "--dir", dirOf(a)];
      const r = await runJson<Record<string, unknown>>(BINARY, argv);
      return ok({
        ok: true,
        campaign_id: r.campaign_id,
        total_edges: r.total_edges,
        coverage_saturation: r.coverage_saturation,
        corpus_entries: r.corpus_entries,
        last_progress: r.last_progress_ms,
        note:
          "total_edges and coverage_saturation are null when the target is " +
          "uninstrumented or did not report a guard count. Null means not measurable, " +
          "which is different from zero.",
      });
    }

    case "aether_corpus_analyze": {
      const a = schemas.corpus_analyze.parse(rawArgs);
      const argv = ["corpus", "stats", ...(a.campaign_id ? [a.campaign_id] : []), "--dir", dirOf(a)];
      const r = await runJson<{ top_inputs?: unknown[] }>(BINARY, argv);
      const limit = a.limit ?? 10;
      return ok({
        ...r,
        top_inputs: (r.top_inputs ?? []).slice(0, limit),
      });
    }

    case "aether_findings_list": {
      const a = schemas.findings_list.parse(rawArgs);
      const argv = ["findings", "list", ...(a.campaign_id ? [a.campaign_id] : []), "--dir", dirOf(a), "--limit", String(a.limit ?? 20)];
      if (a.status) argv.push("--status", a.status);
      const r = await runJson<{ findings?: unknown[] }>(BINARY, argv);
      const findings = r.findings ?? [];
      return ok({
        ...r,
        note:
          findings.length === 0
            ? "No findings. This describes this campaign under its budget and " +
              "configuration; it is not evidence that the target is free of defects."
            : "Only 'reproducible' and 'intermittent' are established defects. " +
              "'unconfirmed' means observed once and never reproduced.",
      });
    }

    case "aether_finding_detail": {
      const a = schemas.finding_detail.parse(rawArgs);
      const r = await runJson<Record<string, unknown>>(BINARY, [
        "findings",
        "show",
        a.finding_id,
        "--dir",
        dirOf(a),
      ]);
      return ok(r);
    }

    case "aether_finding_validate": {
      const a = schemas.finding_validate.parse(rawArgs);
      const argv = [
        "findings",
        "validate",
        a.finding_id,
        "--config",
        a.config_path,
        "--dir",
        dirOf(a),
      ];
      if (a.attempts) argv.push("--attempts", String(a.attempts));
      // Re-running a target several times takes real time; allow for it.
      const r = await runJson<Record<string, unknown>>(BINARY, argv, { timeoutMs: 300_000 });
      return ok(r);
    }

    case "aether_finding_minimize": {
      const a = schemas.finding_minimize.parse(rawArgs);
      const r = await runJson<Record<string, unknown>>(
        BINARY,
        ["findings", "minimize", a.finding_id, "--config", a.config_path, "--dir", dirOf(a)],
        { timeoutMs: 600_000 },
      );
      return ok(r);
    }

    case "aether_report_generate": {
      const a = schemas.report_generate.parse(rawArgs);
      const format = a.format ?? "markdown";
      const dir = dirOf(a);
      const argv = [
        "report",
        "generate",
        ...(a.campaign_id ? [a.campaign_id] : []),
        "--dir",
        dir,
        "--format",
        format,
      ];
      if (a.output_path) {
        argv.push("--output", a.output_path);
        const r = await runJson<Record<string, unknown>>(BINARY, argv);
        return ok(r);
      }
      // Without --json the CLI prints the report body itself.
      const r = await runCli(BINARY, argv);
      if (r.code !== 0) {
        return fail("engine_error", r.stderr.trim() || `report generation failed (${r.code})`);
      }
      const MAX_INLINE = 60_000;
      const body = r.stdout;
      return ok({
        ok: true,
        format,
        truncated: body.length > MAX_INLINE || r.truncated,
        report: body.length > MAX_INLINE ? body.slice(0, MAX_INLINE) : body,
        hint:
          body.length > MAX_INLINE
            ? "The report was truncated. Pass output_path to write the full report to a file."
            : undefined,
      });
    }

    case "aether_benchmark_list": {
      const r = await runJson<Record<string, unknown>>(BINARY, ["benchmark", "list"]);
      return ok(r);
    }

    default:
      return fail("unknown_tool", `no tool named ${name}`);
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      return await dispatch(name, args ?? {});
    } catch (e) {
      if (e instanceof AetherError) {
        // The engine's stable error kind travels through, so the model can
        // distinguish a scope refusal from a missing binary.
        return fail(e.kind, e.message, hintFor(e.kind));
      }
      if (e instanceof z.ZodError) {
        return fail(
          "invalid_arguments",
          e.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; "),
        );
      }
      return fail("internal_error", e instanceof Error ? e.message : String(e));
    }
  });

  await server.connect(new StdioServerTransport());
}

function hintFor(kind: string): string | undefined {
  switch (kind) {
    case "binary_not_found":
      return "Build the engine with `cargo build --release`, or set AETHER_BINARY to the aether binary.";
    case "scope_denied":
      return "The scope policy refused this target. Local execution is allowed by default; a network target needs an explicit host entry, an authorization note and a rate limit in the configuration. Supplying an address is not authorization to test it.";
    case "target_invalid":
      return "Check the binary path exists and is executable. Build it with runtime/aether-cc to get coverage feedback.";
    case "config_invalid":
      return "Run aether_campaign_create first to see exactly which field was rejected.";
    case "not_found":
      return "Use aether_campaign_list or aether_findings_list to see what exists.";
    case "unsupported_capability":
      return "Run aether_environment_check to see what this host supports.";
    case "timeout":
      return "Start long work with aether_campaign_start and poll aether_campaign_status instead of blocking.";
    default:
      return undefined;
  }
}

main().catch((e) => {
  process.stderr.write(`aether-mcp-server failed to start: ${e}\n`);
  process.exit(1);
});
