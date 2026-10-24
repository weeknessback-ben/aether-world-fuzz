/**
 * Background campaign jobs.
 *
 * A fuzzing campaign runs for minutes or hours. An MCP tool call that blocked
 * for that long would be useless: the conversation could not check on it,
 * cancel it, or do anything else. So `aether_campaign_start` spawns the CLI
 * detached, returns a job id immediately, and the campaign is observed through
 * `aether_campaign_status` and stopped through `aether_campaign_cancel`.
 *
 * Job state lives in this process only. Cancellation does not: it goes through
 * the CLI, which writes a sentinel file the campaign watches, so a campaign
 * survives this server restarting and can still be stopped afterwards.
 */

import { spawn } from "node:child_process";
import { mkdirSync, openSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export type JobState = "starting" | "running" | "completed" | "failed" | "cancelled";

export interface Job {
  jobId: string;
  campaignId?: string;
  state: JobState;
  pid?: number;
  startedAt: string;
  finishedAt?: string;
  exitCode?: number;
  outputDir: string;
  logPath: string;
  configPath: string;
  /** Set when the job failed to start or exited abnormally. */
  error?: string;
}

const jobs = new Map<string, Job>();
let counter = 0;

function newJobId(): string {
  counter += 1;
  return `job-${Date.now().toString(36)}-${counter.toString(36)}`;
}

/**
 * Start a campaign in the background.
 *
 * Output is redirected to a log file rather than piped, so the campaign is not
 * blocked by nobody reading its stdout and the log survives this process.
 */
export function startCampaign(
  binary: string,
  configPath: string,
  outputDir: string,
  extraArgs: string[],
  cwd?: string,
): Job {
  const jobId = newJobId();
  mkdirSync(outputDir, { recursive: true });
  const logPath = join(outputDir, `${jobId}.log`);

  const job: Job = {
    jobId,
    state: "starting",
    startedAt: new Date().toISOString(),
    outputDir,
    logPath,
    configPath,
  };
  jobs.set(jobId, job);

  try {
    const log = openSync(logPath, "a");
    const child = spawn(
      binary,
      ["--json", "campaign", "run", "--config", configPath, ...extraArgs],
      {
        cwd,
        shell: false,
        detached: true,
        stdio: ["ignore", log, log],
      },
    );
    job.pid = child.pid;
    job.state = "running";

    child.on("error", (e) => {
      job.state = "failed";
      job.error = e.message;
      job.finishedAt = new Date().toISOString();
    });
    child.on("exit", (code) => {
      job.exitCode = code ?? -1;
      // Exit code 3 means findings were confirmed, which is a successful run.
      job.state = code === 0 || code === 3 ? "completed" : "failed";
      if (code !== 0 && code !== 3) {
        job.error = `the campaign exited with code ${code}; see ${logPath}`;
      }
      job.finishedAt = new Date().toISOString();
    });
    // Let this server exit without waiting for the campaign.
    child.unref();
  } catch (e) {
    job.state = "failed";
    job.error = e instanceof Error ? e.message : String(e);
    job.finishedAt = new Date().toISOString();
  }
  return job;
}

export function getJob(jobId: string): Job | undefined {
  return jobs.get(jobId);
}

export function listJobs(): Job[] {
  return [...jobs.values()].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}

export function markCancelled(jobId: string): void {
  const j = jobs.get(jobId);
  if (j && (j.state === "running" || j.state === "starting")) {
    j.state = "cancelled";
  }
}

/**
 * Discover a job's campaign id by reading the campaign's own status file.
 *
 * The id is minted by the engine, not by this server, so it is not knowable
 * at spawn time. Looking for the newest status file under the output
 * directory is how a job is tied to its campaign.
 */
export function attachCampaignId(job: Job, campaignIds: string[]): void {
  if (job.campaignId) return;
  for (const id of campaignIds) {
    const status = join(job.outputDir, id, "status.json");
    if (!existsSync(status)) continue;
    try {
      const raw = JSON.parse(readFileSync(status, "utf8")) as { campaign_id?: string };
      if (raw.campaign_id === id) {
        job.campaignId = id;
        return;
      }
    } catch {
      // A half-written status file is not an error worth surfacing; it will be
      // complete on the next poll.
    }
  }
}

/** Tail of a job's log, bounded, for diagnosing a failed start. */
export function logTail(job: Job, maxBytes = 4000): string {
  try {
    const body = readFileSync(job.logPath, "utf8");
    return body.length <= maxBytes ? body : `...[truncated]\n${body.slice(-maxBytes)}`;
  } catch {
    return "";
  }
}
