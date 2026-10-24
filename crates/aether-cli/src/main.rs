//! The `aether` command line interface.
//!
//! A thin, honest layer over `aether-core`: it parses arguments, calls the
//! engine, and renders the result. It contains no fuzzing logic of its own, so
//! the CLI and the MCP server cannot drift apart in behaviour.
//!
//! Conventions, applied consistently so the tool is scriptable:
//!
//! * `--json` on every command that produces output, for machine consumption.
//! * Exit codes are meaningful: 0 success, 1 a usage or configuration problem,
//!   2 an engine failure, 3 the campaign found something. The last one lets CI
//!   fail a build on a finding without parsing output.
//! * Errors go to stderr and carry the engine's stable error kind, so a script
//!   can branch on the kind rather than on prose.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use aether_core::config::{self, Config};

mod commands;

/// Exit codes, documented because scripts depend on them.
pub const EXIT_OK: u8 = 0;
pub const EXIT_USAGE: u8 = 1;
pub const EXIT_ENGINE: u8 = 2;
pub const EXIT_FINDINGS: u8 = 3;

#[derive(Parser)]
#[command(
    name = "aether",
    version,
    about = "AETHER - adaptive hybrid fuzzing engine",
    long_about = "AETHER runs coverage-guided fuzzing campaigns with adaptive strategy \
                  selection and an evidence pipeline that reproduces and minimises what it \
                  finds.\n\nStart with `aether doctor` to see what this host supports."
)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Reduce output to warnings and errors.
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report what this host can and cannot do.
    Doctor,

    /// Inspect a target before committing to a campaign.
    #[command(subcommand)]
    Target(TargetCommand),

    /// Create, run, monitor and cancel campaigns.
    #[command(subcommand)]
    Campaign(CampaignCommand),

    /// Inspect and manage the corpus.
    #[command(subcommand)]
    Corpus(CorpusCommand),

    /// List and validate findings.
    #[command(subcommand)]
    Findings(FindingsCommand),

    /// Generate a report from a stored campaign.
    #[command(subcommand)]
    Report(ReportCommand),

    /// Run benchmark experiments.
    #[command(subcommand)]
    Benchmark(BenchmarkCommand),

    /// Print an example configuration.
    Init {
        /// Named profile to base it on.
        #[arg(long, default_value = "quick-local")]
        profile: String,
        /// Target binary to reference.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Write to this path instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TargetCommand {
    /// Probe a target: instrumentation, fork server, feedback signals.
    Inspect(TargetInspectArgs),
}

#[derive(Args)]
struct TargetInspectArgs {
    /// Target binary.
    binary: PathBuf,
    /// How the target receives input.
    #[arg(long, value_parser = ["stdin", "file-arg"], default_value = "stdin")]
    input_mode: String,
    /// Arguments to pass; `@@` is replaced by the test case path.
    #[arg(long, num_args = 0..)]
    args: Vec<String>,
    /// Per-run deadline in milliseconds.
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

#[derive(Subcommand)]
enum CampaignCommand {
    /// Validate a configuration and register a campaign without running it.
    Create {
        /// Configuration file.
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Run a campaign to completion.
    Run(CampaignRunArgs),
    /// Show the status of a campaign.
    Status {
        /// Campaign id. Defaults to the most recent.
        campaign_id: Option<String>,
        /// Output directory holding campaign state.
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
    /// Request cancellation of a running campaign.
    Cancel {
        campaign_id: String,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
    /// List known campaigns.
    List {
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Args)]
struct CampaignRunArgs {
    /// Configuration file.
    #[arg(long, short)]
    config: PathBuf,
    /// Named profile to apply on top of the file.
    #[arg(long)]
    profile: Option<String>,
    /// Directory of seed inputs.
    #[arg(long)]
    seeds: Option<PathBuf>,
    /// Override the wall-clock budget, in seconds.
    #[arg(long)]
    duration: Option<u64>,
    /// Override the execution budget.
    #[arg(long)]
    max_execs: Option<u64>,
    /// Override the random seed.
    #[arg(long)]
    seed: Option<u64>,
    /// Override the worker count.
    #[arg(long)]
    workers: Option<u32>,
    /// Restrict to these strategies.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    strategies: Option<Vec<String>>,
    /// Resume from a previous campaign's checkpoint.
    #[arg(long)]
    resume: Option<String>,
    /// Exit 0 even when findings were confirmed.
    #[arg(long)]
    no_fail_on_findings: bool,
}

#[derive(Subcommand)]
enum CorpusCommand {
    /// Corpus statistics.
    Stats {
        campaign_id: Option<String>,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
    /// Export corpus inputs as files.
    Export {
        campaign_id: String,
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum FindingsCommand {
    /// List findings for a campaign.
    List {
        campaign_id: Option<String>,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
        /// Only findings with this status.
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one finding in full.
    Show {
        finding_id: String,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
    /// Re-run a finding's input to re-check reproducibility.
    Validate {
        finding_id: String,
        #[arg(long, short)]
        config: PathBuf,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
        /// Re-run this many times.
        #[arg(long)]
        attempts: Option<u32>,
    },
    /// Minimise a finding's triggering input.
    Minimize {
        finding_id: String,
        #[arg(long, short)]
        config: PathBuf,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReportCommand {
    /// Generate a report for a campaign.
    Generate {
        campaign_id: Option<String>,
        #[arg(long, default_value = ".aether")]
        dir: PathBuf,
        /// Format: json, markdown, sarif or bench-json.
        #[arg(long, default_value = "markdown")]
        format: String,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BenchmarkCommand {
    /// Run a benchmark experiment.
    Run {
        /// Experiment to run: a, b, c, d, e, f, g, or all.
        #[arg(long, default_value = "all")]
        experiment: String,
        #[arg(long, short)]
        config: Option<PathBuf>,
        /// Independent repetitions per configuration.
        #[arg(long, default_value_t = 3)]
        trials: u32,
        /// Seconds per campaign.
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// List the available experiments.
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let ctx = commands::Ctx {
        json: cli.json,
        quiet: cli.quiet,
    };

    let code = match run(cli.command, &ctx) {
        Ok(code) => code,
        Err(e) => {
            // Errors carry the engine's stable kind so a script can branch on
            // it rather than on the message text.
            if ctx.json {
                let body = serde_json::json!({
                    "ok": false,
                    "error": { "kind": e.kind(), "message": e.to_string() },
                });
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
            } else {
                eprintln!("aether: {e}");
            }
            match e.kind() {
                "config_invalid" | "target_invalid" | "scope_denied" | "not_found" => EXIT_USAGE,
                _ => EXIT_ENGINE,
            }
        }
    };
    ExitCode::from(code)
}

fn run(command: Command, ctx: &commands::Ctx) -> aether_core::Result<u8> {
    match command {
        Command::Doctor => commands::doctor(ctx),

        Command::Target(TargetCommand::Inspect(a)) => {
            commands::target_inspect(ctx, &a.binary, &a.input_mode, &a.args, a.timeout_ms)
        }

        Command::Campaign(CampaignCommand::Create { config }) => {
            commands::campaign_create(ctx, &config)
        }
        Command::Campaign(CampaignCommand::Run(a)) => {
            let mut cfg = Config::load(&a.config)?;
            if let Some(p) = &a.profile {
                config::apply_profile(&mut cfg, p)?;
            }
            if let Some(d) = a.duration {
                cfg.campaign.duration_secs = d;
            }
            if let Some(m) = a.max_execs {
                cfg.campaign.max_execs = m;
            }
            if let Some(s) = a.seed {
                cfg.campaign.seed = s;
            }
            if let Some(w) = a.workers {
                cfg.campaign.workers = w;
            }
            if let Some(s) = a.strategies {
                cfg.strategies.enabled = s;
            }
            cfg.validate()?;
            commands::campaign_run(
                ctx,
                cfg,
                a.seeds.as_deref(),
                a.resume.as_deref(),
                !a.no_fail_on_findings,
            )
        }
        Command::Campaign(CampaignCommand::Status { campaign_id, dir }) => {
            commands::campaign_status(ctx, &dir, campaign_id.as_deref())
        }
        Command::Campaign(CampaignCommand::Cancel { campaign_id, dir }) => {
            commands::campaign_cancel(ctx, &dir, &campaign_id)
        }
        Command::Campaign(CampaignCommand::List { dir, limit }) => {
            commands::campaign_list(ctx, &dir, limit)
        }

        Command::Corpus(CorpusCommand::Stats { campaign_id, dir }) => {
            commands::corpus_stats(ctx, &dir, campaign_id.as_deref())
        }
        Command::Corpus(CorpusCommand::Export {
            campaign_id,
            output,
            dir,
        }) => commands::corpus_export(ctx, &dir, &campaign_id, &output),

        Command::Findings(FindingsCommand::List {
            campaign_id,
            dir,
            status,
            limit,
        }) => commands::findings_list(ctx, &dir, campaign_id.as_deref(), status.as_deref(), limit),
        Command::Findings(FindingsCommand::Show { finding_id, dir }) => {
            commands::findings_show(ctx, &dir, &finding_id)
        }
        Command::Findings(FindingsCommand::Validate {
            finding_id,
            config,
            dir,
            attempts,
        }) => commands::findings_validate(ctx, &dir, &finding_id, &config, attempts),
        Command::Findings(FindingsCommand::Minimize {
            finding_id,
            config,
            dir,
        }) => commands::findings_minimize(ctx, &dir, &finding_id, &config),

        Command::Report(ReportCommand::Generate {
            campaign_id,
            dir,
            format,
            output,
        }) => commands::report_generate(
            ctx,
            &dir,
            campaign_id.as_deref(),
            &format,
            output.as_deref(),
        ),

        Command::Benchmark(BenchmarkCommand::Run {
            experiment,
            config,
            trials,
            duration,
            output,
        }) => commands::benchmark_run(
            ctx,
            &experiment,
            config.as_deref(),
            trials,
            duration,
            output.as_deref(),
        ),
        Command::Benchmark(BenchmarkCommand::List) => commands::benchmark_list(ctx),

        Command::Init {
            profile,
            binary,
            output,
        } => commands::init(ctx, &profile, binary.as_deref(), output.as_deref()),
    }
}
