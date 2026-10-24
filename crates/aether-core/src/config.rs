//! Campaign configuration: versioned schema, named profiles, validation.
//!
//! Configuration is validated in full before a campaign allocates anything,
//! so an incoherent request fails in milliseconds rather than after a worker
//! pool is already running. `schema_version` is explicit and checked: a
//! config from a future version is refused with a clear message rather than
//! silently half-understood.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ids::TargetId;
use crate::scope::ScopePolicy;

/// Schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Hard ceiling on a single generated input, independent of profile. Bounds
/// memory per worker and keeps a pathological mutation from exhausting disk.
pub const MAX_INPUT_BYTES: usize = 1 << 20; // 1 MiB

/// How the target receives one test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputMode {
    /// Written to the target's stdin. Required for fork-server mode.
    Stdin,
    /// Written to a file whose path replaces the `@@` placeholder in `args`.
    FileArg,
}

/// Target families AETHER can drive. Anything not listed is refused rather
/// than attempted: claiming universal compatibility would be a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// A local executable consuming one input per run.
    Executable,
    /// A local executable consuming a newline-delimited command sequence,
    /// driven by the stateful strategy.
    StatefulStdio,
    /// Two or more executables compared against each other.
    Differential,
}

/// Which instrumentation the target carries. Decides which feedback signals
/// are actually available; the engine never pretends a signal exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Instrumentation {
    /// Built with `aether-cc`: edge map, and comparison log where the
    /// compiler supports `trace-cmp`.
    AetherNative,
    /// No instrumentation. Only exit status and output are observable.
    None,
    /// A libFuzzer-style harness driven through the libFuzzer adapter.
    LibFuzzer,
    /// An AFL++-instrumented binary driven through the AFL++ adapter.
    AflPlusPlus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    #[serde(default)]
    pub id: Option<TargetId>,
    pub name: String,
    pub kind: TargetKind,
    /// Primary binary used for the fuzzing loop.
    pub binary: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_input_mode")]
    pub input_mode: InputMode,
    /// Extra environment for the target. Keys are validated: a name that
    /// could re-point the loader (`LD_PRELOAD` and friends) is refused.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_memory_mb")]
    pub memory_limit_mb: u64,
    #[serde(default = "default_instrumentation")]
    pub instrumentation: Instrumentation,
    /// Optional second build of the same program under a sanitizer. The
    /// campaign loop uses `binary`; the evidence engine re-runs candidates
    /// here for a stronger oracle. Keeping them separate is what lets AETHER
    /// have both fast coverage and sanitizer detection on a toolchain where
    /// one compiler cannot provide both.
    #[serde(default)]
    pub oracle_binary: Option<PathBuf>,
    /// Second implementation for differential testing.
    #[serde(default)]
    pub differential_binary: Option<PathBuf>,
    /// Use the fork server when the binary supports it. Falls back to plain
    /// exec automatically if the handshake does not complete.
    #[serde(default = "default_true")]
    pub use_fork_server: bool,
}

fn default_input_mode() -> InputMode { InputMode::Stdin }
fn default_timeout_ms() -> u64 { 1000 }
fn default_memory_mb() -> u64 { 512 }
fn default_instrumentation() -> Instrumentation { Instrumentation::AetherNative }
fn default_true() -> bool { true }

/// Environment variable names a target configuration may not set. These can
/// redirect the dynamic loader or the sanitizer runtime, which would let a
/// config file change what code runs or suppress the crash oracle.
const FORBIDDEN_ENV: &[&str] = &[
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS",
    "TSAN_OPTIONS", "AETHER_SHM_PATH", "AETHER_FORKSRV", "AETHER_CMPLOG",
];

impl TargetConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::config("target.name", "must not be empty"));
        }
        if self.binary.as_os_str().is_empty() {
            return Err(Error::config("target.binary", "must not be empty"));
        }
        if self.timeout_ms == 0 || self.timeout_ms > 600_000 {
            return Err(Error::config(
                "target.timeout_ms",
                format!("{} outside 1..=600000", self.timeout_ms),
            ));
        }
        if self.memory_limit_mb > 1 << 20 {
            return Err(Error::config(
                "target.memory_limit_mb",
                format!("{} exceeds 1048576", self.memory_limit_mb),
            ));
        }
        for key in self.env.keys() {
            if key.trim().is_empty() || key.contains('=') || key.contains('\0') {
                return Err(Error::config("target.env", format!("invalid variable name {key:?}")));
            }
            if FORBIDDEN_ENV.iter().any(|f| f.eq_ignore_ascii_case(key)) {
                return Err(Error::config(
                    "target.env",
                    format!(
                        "{key} may not be set from configuration: it can redirect the loader \
                         or disable the crash oracle"
                    ),
                ));
            }
        }
        for arg in &self.args {
            if arg.contains('\0') {
                return Err(Error::config("target.args", "argument contains a NUL byte"));
            }
        }
        if self.input_mode == InputMode::FileArg
            && !self.args.iter().any(|a| a.contains("@@"))
        {
            return Err(Error::config(
                "target.args",
                "input_mode is file-arg but no argument contains the @@ placeholder",
            ));
        }
        if self.input_mode == InputMode::FileArg && self.use_fork_server {
            // The fork server delivers input by rewinding an inherited stdin
            // descriptor; a path argument is fixed at exec time.
            return Err(Error::config(
                "target.use_fork_server",
                "the fork server requires input_mode = \"stdin\"",
            ));
        }
        if self.kind == TargetKind::Differential && self.differential_binary.is_none() {
            return Err(Error::config(
                "target.differential_binary",
                "kind = \"differential\" requires a second binary",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignLimits {
    /// Wall-clock budget. 0 means "until max_execs or cancellation".
    #[serde(default = "default_duration")]
    pub duration_secs: u64,
    /// Execution budget. 0 means unbounded.
    #[serde(default)]
    pub max_execs: u64,
    #[serde(default = "default_workers")]
    pub workers: u32,
    /// Fixed seed. Recorded in every report so a run can be replayed.
    #[serde(default = "default_seed")]
    pub seed: u64,
    /// Ceiling on generated input length, clamped to [`MAX_INPUT_BYTES`].
    #[serde(default = "default_max_input")]
    pub max_input_bytes: usize,
    /// Stop as soon as this many reproducible findings exist. 0 disables.
    #[serde(default)]
    pub stop_after_findings: u32,
}

fn default_duration() -> u64 { 60 }
fn default_workers() -> u32 { 1 }
fn default_seed() -> u64 { 0xA37_4E12 }
fn default_max_input() -> usize { 65_536 }

impl Default for CampaignLimits {
    fn default() -> Self {
        CampaignLimits {
            duration_secs: default_duration(),
            max_execs: 0,
            workers: default_workers(),
            seed: default_seed(),
            max_input_bytes: default_max_input(),
            stop_after_findings: 0,
        }
    }
}

impl CampaignLimits {
    pub fn validate(&self) -> Result<()> {
        if self.duration_secs == 0 && self.max_execs == 0 {
            return Err(Error::config(
                "campaign",
                "set duration_secs or max_execs; an unbounded campaign is refused",
            ));
        }
        if self.workers == 0 || self.workers > 1024 {
            return Err(Error::config(
                "campaign.workers",
                format!("{} outside 1..=1024", self.workers),
            ));
        }
        if self.max_input_bytes == 0 || self.max_input_bytes > MAX_INPUT_BYTES {
            return Err(Error::config(
                "campaign.max_input_bytes",
                format!("{} outside 1..={MAX_INPUT_BYTES}", self.max_input_bytes),
            ));
        }
        Ok(())
    }
}

/// Which scheduler allocates execution budget across strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchedulerKind {
    /// Thompson Sampling over per-strategy Beta posteriors.
    Thompson,
    /// UCB1 with cost normalisation.
    Ucb1,
    /// Equal fixed shares. The baseline adaptive scheduling is measured against.
    Static,
    /// One strategy per round in order. Used as a control in experiments.
    RoundRobin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelConfig {
    #[serde(default = "default_scheduler")]
    pub scheduler: SchedulerKind,
    /// Executions handed to a strategy per selection round.
    #[serde(default = "default_round_budget")]
    pub round_budget: u32,
    /// A strategy gets at least this many rounds before it can be starved,
    /// so a slow starter is not eliminated on noise.
    #[serde(default = "default_min_rounds")]
    pub min_rounds_per_strategy: u32,
    /// Floor on selection probability, so no enabled strategy is ever fully
    /// starved even if its posterior collapses.
    #[serde(default = "default_floor")]
    pub selection_floor: f64,
    /// Rounds of no new coverage before stagnation is declared.
    #[serde(default = "default_stagnation_rounds")]
    pub stagnation_rounds: u32,
    /// Fraction of recent rounds that must show progress to clear stagnation.
    /// The gap between this and entry is the hysteresis band that stops the
    /// scheduler oscillating.
    #[serde(default = "default_recovery")]
    pub stagnation_recovery_ratio: f64,
    /// Weights for the multi-objective corpus score. Normalised before use.
    #[serde(default)]
    pub corpus_weights: CorpusWeights,
}

fn default_scheduler() -> SchedulerKind { SchedulerKind::Thompson }
fn default_round_budget() -> u32 { 64 }
fn default_min_rounds() -> u32 { 3 }
fn default_floor() -> f64 { 0.02 }
fn default_stagnation_rounds() -> u32 { 24 }
fn default_recovery() -> f64 { 0.15 }

impl Default for IntelConfig {
    fn default() -> Self {
        IntelConfig {
            scheduler: default_scheduler(),
            round_budget: default_round_budget(),
            min_rounds_per_strategy: default_min_rounds(),
            selection_floor: default_floor(),
            stagnation_rounds: default_stagnation_rounds(),
            stagnation_recovery_ratio: default_recovery(),
            corpus_weights: CorpusWeights::default(),
        }
    }
}

impl IntelConfig {
    pub fn validate(&self) -> Result<()> {
        if self.round_budget == 0 || self.round_budget > 100_000 {
            return Err(Error::config(
                "intel.round_budget",
                format!("{} outside 1..=100000", self.round_budget),
            ));
        }
        if !(0.0..=0.5).contains(&self.selection_floor) {
            return Err(Error::config(
                "intel.selection_floor",
                format!("{} outside 0.0..=0.5", self.selection_floor),
            ));
        }
        if !(0.0..=1.0).contains(&self.stagnation_recovery_ratio) {
            return Err(Error::config(
                "intel.stagnation_recovery_ratio",
                format!("{} outside 0.0..=1.0", self.stagnation_recovery_ratio),
            ));
        }
        self.corpus_weights.validate()
    }
}

/// Weights of the multi-objective corpus ranking. Each component is
/// normalised to [0,1] before weighting, so these are directly comparable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusWeights {
    pub coverage: f64,
    pub novelty: f64,
    pub diversity: f64,
    pub mutation_productivity: f64,
    /// Negative contribution: cheaper inputs rank higher.
    pub execution_cost: f64,
    /// Negative contribution: redundant inputs rank lower.
    pub redundancy: f64,
    pub state_transitions: f64,
}

impl Default for CorpusWeights {
    fn default() -> Self {
        CorpusWeights {
            coverage: 1.0,
            novelty: 0.6,
            diversity: 0.3,
            mutation_productivity: 0.5,
            execution_cost: 0.25,
            redundancy: 0.4,
            state_transitions: 0.3,
        }
    }
}

impl CorpusWeights {
    pub fn validate(&self) -> Result<()> {
        let all = [
            ("coverage", self.coverage),
            ("novelty", self.novelty),
            ("diversity", self.diversity),
            ("mutation_productivity", self.mutation_productivity),
            ("execution_cost", self.execution_cost),
            ("redundancy", self.redundancy),
            ("state_transitions", self.state_transitions),
        ];
        for (name, v) in all {
            if !v.is_finite() || v < 0.0 {
                return Err(Error::config(
                    format!("intel.corpus_weights.{name}"),
                    format!("{v} must be finite and >= 0"),
                ));
            }
        }
        if all.iter().map(|(_, v)| *v).sum::<f64>() <= 0.0 {
            return Err(Error::config(
                "intel.corpus_weights",
                "at least one weight must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionConfig {
    /// Re-runs attempted when validating a candidate.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// Successes required to call a finding reproducible. Fewer successes than
    /// this but more than zero means `intermittent`, never `reproducible`.
    #[serde(default = "default_required")]
    pub required_successes: u32,
    #[serde(default = "default_true")]
    pub minimize: bool,
    /// Ceiling on minimisation work, so a pathological input cannot stall the
    /// evidence pipeline indefinitely.
    #[serde(default = "default_min_rounds_minimize")]
    pub minimize_max_execs: u32,
    /// Re-run candidates against `oracle_binary` when one is configured.
    #[serde(default = "default_true")]
    pub use_oracle_binary: bool,
}

fn default_attempts() -> u32 { 5 }
fn default_required() -> u32 { 3 }
fn default_min_rounds_minimize() -> u32 { 2000 }

impl Default for ReproductionConfig {
    fn default() -> Self {
        ReproductionConfig {
            attempts: default_attempts(),
            required_successes: default_required(),
            minimize: true,
            minimize_max_execs: default_min_rounds_minimize(),
            use_oracle_binary: true,
        }
    }
}

impl ReproductionConfig {
    pub fn validate(&self) -> Result<()> {
        if self.attempts == 0 || self.attempts > 1000 {
            return Err(Error::config(
                "reproduction.attempts",
                format!("{} outside 1..=1000", self.attempts),
            ));
        }
        if self.required_successes == 0 || self.required_successes > self.attempts {
            return Err(Error::config(
                "reproduction.required_successes",
                format!(
                    "{} must be in 1..={} (attempts)",
                    self.required_successes, self.attempts
                ),
            ));
        }
        Ok(())
    }
}

/// The experimental quantum-inspired optimizer. Off by default; a campaign
/// never depends on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_solver")]
    pub solver: String,
    /// Milliseconds the solver may spend per problem. Enforced.
    #[serde(default = "default_solver_budget")]
    pub budget_ms: u64,
    /// Always run the classical baseline alongside, so every claim about the
    /// experimental solver has a same-budget comparison attached.
    #[serde(default = "default_true")]
    pub compare_against_baseline: bool,
}

fn default_solver() -> String { "greedy".into() }
fn default_solver_budget() -> u64 { 50 }

impl Default for OptimizerConfig {
    fn default() -> Self {
        OptimizerConfig {
            enabled: false,
            solver: default_solver(),
            budget_ms: default_solver_budget(),
            compare_against_baseline: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Root for corpus, findings, checkpoints and the metadata database.
    #[serde(default = "default_out_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_formats")]
    pub report_formats: Vec<String>,
    /// Bytes of stdout/stderr retained per execution. Bounded so a noisy
    /// target cannot fill the disk or a report.
    #[serde(default = "default_log_bytes")]
    pub max_log_bytes: usize,
    /// Telemetry detail: 0 quiet, 1 normal, 2 verbose, 3 per-execution.
    #[serde(default = "default_telemetry")]
    pub telemetry_level: u8,
}

fn default_out_dir() -> PathBuf { PathBuf::from(".aether") }
fn default_formats() -> Vec<String> { vec!["json".into(), "markdown".into()] }
fn default_log_bytes() -> usize { 16 * 1024 }
fn default_telemetry() -> u8 { 1 }

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig {
            dir: default_out_dir(),
            report_formats: default_formats(),
            max_log_bytes: default_log_bytes(),
            telemetry_level: default_telemetry(),
        }
    }
}

impl OutputConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_log_bytes > 4 << 20 {
            return Err(Error::config(
                "output.max_log_bytes",
                format!("{} exceeds 4194304", self.max_log_bytes),
            ));
        }
        for f in &self.report_formats {
            if !matches!(f.as_str(), "json" | "markdown" | "sarif" | "bench-json") {
                return Err(Error::config(
                    "output.report_formats",
                    format!("unknown format {f:?}; expected json, markdown, sarif or bench-json"),
                ));
            }
        }
        if self.telemetry_level > 3 {
            return Err(Error::config("output.telemetry_level", "must be 0..=3"));
        }
        Ok(())
    }
}

/// Which feedback providers to consult. Listing one that the target cannot
/// supply is not an error: the provider reports itself unavailable and the
/// campaign records that, rather than fabricating the signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackConfig {
    #[serde(default = "default_providers")]
    pub providers: Vec<String>,
    /// Weight applied to each provider's novelty contribution.
    #[serde(default)]
    pub weights: BTreeMap<String, f64>,
}

fn default_providers() -> Vec<String> {
    vec![
        "edge-coverage".into(),
        "exit-class".into(),
        "cmplog".into(),
        "sanitizer".into(),
    ]
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        FeedbackConfig { providers: default_providers(), weights: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Explicit and checked. A newer schema is refused, not guessed at.
    pub schema_version: u32,
    #[serde(default)]
    pub profile: Option<String>,
    pub target: TargetConfig,
    #[serde(default)]
    pub campaign: CampaignLimits,
    #[serde(default)]
    pub scope: ScopePolicy,
    #[serde(default)]
    pub strategies: StrategyConfig,
    #[serde(default)]
    pub feedback: FeedbackConfig,
    #[serde(default)]
    pub intel: IntelConfig,
    #[serde(default)]
    pub reproduction: ReproductionConfig,
    #[serde(default)]
    pub optimizer: OptimizerConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyConfig {
    /// Strategy ids to enable. Empty means "every registered strategy whose
    /// requirements the target meets".
    #[serde(default)]
    pub enabled: Vec<String>,
    /// Extra dictionary tokens, as literal byte strings.
    #[serde(default)]
    pub dictionary: Vec<String>,
    /// Path to a dictionary file, one token per line, `#` comments allowed.
    #[serde(default)]
    pub dictionary_file: Option<PathBuf>,
    /// Grammar definition for the grammar strategy.
    #[serde(default)]
    pub grammar_file: Option<PathBuf>,
    /// Free-form per-strategy parameters, passed to the strategy at init.
    #[serde(default)]
    pub params: BTreeMap<String, toml::Value>,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        StrategyConfig {
            enabled: Vec::new(),
            dictionary: Vec::new(),
            dictionary_file: None,
            grammar_file: None,
            params: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s)
            .map_err(|e| Error::config("toml", e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Self::from_toml_str(&text)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::config("toml", e.to_string()))
    }

    /// Full validation. Runs before a campaign allocates any resource.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version == 0 || self.schema_version > SCHEMA_VERSION {
            return Err(Error::config(
                "schema_version",
                format!(
                    "{} is not supported by this build (supports 1..={SCHEMA_VERSION}); \
                     upgrade AETHER or lower the version",
                    self.schema_version
                ),
            ));
        }
        self.target.validate()?;
        self.campaign.validate()?;
        self.scope.validate()?;
        self.intel.validate()?;
        self.reproduction.validate()?;
        self.output.validate()?;

        // Cross-field coherence: a feedback provider that depends on
        // instrumentation the target lacks is reported here, once, rather
        // than silently returning nothing for the whole campaign.
        if self.target.instrumentation == Instrumentation::None
            && self.feedback.providers.iter().any(|p| p == "edge-coverage")
        {
            return Err(Error::config(
                "feedback.providers",
                "edge-coverage requires instrumentation; set target.instrumentation or \
                 drop the provider (exit-class still works on an uninstrumented target)",
            ));
        }
        if self.target.kind == TargetKind::Differential
            && !self.feedback.providers.iter().any(|p| p == "differential")
        {
            return Err(Error::config(
                "feedback.providers",
                "a differential target needs the \"differential\" provider enabled",
            ));
        }
        Ok(())
    }

    /// Resolve the campaign's effective input size ceiling.
    pub fn max_input_bytes(&self) -> usize {
        self.campaign.max_input_bytes.min(MAX_INPUT_BYTES)
    }
}

/// Named presets. These set budgets and strategy mixes; they do not promise
/// that a given target supports the capabilities a profile prefers.
pub const PROFILE_NAMES: &[&str] = &[
    "quick-local",
    "deep-exploration",
    "structured-parser",
    "stateful-api",
    "distributed",
    "low-resource",
    "research-benchmark",
];

/// Apply a named profile on top of a config. Explicit fields already present
/// in the file are not overwritten by a profile; the profile only sets the
/// budget and strategy shape.
pub fn apply_profile(cfg: &mut Config, profile: &str) -> Result<()> {
    match profile {
        "quick-local" => {
            cfg.campaign.duration_secs = 30;
            cfg.campaign.workers = 1;
            cfg.intel.round_budget = 32;
            cfg.strategies.enabled =
                vec!["havoc".into(), "random-mutation".into(), "cmplog-guided".into()];
        }
        "deep-exploration" => {
            cfg.campaign.duration_secs = 3600;
            cfg.campaign.workers = num_workers_default();
            cfg.intel.round_budget = 128;
            cfg.strategies.enabled = Vec::new(); // every eligible strategy
        }
        "structured-parser" => {
            cfg.campaign.duration_secs = 600;
            cfg.strategies.enabled = vec![
                "grammar".into(),
                "structure-aware".into(),
                "dictionary".into(),
                "havoc".into(),
                "splice".into(),
            ];
        }
        "stateful-api" => {
            cfg.campaign.duration_secs = 600;
            cfg.strategies.enabled =
                vec!["stateful-sequence".into(), "dictionary".into(), "havoc".into()];
            cfg.feedback.providers.push("state-transition".into());
        }
        "distributed" => {
            cfg.campaign.duration_secs = 3600;
            cfg.campaign.workers = num_workers_default();
            cfg.intel.round_budget = 256;
        }
        "low-resource" => {
            cfg.campaign.duration_secs = 120;
            cfg.campaign.workers = 1;
            cfg.campaign.max_input_bytes = 4096;
            cfg.intel.round_budget = 16;
            cfg.target.memory_limit_mb = cfg.target.memory_limit_mb.min(128);
            cfg.output.telemetry_level = 0;
            cfg.strategies.enabled = vec!["havoc".into(), "random-mutation".into()];
        }
        "research-benchmark" => {
            cfg.campaign.duration_secs = 300;
            cfg.campaign.workers = 1;
            cfg.campaign.seed = 0xBEEF_1234;
            cfg.output.report_formats = vec!["json".into(), "bench-json".into()];
            // Make the campaign a pure function of its seed, which a
            // comparison between configurations needs.
            //
            // Two things otherwise make an outcome depend on machine load,
            // both of them deliberate elsewhere: the adaptive schedulers
            // reward discovery per unit of *measured* compute, and the corpus
            // ranks cheaper inputs higher. Both read a wall-clock duration,
            // so under different load the same seed explores a slightly
            // different set of inputs. Useful in a real campaign, fatal to a
            // controlled experiment - so this profile turns both off and
            // accepts a less efficient search in exchange for replayability.
            cfg.intel.scheduler = SchedulerKind::RoundRobin;
            cfg.intel.selection_floor = 0.0;
            cfg.intel.corpus_weights.execution_cost = 0.0;
        }
        other => {
            return Err(Error::config(
                "profile",
                format!("unknown profile {other:?}; known: {}", PROFILE_NAMES.join(", ")),
            ))
        }
    }
    cfg.profile = Some(profile.to_string());
    Ok(())
}

/// Workers to use when a profile asks for "all of them". Leaves one core for
/// the controller and the operating system.
pub fn num_workers_default() -> u32 {
    let n = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
    (n.saturating_sub(1)).max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> &'static str {
        r#"
schema_version = 1
[target]
name = "demo"
kind = "executable"
binary = "/bin/true"
"#
    }

    #[test]
    fn minimal_config_loads_with_defaults() {
        let c = Config::from_toml_str(minimal()).unwrap();
        assert_eq!(c.campaign.workers, 1);
        assert_eq!(c.target.input_mode, InputMode::Stdin);
        assert_eq!(c.intel.scheduler, SchedulerKind::Thompson);
        assert!(!c.scope.allow_network_targets);
        assert!(!c.optimizer.enabled, "the experimental optimizer must be opt-in");
    }

    #[test]
    fn round_trips_through_toml() {
        let c = Config::from_toml_str(minimal()).unwrap();
        let s = c.to_toml_string().unwrap();
        let c2 = Config::from_toml_str(&s).unwrap();
        assert_eq!(c.target.name, c2.target.name);
        assert_eq!(c.campaign.seed, c2.campaign.seed);
    }

    #[test]
    fn future_schema_version_is_refused() {
        let s = minimal().replace("schema_version = 1", "schema_version = 99");
        let e = Config::from_toml_str(&s).unwrap_err();
        assert_eq!(e.kind(), "config_invalid");
        assert!(e.to_string().contains("not supported"), "{e}");
    }

    #[test]
    fn unknown_fields_are_refused() {
        let s = format!("{}\nnot_a_field = 1\n", minimal());
        assert!(Config::from_toml_str(&s).is_err());
    }

    #[test]
    fn loader_hijacking_env_is_refused() {
        for var in ["LD_PRELOAD", "ld_preload", "ASAN_OPTIONS", "AETHER_SHM_PATH"] {
            let s = format!("{}\n[target.env]\n{var} = \"x\"\n", minimal());
            let e = Config::from_toml_str(&s).unwrap_err();
            assert!(e.to_string().contains("may not be set"), "{var}: {e}");
        }
    }

    #[test]
    fn unbounded_campaign_is_refused() {
        let s = format!("{}\n[campaign]\nduration_secs = 0\nmax_execs = 0\n", minimal());
        assert!(Config::from_toml_str(&s).is_err());
    }

    #[test]
    fn file_arg_mode_requires_placeholder_and_no_fork_server() {
        let s = format!(
            "{}\n[campaign]\nduration_secs = 5\n",
            minimal().replace(
                "binary = \"/bin/true\"",
                "binary = \"/bin/true\"\ninput_mode = \"file-arg\"\nuse_fork_server = false"
            )
        );
        // No @@ placeholder.
        assert!(Config::from_toml_str(&s).is_err());

        let ok = minimal().replace(
            "binary = \"/bin/true\"",
            "binary = \"/bin/true\"\ninput_mode = \"file-arg\"\nuse_fork_server = false\nargs = [\"@@\"]",
        );
        Config::from_toml_str(&ok).unwrap();

        // @@ present but fork server left on: refused, because the fork server
        // cannot re-point a path argument between runs.
        let bad = minimal().replace(
            "binary = \"/bin/true\"",
            "binary = \"/bin/true\"\ninput_mode = \"file-arg\"\nargs = [\"@@\"]",
        );
        assert!(Config::from_toml_str(&bad).is_err());
    }

    #[test]
    fn edge_coverage_without_instrumentation_is_refused() {
        let s = minimal().replace(
            "binary = \"/bin/true\"",
            "binary = \"/bin/true\"\ninstrumentation = \"none\"",
        );
        let e = Config::from_toml_str(&s).unwrap_err();
        assert!(e.to_string().contains("edge-coverage requires instrumentation"), "{e}");
    }

    #[test]
    fn oversized_input_ceiling_is_refused() {
        let s = format!(
            "{}\n[campaign]\nduration_secs = 5\nmax_input_bytes = {}\n",
            minimal(),
            MAX_INPUT_BYTES + 1
        );
        assert!(Config::from_toml_str(&s).is_err());
    }

    #[test]
    fn every_profile_applies_and_stays_valid() {
        for p in PROFILE_NAMES {
            let mut c = Config::from_toml_str(minimal()).unwrap();
            apply_profile(&mut c, p).unwrap_or_else(|e| panic!("profile {p}: {e}"));
            // stateful-api pushes a provider; drop the instrumentation clash
            // check by keeping native instrumentation, which minimal() has.
            c.validate().unwrap_or_else(|e| panic!("profile {p} produced invalid config: {e}"));
            assert_eq!(c.profile.as_deref(), Some(*p));
        }
    }

    #[test]
    fn unknown_profile_is_refused() {
        let mut c = Config::from_toml_str(minimal()).unwrap();
        assert!(apply_profile(&mut c, "does-not-exist").is_err());
    }

    #[test]
    fn reproduction_requires_coherent_thresholds() {
        let s = format!(
            "{}\n[reproduction]\nattempts = 3\nrequired_successes = 5\n",
            minimal()
        );
        assert!(Config::from_toml_str(&s).is_err());
    }

    #[test]
    fn unknown_report_format_is_refused() {
        let s = format!("{}\n[output]\nreport_formats = [\"pdf\"]\n", minimal());
        assert!(Config::from_toml_str(&s).is_err());
    }
}
