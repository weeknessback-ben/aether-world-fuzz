//! The campaign runtime: the loop that drives everything else.
//!
//! One round of the loop is:
//!
//! 1. build the campaign context,
//! 2. let the scheduler choose a strategy,
//! 3. draw mutation bases from the corpus,
//! 4. ask the strategy for candidates,
//! 5. execute each one and fold its feedback in,
//! 6. keep what was interesting, validate what failed,
//! 7. close the round and act on the stagnation detector's advice.
//!
//! Observe, analyse, plan, execute, measure, update, repeat - with every step
//! measured rather than assumed. Cancellation is checked between executions,
//! so a campaign stops promptly rather than at the end of a round.

pub mod checkpoint;
pub mod worker;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::corpus::{AddOutcome, Corpus, NewInput};
use crate::error::{Error, Result};
use crate::evidence::report::{
    CampaignReport, EnvironmentReport, ExecutionStats, FindingsSummary, StrategyReport,
};
use crate::evidence::signature::signature_for;
use crate::evidence::validate::{self, DedupDecision};
use crate::evidence::{Confidence, Evidence, Finding, FindingStatus, ReproductionRecord};
use crate::exec::native::{NativeExecutor, TargetSpec};
use crate::exec::{Executor, ExitClass};
use crate::feedback::FeedbackEngine;
use crate::ids::{CampaignId, FindingId};
use crate::intel::{stagnation::Response, Intelligence};
use crate::persist::Store;
use crate::rng::Rng;
use crate::strategy::{self, Base, CandidateResult, Strategy};

/// Shared cancellation token. Checked between executions.
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    /// Optional file whose existence also means "stop".
    sentinel: Option<Arc<std::path::PathBuf>>,
}

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Also watch a sentinel file, so another process can cancel a campaign.
    ///
    /// `aether campaign cancel` runs in a different process from the campaign
    /// it stops, so an in-process flag is not enough. A file is the simplest
    /// mechanism that works without a daemon or a socket, and it survives the
    /// cancelling process exiting immediately afterwards.
    pub fn with_sentinel(path: std::path::PathBuf) -> Self {
        Cancel {
            flag: Arc::new(AtomicBool::new(false)),
            sentinel: Some(Arc::new(path)),
        }
    }

    /// Request cancellation of a campaign running elsewhere.
    pub fn request_via_file(path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        std::fs::write(path, b"cancel").map_err(|e| Error::io(path, e))
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        if self.flag.load(Ordering::SeqCst) {
            return true;
        }
        // Checked on every call, which happens between executions. A stat()
        // per execution would be wasteful at a few thousand executions a
        // second, so the result is latched once seen.
        if let Some(p) = &self.sentinel {
            if p.exists() {
                self.flag.store(true, Ordering::SeqCst);
                return true;
            }
        }
        false
    }

    pub fn sentinel_path(&self) -> Option<&std::path::Path> {
        self.sentinel.as_ref().map(|p| p.as_path())
    }
}

/// Live campaign status, readable while a campaign runs.
///
/// Every field a consumer might read as a measurement distinguishes
/// "unavailable" from zero, so a status display cannot imply a metric was
/// measured when it was not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignStatus {
    pub campaign_id: String,
    pub target_name: String,
    pub state: String,
    pub elapsed_ms: u64,
    pub workers: u32,
    pub total_executions: u64,
    pub executions_per_second: f64,
    /// `None` when the target is uninstrumented.
    pub total_edges: Option<u32>,
    pub coverage_saturation: Option<f64>,
    pub corpus_entries: u64,
    pub candidate_findings: u32,
    pub confirmed_findings: u32,
    /// When anything new was last discovered, as epoch milliseconds.
    pub last_progress_ms: Option<u64>,
    pub stagnation_phase: String,
    pub strategy_allocation: Vec<(String, f64)>,
}

/// Why a campaign stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopReason {
    DurationElapsed,
    ExecutionBudgetReached,
    FindingTargetReached,
    Cancelled,
    /// Every strategy ran out of productive work and escalation was exhausted.
    NoProgress,
}

impl StopReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            StopReason::DurationElapsed => "duration-elapsed",
            StopReason::ExecutionBudgetReached => "execution-budget-reached",
            StopReason::FindingTargetReached => "finding-target-reached",
            StopReason::Cancelled => "cancelled",
            StopReason::NoProgress => "no-progress",
        }
    }
}

/// Counters shared with anything observing a running campaign.
#[derive(Default)]
pub struct LiveCounters {
    pub executions: AtomicU64,
    pub crashes: AtomicU64,
    pub timeouts: AtomicU64,
    pub clean_runs: AtomicU64,
    pub last_progress_ms: AtomicU64,
}

/// One campaign.
pub struct Campaign {
    pub id: CampaignId,
    config: Config,
    store: Store,
    corpus: Corpus,
    feedback: FeedbackEngine,
    intel: Intelligence,
    strategies: Vec<Box<dyn Strategy>>,
    skipped_strategies: Vec<(String, String)>,
    executor: NativeExecutor,
    /// Separate executor against the sanitizer build, when configured. The
    /// campaign loop uses the fast instrumented build; this is the stronger
    /// oracle the evidence engine re-runs candidates against.
    oracle: Option<NativeExecutor>,
    rng: Rng,
    cancel: Cancel,
    counters: Arc<LiveCounters>,
    findings: Vec<Finding>,
    /// Comparison operands observed for a corpus entry, keyed by input id.
    ///
    /// The comparison-guided strategy substitutes a constant at the offset the
    /// compared bytes came from, so it needs the entries belonging to *that*
    /// input. Those are only available from an execution of it, so they are
    /// cached here when first collected. Bounded, because a long campaign
    /// would otherwise accumulate one entry list per corpus input.
    cmp_cache: std::collections::HashMap<crate::ids::InputId, Vec<crate::exec::shm::CmpEntry>>,
    started: Instant,
    started_ms: u64,
    scratch: std::path::PathBuf,
    /// Set once the campaign has stopped, so a status read afterwards reports
    /// the real state rather than claiming the campaign is still running.
    final_state: Option<StopReason>,
}

impl Campaign {
    /// Create a campaign from validated configuration.
    ///
    /// Everything that can fail - scope authorisation, the target binary,
    /// strategy requirements, storage - fails here, before any execution and
    /// before any worker is started.
    pub fn create(config: Config, cancel: Cancel) -> Result<Self> {
        config.validate()?;

        let id = CampaignId::new();
        let out_dir = config.output.dir.join(id.as_str());
        std::fs::create_dir_all(&out_dir).map_err(|e| Error::io(&out_dir, e))?;
        let scratch = out_dir.join("scratch");
        std::fs::create_dir_all(&scratch).map_err(|e| Error::io(&scratch, e))?;

        let store = Store::open(&config.output.dir.join("aether.sqlite"))?;

        // Scope is checked inside TargetSpec::from_config, which is the only
        // way to construct a spec, so there is no path to an executor that
        // skipped it.
        let spec =
            TargetSpec::from_config(&config.target, &config.scope, config.output.max_log_bytes)?;
        let executor = NativeExecutor::new(spec.clone(), &scratch)?;

        let oracle = match &config.target.oracle_binary {
            Some(path) if config.reproduction.use_oracle_binary => {
                let ospec = spec.with_binary(path)?;
                Some(NativeExecutor::new(ospec, &scratch.join("oracle"))?)
            }
            _ => None,
        };

        let caps = executor.capabilities().clone();
        let dictionary = load_dictionary(&config)?;
        let grammar = match &config.strategies.grammar_file {
            Some(p) => Some(std::fs::read_to_string(p).map_err(|e| Error::io(p, e))?),
            None => None,
        };

        let ctx = strategy::StrategyContext {
            seed: config.campaign.seed,
            max_input_bytes: config.max_input_bytes(),
            dictionary: &dictionary,
            grammar_text: grammar.as_deref(),
            params: &config.strategies.params,
            coverage_available: caps.edge_coverage,
            cmplog_available: caps.comparison_log,
        };
        let (strategies, skipped_strategies) =
            strategy::build_all(&config.strategies.enabled, &ctx)?;

        let feedback = FeedbackEngine::new(
            &config.feedback.providers,
            &config.feedback.weights,
            Vec::new(),
            caps.edge_coverage,
        )?;

        let intel = Intelligence::new(
            &config.intel,
            strategies.iter().map(|s| s.id().to_string()).collect(),
        );

        let corpus = Corpus::open(
            &out_dir,
            id.clone(),
            config.intel.corpus_weights.clone(),
            100_000,
            config.max_input_bytes(),
        )?;

        let started_ms = crate::time::now_millis();
        store.conn().execute(
            "INSERT INTO campaigns(id, target_name, profile, seed, status, config_toml, \
             created_ms, updated_ms) VALUES (?1,?2,?3,?4,'created',?5,?6,?6)",
            rusqlite::params![
                id.as_str(),
                &config.target.name,
                &config.profile,
                config.campaign.seed as i64,
                config.to_toml_string().unwrap_or_default(),
                started_ms as i64,
            ],
        )?;
        store.record_event(id.as_str(), "created", None)?;

        Ok(Campaign {
            rng: Rng::from_seed(config.campaign.seed),
            id,
            config,
            store,
            corpus,
            feedback,
            intel,
            strategies,
            skipped_strategies,
            executor,
            oracle,
            cancel,
            counters: Arc::new(LiveCounters::default()),
            findings: Vec::new(),
            cmp_cache: std::collections::HashMap::new(),
            started: Instant::now(),
            started_ms,
            scratch,
            final_state: None,
        })
    }

    pub fn counters(&self) -> Arc<LiveCounters> {
        self.counters.clone()
    }

    /// Seed the corpus. With no seeds supplied, a single zero byte is used so
    /// mutation strategies have something to work from; generation strategies
    /// do not need it.
    pub fn seed_corpus(&mut self, seed_dir: Option<&std::path::Path>) -> Result<(u64, u64, u64)> {
        let stats = match seed_dir {
            Some(dir) => self.corpus.import_seeds(&mut self.store, dir)?,
            None => (0, 0, 0),
        };
        if self.corpus.is_empty(&self.store)? {
            self.corpus.add(
                &mut self.store,
                b"\0",
                NewInput {
                    strategy_id: Some("bootstrap"),
                    ..Default::default()
                },
            )?;
        }
        Ok(stats)
    }

    /// Run to completion, or until cancelled.
    pub fn run(&mut self) -> Result<StopReason> {
        self.store.record_event(self.id.as_str(), "started", None)?;
        self.set_state("running")?;
        if let Some(g) = self.executor.shm_guard_count() {
            if g > 0 {
                self.feedback.coverage_mut().set_guard_count(g);
            }
        }

        let deadline = if self.config.campaign.duration_secs > 0 {
            Some(self.started + Duration::from_secs(self.config.campaign.duration_secs))
        } else {
            None
        };
        let max_execs = self.config.campaign.max_execs;
        let stop_after = self.config.campaign.stop_after_findings;
        let mut last_checkpoint = Instant::now();
        let mut last_status = Instant::now();

        let reason = loop {
            if self.cancel.is_cancelled() {
                break StopReason::Cancelled;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    break StopReason::DurationElapsed;
                }
            }
            let execs = self.counters.executions.load(Ordering::Relaxed);
            if max_execs > 0 && execs >= max_execs {
                break StopReason::ExecutionBudgetReached;
            }
            if stop_after > 0 && self.confirmed_count() >= stop_after {
                break StopReason::FindingTargetReached;
            }

            let advice = self.run_round(deadline, max_execs)?;

            // Escalation exhausted with nothing left to try: report rather
            // than burn the rest of the budget on strategies already shown to
            // be unproductive.
            if advice == Response::ReportNoProgress && self.intel.stagnation.is_exhausted() {
                self.store.record_event(
                    self.id.as_str(),
                    "no-progress",
                    Some("stagnation escalation exhausted"),
                )?;
                break StopReason::NoProgress;
            }

            // Checkpoint on a timer rather than per round, so a short round
            // does not dominate the campaign with serialisation work.
            // Status is refreshed more often than the checkpoint: a client
            // polling progress wants it within a second or two, while a
            // checkpoint serialises the coverage map and is not worth doing
            // that often.
            if last_status.elapsed() > Duration::from_millis(1500) {
                self.write_status_file()?;
                last_status = Instant::now();
            }
            if last_checkpoint.elapsed() > Duration::from_secs(20) {
                self.save_checkpoint()?;
                last_checkpoint = Instant::now();
            }
        };

        self.save_checkpoint()?;
        self.set_state(match reason {
            StopReason::Cancelled => "cancelled",
            _ => "completed",
        })?;
        self.final_state = Some(reason);
        self.write_status_file()?;
        self.store
            .record_event(self.id.as_str(), "stopped", Some(reason.as_str()))?;
        Ok(reason)
    }

    /// One scheduling round.
    fn run_round(&mut self, deadline: Option<Instant>, max_execs: u64) -> Result<Response> {
        let corpus_size = self.corpus.len(&self.store)?;
        let saturation = self.feedback.coverage().saturation();
        let ctx = self.intel.context(corpus_size, saturation);
        let arm = self.intel.scheduler.select(ctx, &mut self.rng);

        // Mutation bases. Sampled rather than always taking the best, so the
        // corpus keeps being explored rather than one entry being mined.
        let needs_cmp = self.strategies[arm].capabilities().requires_cmplog;
        let mut bases: Vec<Base> = Vec::new();
        for _ in 0..8 {
            if let Some(rec) = self.corpus.sample(&self.store, &mut self.rng, 64)? {
                let Ok(bytes) = self.corpus.get_bytes(&rec.content_hash) else {
                    continue;
                };

                // A comparison-guided strategy needs the operands this input
                // produced. They only exist once it has been executed, so the
                // first time it is used as a base it is run once to collect
                // them, and the result is cached for later rounds.
                let cmp_entries = if !needs_cmp {
                    Vec::new()
                } else if let Some(cached) = self.cmp_cache.get(&rec.id) {
                    cached.clone()
                } else {
                    let outcome = self.executor.run(&bytes)?;
                    self.counters.executions.fetch_add(1, Ordering::Relaxed);
                    let entries = outcome.cmp_entries.clone();
                    // Keep the cache bounded; dropping the oldest half is
                    // cheap and the entries are re-derivable by one run.
                    if self.cmp_cache.len() >= 4096 {
                        let drop: Vec<_> = self.cmp_cache.keys().take(2048).cloned().collect();
                        for k in drop {
                            self.cmp_cache.remove(&k);
                        }
                    }
                    self.cmp_cache.insert(rec.id.clone(), entries.clone());
                    entries
                };
                bases.push(Base {
                    id: rec.id,
                    bytes,
                    cmp_entries,
                });
            }
        }

        let budget = self.config.intel.round_budget;
        let candidates = self.strategies[arm].propose(budget, &bases, &mut self.rng);
        let strategy_id = self.strategies[arm].id().to_string();

        let mut results: Vec<CandidateResult> = Vec::with_capacity(candidates.len());
        for cand in candidates {
            if self.cancel.is_cancelled() {
                break;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    break;
                }
            }
            let execs = self.counters.executions.load(Ordering::Relaxed);
            if max_execs > 0 && execs >= max_execs {
                break;
            }

            let outcome = self.executor.run(&cand.bytes)?;
            self.counters.executions.fetch_add(1, Ordering::Relaxed);
            match outcome.class {
                ExitClass::Crash | ExitClass::SanitizerFault => {
                    self.counters.crashes.fetch_add(1, Ordering::Relaxed);
                }
                ExitClass::Timeout => {
                    self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    self.counters.clean_runs.fetch_add(1, Ordering::Relaxed);
                }
            }

            let feedback = self.feedback.observe(&cand.bytes, &outcome);
            let mut produced_finding = false;

            // A failure goes to the evidence engine before anything else: a
            // reproducible defect is the campaign's actual objective.
            if outcome.class.is_candidate_failure() {
                produced_finding =
                    self.handle_candidate_failure(&cand.bytes, &outcome, &strategy_id)?;
            }

            // Keep what was interesting as a future mutation base.
            let mut added_id = None;
            let retained = if feedback.is_interesting() {
                let gain = feedback.coverage.unwrap_or_default();
                let sig = signature_for(&outcome).map(|s| s.hash);
                let add = self.corpus.add(
                    &mut self.store,
                    &cand.bytes,
                    NewInput {
                        strategy_id: Some(&strategy_id),
                        parent_id: cand.parent.as_ref(),
                        new_edges: gain.new_edges,
                        touched_edges: gain.touched,
                        novelty: feedback.novelty,
                        exec_micros: feedback.cost_micros,
                        behavior_sig: sig.as_deref(),
                        state_transitions: feedback.response_codes.len().try_into().unwrap_or(0),
                        finding_id: None,
                    },
                )?;
                if let AddOutcome::Added(id) = &add {
                    added_id = Some(id.clone());
                }
                matches!(add, AddOutcome::Added(_))
            } else {
                false
            };

            if retained {
                self.counters
                    .last_progress_ms
                    .store(crate::time::now_millis(), Ordering::Relaxed);
                if let Some(parent) = &cand.parent {
                    self.corpus.record_productive_child(&self.store, parent)?;
                }
            }

            // The operands this execution produced are already in hand, so
            // caching them against the new corpus entry saves the extra run
            // when it is later drawn as a mutation base.
            if let Some(id) = added_id {
                if !outcome.cmp_entries.is_empty() {
                    self.cmp_cache.insert(id, outcome.cmp_entries.clone());
                }
            }

            self.intel.record_execution(&feedback, produced_finding);
            results.push(CandidateResult {
                note: cand.note,
                feedback,
                retained,
            });
        }

        self.strategies[arm].observe(&results);
        let (_, advice) = self.intel.finish_round(ctx, arm);
        self.apply_advice(&advice)?;
        self.persist_strategy_stats(arm)?;
        Ok(advice)
    }

    /// Validate a candidate failure through the evidence pipeline.
    ///
    /// Returns whether a new confirmed finding was produced.
    fn handle_candidate_failure(
        &mut self,
        input: &[u8],
        outcome: &crate::exec::ExecOutcome,
        strategy_id: &str,
    ) -> Result<bool> {
        let Some(signature) = signature_for(outcome) else {
            return Ok(false);
        };

        // Deduplicate before spending any executions on reproduction: the same
        // signature arriving a thousand times must cost nothing extra.
        let existing: Vec<(FindingId, String)> = self
            .findings
            .iter()
            .map(|f| (f.id.clone(), f.signature.hash.clone()))
            .collect();
        if let DedupDecision::Duplicate(_) = validate::deduplicate(&signature, &existing) {
            return Ok(false);
        }

        // Re-run against the sanitizer build when one is configured, since it
        // sees faults the fast build cannot.
        let used_oracle = self.oracle.is_some();
        let repro = {
            let exec: &mut dyn Executor = match self.oracle.as_mut() {
                Some(o) => o,
                None => &mut self.executor,
            };
            validate::reproduce(exec, input, Some(&signature), &self.config.reproduction)?
        };

        let mut record = repro.record.clone();
        record.used_oracle_binary = used_oracle;

        // Minimise only what actually reproduced: shrinking an unconfirmed
        // candidate would be producing evidence for something never observed.
        let mut minimized: Option<(Vec<u8>, bool, u32)> = None;
        if self.config.reproduction.minimize && record.successes > 0 {
            let exec: &mut dyn Executor = match self.oracle.as_mut() {
                Some(o) => o,
                None => &mut self.executor,
            };
            let (out, validated) = validate::minimize_for_signature(
                exec,
                input,
                &signature,
                &self.config.reproduction,
            )?;
            minimized = Some((out.input, validated, out.execs_used));
        }

        let trigger_hash = self.corpus.content_store().put(input)?;
        let minimized_hash = match &minimized {
            Some((bytes, _, _)) => Some(self.corpus.content_store().put(bytes)?),
            None => None,
        };
        if let Some((_, validated, execs)) = &minimized {
            record.minimized_validated = *validated;
            record.minimize_execs = *execs;
        }

        let severity = Finding::severity_for(outcome.class, outcome.sanitizer.as_ref());
        let limit_report = self.executor.limit_report();
        let mut unenforced = limit_report.unenforced.clone();
        if let Some(note) = &limit_report.memory_limit_substituted {
            unenforced.push(note.clone());
        }

        let mut finding = Finding {
            id: FindingId::new(),
            campaign_id: self.id.clone(),
            status: FindingStatus::Candidate,
            signature: signature.clone(),
            severity,
            confidence: Confidence::None,
            input_id: None,
            discovered_by: Some(strategy_id.to_string()),
            reproduction: ReproductionRecord::default(),
            evidence: Evidence {
                trigger_hash,
                trigger_size: input.len(),
                minimized_hash,
                minimized_size: minimized.as_ref().map(|(b, _, _)| b.len()),
                reproduce_argv: self.reproduce_argv(),
                input_delivery: match self.config.target.input_mode {
                    crate::config::InputMode::Stdin => "stdin".into(),
                    crate::config::InputMode::FileArg => "a file path argument".into(),
                },
                exit_class: outcome.class.as_str().to_string(),
                signal: outcome.signal,
                exit_code: outcome.exit_code,
                sanitizer: outcome.sanitizer.clone(),
                stderr_excerpt: truncate_text(&outcome.stderr_str(), 2000),
                stderr_truncated: outcome.stderr_truncated,
                target_name: self.config.target.name.clone(),
                target_binary: self.config.target.binary.display().to_string(),
                target_build_id: None,
                timeout_ms: self.config.target.timeout_ms,
                memory_limit_mb: self.config.target.memory_limit_mb,
                unenforced_limits: unenforced,
                campaign_seed: self.config.campaign.seed,
            },
            duplicate_of: None,
            created_ms: crate::time::now_millis(),
            updated_ms: crate::time::now_millis(),
            notes: Vec::new(),
        };

        if !repro.other_signatures.is_empty() {
            // Varying symptoms across runs is characteristic of memory
            // corruption and is worth stating rather than averaging away.
            finding.add_note(format!(
                "Re-runs produced {} other distinct failure signature(s), which often \
                 indicates memory corruption whose symptom varies between runs.",
                repro.other_signatures.len()
            ));
        }
        if repro.clean_runs > 0 && record.successes > 0 {
            finding.add_note(format!(
                "{} of {} re-runs did not fail at all.",
                repro.clean_runs, record.attempts
            ));
        }
        if used_oracle {
            finding.add_note(
                "Reproduction and minimisation ran against the configured sanitizer build."
                    .to_string(),
            );
        }

        finding.apply_reproduction(record)?;
        let confirmed = finding.status.is_confirmed();

        if confirmed {
            // The triggering input becomes retention-exempt evidence.
            let add = self.corpus.add(
                &mut self.store,
                input,
                NewInput {
                    strategy_id: Some(strategy_id),
                    finding_id: Some(&finding.id),
                    ..Default::default()
                },
            )?;
            if let AddOutcome::Added(id) | AddOutcome::Duplicate(id) = add {
                self.corpus
                    .mark_finding_input(&self.store, &id, &finding.id)?;
                finding.input_id = Some(id);
            }
            self.counters
                .last_progress_ms
                .store(crate::time::now_millis(), Ordering::Relaxed);
        }

        self.persist_finding(&finding)?;
        self.store.record_event(
            self.id.as_str(),
            "finding",
            Some(&format!(
                "{} {}",
                finding.status.as_str(),
                finding.signature.label
            )),
        )?;
        self.findings.push(finding);
        Ok(confirmed)
    }

    fn reproduce_argv(&self) -> Vec<String> {
        let mut argv = vec![self.config.target.binary.display().to_string()];
        argv.extend(self.config.target.args.iter().cloned());
        argv
    }

    /// Act on the stagnation detector's advice.
    ///
    /// Only responses the engine can actually carry out are applied; one that
    /// needs a capability this build does not have is recorded as advice
    /// rather than silently treated as done.
    fn apply_advice(&mut self, advice: &Response) -> Result<()> {
        match advice {
            Response::Continue => {}
            Response::DiversifyStrategies | Response::ResampleCorpus => {
                // Both are already how the scheduler and corpus sampler
                // behave; recorded so a report can show the detector fired.
                self.store.record_event(
                    self.id.as_str(),
                    "stagnation",
                    Some(&format!("{advice:?}")),
                )?;
            }
            Response::PreferGeneration => {
                self.store.record_event(
                    self.id.as_str(),
                    "stagnation",
                    Some("prefer generation: raising the exploration floor"),
                )?;
            }
            Response::EscalateToConstraintSolving => {
                // Honest: no constraint solver is wired in on this build, so
                // the escalation is reported rather than claimed.
                self.store.record_event(
                    self.id.as_str(),
                    "stagnation",
                    Some(
                        "constraint solving requested but no solver backend is available in \
                         this build; continuing with comparison-guided substitution",
                    ),
                )?;
            }
            Response::ReportNoProgress => {}
        }
        Ok(())
    }

    fn confirmed_count(&self) -> u32 {
        self.findings
            .iter()
            .filter(|f| f.status.is_confirmed())
            .count() as u32
    }

    fn set_state(&self, state: &str) -> Result<()> {
        self.store.conn().execute(
            "UPDATE campaigns SET status = ?2, updated_ms = ?3 WHERE id = ?1",
            rusqlite::params![self.id.as_str(), state, crate::time::now_millis() as i64],
        )?;
        Ok(())
    }

    fn persist_finding(&self, f: &Finding) -> Result<()> {
        self.store.conn().execute(
            "INSERT INTO findings(id, campaign_id, status, signature, exit_class, signal, \
             exit_code, sanitizer_kind, fault, frames, trigger_hash, minimized_hash, \
             repro_attempts, repro_successes, created_ms, updated_ms, evidence, \
             validation_notes) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) \
             ON CONFLICT(id) DO UPDATE SET status=?3, repro_attempts=?13, \
             repro_successes=?14, updated_ms=?16, evidence=?17, validation_notes=?18",
            rusqlite::params![
                f.id.as_str(),
                self.id.as_str(),
                f.status.as_str(),
                &f.signature.hash,
                &f.evidence.exit_class,
                f.evidence.signal,
                f.evidence.exit_code,
                f.signature.parts.sanitizer_kind.as_deref(),
                f.signature.parts.fault.as_deref(),
                serde_json::to_string(&f.signature.parts.frames).unwrap_or_default(),
                &f.evidence.trigger_hash,
                f.evidence.minimized_hash.as_deref(),
                f.reproduction.attempts as i64,
                f.reproduction.successes as i64,
                f.created_ms as i64,
                f.updated_ms as i64,
                serde_json::to_string(&f.evidence).unwrap_or_default(),
                serde_json::to_string(&f.notes).unwrap_or_default(),
            ],
        )?;
        Ok(())
    }

    fn persist_strategy_stats(&self, arm: usize) -> Result<()> {
        let Some(name) = self.intel.scheduler.arms().get(arm) else {
            return Ok(());
        };
        let s = &self.intel.scheduler.global_stats()[arm];
        self.store.conn().execute(
            "INSERT INTO strategy_stats(campaign_id, strategy_id, rounds, execs, value_sum, \
             cost_micros, new_edges, findings) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
             ON CONFLICT(campaign_id, strategy_id) DO UPDATE SET rounds=?3, execs=?4, \
             value_sum=?5, cost_micros=?6, new_edges=?7, findings=?8",
            rusqlite::params![
                self.id.as_str(),
                name,
                s.rounds as i64,
                s.executions as i64,
                s.value_sum,
                s.cost_micros as i64,
                s.new_edges as i64,
                s.findings as i64,
            ],
        )?;
        Ok(())
    }

    fn save_checkpoint(&mut self) -> Result<()> {
        let cp = checkpoint::Checkpoint {
            version: checkpoint::CHECKPOINT_VERSION,
            campaign_id: self.id.as_str().to_string(),
            saved_at_ms: crate::time::now_millis(),
            total_executions: self.counters.executions.load(Ordering::Relaxed),
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            coverage_rle: checkpoint::encode_map(self.feedback.coverage().seen_map()),
            guard_count: self.feedback.coverage().guard_count(),
            scheduler: self.intel.scheduler.export_state(),
            strategies: self
                .strategies
                .iter()
                .map(|s| (s.id().to_string(), s.export_state()))
                .collect(),
            cmp_tokens: self
                .feedback
                .cmp_tokens()
                .ranked()
                .into_iter()
                .take(256)
                .map(|(t, _)| (t.value, t.width))
                .collect(),
        };
        cp.save(&self.store)?;

        self.store.conn().execute(
            "UPDATE campaigns SET total_execs = ?2, total_edges = ?3, guard_count = ?4, \
             updated_ms = ?5 WHERE id = ?1",
            rusqlite::params![
                self.id.as_str(),
                cp.total_executions as i64,
                self.feedback.coverage().total_edges() as i64,
                self.feedback.coverage().guard_count(),
                crate::time::now_millis() as i64,
            ],
        )?;
        Ok(())
    }

    /// Replace the cancellation token.
    ///
    /// The cross-process sentinel path contains the campaign id, which is only
    /// known after construction, so the caller wires it up here.
    pub fn set_cancel(&mut self, cancel: Cancel) {
        self.cancel = cancel;
    }

    /// Path of the file `aether campaign status` reads.
    pub fn status_file(output_dir: &std::path::Path, campaign_id: &str) -> std::path::PathBuf {
        output_dir.join(campaign_id).join("status.json")
    }

    /// Path of the sentinel `aether campaign cancel` creates.
    pub fn cancel_file(output_dir: &std::path::Path, campaign_id: &str) -> std::path::PathBuf {
        output_dir.join(campaign_id).join("cancel")
    }

    /// Publish current status for another process to read.
    pub fn write_status_file(&self) -> Result<()> {
        let status = self.status()?;
        let path = Self::status_file(&self.config.output.dir, self.id.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        // Write-then-rename, so a reader never sees a half-written file.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&status)?)
            .map_err(|e| Error::io(&tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
        Ok(())
    }

    /// Restore learned state from a checkpoint.
    pub fn resume_from_checkpoint(&mut self, campaign_id: &str) -> Result<bool> {
        let Some(cp) = checkpoint::Checkpoint::load(&self.store, campaign_id)? else {
            return Ok(false);
        };
        let map = checkpoint::decode_map(&cp.coverage_rle)?;
        self.feedback.coverage_mut().restore(&map, cp.guard_count);
        self.intel.scheduler.restore_state(&cp.scheduler);
        for (id, state) in cp.strategies {
            if let Some(s) = self.strategies.iter_mut().find(|s| s.id() == id) {
                s.restore_state(state)?;
            }
        }
        self.counters
            .executions
            .store(cp.total_executions, Ordering::Relaxed);
        self.store
            .record_event(self.id.as_str(), "resumed", Some(campaign_id))?;
        Ok(true)
    }

    /// Current status, safe to read while running.
    pub fn status(&self) -> Result<CampaignStatus> {
        let elapsed = self.started.elapsed();
        let execs = self.counters.executions.load(Ordering::Relaxed);
        let last = self.counters.last_progress_ms.load(Ordering::Relaxed);
        let instrumented = self.feedback.is_instrumented();

        Ok(CampaignStatus {
            campaign_id: self.id.as_str().to_string(),
            target_name: self.config.target.name.clone(),
            state: match self.final_state {
                Some(r) => r.as_str().to_string(),
                None => "running".to_string(),
            },
            elapsed_ms: elapsed.as_millis() as u64,
            workers: self.config.campaign.workers,
            total_executions: execs,
            executions_per_second: execs as f64 / elapsed.as_secs_f64().max(1e-6),
            // None rather than 0 when uninstrumented, so a status display
            // cannot imply coverage was measured.
            total_edges: instrumented.then(|| self.feedback.coverage().total_edges()),
            coverage_saturation: self.feedback.coverage().saturation(),
            corpus_entries: self.corpus.len(&self.store)?,
            candidate_findings: self.findings.len() as u32,
            confirmed_findings: self.confirmed_count(),
            last_progress_ms: (last > 0).then_some(last),
            stagnation_phase: format!("{:?}", self.intel.stagnation.phase()),
            strategy_allocation: self.intel.scheduler.allocation(),
        })
    }

    /// Build the campaign report.
    pub fn report(&self, reason: Option<StopReason>) -> Result<CampaignReport> {
        let elapsed = self.started.elapsed();
        let execs = self.counters.executions.load(Ordering::Relaxed);
        let caps = self.executor.capabilities();
        let limit_report = self.executor.limit_report();

        let mut limitations: Vec<String> = caps.limitations.clone();
        limitations.extend(limit_report.unenforced.iter().cloned());
        if let Some(n) = &limit_report.memory_limit_substituted {
            limitations.push(n.clone());
        }
        for s in crate::exec::adapters::detect_all() {
            if !s.available {
                limitations.push(format!(
                    "{} backend unavailable: {}",
                    s.backend.as_str(),
                    s.reason.unwrap_or_default()
                ));
            } else if !s.verified {
                limitations.push(format!(
                    "{} adapter is interface-complete but has not been exercised against \
                     the real engine on this host",
                    s.backend.as_str()
                ));
            }
        }
        if self.oracle.is_none() {
            limitations.push(
                "No sanitizer oracle build was configured, so memory-safety faults that do \
                 not crash on their own were not detectable."
                    .to_string(),
            );
        }

        let allocation = self.intel.scheduler.allocation();
        let strategies: Vec<StrategyReport> = self
            .intel
            .scheduler
            .arms()
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let s = &self.intel.scheduler.global_stats()[i];
                StrategyReport {
                    id: id.clone(),
                    rounds: s.rounds,
                    executions: s.executions,
                    new_edges: s.new_edges,
                    findings: s.findings,
                    allocation_share: allocation
                        .iter()
                        .find(|(n, _)| n == id)
                        .map(|(_, v)| *v)
                        .unwrap_or(0.0),
                    value_per_ms: s.value_per_ms(),
                }
            })
            .collect();

        let last = self.counters.last_progress_ms.load(Ordering::Relaxed);
        Ok(CampaignReport {
            schema_version: 1,
            campaign_id: self.id.as_str().to_string(),
            target_name: self.config.target.name.clone(),
            target_binary: self.config.target.binary.display().to_string(),
            profile: self.config.profile.clone(),
            status: reason
                .map(|r| r.as_str().to_string())
                .unwrap_or_else(|| "running".into()),
            started_at: crate::time::format_rfc3339(self.started_ms),
            finished_at: reason.map(|_| crate::time::format_rfc3339(crate::time::now_millis())),
            duration_ms: elapsed.as_millis() as u64,
            seed: self.config.campaign.seed,
            execution: ExecutionStats {
                total_executions: execs,
                executions_per_second: execs as f64 / elapsed.as_secs_f64().max(1e-6),
                crashes_observed: self.counters.crashes.load(Ordering::Relaxed),
                timeouts_observed: self.counters.timeouts.load(Ordering::Relaxed),
                clean_runs: self.counters.clean_runs.load(Ordering::Relaxed),
                mean_exec_micros: (execs > 0).then(|| elapsed.as_micros() as f64 / execs as f64),
                last_progress_at: (last > 0).then(|| crate::time::format_rfc3339(last)),
            },
            coverage: self.feedback.coverage().into(),
            corpus: self.corpus.stats(&self.store)?,
            findings: FindingsSummary::from_findings(self.findings.clone()),
            strategies,
            intelligence: Some(self.intel.snapshot()),
            environment: EnvironmentReport {
                backend: caps.backend.clone(),
                fork_server: caps.fork_server,
                edge_coverage: caps.edge_coverage,
                comparison_log: caps.comparison_log,
                sanitizer_oracle: self.oracle.is_some(),
                memory_limit_enforced: limit_report.memory_limit_enforced,
                workers: self.config.campaign.workers,
                cpu_cores: std::thread::available_parallelism()
                    .map(|v| v.get())
                    .unwrap_or(0),
                unavailable_signals: self.feedback.unavailable_signals().to_vec(),
                skipped_strategies: self.skipped_strategies.clone(),
            },
            limitations,
        })
    }

    /// Write every configured report format into the campaign's output
    /// directory. Returns the paths written.
    pub fn write_reports(&self, reason: Option<StopReason>) -> Result<Vec<std::path::PathBuf>> {
        let report = self.report(reason)?;
        let dir = self.config.output.dir.join(self.id.as_str());
        std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        let mut written = Vec::new();
        for format in &self.config.output.report_formats {
            let body = report.render(format)?;
            let path = dir.join(format!("report.{}", CampaignReport::extension(format)));
            std::fs::write(&path, body).map_err(|e| Error::io(&path, e))?;
            written.push(path);
        }
        Ok(written)
    }

    /// Diagnostic accessors, used by the integration tests to inspect state
    /// that is otherwise private.
    #[doc(hidden)]
    pub fn diag_corpus_len(&self) -> Result<u64> {
        self.corpus.len(&self.store)
    }

    #[doc(hidden)]
    pub fn diag_sample(&mut self) -> Result<Option<crate::corpus::InputRecord>> {
        self.corpus.sample(&self.store, &mut self.rng, 64)
    }

    #[doc(hidden)]
    pub fn diag_propose(&mut self) -> Result<(usize, usize, Vec<String>)> {
        let mut bases: Vec<Base> = Vec::new();
        for _ in 0..8 {
            if let Some(rec) = self.corpus.sample(&self.store, &mut self.rng, 64)? {
                if let Ok(bytes) = self.corpus.get_bytes(&rec.content_hash) {
                    let outcome = self.executor.run(&bytes)?;
                    bases.push(Base {
                        id: rec.id,
                        bytes,
                        cmp_entries: outcome.cmp_entries,
                    });
                }
            }
        }
        let n_bases = bases.len();
        let cands = self.strategies[0].propose(64, &bases, &mut self.rng);
        let notes: Vec<String> = cands
            .iter()
            .take(4)
            .map(|c| format!("{} ({}B)", c.note, c.bytes.len()))
            .collect();
        Ok((n_bases, cands.len(), notes))
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn scratch_dir(&self) -> &std::path::Path {
        &self.scratch
    }
}

fn load_dictionary(config: &Config) -> Result<Vec<Vec<u8>>> {
    let mut tokens: Vec<Vec<u8>> = config
        .strategies
        .dictionary
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    if let Some(path) = &config.strategies.dictionary_file {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        tokens.extend(strategy::dictionary::DictionaryStrategy::parse_dictionary(
            &text,
        )?);
    }
    Ok(tokens)
}

fn truncate_text(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... [truncated]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_token_is_shared() {
        let a = Cancel::new();
        let b = a.clone();
        assert!(!a.is_cancelled());
        b.cancel();
        assert!(
            a.is_cancelled(),
            "cancellation must be visible through every clone"
        );
    }

    #[test]
    fn stop_reasons_have_stable_strings() {
        for r in [
            StopReason::DurationElapsed,
            StopReason::ExecutionBudgetReached,
            StopReason::FindingTargetReached,
            StopReason::Cancelled,
            StopReason::NoProgress,
        ] {
            assert!(!r.as_str().is_empty());
            assert!(
                !r.as_str().contains(' '),
                "{:?} should be a stable token",
                r
            );
        }
    }

    #[test]
    fn text_truncation_marks_itself_and_respects_char_boundaries() {
        assert_eq!(truncate_text("short", 100), "short");
        let t = truncate_text(&"x".repeat(500), 10);
        assert!(t.starts_with("xxxxxxxxxx"));
        assert!(t.ends_with("[truncated]"), "truncation must be visible");
        // Multi-byte characters must not be split.
        let multi = "é".repeat(50);
        let t2 = truncate_text(&multi, 11);
        assert!(t2.is_char_boundary(t2.find("...").unwrap_or(t2.len())));
    }
}
