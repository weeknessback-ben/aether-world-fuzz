//! Multi-worker campaign execution.
//!
//! The abstraction lives in [`super::worker`]; this is the loop that actually
//! runs. Each worker is an OS thread with its own executor, its own coverage
//! region, its own scratch directory, its own strategy instances and its own
//! RNG stream derived from `(campaign_seed, worker_index)` - so adding a
//! worker does not perturb the streams the existing workers draw from.
//!
//! # Why coverage is two-tiered
//!
//! Novelty has to be judged campaign-wide. If each worker judged it against
//! its own map alone, four workers would each "discover" the same edge and the
//! corpus would fill with four equivalent inputs. But taking a global lock on
//! every execution would serialise a loop that runs thousands of times a
//! second per worker, and the lock would cost more than the parallelism it
//! protects.
//!
//! So each worker checks its **own** coverage map first - the one inside its
//! [`FeedbackEngine`], with no lock. Only a locally-interesting run, a small
//! fraction of executions, takes the shared lock to confirm against the global
//! map. Workers merge the global map back into their local one whenever
//! another worker has found something, so a worker stops re-proposing what is
//! already found.
//!
//! The cost of that design is measured rather than hidden: a run novel locally
//! but not globally still pays one lock acquisition, and two workers can
//! briefly both believe they found the same edge. Neither affects correctness -
//! the global check is authoritative - and [`ParallelStats::redundant_discoveries`]
//! counts how often it happens.
//!
//! # What the controller keeps
//!
//! Workers do not validate failures. Reproduction re-runs an input several
//! times; doing that inside a worker would stall its loop, and two workers
//! hitting the same defect would validate it twice. Workers report candidate
//! failures and the controller puts them through the evidence pipeline once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::corpus::{AddOutcome, Corpus, NewInput};
use crate::error::{Error, Result};
use crate::evidence::signature::signature_for;
use crate::exec::native::{NativeExecutor, TargetSpec};
use crate::exec::sanitizer::SanitizerReport;
use crate::exec::shm::CmpEntry;
use crate::exec::{Executor, ExitClass};
use crate::feedback::coverage::{CoverageGain, CoverageTracker};
use crate::feedback::FeedbackEngine;
use crate::ids::InputId;
use crate::intel::{bandit::ArmStats, Intelligence};
use crate::persist::Store;
use crate::rng::Rng;
use crate::strategy::{self, Base, CandidateResult};

pub use super::worker::SharedState;
use super::{Cancel, LiveCounters};

/// State every worker shares, behind one lock.
///
/// Deliberately coarse. A lock per component would invite deadlock between
/// workers taking them in different orders, and the critical section is short:
/// a coverage check and at most one corpus insert.
pub struct Shared {
    pub store: Store,
    pub corpus: Corpus,
    /// Campaign-wide coverage: the authority on what counts as novel.
    pub coverage: CoverageTracker,
    /// Bumped on every global discovery, so a worker can tell its local map is
    /// stale without comparing 64 KiB.
    pub generation: u64,
    /// Per-arm round statistics summed across every worker, and the best
    /// value-per-millisecond any of them has seen.
    ///
    /// Shared because a worker scheduling on its own slice of the rounds
    /// cannot tell a much-better strategy from an average one. There is one
    /// round outcome per round, not per execution, so publishing it costs
    /// roughly one lock acquisition per sixty executions.
    pub arm_totals: Vec<ArmStats>,
    pub value_scale: f64,
}

/// How the pool actually ran, so a scaling claim can be checked instead of
/// assumed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParallelStats {
    pub workers: u32,
    pub executions: u64,
    /// Runs a worker judged interesting that the global map had already seen.
    /// A direct measure of what the two-tier design costs.
    pub redundant_discoveries: u64,
    /// Runs confirmed novel against the global map.
    pub confirmed_discoveries: u64,
    /// Microseconds spent waiting for the shared lock, summed over workers.
    pub lock_wait_micros: u64,
    /// Per-worker execution counts, for spotting an unbalanced pool.
    pub per_worker_executions: Vec<u64>,
    /// Edges each worker's own map reached. Compared against the campaign-wide
    /// total this says whether a worker explored ground the shared map never
    /// recorded - which would mean coverage is being under-reported rather
    /// than merely found redundantly.
    pub per_worker_local_edges: Vec<u32>,
    /// Workers that stopped early, with the reason. Never silently dropped.
    pub worker_failures: Vec<(u32, String)>,
    /// Per-strategy statistics summed across workers. Each worker runs its own
    /// scheduler, so these are real campaign-wide totals rather than one
    /// worker's view - and reporting them is what stops a pooled campaign
    /// listing every strategy at zero executions.
    pub strategy_stats: Vec<(String, ArmStats)>,
}

impl ParallelStats {
    /// Share of discoveries that turned out to be redundant.
    pub fn redundancy_rate(&self) -> f64 {
        let total = self.redundant_discoveries + self.confirmed_discoveries;
        if total == 0 {
            0.0
        } else {
            self.redundant_discoveries as f64 / total as f64
        }
    }

    /// Lock wait as a fraction of total worker time.
    pub fn lock_overhead(&self, wall_clock: Duration) -> f64 {
        let worker_micros = wall_clock.as_micros() as f64 * f64::from(self.workers.max(1));
        if worker_micros <= 0.0 {
            0.0
        } else {
            self.lock_wait_micros as f64 / worker_micros
        }
    }

    /// Imbalance between the busiest and least busy worker, in `[0, 1]`. Near
    /// zero is a well-balanced pool; near one means one worker did nearly all
    /// the work.
    pub fn imbalance(&self) -> f64 {
        if self.per_worker_executions.len() < 2 {
            return 0.0;
        }
        let max = *self.per_worker_executions.iter().max().unwrap_or(&0) as f64;
        let min = *self.per_worker_executions.iter().min().unwrap_or(&0) as f64;
        if max <= 0.0 {
            0.0
        } else {
            (max - min) / max
        }
    }
}

/// A failure a worker observed, for the controller to validate.
pub struct CandidateFailure {
    pub input: Vec<u8>,
    pub strategy: String,
    pub class: ExitClass,
    pub signal: Option<i32>,
    pub exit_code: Option<i32>,
    pub sanitizer: Option<SanitizerReport>,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub duration: Duration,
}

impl CandidateFailure {
    /// Rebuild the outcome the worker saw, so the evidence engine classifies
    /// the failure from what was actually observed rather than from a re-run
    /// that may behave differently.
    ///
    /// Coverage and comparison operands are deliberately absent: they are not
    /// carried across threads (a 64 KiB map per candidate, for a signature
    /// that does not use it), and `None` says "not carried" rather than
    /// implying an uninstrumented target produced it.
    pub fn as_outcome(&self) -> crate::exec::ExecOutcome {
        crate::exec::ExecOutcome {
            class: self.class,
            exit_code: self.exit_code,
            signal: self.signal,
            duration: self.duration,
            stdout: Vec::new(),
            stderr: self.stderr.clone(),
            stdout_truncated: false,
            stderr_truncated: self.stderr_truncated,
            sanitizer: self.sanitizer.clone(),
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }
}

/// What one worker reports back.
struct WorkerReport {
    worker: u32,
    executions: u64,
    redundant: u64,
    confirmed: u64,
    local_edges: u32,
    strategy_stats: Vec<(String, ArmStats)>,
    candidates: Vec<CandidateFailure>,
    error: Option<String>,
}

/// At most this many candidate failures per worker. A target that crashes on
/// nearly every input would otherwise fill memory with inputs the controller
/// will deduplicate down to one finding anyway.
const MAX_CANDIDATES_PER_WORKER: usize = 64;

/// Run a campaign across `config.campaign.workers` threads.
///
/// Returns the aggregate statistics and the candidate failures found. The
/// controller owns validation, so a defect found by three workers is validated
/// once.
/// How often the controller's `tick` runs while the pool is working.
const TICK_INTERVAL: Duration = Duration::from_millis(250);

#[allow(clippy::too_many_arguments)]
pub fn run_workers(
    config: &Config,
    shared: SharedState<Shared>,
    counters: Arc<LiveCounters>,
    cancel: Cancel,
    scratch_root: &std::path::Path,
    deadline: Option<Instant>,
    max_execs: u64,
    // Called while the pool runs, so the controller can refresh the campaign
    // status file. Without it a client polling a pooled campaign would see
    // nothing change until the pool stopped.
    mut tick: impl FnMut(),
) -> Result<(ParallelStats, Vec<CandidateFailure>)> {
    let workers = config.campaign.workers.max(1);
    let lock_before = shared.contention_micros();
    // Set when any worker hits an unrecoverable executor error, so the others
    // stop promptly instead of running out the clock against a broken target.
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(workers as usize);
    for index in 0..workers {
        let config = config.clone();
        let shared = shared.clone();
        let counters = counters.clone();
        let cancel = cancel.clone();
        let stop = stop.clone();
        let scratch = scratch_root.join(format!("worker-{index}"));

        let handle = std::thread::Builder::new()
            .name(format!("aether-worker-{index}"))
            .spawn(move || {
                worker_loop(
                    index, &config, shared, counters, cancel, stop, &scratch, deadline, max_execs,
                )
            })
            .map_err(|e| Error::exec("worker", format!("could not spawn worker {index}: {e}")))?;
        handles.push(handle);
    }

    let mut stats = ParallelStats {
        workers,
        ..Default::default()
    };
    let mut candidates = Vec::new();

    // Wait by polling rather than joining straight away, so the controller
    // keeps reporting progress and a cancellation is seen promptly.
    while handles.iter().any(|h| !h.is_finished()) {
        tick();
        std::thread::sleep(TICK_INTERVAL);
    }

    for (i, h) in handles.into_iter().enumerate() {
        match h.join() {
            Ok(report) => {
                stats.executions += report.executions;
                stats.redundant_discoveries += report.redundant;
                stats.confirmed_discoveries += report.confirmed;
                stats.per_worker_executions.push(report.executions);
                stats.per_worker_local_edges.push(report.local_edges);
                for (id, arm) in &report.strategy_stats {
                    match stats.strategy_stats.iter_mut().find(|(n, _)| n == id) {
                        Some((_, acc)) => acc.absorb(arm),
                        None => stats.strategy_stats.push((id.clone(), arm.clone())),
                    }
                }
                if let Some(e) = report.error {
                    stats.worker_failures.push((report.worker, e));
                }
                candidates.extend(report.candidates);
            }
            Err(_) => {
                // A panicked worker must not take the campaign down: the other
                // workers' executions are still valid, and the failure is
                // reported rather than swallowed.
                stats.worker_failures.push((
                    i as u32,
                    "worker thread panicked; its executions are not counted".to_string(),
                ));
                stats.per_worker_executions.push(0);
                stats.per_worker_local_edges.push(0);
            }
        }
    }
    stats.lock_wait_micros = shared.contention_micros().saturating_sub(lock_before);
    Ok((stats, candidates))
}

/// Everything a worker needs that can fail to build, so a worker which cannot
/// start reports why instead of silently contributing nothing.
struct WorkerParts {
    executor: NativeExecutor,
    strategies: Vec<Box<dyn strategy::Strategy>>,
    feedback: FeedbackEngine,
}

fn build_worker(index: u32, config: &Config, scratch: &std::path::Path) -> Result<WorkerParts> {
    let spec = TargetSpec::from_config(&config.target, &config.scope, config.output.max_log_bytes)?;
    let executor = NativeExecutor::new(spec, scratch)?;
    let caps = executor.capabilities().clone();

    let dictionary: Vec<Vec<u8>> = config
        .strategies
        .dictionary
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    let grammar = match &config.strategies.grammar_file {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| Error::io(p, e))?),
        None => None,
    };
    let ctx = strategy::StrategyContext {
        // Each worker draws from its own derived stream, so the pool replays
        // under a fixed seed and adding a worker leaves the others' streams
        // untouched.
        seed: Rng::derive(config.campaign.seed, "worker", u64::from(index)).next_u64(),
        max_input_bytes: config.max_input_bytes(),
        dictionary: &dictionary,
        grammar_text: grammar.as_deref(),
        params: &config.strategies.params,
        coverage_available: caps.edge_coverage,
        cmplog_available: caps.comparison_log,
    };
    let (strategies, _skipped) = strategy::build_all(&config.strategies.enabled, &ctx)?;
    let feedback = FeedbackEngine::new(
        &config.feedback.providers,
        &config.feedback.weights,
        Vec::new(),
        caps.edge_coverage,
    )?;
    Ok(WorkerParts {
        executor,
        strategies,
        feedback,
    })
}

#[allow(clippy::too_many_arguments)]
fn worker_loop(
    index: u32,
    config: &Config,
    shared: SharedState<Shared>,
    counters: Arc<LiveCounters>,
    cancel: Cancel,
    stop: Arc<AtomicBool>,
    scratch: &std::path::Path,
    deadline: Option<Instant>,
    max_execs: u64,
) -> WorkerReport {
    let mut report = WorkerReport {
        worker: index,
        executions: 0,
        redundant: 0,
        confirmed: 0,
        local_edges: 0,
        strategy_stats: Vec::new(),
        candidates: Vec::new(),
        error: None,
    };

    let WorkerParts {
        mut executor,
        mut strategies,
        mut feedback,
    } = match build_worker(index, config, scratch) {
        Ok(p) => p,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };

    let mut intel = Intelligence::new(
        &config.intel,
        strategies.iter().map(|s| s.id().to_string()).collect(),
    );
    let mut rng = Rng::derive(config.campaign.seed, "worker-rng", u64::from(index));
    if let Some(g) = executor.shm_guard_count() {
        if g > 0 {
            feedback.coverage_mut().set_guard_count(g);
        }
    }
    let mut local_generation = 0u64;
    let mut cmp_cache: HashMap<InputId, Vec<CmpEntry>> = HashMap::new();
    // What this worker has already contributed to the pool's totals, so each
    // round publishes a delta rather than its whole history.
    let mut published: Vec<ArmStats> = vec![ArmStats::default(); strategies.len()];

    let should_stop = |report: &WorkerReport| {
        let _ = report;
        cancel.is_cancelled()
            || stop.load(Ordering::Relaxed)
            || deadline.is_some_and(|d| Instant::now() >= d)
            || (max_execs > 0 && counters.executions.load(Ordering::Relaxed) >= max_execs)
    };

    'rounds: loop {
        if should_stop(&report) {
            break;
        }

        // One lock per round for the campaign-wide view, then release it
        // before doing any work with it.
        let (corpus_size, saturation, generation) = shared.with(|s| {
            (
                s.corpus.len(&s.store).unwrap_or(0),
                s.coverage.saturation(),
                s.generation,
            )
        });

        // Refresh the local map when another worker has discovered something,
        // so this worker stops re-proposing what is already found.
        if generation != local_generation {
            shared.with(|s| {
                feedback.coverage_mut().merge(&s.coverage);
            });
            local_generation = generation;
        }

        let ctx = intel.context(corpus_size, saturation);
        let arm = intel.scheduler.select(ctx, &mut rng);
        let needs_cmp = strategies[arm].capabilities().requires_cmplog;

        // Draw mutation bases under the lock; execute outside it.
        let drawn = shared.with(|s| {
            let mut out = Vec::new();
            for _ in 0..8 {
                match s.corpus.sample(&s.store, &mut rng, 64) {
                    Ok(Some(rec)) => match s.corpus.get_bytes(&rec.content_hash) {
                        Ok(bytes) => out.push((rec.id, bytes)),
                        Err(_) => continue,
                    },
                    _ => break,
                }
            }
            out
        });
        if drawn.is_empty() {
            // Nothing to mutate yet. Yield rather than spin: another worker is
            // still seeding the corpus.
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }

        let mut bases: Vec<Base> = Vec::with_capacity(drawn.len());
        for (id, bytes) in drawn {
            // A comparison-guided strategy needs the operands an input
            // produced, which only exist once it has run. Collect them on
            // first use and cache them.
            let cmp_entries = if !needs_cmp {
                Vec::new()
            } else if let Some(cached) = cmp_cache.get(&id) {
                cached.clone()
            } else {
                match executor.run(&bytes) {
                    Ok(o) => {
                        report.executions += 1;
                        counters.executions.fetch_add(1, Ordering::Relaxed);
                        if cmp_cache.len() >= 2048 {
                            cmp_cache.clear();
                        }
                        cmp_cache.insert(id.clone(), o.cmp_entries.clone());
                        o.cmp_entries
                    }
                    Err(e) => {
                        report.error = Some(e.to_string());
                        stop.store(true, Ordering::Relaxed);
                        break 'rounds;
                    }
                }
            };
            bases.push(Base {
                id,
                bytes,
                cmp_entries,
            });
        }

        let candidates = strategies[arm].propose(config.intel.round_budget, &bases, &mut rng);
        let strategy_id = strategies[arm].id().to_string();
        let mut results: Vec<CandidateResult> = Vec::with_capacity(candidates.len());

        for cand in candidates {
            if should_stop(&report) {
                break;
            }

            let outcome = match executor.run(&cand.bytes) {
                Ok(o) => o,
                Err(e) => {
                    report.error = Some(e.to_string());
                    stop.store(true, Ordering::Relaxed);
                    break 'rounds;
                }
            };
            report.executions += 1;
            counters.executions.fetch_add(1, Ordering::Relaxed);
            match outcome.class {
                ExitClass::Crash | ExitClass::SanitizerFault => {
                    counters.crashes.fetch_add(1, Ordering::Relaxed);
                }
                ExitClass::Timeout => {
                    counters.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    counters.clean_runs.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Local judgement first: the common path takes no lock.
            let fb = feedback.observe(&cand.bytes, &outcome);
            let mut retained = false;

            if fb.is_interesting() {
                // Coverage novelty is confirmed against the campaign-wide map,
                // which is the authority: without that, four workers would
                // each "discover" the same edge.
                let (coverage_novel, gain) = shared.with(|s| match outcome.coverage.as_ref() {
                    Some(map) => {
                        let gain = s.coverage.observe(map);
                        if gain.is_novel() {
                            s.generation += 1;
                        }
                        (gain.is_novel(), gain)
                    }
                    None => (false, CoverageGain::default()),
                });

                // Semantic novelty is a worker-local judgement, and it counts
                // on its own. Each worker's providers carry their own state,
                // and - the reason this matters - an input that reaches a new
                // comparison constant is worth keeping even when every edge it
                // touched is already known. That is precisely how the
                // comparison-guided ladder is built: a new constant is
                // observed first, and the edge behind it is only reached once
                // that input has been mutated. Gating retention on coverage
                // alone starves the ladder; measured on `crash_magic`, doing
                // so held a worker at 6 edges where the sequential loop
                // reached 12.
                let semantic_novel = fb.novelty > 0.0 || fb.invariant_violated.is_some();

                if coverage_novel || semantic_novel {
                    if coverage_novel {
                        report.confirmed += 1;
                    }
                    let sig = signature_for(&outcome).map(|s| s.hash);
                    let added = shared.with(|s| {
                        let add = s.corpus.add(
                            &mut s.store,
                            &cand.bytes,
                            NewInput {
                                strategy_id: Some(&strategy_id),
                                parent_id: cand.parent.as_ref(),
                                new_edges: gain.new_edges,
                                touched_edges: gain.touched,
                                novelty: fb.novelty,
                                exec_micros: fb.cost_micros,
                                behavior_sig: sig.as_deref(),
                                state_transitions: fb.response_codes.len().try_into().unwrap_or(0),
                                finding_id: None,
                            },
                        );
                        match add {
                            Ok(AddOutcome::Added(id)) => {
                                // Credit the parent for a productive child, so
                                // corpus scoring favours bases that pay off -
                                // the same signal the sequential loop records.
                                if let Some(parent) = &cand.parent {
                                    let _ = s.corpus.record_productive_child(&s.store, parent);
                                }
                                Some(id)
                            }
                            _ => None,
                        }
                    });
                    if let Some(id) = added {
                        retained = true;
                        // The operands this run produced are already in hand,
                        // so caching them against the new entry saves the
                        // extra execution when it is later drawn as a base.
                        if !outcome.cmp_entries.is_empty() {
                            if cmp_cache.len() >= 2048 {
                                cmp_cache.clear();
                            }
                            cmp_cache.insert(id, outcome.cmp_entries.clone());
                        }
                        counters
                            .last_progress_ms
                            .store(crate::time::now_millis(), Ordering::Relaxed);
                    }
                } else {
                    // Locally novel coverage that the shared map already held:
                    // another worker got there first. Counted, so the cost of
                    // the two-tier design is visible rather than invisible.
                    report.redundant += 1;
                }
            }

            // Failures go to the controller. Validating here would stall this
            // worker's loop and duplicate work across workers.
            let is_failure = outcome.class.is_candidate_failure();
            if is_failure && report.candidates.len() < MAX_CANDIDATES_PER_WORKER {
                report.candidates.push(CandidateFailure {
                    input: cand.bytes.clone(),
                    strategy: strategy_id.clone(),
                    class: outcome.class,
                    signal: outcome.signal,
                    exit_code: outcome.exit_code,
                    sanitizer: outcome.sanitizer.clone(),
                    stderr: outcome.stderr.clone(),
                    stderr_truncated: outcome.stderr_truncated,
                    duration: outcome.duration,
                });
            }

            // A candidate failure is the campaign's objective, so the
            // scheduler is told about it here even though validation happens
            // in the controller.
            intel.record_execution(&fb, is_failure);
            results.push(CandidateResult {
                note: cand.note,
                feedback: fb,
                retained,
            });
        }

        strategies[arm].observe(&results);
        intel.finish_round(ctx, arm);

        // Publish this round into the pool and take the pool's view back, so
        // every worker schedules on all the workers' evidence rather than on
        // its own slice of it. One lock per round.
        let (totals, scale) = shared.with(|s| {
            for (i, own) in intel.scheduler.global_totals().iter().enumerate() {
                if let Some(slot) = s.arm_totals.get_mut(i) {
                    // `own` is cumulative, and `published` records what this
                    // worker has already contributed, so only the delta is
                    // added.
                    let delta_rounds = own.rounds.saturating_sub(published[i].rounds);
                    if delta_rounds == 0 {
                        continue;
                    }
                    slot.absorb(&ArmStats {
                        rounds: delta_rounds,
                        executions: own.executions.saturating_sub(published[i].executions),
                        productive_rounds: own
                            .productive_rounds
                            .saturating_sub(published[i].productive_rounds),
                        value_sum: (own.value_sum - published[i].value_sum).max(0.0),
                        cost_micros: own.cost_micros.saturating_sub(published[i].cost_micros),
                        new_edges: own.new_edges.saturating_sub(published[i].new_edges),
                        findings: own.findings.saturating_sub(published[i].findings),
                    });
                }
            }
            let scale = intel.scheduler.value_scale();
            if scale > s.value_scale {
                s.value_scale = scale;
            }
            (s.arm_totals.clone(), s.value_scale)
        });
        published = intel.scheduler.global_totals().to_vec();
        intel.scheduler.absorb_pool_totals(&totals, scale);
    }

    report.local_edges = feedback.coverage().total_edges();
    report.strategy_stats = intel
        .scheduler
        .arms()
        .iter()
        .cloned()
        .zip(intel.scheduler.global_stats().iter().cloned())
        .collect();
    report
}

/// Scaling efficiency: throughput per worker relative to a single worker.
///
/// Reported rather than assumed. Workers contend for the shared corpus lock,
/// for memory bandwidth and - on a small host - for cores with the controller
/// itself, so this is well under 1.0 in practice.
pub fn scaling_efficiency(single_worker_eps: f64, n_worker_eps: f64, workers: u32) -> f64 {
    if single_worker_eps <= 0.0 || workers == 0 {
        return 0.0;
    }
    (n_worker_eps / single_worker_eps) / f64::from(workers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redundancy_rate_is_a_fraction_of_discoveries() {
        let mut s = ParallelStats::default();
        assert_eq!(s.redundancy_rate(), 0.0, "no discoveries means no rate");
        s.confirmed_discoveries = 75;
        s.redundant_discoveries = 25;
        assert_eq!(s.redundancy_rate(), 0.25);
    }

    #[test]
    fn imbalance_detects_an_uneven_pool() {
        let balanced = ParallelStats {
            per_worker_executions: vec![1000, 1010, 995, 1005],
            ..Default::default()
        };
        assert!(balanced.imbalance() < 0.05, "got {}", balanced.imbalance());

        let uneven = ParallelStats {
            per_worker_executions: vec![4000, 10, 20, 15],
            ..Default::default()
        };
        assert!(uneven.imbalance() > 0.9, "got {}", uneven.imbalance());

        // A single worker cannot be unbalanced, and neither can none.
        let single = ParallelStats {
            per_worker_executions: vec![500],
            ..Default::default()
        };
        assert_eq!(single.imbalance(), 0.0);
        assert_eq!(ParallelStats::default().imbalance(), 0.0);
    }

    #[test]
    fn lock_overhead_is_relative_to_total_worker_time() {
        let s = ParallelStats {
            workers: 4,
            // One second of waiting across four workers each running for one
            // second is a quarter of the total worker time.
            lock_wait_micros: 1_000_000,
            ..Default::default()
        };
        let o = s.lock_overhead(Duration::from_secs(1));
        assert!((o - 0.25).abs() < 1e-9, "got {o}");
        assert_eq!(
            s.lock_overhead(Duration::ZERO),
            0.0,
            "must not divide by zero"
        );
    }

    #[test]
    fn scaling_efficiency_reports_what_was_measured() {
        // Perfect scaling is 1.0; anything less is the honest number.
        assert_eq!(scaling_efficiency(1000.0, 4000.0, 4), 1.0);
        assert_eq!(scaling_efficiency(1000.0, 2000.0, 4), 0.5);
        assert_eq!(scaling_efficiency(1000.0, 1000.0, 4), 0.25);
        // Degenerate inputs must not produce a misleading number.
        assert_eq!(scaling_efficiency(0.0, 4000.0, 4), 0.0);
        assert_eq!(scaling_efficiency(1000.0, 4000.0, 0), 0.0);
    }

    #[test]
    fn worker_failures_are_recorded_not_swallowed() {
        let s = ParallelStats {
            workers: 2,
            worker_failures: vec![(1, "target binary vanished".into())],
            ..Default::default()
        };
        assert_eq!(s.worker_failures.len(), 1);
        assert_eq!(s.worker_failures[0].0, 1);
    }
}
