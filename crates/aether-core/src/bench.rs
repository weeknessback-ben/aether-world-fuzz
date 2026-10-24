//! Benchmark experiments.
//!
//! Each experiment runs the same target under two or more configurations that
//! differ in exactly one thing, repeats each configuration several times, and
//! reports the distribution rather than a single number. The rules are the
//! same throughout:
//!
//! * **Equal budgets.** Configurations differ in the variable under test and
//!   nothing else. A comparison between runs of different lengths is not a
//!   comparison.
//! * **Several trials.** A fuzzing campaign is stochastic, so one run is an
//!   anecdote. Minimum, median and maximum are reported, not just a mean.
//! * **Fixed, recorded seeds.** Each trial's seed is derived from the
//!   experiment and trial index, so the whole experiment replays.
//! * **Incompatible configurations are skipped explicitly**, with the reason,
//!   rather than silently falling back to something else and being compared as
//!   though it were the thing asked for.
//!
//! Where an experiment cannot be run at all on this build, it says so rather
//! than reporting a substitute.

use serde::{Deserialize, Serialize};

use crate::config::{Config, Instrumentation, SchedulerKind};
use crate::error::{Error, Result};
use crate::runtime::{Campaign, Cancel};

/// Catalogue of experiments, matching the specification's A through G.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub implemented: bool,
    pub unimplemented_reason: &'static str,
}

pub const EXPERIMENTS: &[ExperimentInfo] = &[
    ExperimentInfo {
        id: "a",
        title: "Black-box execution versus coverage-guided exploration",
        description: "Same target, same budget, with and without instrumentation feedback. \
                      Measures what coverage guidance is worth.",
        implemented: true,
        unimplemented_reason: "",
    },
    ExperimentInfo {
        id: "b",
        title: "Static allocation versus adaptive scheduling",
        description: "Equal fixed strategy shares against Thompson Sampling over measured \
                      value per unit of compute.",
        implemented: true,
        unimplemented_reason: "",
    },
    ExperimentInfo {
        id: "c",
        title: "Mutation only versus hybrid mutation and generation",
        description: "Byte-level mutation against a mix that includes structure-aware \
                      mutation and dictionary insertion.",
        implemented: true,
        unimplemented_reason: "",
    },
    ExperimentInfo {
        id: "d",
        title: "Coverage-only feedback versus coverage plus semantic signals",
        description: "Edge coverage alone against coverage with exit-class and \
                      response-transition novelty.",
        implemented: true,
        unimplemented_reason: "",
    },
    ExperimentInfo {
        id: "e",
        title: "Blind exploration versus comparison-guided substitution",
        description: "The constraint-assistance comparison AETHER can actually make: \
                      byte mutation against input-to-state substitution from the \
                      comparison log.",
        implemented: true,
        unimplemented_reason: "",
    },
    ExperimentInfo {
        id: "f",
        title: "Classical optimiser versus quantum-inspired optimisers",
        description: "Greedy against simulated annealing, a quantum-inspired evolutionary \
                      algorithm and simulated quantum annealing, at equal budget with \
                      exhaustive ground truth where the instance is small enough. Run \
                      through `cargo test --test optimizer_tuning`, which carries the \
                      hyperparameter sweeps as well.",
        implemented: false,
        unimplemented_reason: "This experiment benchmarks solvers rather than campaigns, so \
                               it lives in tests/optimizer_tuning.rs where the sweep \
                               harness is. Results are recorded in docs/DECISIONS.md D13.",
    },
    ExperimentInfo {
        id: "g",
        title: "One worker versus several",
        description: "Scaling efficiency across worker counts at equal wall-clock budget. \
                      Equal wall clock rather than equal executions, because the question \
                      is how much throughput and coverage an extra worker buys - which \
                      equal wall clock measures directly. Note that a worker count above \
                      the host's core count measures oversubscription, not scaling.",
        implemented: true,
        unimplemented_reason: "",
    },
];

/// Metrics from one campaign run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialMetrics {
    pub arm: String,
    pub trial: u32,
    pub seed: u64,
    pub duration_ms: u64,
    pub executions: u64,
    pub executions_per_second: f64,
    pub total_edges: u32,
    pub guard_count: Option<u32>,
    pub corpus_entries: u64,
    pub distinct_behaviors: u64,
    pub findings_reproducible: u32,
    pub findings_intermittent: u32,
    pub crashes_observed: u64,
    pub timeouts_observed: u64,
    /// Time to the first confirmed finding, when one was found.
    pub time_to_first_finding_ms: Option<u64>,
    /// CPU microseconds per newly reached edge. `None` when no edge was
    /// reached, rather than a division by zero reported as a number.
    pub micros_per_edge: Option<f64>,
}

/// One configuration under test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmSummary {
    pub arm: String,
    pub description: String,
    pub trials: u32,
    /// Empty when the configuration could not be run here, with `skipped`
    /// giving the reason.
    pub metrics: Vec<TrialMetrics>,
    pub skipped: Option<String>,
}

impl ArmSummary {
    fn stat(&self, f: impl Fn(&TrialMetrics) -> f64) -> Option<(f64, f64, f64, f64)> {
        if self.metrics.is_empty() {
            return None;
        }
        let mut v: Vec<f64> = self.metrics.iter().map(&f).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        Some((v[0], v[v.len() / 2], v[v.len() - 1], mean))
    }

    pub fn median_edges(&self) -> Option<f64> {
        self.stat(|m| m.total_edges as f64).map(|s| s.1)
    }

    pub fn findings_total(&self) -> u32 {
        self.metrics.iter().map(|m| m.findings_reproducible).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentResults {
    pub experiment: String,
    pub title: String,
    pub target: String,
    pub trials: u32,
    pub duration_secs: u64,
    pub arms: Vec<ArmSummary>,
    /// Statements the data supports, with their numbers. Nothing is asserted
    /// here that the metrics above do not show.
    pub observations: Vec<String>,
    pub caveats: Vec<String>,
}

impl ExperimentResults {
    pub fn render_table(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Experiment {}: {}\n", self.experiment, self.title));
        s.push_str(&format!(
            "Target: {}  |  {} trials per arm  |  {}s per campaign\n\n",
            self.target, self.trials, self.duration_secs
        ));
        s.push_str(&format!(
            "{:<28} {:>12} {:>20} {:>20} {:>10}\n",
            "ARM", "EXEC/S", "EDGES min/med/max", "EXECS min/med/max", "FINDINGS"
        ));
        for a in &self.arms {
            if let Some(reason) = &a.skipped {
                s.push_str(&format!("{:<28} skipped: {}\n", a.arm, reason));
                continue;
            }
            let eps = a
                .stat(|m| m.executions_per_second)
                .map(|x| x.1)
                .unwrap_or(0.0);
            let edges = a
                .stat(|m| m.total_edges as f64)
                .map(|(lo, med, hi, _)| format!("{lo:.0}/{med:.0}/{hi:.0}"))
                .unwrap_or_else(|| "-".into());
            let execs = a
                .stat(|m| m.executions as f64)
                .map(|(lo, med, hi, _)| format!("{lo:.0}/{med:.0}/{hi:.0}"))
                .unwrap_or_else(|| "-".into());
            s.push_str(&format!(
                "{:<28} {:>12.0} {:>20} {:>20} {:>10}\n",
                a.arm,
                eps,
                edges,
                execs,
                a.findings_total()
            ));
        }
        if !self.observations.is_empty() {
            s.push_str("\nObservations:\n");
            for o in &self.observations {
                s.push_str(&format!("  - {o}\n"));
            }
        }
        if !self.caveats.is_empty() {
            s.push_str("\nCaveats:\n");
            for c in &self.caveats {
                s.push_str(&format!("  - {c}\n"));
            }
        }
        s
    }
}

/// Run one experiment, or all of the implemented ones.
pub fn run_experiment(
    experiment: &str,
    base: Config,
    trials: u32,
    duration_secs: u64,
) -> Result<ExperimentResults> {
    let id = experiment.to_ascii_lowercase();
    let info = EXPERIMENTS.iter().find(|e| e.id == id).ok_or_else(|| {
        Error::config(
            "experiment",
            format!(
                "unknown experiment {experiment:?}; known: {}",
                EXPERIMENTS
                    .iter()
                    .map(|e| e.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;

    if !info.implemented {
        return Err(Error::unsupported_with_remedy(
            format!("experiment {}", info.id),
            info.unimplemented_reason,
            "run `aether benchmark list` to see which experiments this build can run",
        ));
    }

    let arms = match id.as_str() {
        "a" => vec![
            arm("black-box", "no instrumentation feedback", |c| {
                c.target.instrumentation = Instrumentation::None;
                c.target.use_fork_server = false;
                c.feedback.providers = vec!["exit-class".into(), "sanitizer".into()];
                c.strategies.enabled = vec!["havoc".into(), "random-mutation".into()];
            }),
            arm("coverage-guided", "edge coverage drives the corpus", |c| {
                c.feedback.providers = vec![
                    "edge-coverage".into(),
                    "exit-class".into(),
                    "sanitizer".into(),
                ];
                c.strategies.enabled = vec!["havoc".into(), "random-mutation".into()];
            }),
        ],
        "b" => vec![
            arm(
                "static-allocation",
                "equal fixed shares per strategy",
                |c| {
                    c.intel.scheduler = SchedulerKind::Static;
                },
            ),
            arm(
                "adaptive-thompson",
                "Thompson Sampling on value per compute",
                |c| {
                    c.intel.scheduler = SchedulerKind::Thompson;
                },
            ),
        ],
        "c" => vec![
            arm("mutation-only", "byte-level mutation", |c| {
                c.strategies.enabled =
                    vec!["havoc".into(), "random-mutation".into(), "boundary".into()];
            }),
            arm("hybrid", "mutation plus structure and dictionary", |c| {
                c.strategies.enabled = vec![
                    "havoc".into(),
                    "random-mutation".into(),
                    "structure-aware".into(),
                    "dictionary".into(),
                    "splice".into(),
                ];
            }),
        ],
        "d" => vec![
            arm("coverage-only", "edge coverage alone", |c| {
                c.feedback.providers = vec!["edge-coverage".into()];
            }),
            arm(
                "coverage-plus-semantic",
                "coverage with exit-class and transitions",
                |c| {
                    c.feedback.providers = vec![
                        "edge-coverage".into(),
                        "exit-class".into(),
                        "state-transition".into(),
                        "sanitizer".into(),
                    ];
                },
            ),
        ],
        "e" => vec![
            arm("blind-mutation", "random byte mutation only", |c| {
                c.strategies.enabled = vec!["random-mutation".into()];
            }),
            arm("comparison-guided", "input-to-state substitution", |c| {
                c.strategies.enabled = vec!["cmplog-guided".into()];
            }),
        ],
        "g" => vec![
            arm("1-worker", "the sequential campaign loop", |c| {
                c.campaign.workers = 1;
            }),
            arm("2-workers", "two worker threads on a shared corpus", |c| {
                c.campaign.workers = 2;
            }),
            arm("4-workers", "four worker threads on a shared corpus", |c| {
                c.campaign.workers = 4;
            }),
        ],
        other => {
            return Err(Error::config(
                "experiment",
                format!("unhandled experiment {other}"),
            ))
        }
    };

    let mut summaries = Vec::new();
    for (name, description, apply) in arms {
        let mut metrics = Vec::new();
        let mut skipped = None;

        for trial in 0..trials.max(1) {
            let mut cfg = base.clone();
            // The benchmark profile makes a campaign a pure function of its
            // seed; see its definition for what that turns off and why.
            crate::config::apply_profile(&mut cfg, "research-benchmark")?;
            cfg.campaign.duration_secs = duration_secs;
            cfg.campaign.max_execs = 0;
            cfg.campaign.workers = 1;
            // Seed derived from the experiment and trial, so the whole
            // experiment replays and the arms see the same seeds.
            cfg.campaign.seed = seed_for(&id, trial);
            cfg.output.report_formats = vec!["json".into(), "bench-json".into()];
            apply(&mut cfg);

            match run_one(cfg, &name, trial) {
                Ok(m) => metrics.push(m),
                Err(e) => {
                    // An arm that cannot run here is reported as skipped with
                    // its reason, not silently replaced by something else.
                    skipped = Some(e.to_string());
                    break;
                }
            }
        }
        summaries.push(ArmSummary {
            arm: name,
            description,
            trials: trials.max(1),
            metrics,
            skipped,
        });
    }

    let observations = observe(&id, &summaries);
    Ok(ExperimentResults {
        experiment: id.clone(),
        title: info.title.to_string(),
        target: base.target.name.clone(),
        trials: trials.max(1),
        duration_secs,
        arms: summaries,
        observations,
        caveats: {
            let mut c = vec![if id == "g" {
                format!(
                    "Single host with {} logical cores, short campaigns. These numbers \
                     describe this target on this machine and do not generalise.",
                    std::thread::available_parallelism()
                        .map(|n| n.get().to_string())
                        .unwrap_or_else(|_| "an unknown number of".into())
                )
            } else {
                "Single host, single worker, short campaigns. These numbers describe this \
                 target on this machine and do not generalise to other targets."
                    .to_string()
            }];
            c.extend([
                "Fuzzing is stochastic: with a small number of trials, a difference smaller \
             than the spread between trials is not a result."
                    .into(),
                "Coverage is a proxy. The quantity that matters is reproducible findings, and \
             a short campaign against a target with few defects will show none."
                    .into(),
            ]);
            if id == "g" {
                c.push(
                    "The pool's controller thread also needs a core, and a pooled campaign \
                     does not apply stagnation escalation, so these arms differ in more \
                     than worker count."
                        .into(),
                );
            }
            c
        },
    })
}

/// What the worker-count arms actually showed.
///
/// Scaling efficiency is throughput per worker relative to the single-worker
/// arm. It is reported as measured: a pool contends for the shared corpus
/// lock, for memory bandwidth and for cores with its own controller thread, so
/// a figure below 1.0 is the expected result and not a defect. Where the
/// measurement cannot support a conclusion, that is what is said.
fn observe_scaling(arms: &[ArmSummary]) -> Vec<String> {
    let mut out = Vec::new();
    for arm in arms {
        if let Some(r) = &arm.skipped {
            out.push(format!("Arm `{}` could not be run here: {r}", arm.arm));
        }
    }

    let cores = std::thread::available_parallelism().map(|n| n.get()).ok();
    let eps = |a: &ArmSummary| a.stat(|m| m.executions_per_second).map(|s| s.1);
    let Some(base_eps) = arms.first().and_then(eps) else {
        out.push(
            "The single-worker arm produced no throughput measurement, so no scaling \
             figure can be computed from this run."
                .to_string(),
        );
        return out;
    };

    for a in arms {
        let Some(e) = eps(a) else { continue };
        // The worker count is the leading number of the arm name.
        let workers: u32 = a
            .arm
            .split('-')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1);
        let efficiency = crate::runtime::parallel::scaling_efficiency(base_eps, e, workers);
        let edges = a
            .median_edges()
            .map(|v| format!("{v:.0}"))
            .unwrap_or_else(|| "not measured".into());
        let note = match cores {
            Some(c) if workers as usize > c => format!(
                " (above this host's {c} logical cores, so this arm measures \
                 oversubscription rather than scaling)"
            ),
            _ => String::new(),
        };
        out.push(format!(
            "`{}`: {e:.0} exec/s median, {:.2}x the single-worker rate, scaling efficiency \
             {efficiency:.2} per worker; median coverage {edges} edges{note}.",
            a.arm,
            e / base_eps
        ));
        if efficiency > 1.0 {
            // A figure above 1.0 cannot mean the pool beat perfect scaling.
            // It means the baseline is not a clean reference: the
            // single-worker arm runs the sequential campaign loop, which is a
            // different code path from a worker. Measured on this host, that
            // path costs about 418 microseconds of CPU per execution against
            // 336 to 366 for a pooled worker, which is where the excess comes
            // from. Said plainly rather than left as an implied speedup.
            out.push(format!(
                "The {:.2} figure for `{}` is above 1.0, which cannot mean better than \
                 perfect scaling. The single-worker arm runs the sequential campaign loop, \
                 a different and more expensive code path than a pooled worker, so it is \
                 not a clean baseline; treat the throughput ratio as the measurement and \
                 the efficiency figure as approximate.",
                efficiency, a.arm
            ));
        }
    }

    // Coverage is the quantity that matters, so say whether the extra workers
    // bought any - and whether the difference clears the between-trial spread.
    let spread = |s: &ArmSummary| {
        s.stat(|m| m.total_edges as f64)
            .map(|(lo, _, hi, _)| hi - lo)
            .unwrap_or(0.0)
    };
    if let (Some(first), Some(last)) = (arms.first(), arms.last()) {
        if let (Some(e0), Some(e1)) = (first.median_edges(), last.median_edges()) {
            let max_spread = spread(first).max(spread(last));
            let diff = (e1 - e0).abs();
            if diff <= max_spread {
                out.push(format!(
                    "Median coverage differs by {diff:.0} edges between `{}` and `{}`, \
                     within the {max_spread:.0}-edge spread between trials of a single \
                     arm. On this evidence the extra workers bought throughput but no \
                     measurable additional coverage at this budget.",
                    first.arm, last.arm
                ));
            } else {
                out.push(format!(
                    "`{}` reached median {e1:.0} edges against {e0:.0} for `{}`, a \
                     difference of {diff:.0} edges exceeding the {max_spread:.0}-edge \
                     between-trial spread.",
                    last.arm, first.arm
                ));
            }
        }
    }

    // Redundancy and lock contention are the costs of the design; they are
    // measured per campaign and reported rather than assumed away.
    out.push(
        "Redundant discoveries and lock wait are recorded per campaign in the report's \
         `parallel` section; see it for what the two-tier coverage check cost on these runs."
            .to_string(),
    );
    out
}

type ArmSpec = (String, String, Box<dyn Fn(&mut Config)>);

fn arm(name: &str, description: &str, f: impl Fn(&mut Config) + 'static) -> ArmSpec {
    (name.to_string(), description.to_string(), Box::new(f))
}

fn seed_for(experiment: &str, trial: u32) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(experiment.as_bytes());
    h.update(&trial.to_le_bytes());
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// Microseconds of wall clock per newly reached edge.
///
/// `None` when no edge was reached: a rate computed by dividing by zero would
/// be reported as a measurement, which it is not.
fn micros_per_edge(duration_ms: u64, total_edges: u32) -> Option<f64> {
    (total_edges > 0).then(|| (duration_ms as f64 * 1000.0) / total_edges as f64)
}

fn run_one(cfg: Config, arm: &str, trial: u32) -> Result<TrialMetrics> {
    let seed = cfg.campaign.seed;
    let mut campaign = Campaign::create(cfg, Cancel::new())?;
    campaign.seed_corpus(None)?;
    let reason = campaign.run()?;
    let r = campaign.report(Some(reason))?;

    let first_finding = r
        .findings
        .items
        .iter()
        .filter(|f| f.status.is_confirmed())
        .map(|f| f.created_ms)
        .min();
    let started = r.findings.items.first().map(|_| 0u64).unwrap_or(0);
    let _ = started;

    Ok(TrialMetrics {
        arm: arm.to_string(),
        trial,
        seed,
        duration_ms: r.duration_ms,
        executions: r.execution.total_executions,
        executions_per_second: r.execution.executions_per_second,
        total_edges: r.coverage.total_edges,
        guard_count: r.coverage.guard_count,
        corpus_entries: r.corpus.entries,
        distinct_behaviors: r.corpus.distinct_behaviors,
        findings_reproducible: r.findings.reproducible,
        findings_intermittent: r.findings.intermittent,
        crashes_observed: r.execution.crashes_observed,
        timeouts_observed: r.execution.timeouts_observed,
        time_to_first_finding_ms: first_finding,
        // None rather than a division by zero dressed up as a measurement.
        micros_per_edge: micros_per_edge(r.duration_ms, r.coverage.total_edges),
    })
}

/// Statements the numbers support. Where they do not support a conclusion,
/// that is what gets reported.
fn observe(experiment: &str, arms: &[ArmSummary]) -> Vec<String> {
    let mut out = Vec::new();
    if arms.len() < 2 {
        return out;
    }
    if experiment == "g" {
        return observe_scaling(arms);
    }
    let (a, b) = (&arms[0], &arms[1]);

    for arm in arms {
        if let Some(r) = &arm.skipped {
            out.push(format!("Arm `{}` could not be run here: {r}", arm.arm));
        }
    }
    let (Some(ea), Some(eb)) = (a.median_edges(), b.median_edges()) else {
        return out;
    };

    // Spread within an arm bounds what a difference between arms can mean.
    let spread = |s: &ArmSummary| {
        s.stat(|m| m.total_edges as f64)
            .map(|(lo, _, hi, _)| hi - lo)
            .unwrap_or(0.0)
    };
    let max_spread = spread(a).max(spread(b));
    let diff = (eb - ea).abs();

    if diff <= max_spread {
        out.push(format!(
            "Median coverage differs by {diff:.0} edges ({:.0} for `{}` against {:.0} for \
             `{}`), which is within the {max_spread:.0}-edge spread between trials of a \
             single arm. On this evidence the two are not distinguishable.",
            ea, a.arm, eb, b.arm
        ));
    } else if eb > ea {
        out.push(format!(
            "`{}` reached more of the target: median {:.0} edges against {:.0} for `{}`, a \
             difference of {diff:.0} edges exceeding the {max_spread:.0}-edge between-trial \
             spread.",
            b.arm, eb, ea, a.arm
        ));
    } else {
        out.push(format!(
            "`{}` reached more of the target: median {:.0} edges against {:.0} for `{}`, a \
             difference of {diff:.0} edges exceeding the {max_spread:.0}-edge between-trial \
             spread.",
            a.arm, ea, eb, b.arm
        ));
    }

    let (fa, fb) = (a.findings_total(), b.findings_total());
    if fa != fb {
        out.push(format!(
            "Reproducible findings: {fa} for `{}`, {fb} for `{}`.",
            a.arm, b.arm
        ));
    } else if fa == 0 {
        out.push(
            "Neither arm produced a reproducible finding, so this experiment compares \
             coverage only."
                .to_string(),
        );
    }

    if experiment == "a" {
        out.push(
            "The black-box arm has no coverage signal at all, so its corpus cannot grow on \
             exploration value; its edge count is measured by the instrumented build for \
             comparison only."
                .to_string(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_experiment_is_catalogued_with_an_honest_status() {
        assert_eq!(
            EXPERIMENTS.len(),
            7,
            "the specification defines A through G"
        );
        for e in EXPERIMENTS {
            assert!(!e.title.is_empty());
            assert!(!e.description.is_empty());
            if !e.implemented {
                assert!(
                    !e.unimplemented_reason.is_empty(),
                    "{} is unimplemented with no reason given",
                    e.id
                );
            }
        }
    }

    #[test]
    fn unimplemented_experiments_refuse_rather_than_substitute() {
        // Experiment F benchmarks solvers rather than campaigns, so this
        // harness cannot run it. Running something else and labelling it F
        // would be fabricating a result.
        let cfg = Config::from_toml_str(
            "schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n",
        )
        .unwrap();
        let e = run_experiment("f", cfg, 1, 1).unwrap_err();
        assert_eq!(e.kind(), "unsupported_capability");
        assert!(
            e.to_string().contains("optimizer_tuning"),
            "the refusal should point at where the experiment does live: {e}"
        );
    }

    #[test]
    fn every_experiment_either_has_arms_or_says_why_not() {
        // The catalogue and the dispatch must not drift: an experiment marked
        // implemented with no arms would report an empty result as a finding,
        // and one marked unimplemented must carry a reason.
        for info in EXPERIMENTS {
            if info.implemented {
                assert!(
                    info.unimplemented_reason.is_empty(),
                    "experiment {} is implemented but carries a reason it is not",
                    info.id
                );
            } else {
                assert!(
                    !info.unimplemented_reason.is_empty(),
                    "experiment {} is not implemented and gives no reason",
                    info.id
                );
            }
        }
    }

    #[test]
    fn the_scaling_observer_never_claims_better_than_perfect_scaling() {
        // A per-worker efficiency above 1.0 means the baseline is not a clean
        // reference, not that the pool beat perfect scaling. The observer must
        // say so next to the number rather than let it read as a speedup.
        let arm = |name: &str, eps: f64, edges: u32| ArmSummary {
            arm: name.to_string(),
            description: String::new(),
            trials: 1,
            metrics: vec![TrialMetrics {
                arm: name.to_string(),
                trial: 0,
                seed: 1,
                duration_ms: 1000,
                executions: eps as u64,
                executions_per_second: eps,
                total_edges: edges,
                guard_count: Some(100),
                corpus_entries: 1,
                distinct_behaviors: 1,
                findings_reproducible: 0,
                findings_intermittent: 0,
                crashes_observed: 0,
                timeouts_observed: 0,
                time_to_first_finding_ms: None,
                micros_per_edge: None,
            }],
            skipped: None,
        };

        // Super-linear: must be flagged.
        let out = observe_scaling(&[arm("1-worker", 1000.0, 9), arm("2-workers", 2400.0, 9)]);
        assert!(
            out.iter().any(|o| o.contains("cannot mean better than")),
            "a >1.0 efficiency must be explained: {out:?}"
        );

        // Sub-linear: nothing to explain away.
        let out = observe_scaling(&[arm("1-worker", 1000.0, 9), arm("2-workers", 1500.0, 9)]);
        assert!(
            !out.iter().any(|o| o.contains("cannot mean better than")),
            "sub-linear scaling needs no caveat: {out:?}"
        );
        assert!(
            out.iter().any(|o| o.contains("0.75")),
            "the efficiency figure should be reported: {out:?}"
        );
    }

    #[test]
    fn scaling_reports_no_coverage_gain_when_there_is_none() {
        let arm = |name: &str, eps: f64, edges: &[u32]| ArmSummary {
            arm: name.to_string(),
            description: String::new(),
            trials: edges.len() as u32,
            metrics: edges
                .iter()
                .enumerate()
                .map(|(i, &e)| TrialMetrics {
                    arm: name.to_string(),
                    trial: i as u32,
                    seed: i as u64,
                    duration_ms: 1000,
                    executions: eps as u64,
                    executions_per_second: eps,
                    total_edges: e,
                    guard_count: Some(100),
                    corpus_entries: 1,
                    distinct_behaviors: 1,
                    findings_reproducible: 0,
                    findings_intermittent: 0,
                    crashes_observed: 0,
                    timeouts_observed: 0,
                    time_to_first_finding_ms: None,
                    micros_per_edge: None,
                })
                .collect(),
            skipped: None,
        };
        let out = observe_scaling(&[
            arm("1-worker", 1000.0, &[9, 9, 9]),
            arm("4-workers", 4000.0, &[9, 9, 9]),
        ]);
        assert!(
            out.iter()
                .any(|o| o.contains("no measurable additional coverage")),
            "equal coverage must be reported as no gain: {out:?}"
        );
    }

    #[test]
    fn unknown_experiments_are_refused() {
        let cfg = Config::from_toml_str(
            "schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n",
        )
        .unwrap();
        let e = run_experiment("z", cfg, 1, 1).unwrap_err();
        assert!(e.to_string().contains("unknown experiment"), "{e}");
    }

    #[test]
    fn seeds_are_derived_and_stable() {
        assert_eq!(seed_for("a", 0), seed_for("a", 0));
        assert_ne!(seed_for("a", 0), seed_for("a", 1));
        assert_ne!(seed_for("a", 0), seed_for("b", 0));
    }

    fn metrics(arm: &str, edges: u32, findings: u32) -> TrialMetrics {
        TrialMetrics {
            arm: arm.into(),
            trial: 0,
            seed: 1,
            duration_ms: 1000,
            executions: 1000,
            executions_per_second: 1000.0,
            total_edges: edges,
            guard_count: Some(100),
            corpus_entries: 10,
            distinct_behaviors: 3,
            findings_reproducible: findings,
            findings_intermittent: 0,
            crashes_observed: 0,
            timeouts_observed: 0,
            time_to_first_finding_ms: None,
            micros_per_edge: Some(10.0),
        }
    }

    fn summary(arm: &str, edge_values: &[u32]) -> ArmSummary {
        ArmSummary {
            arm: arm.into(),
            description: String::new(),
            trials: edge_values.len() as u32,
            metrics: edge_values.iter().map(|e| metrics(arm, *e, 0)).collect(),
            skipped: None,
        }
    }

    #[test]
    fn a_difference_inside_the_trial_spread_is_not_reported_as_a_result() {
        // The guard against over-reading noise: arm B's median is higher, but
        // by less than the variation between B's own trials.
        let arms = vec![summary("a", &[10, 20, 30]), summary("b", &[15, 25, 35])];
        let obs = observe("x", &arms);
        assert!(
            obs.iter().any(|o| o.contains("not distinguishable")),
            "a within-spread difference was reported as a finding: {obs:?}"
        );
    }

    #[test]
    fn a_difference_exceeding_the_spread_is_reported() {
        let arms = vec![summary("a", &[10, 10, 11]), summary("b", &[90, 91, 92])];
        let obs = observe("x", &arms);
        assert!(
            obs.iter().any(|o| o.contains("reached more of the target")),
            "a clear difference was not reported: {obs:?}"
        );
        assert!(obs.iter().any(|o| o.contains("`b`")));
    }

    #[test]
    fn skipped_arms_are_surfaced() {
        let mut arms = vec![summary("a", &[10]), summary("b", &[20])];
        arms[1].skipped = Some("needs a comparison log".into());
        arms[1].metrics.clear();
        let obs = observe("x", &arms);
        assert!(
            obs.iter().any(|o| o.contains("could not be run")),
            "{obs:?}"
        );
    }

    #[test]
    fn no_findings_in_either_arm_is_stated_plainly() {
        let arms = vec![summary("a", &[10, 10, 10]), summary("b", &[10, 10, 10])];
        let obs = observe("x", &arms);
        assert!(
            obs.iter().any(|o| o.contains("compares coverage only")),
            "{obs:?}"
        );
    }

    #[test]
    fn results_render_without_panicking_on_empty_arms() {
        let r = ExperimentResults {
            experiment: "a".into(),
            title: "t".into(),
            target: "demo".into(),
            trials: 0,
            duration_secs: 1,
            arms: vec![ArmSummary {
                arm: "x".into(),
                description: String::new(),
                trials: 0,
                metrics: Vec::new(),
                skipped: Some("unavailable".into()),
            }],
            observations: Vec::new(),
            caveats: vec!["c".into()],
        };
        let table = r.render_table();
        assert!(table.contains("skipped: unavailable"));
        assert!(table.contains("Caveats:"));
    }

    #[test]
    fn micros_per_edge_is_none_when_no_edge_was_reached() {
        assert_eq!(
            micros_per_edge(1000, 0),
            None,
            "zero edges must not yield a rate"
        );
        assert_eq!(micros_per_edge(1000, 10), Some(100_000.0));
    }
}
