//! The intelligence engine: deciding what to try next, and with what.
//!
//! * [`bandit`] allocates execution budget across strategies from measured
//!   value per unit of compute.
//! * [`stagnation`] detects when discovery has stopped and escalates from
//!   cheap responses to expensive ones.
//! * [`qubo`] is the experimental quantum-inspired optimisation lab, off by
//!   default, for combinatorial choices such as corpus subset selection.

pub mod bandit;
pub mod qubo;
pub mod stagnation;

use serde::{Deserialize, Serialize};

use crate::config::IntelConfig;
use crate::feedback::Feedback;

/// A single place for the per-round bookkeeping the scheduler and the
/// stagnation detector both need, so the campaign loop does not have to keep
/// the two in step itself.
pub struct Intelligence {
    pub scheduler: bandit::Scheduler,
    pub stagnation: stagnation::StagnationDetector,
    stagnation_threshold: u32,
    /// Accumulator for the round currently in flight.
    round_value: f64,
    round_execs: u64,
    round_cost_micros: u64,
    round_new_edges: u64,
    round_findings: u32,
}

impl Intelligence {
    pub fn new(cfg: &IntelConfig, strategies: Vec<String>) -> Self {
        Intelligence {
            scheduler: bandit::Scheduler::new(
                cfg.scheduler,
                strategies,
                cfg.round_budget,
                cfg.min_rounds_per_strategy,
                cfg.selection_floor,
            ),
            stagnation: stagnation::StagnationDetector::new(
                cfg.stagnation_rounds,
                cfg.stagnation_recovery_ratio,
            ),
            stagnation_threshold: cfg.stagnation_rounds.max(2),
            round_value: 0.0,
            round_execs: 0,
            round_cost_micros: 0,
            round_new_edges: 0,
            round_findings: 0,
        }
    }

    /// Current campaign context for arm selection.
    pub fn context(&self, corpus_size: u64, saturation: Option<f64>) -> bandit::Context {
        bandit::Context::new(
            self.stagnation.barren_rounds(),
            self.stagnation_threshold,
            corpus_size,
            saturation,
        )
    }

    /// Fold one execution's feedback into the round accumulator.
    pub fn record_execution(&mut self, feedback: &Feedback, finding: bool) {
        self.round_execs += 1;
        self.round_cost_micros += feedback.cost_micros;
        if let Some(c) = feedback.coverage {
            self.round_value += c.score();
            self.round_new_edges += c.new_edges as u64;
        }
        self.round_value += feedback.novelty * 5.0;
        self.round_value += feedback.new_cmp_tokens as f64 * 0.5;
        if finding {
            self.round_findings += 1;
            // A reproducible finding is the campaign's actual objective, so it
            // carries far more weight than coverage in the reward signal.
            self.round_value += 100.0;
        }
    }

    /// Close the round: update the scheduler and the stagnation detector, and
    /// return the detector's advice.
    pub fn finish_round(
        &mut self,
        ctx: bandit::Context,
        arm: usize,
    ) -> (bandit::RoundOutcome, stagnation::Response) {
        let outcome = bandit::RoundOutcome {
            executions: self.round_execs,
            value: self.round_value,
            cost_micros: self.round_cost_micros,
            new_edges: self.round_new_edges,
            findings: self.round_findings,
        };
        self.scheduler.update(ctx, arm, outcome);
        let advice = self.stagnation.observe(outcome.produced_anything());

        self.round_value = 0.0;
        self.round_execs = 0;
        self.round_cost_micros = 0;
        self.round_new_edges = 0;
        self.round_findings = 0;

        (outcome, advice)
    }

    pub fn snapshot(&self) -> IntelSnapshot {
        IntelSnapshot {
            round: self.scheduler.round(),
            allocation: self.scheduler.allocation(),
            stagnation: self.stagnation.state(),
            recent_decisions: self
                .scheduler
                .decisions()
                .iter()
                .rev()
                .take(10)
                .cloned()
                .collect(),
        }
    }
}

/// Serialisable view of the intelligence engine, for status and reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSnapshot {
    pub round: u64,
    pub allocation: Vec<(String, f64)>,
    pub stagnation: stagnation::StagnationState,
    pub recent_decisions: Vec<bandit::Decision>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::coverage::CoverageGain;

    fn intel() -> Intelligence {
        Intelligence::new(&IntelConfig::default(), vec!["a".into(), "b".into()])
    }

    #[test]
    fn records_executions_into_the_round_accumulator() {
        let mut i = intel();
        let fb = Feedback {
            coverage: Some(CoverageGain {
                new_edges: 3,
                new_buckets: 1,
                touched: 10,
            }),
            cost_micros: 1000,
            novelty: 0.5,
            new_cmp_tokens: 2,
            ..Default::default()
        };
        i.record_execution(&fb, false);
        let ctx = i.context(0, None);
        let (outcome, _) = i.finish_round(ctx, 0);
        assert_eq!(outcome.executions, 1);
        assert_eq!(outcome.new_edges, 3);
        assert!(outcome.value > 0.0);
        assert!(outcome.produced_anything());
    }

    #[test]
    fn a_finding_dominates_the_reward_signal() {
        // Coverage is a proxy; a reproducible finding is the actual objective.
        let mut a = intel();
        let cov_only = Feedback {
            coverage: Some(CoverageGain {
                new_edges: 5,
                new_buckets: 0,
                touched: 5,
            }),
            cost_micros: 1000,
            ..Default::default()
        };
        a.record_execution(&cov_only, false);
        let (cov_outcome, _) = a.finish_round(a.context(0, None), 0);

        let mut b = intel();
        b.record_execution(
            &Feedback {
                cost_micros: 1000,
                ..Default::default()
            },
            true,
        );
        let (find_outcome, _) = b.finish_round(b.context(0, None), 0);

        assert!(
            find_outcome.value > cov_outcome.value,
            "a finding ({}) should outweigh coverage ({})",
            find_outcome.value,
            cov_outcome.value
        );
    }

    #[test]
    fn the_accumulator_resets_between_rounds() {
        let mut i = intel();
        let fb = Feedback {
            coverage: Some(CoverageGain {
                new_edges: 4,
                new_buckets: 0,
                touched: 4,
            }),
            cost_micros: 500,
            ..Default::default()
        };
        i.record_execution(&fb, false);
        let ctx = i.context(0, None);
        i.finish_round(ctx, 0);
        let (second, _) = i.finish_round(ctx, 0);
        assert_eq!(
            second.executions, 0,
            "round accumulator leaked into the next round"
        );
        assert_eq!(second.value, 0.0);
        assert!(!second.produced_anything());
    }

    #[test]
    fn context_tracks_stagnation_and_corpus_growth() {
        let mut i = intel();
        assert_eq!(i.context(0, None).progress, 0);
        // Many barren rounds should move the context into stagnation.
        for _ in 0..40 {
            let ctx = i.context(10, None);
            i.finish_round(ctx, 0);
        }
        assert_eq!(i.context(10, None).progress, 2);
        assert_eq!(i.context(10_000, Some(0.9)).corpus, 2);
    }

    #[test]
    fn snapshot_reports_allocation_and_decisions() {
        let mut i = intel();
        let mut rng = crate::rng::Rng::from_seed(1);
        for _ in 0..20 {
            let ctx = i.context(5, None);
            let arm = i.scheduler.select(ctx, &mut rng);
            i.record_execution(
                &Feedback {
                    coverage: Some(CoverageGain {
                        new_edges: 1,
                        new_buckets: 0,
                        touched: 1,
                    }),
                    cost_micros: 800,
                    ..Default::default()
                },
                false,
            );
            i.finish_round(ctx, arm);
        }
        let s = i.snapshot();
        assert!(s.round > 0);
        assert_eq!(s.allocation.len(), 2);
        assert!(!s.recent_decisions.is_empty());
        assert!(s.recent_decisions.len() <= 10, "snapshot must stay bounded");
        // Shares must sum to roughly one.
        let total: f64 = s.allocation.iter().map(|(_, v)| v).sum();
        assert!(
            (total - 1.0).abs() < 1e-6,
            "allocation shares summed to {total}"
        );
    }

    #[test]
    fn stagnation_advice_flows_through() {
        let mut i = intel();
        let ctx = i.context(0, None);
        let mut advice = stagnation::Response::Continue;
        for _ in 0..200 {
            let (_, a) = i.finish_round(ctx, 0);
            advice = a;
        }
        assert_ne!(
            advice,
            stagnation::Response::Continue,
            "no advice after 200 barren rounds"
        );
    }
}
