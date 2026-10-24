//! Feedback aggregation: turning one execution into the signals the
//! intelligence engine ranks and schedules on.
//!
//! Edge coverage is the primary signal and is handled directly. Everything
//! else arrives through a [`SemanticProvider`], each of which declares what it
//! can and cannot see. The aggregator combines them into a single normalised
//! novelty value while keeping the components, so a report can say *which*
//! signal fired rather than only that something did.
//!
//! Two properties the aggregator must hold, both tested:
//!
//! * A signal a target cannot supply contributes nothing and is reported as
//!   unavailable - never as a zero that reads like a measurement.
//! * Weighting is normalised, so adding a provider does not silently inflate
//!   every novelty score and make past and present campaigns incomparable.

pub mod cmplog;
pub mod coverage;
pub mod semantic;

use std::collections::BTreeMap;

use crate::exec::ExecOutcome;
use coverage::{CoverageGain, CoverageTracker};
use semantic::{Availability, Observation, ProviderDescription, SemanticProvider};

/// Everything learned from one execution.
#[derive(Debug, Clone, Default)]
pub struct Feedback {
    /// Coverage contribution, or `None` when the target is uninstrumented.
    pub coverage: Option<CoverageGain>,
    /// Comparison constants newly observed this run.
    pub new_cmp_tokens: u32,
    /// Weighted, normalised novelty in `[0, 1]`.
    pub novelty: f64,
    /// Per-provider novelty before weighting, for reporting.
    pub components: BTreeMap<String, f64>,
    /// A declared invariant this run broke.
    pub invariant_violated: Option<String>,
    /// Execution cost, used as the denominator of strategy utility.
    pub cost_micros: u64,
    /// Response status codes the target emitted, in order. Empty for a target
    /// that does not answer with status codes.
    pub response_codes: Vec<u32>,
}

impl Feedback {
    /// Did this run show the campaign anything it had not seen?
    ///
    /// An invariant violation counts even with zero novelty elsewhere: a
    /// target answering wrongly is interesting however familiar its code path.
    pub fn is_interesting(&self) -> bool {
        self.novelty > 0.0
            || self.coverage.map(|c| c.is_novel()).unwrap_or(false)
            || self.invariant_violated.is_some()
    }

    /// Exploration value per unit of compute: the quantity the scheduler
    /// maximises. Cost is floored so a very fast execution cannot produce an
    /// unbounded ratio.
    pub fn value_per_cost(&self) -> f64 {
        let cov = self.coverage.map(|c| c.score()).unwrap_or(0.0);
        let value = cov + self.novelty * 5.0 + self.new_cmp_tokens as f64 * 0.5;
        let cost_ms = (self.cost_micros as f64 / 1000.0).max(0.05);
        value / cost_ms
    }
}

/// Owns the campaign's coverage state and its semantic providers.
pub struct FeedbackEngine {
    coverage: CoverageTracker,
    cmp_tokens: cmplog::CmpTokenStore,
    providers: Vec<Box<dyn SemanticProvider>>,
    weights: BTreeMap<String, f64>,
    /// Providers that reported themselves unusable, kept so a report can say
    /// which signals were absent rather than leaving a silent gap.
    unavailable: Vec<(String, String)>,
    instrumented: bool,
}

impl std::fmt::Debug for FeedbackEngine {
    // Hand-written because the provider list holds trait objects. Prints the
    // provider ids, which is what is useful when a test or a log shows one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedbackEngine")
            .field("providers", &self.providers.iter().map(|p| p.id()).collect::<Vec<_>>())
            .field("instrumented", &self.instrumented)
            .field("total_edges", &self.coverage.total_edges())
            .field("cmp_tokens", &self.cmp_tokens.len())
            .field("unavailable", &self.unavailable)
            .finish()
    }
}

impl FeedbackEngine {
    /// Build an engine from the configured provider list.
    ///
    /// `requested` names providers; unknown names are reported rather than
    /// ignored, because a typo in a config file should not silently disable a
    /// signal the operator asked for.
    pub fn new(
        requested: &[String],
        weights: &BTreeMap<String, f64>,
        invariants: Vec<semantic::Invariant>,
        instrumented: bool,
    ) -> crate::error::Result<Self> {
        let mut providers: Vec<Box<dyn SemanticProvider>> = Vec::new();
        let mut unavailable = Vec::new();

        for name in requested {
            match name.as_str() {
                // Handled directly rather than through a provider.
                "edge-coverage" | "cmplog" | "sanitizer" | "differential" => continue,
                "exit-class" => providers.push(Box::new(semantic::ExitClassProvider::default())),
                "state-transition" => {
                    providers.push(Box::new(semantic::StateTransitionProvider::default()))
                }
                "invariant" => {
                    providers.push(Box::new(semantic::InvariantProvider::new(invariants.clone())))
                }
                other => {
                    return Err(crate::error::Error::config(
                        "feedback.providers",
                        format!(
                            "unknown provider {other:?}; known: edge-coverage, cmplog, \
                             sanitizer, differential, exit-class, state-transition, invariant"
                        ),
                    ))
                }
            }
        }

        // An invariant provider with nothing declared, or any other provider
        // that cannot work here, is recorded and dropped.
        providers.retain(|p| match p.availability() {
            Availability::Available => true,
            Availability::Degraded(reason) => {
                unavailable.push((p.id().to_string(), format!("degraded: {reason}")));
                true
            }
            Availability::Unavailable(reason) => {
                unavailable.push((p.id().to_string(), reason));
                false
            }
        });

        if !instrumented {
            unavailable.push((
                "edge-coverage".to_string(),
                "target is not instrumented".to_string(),
            ));
        }

        Ok(FeedbackEngine {
            coverage: CoverageTracker::new(),
            cmp_tokens: cmplog::CmpTokenStore::new(4096),
            providers,
            weights: weights.clone(),
            unavailable,
            instrumented,
        })
    }

    pub fn coverage(&self) -> &CoverageTracker {
        &self.coverage
    }

    pub fn coverage_mut(&mut self) -> &mut CoverageTracker {
        &mut self.coverage
    }

    pub fn cmp_tokens(&self) -> &cmplog::CmpTokenStore {
        &self.cmp_tokens
    }

    /// Signals requested but unavailable, with reasons.
    pub fn unavailable_signals(&self) -> &[(String, String)] {
        &self.unavailable
    }

    pub fn provider_descriptions(&self) -> Vec<ProviderDescription> {
        self.providers.iter().map(|p| p.describe()).collect()
    }

    fn weight_for(&self, id: &str) -> f64 {
        self.weights.get(id).copied().unwrap_or(1.0).max(0.0)
    }

    /// Fold one execution into campaign state and return what it contributed.
    pub fn observe(&mut self, input: &[u8], outcome: &ExecOutcome) -> Feedback {
        let coverage = outcome.coverage.as_ref().map(|map| self.coverage.observe(map));
        let new_cmp_tokens = self.cmp_tokens.observe(&outcome.cmp_entries);

        let obs = Observation { input, outcome };
        let mut components = BTreeMap::new();
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        let mut invariant_violated = None;
        let mut response_codes = Vec::new();

        for p in self.providers.iter_mut() {
            let r = p.observe(&obs);
            if response_codes.is_empty() && !r.response_codes.is_empty() {
                response_codes = r.response_codes.clone();
            }
            let w = self.weights.get(p.id()).copied().unwrap_or(1.0).max(0.0);
            components.insert(p.id().to_string(), r.novelty);
            weighted_sum += r.novelty * w;
            weight_total += w;
            if invariant_violated.is_none() {
                invariant_violated = r.invariant_violated;
            }
        }

        // Normalise by total weight, so adding a provider changes which
        // signals contribute without inflating the scale. Campaigns with
        // different provider sets stay comparable on this axis.
        let novelty = if weight_total > 0.0 {
            (weighted_sum / weight_total).clamp(0.0, 1.0)
        } else {
            0.0
        };

        Feedback {
            coverage,
            new_cmp_tokens,
            novelty,
            components,
            invariant_violated,
            cost_micros: outcome.duration.as_micros().min(u64::MAX as u128) as u64,
            response_codes,
        }
    }

    /// Evaluate without committing, for a decision that may be discarded.
    pub fn evaluate(&self, outcome: &ExecOutcome) -> Option<CoverageGain> {
        outcome.coverage.as_ref().map(|m| self.coverage.evaluate(m))
    }

    pub fn is_instrumented(&self) -> bool {
        self.instrumented
    }

    /// Confirm the weight lookup is used; kept for the scheduler's context.
    pub fn declared_weight(&self, id: &str) -> f64 {
        self.weight_for(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::shm::MAP_SIZE;
    use crate::exec::ExitClass;
    use std::time::Duration;

    fn outcome_with(
        class: ExitClass,
        stdout: &[u8],
        coverage: Option<Box<[u8; MAP_SIZE]>>,
    ) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: Some(0),
            signal: None,
            duration: Duration::from_millis(1),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: None,
            coverage,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    fn cov(slots: &[(usize, u8)]) -> Box<[u8; MAP_SIZE]> {
        let mut m = Box::new([0u8; MAP_SIZE]);
        for (i, v) in slots {
            m[*i] = *v;
        }
        m
    }

    fn engine(providers: &[&str], instrumented: bool) -> FeedbackEngine {
        FeedbackEngine::new(
            &providers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &BTreeMap::new(),
            Vec::new(),
            instrumented,
        )
        .unwrap()
    }

    #[test]
    fn unknown_provider_is_refused_not_ignored() {
        let e = FeedbackEngine::new(
            &["exit-class".into(), "not-a-provider".into()],
            &BTreeMap::new(),
            Vec::new(),
            true,
        )
        .unwrap_err();
        assert!(e.to_string().contains("unknown provider"), "{e}");
    }

    #[test]
    fn coverage_novelty_flows_through() {
        let mut e = engine(&["edge-coverage", "exit-class"], true);
        let f1 = e.observe(b"a", &outcome_with(ExitClass::Ok, b"", Some(cov(&[(1, 1)]))));
        assert_eq!(f1.coverage.unwrap().new_edges, 1);
        assert!(f1.is_interesting());

        let f2 = e.observe(b"a", &outcome_with(ExitClass::Ok, b"", Some(cov(&[(1, 1)]))));
        assert_eq!(f2.coverage.unwrap().new_edges, 0);
        assert!(!f2.is_interesting(), "identical run must not read as progress");
    }

    #[test]
    fn uninstrumented_target_reports_no_coverage_and_says_why() {
        let mut e = engine(&["exit-class"], false);
        let f = e.observe(b"a", &outcome_with(ExitClass::Ok, b"", None));
        assert!(f.coverage.is_none(), "must be None, not a zeroed gain");
        assert!(e
            .unavailable_signals()
            .iter()
            .any(|(id, r)| id == "edge-coverage" && r.contains("not instrumented")));
    }

    #[test]
    fn invariant_provider_without_declarations_is_recorded_as_unavailable() {
        let e = engine(&["invariant"], true);
        assert!(e
            .unavailable_signals()
            .iter()
            .any(|(id, _)| id == "invariant"));
        assert!(e.provider_descriptions().iter().all(|d| d.id != "invariant"));
    }

    #[test]
    fn invariant_violation_is_interesting_even_with_a_clean_exit() {
        let mut e = FeedbackEngine::new(
            &["invariant".into()],
            &BTreeMap::new(),
            vec![semantic::Invariant {
                name: "no-internal".into(),
                rule: semantic::InvariantRule::StdoutMustNotContain {
                    needle: "INTERNAL".into(),
                },
            }],
            true,
        )
        .unwrap();
        let f = e.observe(b"x", &outcome_with(ExitClass::Ok, b"INTERNAL", None));
        assert_eq!(f.invariant_violated.as_deref(), Some("no-internal"));
        assert!(f.is_interesting());
    }

    #[test]
    fn novelty_is_normalised_so_provider_count_does_not_inflate_it() {
        // Both engines see a first-time observation. With unnormalised
        // summation the two-provider engine would score roughly twice as high
        // for the same amount of discovery.
        let o = outcome_with(ExitClass::Ok, b"230 a\n250 b\n", None);
        let mut one = engine(&["exit-class"], true);
        let mut two = engine(&["exit-class", "state-transition"], true);
        let f1 = one.observe(b"", &o);
        let f2 = two.observe(b"", &o);
        assert!(f1.novelty <= 1.0 && f2.novelty <= 1.0);
        assert_eq!(f1.novelty, 1.0);
        assert_eq!(f2.novelty, 1.0, "both providers fired, so normalised novelty is still 1");
        assert_eq!(f2.components.len(), 2, "components stay visible per provider");
    }

    #[test]
    fn weights_shift_the_balance_between_providers() {
        let mut w = BTreeMap::new();
        w.insert("state-transition".to_string(), 0.0);
        let mut e = FeedbackEngine::new(
            &["exit-class".into(), "state-transition".into()],
            &w,
            Vec::new(),
            true,
        )
        .unwrap();
        // With state-transition weighted to zero, only exit-class contributes.
        let f = e.observe(b"", &outcome_with(ExitClass::Ok, b"230 a\n250 b\n", None));
        assert_eq!(f.novelty, 1.0);
        assert_eq!(e.declared_weight("state-transition"), 0.0);

        // A second run: exit-class is no longer novel, and the only other
        // provider is weighted out, so novelty collapses.
        let f2 = e.observe(b"", &outcome_with(ExitClass::Ok, b"250 b\n230 a\n", None));
        assert_eq!(f2.novelty, 0.0, "a zero-weighted provider must not drive novelty");
    }

    #[test]
    fn value_per_cost_prefers_cheaper_discovery() {
        let cheap = Feedback {
            coverage: Some(CoverageGain { new_edges: 2, new_buckets: 0, touched: 5 }),
            cost_micros: 500,
            ..Default::default()
        };
        let dear = Feedback {
            coverage: Some(CoverageGain { new_edges: 2, new_buckets: 0, touched: 5 }),
            cost_micros: 50_000,
            ..Default::default()
        };
        assert!(
            cheap.value_per_cost() > dear.value_per_cost(),
            "equal discovery at lower cost must score higher"
        );
    }

    #[test]
    fn value_per_cost_is_finite_for_an_instant_execution() {
        let f = Feedback {
            coverage: Some(CoverageGain { new_edges: 1, new_buckets: 0, touched: 1 }),
            cost_micros: 0,
            ..Default::default()
        };
        assert!(f.value_per_cost().is_finite(), "a floored cost must bound the ratio");
    }

    #[test]
    fn nothing_discovered_is_not_interesting() {
        let f = Feedback::default();
        assert!(!f.is_interesting());
        assert_eq!(f.value_per_cost(), 0.0);
    }
}
