//! Oracles: the checks that turn an observation into a reason to look closer.
//!
//! An oracle is not a strategy. A strategy proposes inputs; an oracle decides
//! whether what happened to one is wrong. Differential and metamorphic testing
//! both belong here because neither generates input - both take an input that
//! already ran and ask a further question about it.
//!
//! # They cost executions, and the cost is counted
//!
//! Every oracle check runs the target again: a differential check runs the
//! peer implementation, a metamorphic check runs a transformed input. That
//! compute comes out of the campaign's budget, so each oracle declares
//! [`Oracle::cost_per_check`] and the campaign caps how much of its budget
//! oracles may spend. The spend is reported, not absorbed silently.
//!
//! # A violation is a finding to investigate, not a vulnerability
//!
//! An oracle reports what it observed and which claim failed. It does not
//! assign exploitability or impact. A metamorphic violation in particular has
//! two readings - the target is wrong, or the declared relation does not hold
//! for this target - and the verdict says so rather than picking one.

pub mod differential;
pub mod metamorphic;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::evidence::Severity;
use crate::exec::{ExecOutcome, Executor};

/// What an oracle concluded about one input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleVerdict {
    /// Which oracle spoke.
    pub oracle: String,
    /// The specific claim that failed, e.g. `exit-class` or `trailing-newline`.
    pub relation: String,
    /// A short, stable label - this is what the finding signature is built on,
    /// so it must not contain anything run-specific.
    pub label: String,
    /// Observed facts only. No hypothesis about cause, no severity reasoning.
    pub observed: Vec<String>,
    /// What the failure could mean, stated as alternatives rather than as a
    /// conclusion. Kept separate from `observed` so a report can show the line
    /// between what was measured and what it might imply.
    pub interpretations: Vec<String>,
    pub severity: Severity,
    /// Executions this check consumed.
    pub executions_used: u32,
}

/// Executors an oracle may use, and the budget it may use them within.
pub struct OracleContext<'a> {
    /// The target under test.
    pub primary: &'a mut dyn Executor,
    /// The second implementation, when the target is configured as a
    /// differential pair. `None` means a differential oracle cannot run -
    /// which it reports, rather than comparing the target against itself.
    pub peer: Option<&'a mut dyn Executor>,
    /// Executions this check may spend. An oracle must not exceed it.
    pub budget: u32,
}

impl OracleContext<'_> {
    fn ensure_budget(&self, need: u32, oracle: &str) -> Result<()> {
        if self.budget < need {
            return Err(Error::exec(
                oracle,
                format!(
                    "oracle needs {need} executions but only {} are budgeted",
                    self.budget
                ),
            ));
        }
        Ok(())
    }
}

pub trait Oracle: Send {
    fn id(&self) -> &str;

    /// What this oracle checks, and when it is valid to believe it.
    fn describe(&self) -> String;

    /// Executions one check costs at most. Used to budget, before spending.
    fn cost_per_check(&self) -> u32;

    /// Check one input that has already run.
    ///
    /// `Ok(None)` means the check passed or could not be made; a check that
    /// could not be made says so through [`Oracle::unavailable`] rather than
    /// being reported as a pass.
    fn check(
        &mut self,
        input: &[u8],
        primary: &ExecOutcome,
        ctx: &mut OracleContext<'_>,
    ) -> Result<Option<OracleVerdict>>;

    /// Why this oracle cannot run here, if it cannot. `None` means available.
    fn unavailable(&self, has_peer: bool) -> Option<String> {
        let _ = has_peer;
        None
    }
}

/// How much of a campaign's compute oracles may take, and what they spent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OracleBudget {
    /// Executions oracles are allowed in total. Zero disables them.
    pub allowance: u64,
    pub spent: u64,
    /// Checks that ran.
    pub checks: u64,
    /// Checks skipped because the allowance was exhausted. Reported, so a
    /// reader knows the oracle coverage was partial rather than complete.
    pub skipped_no_budget: u64,
}

impl OracleBudget {
    /// Budget oracles at `fraction` of the campaign's execution budget.
    ///
    /// A fraction rather than a count, because the right spend scales with the
    /// campaign: an oracle that eats a fixed 10,000 executions is free in a
    /// long campaign and the whole budget in a short one.
    pub fn from_fraction(total_execs: u64, fraction: f64) -> Self {
        let f = fraction.clamp(0.0, 1.0);
        OracleBudget {
            allowance: (total_execs as f64 * f) as u64,
            ..Default::default()
        }
    }

    pub fn remaining(&self) -> u64 {
        self.allowance.saturating_sub(self.spent)
    }

    /// Reserve `n` executions, or refuse. Refusal is counted.
    pub fn reserve(&mut self, n: u32) -> bool {
        if self.remaining() < u64::from(n) {
            self.skipped_no_budget += 1;
            false
        } else {
            self.spent += u64::from(n);
            self.checks += 1;
            true
        }
    }

    /// Give back what a check reserved but did not use, so an oracle that
    /// exits early does not consume the whole reservation.
    pub fn refund(&mut self, reserved: u32, used: u32) {
        self.spent = self
            .spent
            .saturating_sub(u64::from(reserved.saturating_sub(used)));
    }

    /// Fraction of the allowance used, or `None` when oracles are disabled -
    /// which is not the same as an allowance that went unused.
    pub fn utilisation(&self) -> Option<f64> {
        if self.allowance == 0 {
            None
        } else {
            Some(self.spent as f64 / self.allowance as f64)
        }
    }
}

/// The oracles that can run, and the ones that cannot with their reasons.
pub type BuiltOracles = (Vec<Box<dyn Oracle>>, Vec<(String, String)>);

/// Build the oracles named in configuration.
///
/// Returns the usable oracles and, separately, the ones that were asked for
/// but cannot run here with the reason - so a campaign reports a missing
/// oracle instead of quietly running without it.
pub fn build(enabled: &[String], relations: &[String], has_peer: bool) -> Result<BuiltOracles> {
    let mut built: Vec<Box<dyn Oracle>> = Vec::new();
    let mut unavailable = Vec::new();

    for name in enabled {
        let oracle: Box<dyn Oracle> = match name.as_str() {
            "differential" => Box::new(differential::DifferentialOracle::new()),
            "metamorphic" => {
                let rels = metamorphic::Relation::parse_all(relations)?;
                if rels.is_empty() {
                    unavailable.push((
                        name.clone(),
                        "no metamorphic relations were declared. A metamorphic relation is a \
                         claim about the target that AETHER cannot infer, so none is assumed \
                         by default; set oracles.metamorphic_relations to declare which hold."
                            .to_string(),
                    ));
                    continue;
                }
                Box::new(metamorphic::MetamorphicOracle::new(rels))
            }
            other => {
                return Err(Error::config(
                    "oracles.enabled",
                    format!("unknown oracle {other:?}; known oracles: differential, metamorphic"),
                ))
            }
        };
        match oracle.unavailable(has_peer) {
            Some(reason) => unavailable.push((name.clone(), reason)),
            None => built.push(oracle),
        }
    }
    Ok((built, unavailable))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_refuses_once_the_allowance_is_gone_and_says_so() {
        let mut b = OracleBudget::from_fraction(1000, 0.1);
        assert_eq!(b.allowance, 100);
        for _ in 0..50 {
            assert!(b.reserve(2), "should fit inside the allowance");
        }
        assert_eq!(b.spent, 100);
        assert!(!b.reserve(1), "allowance is exhausted");
        assert_eq!(b.skipped_no_budget, 1, "a refusal must be counted");
        assert_eq!(b.checks, 50);
    }

    #[test]
    fn a_disabled_budget_reports_no_utilisation_rather_than_zero() {
        let off = OracleBudget::from_fraction(1000, 0.0);
        assert_eq!(off.allowance, 0);
        assert_eq!(
            off.utilisation(),
            None,
            "disabled must be distinguishable from unused"
        );
        let mut on = OracleBudget::from_fraction(1000, 0.5);
        assert_eq!(on.utilisation(), Some(0.0), "unused is a real zero");
        on.reserve(250);
        assert_eq!(on.utilisation(), Some(0.5));
    }

    #[test]
    fn a_fraction_outside_the_unit_interval_is_clamped_not_trusted() {
        assert_eq!(OracleBudget::from_fraction(100, 2.0).allowance, 100);
        assert_eq!(OracleBudget::from_fraction(100, -1.0).allowance, 0);
    }

    #[test]
    fn refund_returns_what_a_check_did_not_use() {
        let mut b = OracleBudget::from_fraction(1000, 1.0);
        assert!(b.reserve(4));
        assert_eq!(b.spent, 4);
        b.refund(4, 1);
        assert_eq!(b.spent, 1, "three unused executions must come back");
        // A refund must never push the spend below zero.
        b.refund(100, 0);
        assert_eq!(b.spent, 0);
    }

    #[test]
    fn metamorphic_without_declared_relations_is_unavailable_not_silent() {
        let (built, unavailable) = build(&["metamorphic".to_string()], &[], false).expect("build");
        assert!(built.is_empty());
        assert_eq!(unavailable.len(), 1);
        assert!(
            unavailable[0].1.contains("no metamorphic relations"),
            "reason should name the missing declaration: {}",
            unavailable[0].1
        );
    }

    #[test]
    fn differential_without_a_peer_is_unavailable_not_self_compared() {
        let (built, unavailable) = build(&["differential".to_string()], &[], false).expect("build");
        assert!(
            built.is_empty(),
            "a differential oracle with no peer must not be built"
        );
        assert_eq!(unavailable.len(), 1);

        let (built, unavailable) = build(&["differential".to_string()], &[], true).expect("build");
        assert_eq!(built.len(), 1);
        assert!(unavailable.is_empty());
    }

    #[test]
    fn an_unknown_oracle_is_an_error_not_a_skip() {
        let Err(e) = build(&["psychic".to_string()], &[], true) else {
            panic!("an unknown oracle name must be refused, not ignored");
        };
        assert!(e.to_string().contains("psychic"), "{e}");
    }
}
