//! Differential oracle: two implementations, one input, one question.
//!
//! # What is compared, and what is not
//!
//! Compared: the exit class, the exit code and standard output. Those are the
//! parts of a run two implementations of the same specification are supposed
//! to agree on.
//!
//! Not compared: standard error, timing, or the coverage map. Diagnostics
//! legitimately differ between implementations - different wording, different
//! verbosity, a different compiler's assertion text - and a build flag can
//! change them without any behavioural difference at all. Comparing them would
//! produce a stream of findings that say nothing about either implementation.
//! Timing differs for the same reason and more so.
//!
//! That choice is a limitation, not a subtlety to leave implied: an
//! implementation that differs *only* in a diagnostic message will not be
//! flagged here.

use crate::error::Result;
use crate::evidence::{Finding, Severity};
use crate::exec::{ExecOutcome, ExitClass};

use super::{Oracle, OracleContext, OracleVerdict};

/// How much of a differing output to quote in the verdict.
const OUTPUT_EXCERPT: usize = 120;

pub struct DifferentialOracle {
    /// Divergences already reported, so the same disagreement does not produce
    /// a finding for every input that exhibits it.
    seen: std::collections::HashSet<String>,
}

impl Default for DifferentialOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl DifferentialOracle {
    pub fn new() -> Self {
        DifferentialOracle {
            seen: std::collections::HashSet::new(),
        }
    }
}

impl Oracle for DifferentialOracle {
    fn id(&self) -> &str {
        "differential"
    }

    fn describe(&self) -> String {
        "Runs a second implementation on the same input and reports a disagreement in exit \
         class, exit code or standard output. Standard error and timing are not compared: \
         they differ legitimately between implementations."
            .to_string()
    }

    fn cost_per_check(&self) -> u32 {
        // One run of the peer. The primary outcome is already in hand.
        1
    }

    fn unavailable(&self, has_peer: bool) -> Option<String> {
        if has_peer {
            None
        } else {
            Some(
                "No second implementation is configured. Set target.kind = \"differential\" \
                 and target.differential_binary to the peer binary. A differential oracle \
                 with one implementation would be comparing the target against itself."
                    .to_string(),
            )
        }
    }

    fn check(
        &mut self,
        input: &[u8],
        primary: &ExecOutcome,
        ctx: &mut OracleContext<'_>,
    ) -> Result<Option<OracleVerdict>> {
        ctx.ensure_budget(self.cost_per_check(), self.id())?;
        let Some(peer) = ctx.peer.as_mut() else {
            // Not an error: the oracle was built, the peer went away. Reported
            // as "no check made" rather than as a pass.
            return Ok(None);
        };
        let other = peer.run(input)?;

        // A timeout on either side is a property of the deadline, not of a
        // disagreement between implementations: a peer built without
        // optimisation can exceed a budget the primary meets. Not a finding.
        if primary.class == ExitClass::Timeout || other.class == ExitClass::Timeout {
            return Ok(None);
        }

        let mut observed = Vec::new();
        let mut relation = None;

        if primary.class != other.class {
            relation = Some("exit-class");
            observed.push(format!(
                "primary exited {} and the peer exited {}",
                primary.class.as_str(),
                other.class.as_str()
            ));
        } else if primary.exit_code != other.exit_code {
            relation = Some("exit-code");
            observed.push(format!(
                "both exited normally but with different codes: primary {:?}, peer {:?}",
                primary.exit_code, other.exit_code
            ));
        } else if primary.stdout != other.stdout {
            // Truncated output cannot be compared honestly: the difference may
            // be entirely past the cut.
            if primary.stdout_truncated || other.stdout_truncated {
                return Ok(None);
            }
            relation = Some("stdout");
            observed.push(format!(
                "identical exit status but different output: primary {} bytes, peer {} bytes",
                primary.stdout.len(),
                other.stdout.len()
            ));
            observed.push(format!(
                "primary output began {:?}",
                excerpt(&primary.stdout)
            ));
            observed.push(format!("peer output began {:?}", excerpt(&other.stdout)));
            if let Some(at) = first_difference(&primary.stdout, &other.stdout) {
                observed.push(format!("outputs first differ at byte {at}"));
            }
        }

        let Some(relation) = relation else {
            return Ok(None);
        };

        // The label must be stable across inputs, because the finding
        // signature is built from it. The specific bytes go in `observed`.
        let label = format!(
            "differential {relation} disagreement ({} vs {})",
            primary.class.as_str(),
            other.class.as_str()
        );
        if !self.seen.insert(label.clone()) {
            // Already reported. Spending reproduction effort on the same
            // disagreement for every input that shows it buys nothing.
            return Ok(None);
        }

        // A crash on either side is a crash first and a disagreement second:
        // the severity follows the evidence, and a sanitizer report is the
        // strongest evidence present.
        let severity = if primary.sanitizer.is_some() || other.sanitizer.is_some() {
            Severity::MemorySafety
        } else if primary.class.is_candidate_failure() || other.class.is_candidate_failure() {
            Finding::severity_for(
                if primary.class.is_candidate_failure() {
                    primary.class
                } else {
                    other.class
                },
                None,
            )
        } else {
            Severity::BehaviouralDifference
        };

        Ok(Some(OracleVerdict {
            oracle: self.id().to_string(),
            relation: relation.to_string(),
            label,
            observed,
            interpretations: vec![
                "One of the two implementations is wrong for this input.".to_string(),
                "Both are behaving as their authors intended and the specification they \
                 share does not determine this case."
                    .to_string(),
                "The two binaries were built from different versions or with different \
                 options, and the difference is a configuration artefact."
                    .to_string(),
            ],
            severity,
            executions_used: 1,
        }))
    }
}

fn excerpt(b: &[u8]) -> String {
    let cut = b.len().min(OUTPUT_EXCERPT);
    let s = String::from_utf8_lossy(&b[..cut]).to_string();
    if b.len() > cut {
        format!("{s}... ({} bytes total)", b.len())
    } else {
        s
    }
}

/// Index of the first differing byte, or `None` when one is a prefix of the
/// other - in which case the length difference is the whole story and is
/// already reported.
fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn outcome(class: ExitClass, code: Option<i32>, stdout: &[u8]) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: code,
            signal: None,
            duration: Duration::from_millis(1),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: None,
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    /// A peer that replays a fixed outcome, so the comparison logic can be
    /// tested without a second binary.
    struct FixedPeer {
        outcome: ExecOutcome,
        runs: u64,
    }

    impl FixedPeer {
        fn new(outcome: ExecOutcome) -> Self {
            FixedPeer { outcome, runs: 0 }
        }
    }

    impl crate::exec::Executor for FixedPeer {
        fn run(&mut self, _input: &[u8]) -> Result<ExecOutcome> {
            self.runs += 1;
            Ok(self.outcome.clone())
        }
        fn capabilities(&self) -> &crate::exec::ExecutorCapabilities {
            unreachable!("not used by the differential comparison")
        }
        fn exec_count(&self) -> u64 {
            self.runs
        }
    }

    fn check(
        o: &mut DifferentialOracle,
        primary: &ExecOutcome,
        peer: ExecOutcome,
    ) -> Option<OracleVerdict> {
        let mut p = FixedPeer::new(peer);
        let mut primary_exec = FixedPeer::new(primary.clone());
        let mut ctx = OracleContext {
            primary: &mut primary_exec,
            peer: Some(&mut p),
            budget: 8,
        };
        o.check(b"input", primary, &mut ctx).expect("check")
    }

    #[test]
    fn agreement_produces_no_verdict() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(0), b"same");
        assert!(check(&mut o, &a, a.clone()).is_none());
    }

    #[test]
    fn a_differing_exit_class_is_reported_with_both_observations() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(0), b"");
        let b = outcome(ExitClass::Crash, None, b"");
        let v = check(&mut o, &a, b).expect("divergence");
        assert_eq!(v.relation, "exit-class");
        // A crash on either side is a crash first, not merely a difference.
        assert_ne!(v.severity, Severity::BehaviouralDifference);
        assert!(v.observed.iter().any(|s| s.contains("primary exited")));
        // The reading is offered as alternatives, never as a conclusion.
        assert!(v.interpretations.len() > 1);
    }

    #[test]
    fn a_differing_exit_code_alone_is_a_behavioural_difference() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(1), b"");
        let b = outcome(ExitClass::Ok, Some(2), b"");
        let v = check(&mut o, &a, b).expect("divergence");
        assert_eq!(v.relation, "exit-code");
        assert_eq!(v.severity, Severity::BehaviouralDifference);
    }

    #[test]
    fn differing_output_reports_where_it_first_differs() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(0), b"hello world");
        let b = outcome(ExitClass::Ok, Some(0), b"hello WORLD");
        let v = check(&mut o, &a, b).expect("divergence");
        assert_eq!(v.relation, "stdout");
        assert!(
            v.observed.iter().any(|s| s.contains("byte 6")),
            "should locate the difference: {:?}",
            v.observed
        );
    }

    #[test]
    fn the_same_disagreement_is_reported_once() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(1), b"");
        let b = outcome(ExitClass::Ok, Some(2), b"");
        assert!(check(&mut o, &a, b.clone()).is_some());
        assert!(
            check(&mut o, &a, b).is_none(),
            "a repeat of the same divergence must not produce a second finding"
        );
    }

    #[test]
    fn a_timeout_on_either_side_is_not_a_disagreement() {
        let mut o = DifferentialOracle::new();
        let clean = outcome(ExitClass::Ok, Some(0), b"");
        let slow = outcome(ExitClass::Timeout, None, b"");
        assert!(
            check(&mut o, &clean, slow.clone()).is_none(),
            "a peer that is merely slower is not a behavioural difference"
        );
        assert!(check(&mut o, &slow, clean).is_none());
    }

    #[test]
    fn truncated_output_is_not_compared() {
        let mut o = DifferentialOracle::new();
        let mut a = outcome(ExitClass::Ok, Some(0), b"abc");
        a.stdout_truncated = true;
        let b = outcome(ExitClass::Ok, Some(0), b"abcdef");
        assert!(
            check(&mut o, &a, b).is_none(),
            "a difference past the capture limit cannot be established"
        );
    }

    #[test]
    fn a_check_without_budget_is_an_error_not_a_silent_pass() {
        let mut o = DifferentialOracle::new();
        let a = outcome(ExitClass::Ok, Some(0), b"");
        let mut peer = FixedPeer::new(a.clone());
        let mut primary = FixedPeer::new(a.clone());
        let mut ctx = OracleContext {
            primary: &mut primary,
            peer: Some(&mut peer),
            budget: 0,
        };
        assert!(o.check(b"i", &a, &mut ctx).is_err());
    }

    #[test]
    fn first_difference_is_none_when_one_is_a_prefix() {
        assert_eq!(first_difference(b"abc", b"abcdef"), None);
        assert_eq!(first_difference(b"abc", b"abd"), Some(2));
    }
}
