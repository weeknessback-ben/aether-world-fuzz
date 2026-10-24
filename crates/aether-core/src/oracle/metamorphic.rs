//! Metamorphic oracle: transform the input, require the stated relation to hold.
//!
//! # Relations are declared, never inferred
//!
//! A metamorphic relation is a claim about the target: "appending a newline to
//! this input must not change what the program does." Whether that is true
//! depends entirely on what the program is, and AETHER cannot find out by
//! looking. So no relation is enabled by default, each one is named in
//! configuration, and each one documents the conditions under which it holds.
//!
//! This matters for how a violation reads. If a declared relation fails, there
//! are two possibilities with equal standing: the target is wrong, or the
//! relation does not hold for this target. The verdict reports both and
//! chooses neither.
//!
//! # Equivalence is on exit class, not on output
//!
//! A transformed input legitimately produces different output - append a
//! record and a well-behaved parser prints one more line. What these relations
//! assert is narrower and defensible: a transformation that preserves validity
//! must not turn a clean run into a crash or a hang. That is the property
//! worth testing and the one these relations check.

use crate::error::{Error, Result};
use crate::evidence::Severity;
use crate::exec::{ExecOutcome, ExitClass};

use super::{Oracle, OracleContext, OracleVerdict};

/// Transformations whose effect on the target is asserted by configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Re-run the input unchanged. The target must behave the same way.
    ///
    /// Valid for any deterministic target. A violation is worth knowing about
    /// on its own terms: a nondeterministic target undermines every
    /// reproduction-based claim the evidence engine makes.
    Determinism,
    /// Append a newline. Valid for line-oriented text input where a trailing
    /// newline is optional.
    TrailingNewline,
    /// Append three spaces. Valid for text input that ignores trailing
    /// whitespace.
    TrailingWhitespace,
    /// Concatenate the input with itself. Valid only for targets that accept a
    /// stream of self-delimiting records, where two copies is a longer valid
    /// stream.
    SelfConcatenation,
    /// Prepend nothing and append nothing, but pad the input to the next
    /// multiple of four with NUL bytes. Valid for targets whose format is
    /// length-prefixed, where trailing padding is outside the described
    /// length and must be ignored.
    NulPadding,
}

impl Relation {
    pub fn as_str(self) -> &'static str {
        match self {
            Relation::Determinism => "determinism",
            Relation::TrailingNewline => "trailing-newline",
            Relation::TrailingWhitespace => "trailing-whitespace",
            Relation::SelfConcatenation => "self-concatenation",
            Relation::NulPadding => "nul-padding",
        }
    }

    /// When believing this relation is justified. Printed in reports, so a
    /// reader can judge a violation without reading the source.
    pub fn validity(self) -> &'static str {
        match self {
            Relation::Determinism => {
                "Holds for any target that does not depend on time, randomness, \
                 uninitialised memory or external state."
            }
            Relation::TrailingNewline => {
                "Holds for line-oriented text input where a trailing newline is optional."
            }
            Relation::TrailingWhitespace => {
                "Holds for text input where trailing whitespace is insignificant."
            }
            Relation::SelfConcatenation => {
                "Holds only where the input format is a stream of self-delimiting records, \
                 so that two copies form a longer valid stream. It does not hold for a \
                 format with a single header or a total-length field."
            }
            Relation::NulPadding => {
                "Holds only where the format is length-prefixed and trailing bytes beyond \
                 the described length are ignored."
            }
        }
    }

    pub fn parse(name: &str) -> Result<Relation> {
        match name {
            "determinism" => Ok(Relation::Determinism),
            "trailing-newline" => Ok(Relation::TrailingNewline),
            "trailing-whitespace" => Ok(Relation::TrailingWhitespace),
            "self-concatenation" => Ok(Relation::SelfConcatenation),
            "nul-padding" => Ok(Relation::NulPadding),
            other => Err(Error::config(
                "oracles.metamorphic_relations",
                format!(
                    "unknown relation {other:?}; known relations: determinism, \
                     trailing-newline, trailing-whitespace, self-concatenation, nul-padding"
                ),
            )),
        }
    }

    pub fn parse_all(names: &[String]) -> Result<Vec<Relation>> {
        let mut out = Vec::new();
        for n in names {
            let r = Relation::parse(n)?;
            if !out.contains(&r) {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Apply the transformation, or `None` when it does not apply to this
    /// input - an empty input has no trailing whitespace to be insignificant.
    pub fn apply(self, input: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
        if input.is_empty() && self != Relation::Determinism {
            return None;
        }
        let out = match self {
            Relation::Determinism => input.to_vec(),
            Relation::TrailingNewline => {
                // Already newline-terminated: the transformation is a no-op
                // and would test nothing.
                if input.last() == Some(&b'\n') {
                    return None;
                }
                let mut v = input.to_vec();
                v.push(b'\n');
                v
            }
            Relation::TrailingWhitespace => {
                let mut v = input.to_vec();
                v.extend_from_slice(b"   ");
                v
            }
            Relation::SelfConcatenation => {
                let mut v = input.to_vec();
                v.extend_from_slice(input);
                v
            }
            Relation::NulPadding => {
                let pad = (4 - input.len() % 4) % 4;
                if pad == 0 {
                    return None;
                }
                let mut v = input.to_vec();
                v.resize(v.len() + pad, 0u8);
                v
            }
        };
        // A transformation that pushes the input past the configured limit
        // would be testing the limit, not the relation.
        if out.len() > max_bytes {
            return None;
        }
        Some(out)
    }
}

pub struct MetamorphicOracle {
    relations: Vec<Relation>,
    max_bytes: usize,
    /// Violations already reported, keyed by label, so one broken relation
    /// does not produce a finding per input.
    seen: std::collections::HashSet<String>,
}

impl MetamorphicOracle {
    pub fn new(relations: Vec<Relation>) -> Self {
        MetamorphicOracle {
            relations,
            // Raised by the campaign from configuration; a generous default so
            // a direct caller is not surprised by silent skips.
            max_bytes: 1 << 20,
            seen: std::collections::HashSet::new(),
        }
    }

    pub fn with_max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = max;
        self
    }

    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }
}

impl Oracle for MetamorphicOracle {
    fn id(&self) -> &str {
        "metamorphic"
    }

    fn describe(&self) -> String {
        format!(
            "Applies declared input transformations and requires the exit class to be \
             preserved. Declared relations: {}.",
            self.relations
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn cost_per_check(&self) -> u32 {
        // One run per relation, at most.
        self.relations.len().try_into().unwrap_or(u32::MAX)
    }

    fn check(
        &mut self,
        input: &[u8],
        primary: &ExecOutcome,
        ctx: &mut OracleContext<'_>,
    ) -> Result<Option<OracleVerdict>> {
        ctx.ensure_budget(1, self.id())?;

        // A relation says a *valid* input stays valid. An input that already
        // crashed or hung says nothing about preservation, and transforming it
        // would only produce another crash to report twice.
        if primary.class != ExitClass::Ok && primary.class != ExitClass::NonZeroExit {
            return Ok(None);
        }

        let mut used = 0u32;
        for &relation in &self.relations {
            if used >= ctx.budget {
                break;
            }
            let Some(transformed) = relation.apply(input, self.max_bytes) else {
                continue;
            };
            let after = ctx.primary.run(&transformed)?;
            used += 1;

            // A transformation that makes the input slower is not a violation
            // of the relation: it is a longer input against a fixed deadline.
            // The exception is determinism, where the input is byte-identical
            // and a timeout really is the target behaving differently.
            if after.class == ExitClass::Timeout && relation != Relation::Determinism {
                continue;
            }
            if after.class == primary.class {
                continue;
            }
            // Clean and non-zero exit are both "the target rejected or
            // accepted this input without failing". A parser that returns 0
            // for one and 2 for the other has not failed a preservation
            // relation, so only a move out of that pair counts.
            if matches!(after.class, ExitClass::Ok | ExitClass::NonZeroExit) {
                continue;
            }

            let label = format!(
                "metamorphic relation {} not preserved ({} became {})",
                relation.as_str(),
                primary.class.as_str(),
                after.class.as_str()
            );
            if !self.seen.insert(label.clone()) {
                continue;
            }

            let severity = if after.sanitizer.is_some() {
                Severity::MemorySafety
            } else if after.class.is_candidate_failure() {
                crate::evidence::Finding::severity_for(after.class, None)
            } else {
                Severity::InvariantViolation
            };

            return Ok(Some(OracleVerdict {
                oracle: self.id().to_string(),
                relation: relation.as_str().to_string(),
                label,
                observed: vec![
                    format!(
                        "the original {}-byte input exited {}",
                        input.len(),
                        primary.class.as_str()
                    ),
                    format!(
                        "after applying `{}` the {}-byte input exited {}",
                        relation.as_str(),
                        transformed.len(),
                        after.class.as_str()
                    ),
                    format!("relation validity: {}", relation.validity()),
                ],
                interpretations: vec![
                    "The target mishandles the transformed input.".to_string(),
                    format!(
                        "The relation `{}` does not hold for this target, and declaring it \
                         was a mistake in the campaign configuration rather than a defect \
                         in the target.",
                        relation.as_str()
                    ),
                ],
                severity,
                executions_used: used,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn outcome(class: ExitClass) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: Some(0),
            signal: None,
            duration: Duration::from_millis(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: None,
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    /// Crashes only on inputs matching a predicate, so a relation can be made
    /// to fail deliberately.
    struct Conditional<F: Fn(&[u8]) -> ExitClass + Send> {
        classify: F,
        runs: u64,
    }

    impl<F: Fn(&[u8]) -> ExitClass + Send> crate::exec::Executor for Conditional<F> {
        fn run(&mut self, input: &[u8]) -> Result<ExecOutcome> {
            self.runs += 1;
            Ok(outcome((self.classify)(input)))
        }
        fn capabilities(&self) -> &crate::exec::ExecutorCapabilities {
            unreachable!("not used by the metamorphic comparison")
        }
        fn exec_count(&self) -> u64 {
            self.runs
        }
    }

    fn run_check<F: Fn(&[u8]) -> ExitClass + Send>(
        o: &mut MetamorphicOracle,
        input: &[u8],
        primary: ExitClass,
        f: F,
    ) -> Option<OracleVerdict> {
        let mut exec = Conditional {
            classify: f,
            runs: 0,
        };
        let mut ctx = OracleContext {
            primary: &mut exec,
            peer: None,
            budget: 16,
        };
        o.check(input, &outcome(primary), &mut ctx).expect("check")
    }

    #[test]
    fn relation_names_round_trip() {
        for r in [
            Relation::Determinism,
            Relation::TrailingNewline,
            Relation::TrailingWhitespace,
            Relation::SelfConcatenation,
            Relation::NulPadding,
        ] {
            assert_eq!(Relation::parse(r.as_str()).expect("parse"), r);
            assert!(
                !r.validity().is_empty(),
                "every relation states its validity"
            );
        }
        assert!(Relation::parse("wishful-thinking").is_err());
    }

    #[test]
    fn parse_all_drops_duplicates_and_rejects_unknowns() {
        let rs = Relation::parse_all(&[
            "determinism".into(),
            "determinism".into(),
            "nul-padding".into(),
        ])
        .expect("parse");
        assert_eq!(rs, vec![Relation::Determinism, Relation::NulPadding]);
        assert!(Relation::parse_all(&["nope".into()]).is_err());
    }

    #[test]
    fn transformations_skip_where_they_would_test_nothing() {
        // Already newline-terminated: appending another tests a different
        // input, not the relation.
        assert!(Relation::TrailingNewline.apply(b"line\n", 100).is_none());
        assert_eq!(
            Relation::TrailingNewline.apply(b"line", 100),
            Some(b"line\n".to_vec())
        );
        // Already aligned: there is no padding to ignore.
        assert!(Relation::NulPadding.apply(b"abcd", 100).is_none());
        assert_eq!(
            Relation::NulPadding.apply(b"abc", 100),
            Some(b"abc\0".to_vec())
        );
        // An empty input has no trailing anything.
        assert!(Relation::TrailingWhitespace.apply(b"", 100).is_none());
        // Determinism applies even to an empty input.
        assert_eq!(Relation::Determinism.apply(b"", 100), Some(Vec::new()));
        // A transformation past the size limit would test the limit.
        assert!(Relation::SelfConcatenation.apply(b"abcdef", 8).is_none());
    }

    #[test]
    fn a_preserved_relation_produces_no_verdict() {
        let mut o =
            MetamorphicOracle::new(vec![Relation::TrailingNewline, Relation::SelfConcatenation]);
        assert!(run_check(&mut o, b"data", ExitClass::Ok, |_| ExitClass::Ok).is_none());
    }

    #[test]
    fn a_crash_after_a_declared_transformation_is_reported() {
        let mut o = MetamorphicOracle::new(vec![Relation::TrailingNewline]);
        let v = run_check(&mut o, b"data", ExitClass::Ok, |i| {
            if i.ends_with(b"\n") {
                ExitClass::Crash
            } else {
                ExitClass::Ok
            }
        })
        .expect("violation");
        assert_eq!(v.relation, "trailing-newline");
        assert!(v.observed.iter().any(|s| s.contains("relation validity")));
        // Both readings must be offered: the target may be wrong, or the
        // declared relation may not hold.
        assert_eq!(v.interpretations.len(), 2);
        assert!(v.interpretations[1].contains("does not hold for this target"));
    }

    #[test]
    fn an_input_that_already_failed_is_not_checked() {
        let mut o = MetamorphicOracle::new(vec![Relation::Determinism]);
        assert!(
            run_check(&mut o, b"data", ExitClass::Crash, |_| ExitClass::Crash).is_none(),
            "preservation says nothing about an input that already crashed"
        );
    }

    #[test]
    fn moving_between_clean_and_nonzero_exit_is_not_a_violation() {
        let mut o = MetamorphicOracle::new(vec![Relation::TrailingWhitespace]);
        assert!(
            run_check(&mut o, b"data", ExitClass::Ok, |i| {
                if i.ends_with(b"   ") {
                    ExitClass::NonZeroExit
                } else {
                    ExitClass::Ok
                }
            })
            .is_none(),
            "a parser rejecting the padded input has not failed preservation"
        );
    }

    #[test]
    fn a_timeout_is_excused_for_a_longer_input_but_not_for_determinism() {
        // A longer input against a fixed deadline is not a relation failure.
        let mut o = MetamorphicOracle::new(vec![Relation::SelfConcatenation]);
        assert!(run_check(&mut o, b"data", ExitClass::Ok, |i| {
            if i.len() > 4 {
                ExitClass::Timeout
            } else {
                ExitClass::Ok
            }
        })
        .is_none());

        // Determinism re-runs the identical bytes, so a timeout there is the
        // target genuinely behaving differently.
        let mut o = MetamorphicOracle::new(vec![Relation::Determinism]);
        let v = run_check(&mut o, b"data", ExitClass::Ok, |_| ExitClass::Timeout)
            .expect("nondeterminism is a real finding");
        assert_eq!(v.relation, "determinism");
    }

    #[test]
    fn the_same_broken_relation_is_reported_once() {
        let mut o = MetamorphicOracle::new(vec![Relation::TrailingNewline]);
        let f = |i: &[u8]| {
            if i.ends_with(b"\n") {
                ExitClass::Crash
            } else {
                ExitClass::Ok
            }
        };
        assert!(run_check(&mut o, b"one", ExitClass::Ok, f).is_some());
        assert!(
            run_check(&mut o, b"two", ExitClass::Ok, f).is_none(),
            "one broken relation must not produce a finding per input"
        );
    }

    #[test]
    fn cost_is_one_execution_per_relation() {
        let o = MetamorphicOracle::new(vec![Relation::Determinism, Relation::NulPadding]);
        assert_eq!(o.cost_per_check(), 2);
    }
}
