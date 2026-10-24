//! Reproduction and minimisation of candidate findings.
//!
//! The pipeline that decides whether a candidate is a defect. Two rules do the
//! real work:
//!
//! * **Reproduction counts, it does not assume.** The input is re-run the
//!   configured number of times and the successes are counted. The status
//!   follows from the counts, through
//!   [`ReproductionRecord::implied_status`](super::ReproductionRecord::implied_status).
//! * **Minimisation preserves the signature.** The predicate is "the same
//!   signature still occurs", not "something still crashes". Shrinking one
//!   defect into a different one would attach the wrong evidence to the
//!   finding, which is worse than not minimising at all.

use crate::config::ReproductionConfig;
use crate::corpus::minimize::{self, MinimizeOutcome};
use crate::error::Result;
use crate::exec::Executor;

use super::signature::{signature_for, Signature};
use super::ReproductionRecord;

/// Outcome of re-running a candidate input.
#[derive(Debug, Clone)]
pub struct ReproductionOutcome {
    pub record: ReproductionRecord,
    /// Signature seen most often across the attempts.
    pub dominant_signature: Option<Signature>,
    /// Signatures other than the dominant one, with counts. A candidate that
    /// produces several distinct failures is worth knowing about: it usually
    /// means memory corruption whose symptom varies between runs.
    pub other_signatures: Vec<(Signature, u32)>,
    /// Attempts where the target did not fail at all.
    pub clean_runs: u32,
}

/// Re-run `input` and count how often the expected signature recurs.
///
/// When `expected` is given, only that signature counts as a success; a
/// different failure is recorded separately rather than counted. That keeps a
/// finding's reproduction rate about *that* finding.
pub fn reproduce(
    executor: &mut dyn Executor,
    input: &[u8],
    expected: Option<&Signature>,
    cfg: &ReproductionConfig,
) -> Result<ReproductionOutcome> {
    let mut successes = 0u32;
    let mut clean_runs = 0u32;
    let mut counts: Vec<(Signature, u32)> = Vec::new();

    for _ in 0..cfg.attempts {
        let outcome = executor.run(input)?;
        match signature_for(&outcome) {
            None => clean_runs += 1,
            Some(sig) => {
                let matches_expected = expected.map(|e| e.hash == sig.hash).unwrap_or(true);
                if matches_expected {
                    successes += 1;
                }
                match counts.iter_mut().find(|(s, _)| s.hash == sig.hash) {
                    Some((_, n)) => *n += 1,
                    None => counts.push((sig, 1)),
                }
            }
        }
    }

    // Most frequently observed signature, as the finding's identity.
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    let dominant = counts.first().map(|(s, _)| s.clone());
    let others = if counts.len() > 1 { counts[1..].to_vec() } else { Vec::new() };

    Ok(ReproductionOutcome {
        record: ReproductionRecord {
            attempts: cfg.attempts,
            successes,
            required: cfg.required_successes,
            minimized_validated: false,
            minimize_execs: 0,
            used_oracle_binary: false,
        },
        dominant_signature: dominant,
        other_signatures: others,
        clean_runs,
    })
}

/// Minimise `input` while the same signature keeps occurring.
///
/// Returns the minimisation outcome and whether the minimised input was
/// re-validated afterwards. Re-validation is not a formality: the minimiser's
/// own predicate checks run in the middle of a reduction sequence, and a final
/// independent check is what confirms the result is genuinely still the finding.
pub fn minimize_for_signature(
    executor: &mut dyn Executor,
    input: &[u8],
    expected: &Signature,
    cfg: &ReproductionConfig,
) -> Result<(MinimizeOutcome, bool)> {
    // The minimiser cannot propagate an error out of its predicate, so an
    // execution failure is recorded here and surfaced afterwards.
    let mut exec_error: Option<crate::error::Error> = None;

    let outcome = minimize::minimize(input, cfg.minimize_max_execs, |candidate| {
        if exec_error.is_some() {
            return false;
        }
        match executor.run(candidate) {
            Ok(o) => signature_for(&o).map(|s| s.hash == expected.hash).unwrap_or(false),
            Err(e) => {
                exec_error = Some(e);
                false
            }
        }
    });

    if let Some(e) = exec_error {
        return Err(e);
    }

    // Independent re-validation of the final result.
    let validated = {
        let o = executor.run(&outcome.input)?;
        signature_for(&o).map(|s| s.hash == expected.hash).unwrap_or(false)
    };

    Ok((outcome, validated))
}

/// Deduplication decision for a new signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupDecision {
    /// Not seen before.
    New,
    /// Same signature as an existing finding.
    Duplicate(crate::ids::FindingId),
}

/// Decide whether `signature` duplicates one of `existing`.
///
/// An exact signature-hash match, nothing fuzzier. A heuristic "looks similar"
/// rule would merge distinct defects, and the cost of that - a defect never
/// reported because it was folded into another - is worse than the cost of
/// listing one defect twice.
pub fn deduplicate(
    signature: &Signature,
    existing: &[(crate::ids::FindingId, String)],
) -> DedupDecision {
    for (id, hash) in existing {
        if *hash == signature.hash {
            return DedupDecision::Duplicate(id.clone());
        }
    }
    DedupDecision::New
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sanitizer::{SanitizerKind, SanitizerReport};
    use crate::exec::{ExecOutcome, ExecutorCapabilities, ExitClass};
    use crate::ids::FindingId;
    use std::time::Duration;

    /// Executor stub with programmable behaviour, so reproduction logic can be
    /// tested without a real target.
    struct StubExecutor {
        caps: ExecutorCapabilities,
        count: u64,
        /// Decides the outcome for a given input and call index.
        behaviour: Box<dyn FnMut(&[u8], u64) -> ExecOutcome + Send>,
    }

    impl StubExecutor {
        fn new(behaviour: impl FnMut(&[u8], u64) -> ExecOutcome + Send + 'static) -> Self {
            StubExecutor {
                caps: ExecutorCapabilities {
                    backend: "stub".into(),
                    edge_coverage: false,
                    comparison_log: false,
                    sanitizer_oracle: true,
                    fork_server: false,
                    memory_limit: false,
                    limitations: Vec::new(),
                },
                count: 0,
                behaviour: Box::new(behaviour),
            }
        }
    }

    impl Executor for StubExecutor {
        fn run(&mut self, input: &[u8]) -> Result<ExecOutcome> {
            let i = self.count;
            self.count += 1;
            Ok((self.behaviour)(input, i))
        }
        fn capabilities(&self) -> &ExecutorCapabilities {
            &self.caps
        }
        fn exec_count(&self) -> u64 {
            self.count
        }
    }

    fn outcome(class: ExitClass, signal: Option<i32>, fault: Option<&str>) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: if signal.is_some() { None } else { Some(0) },
            signal,
            duration: Duration::from_millis(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: fault.map(|f| SanitizerReport {
                kind: SanitizerKind::Address,
                fault: f.to_string(),
                access: Some("write".into()),
                access_size: Some(4),
                frames: vec!["parse".into()],
                summary: String::new(),
            }),
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    fn crash() -> ExecOutcome {
        outcome(ExitClass::Crash, Some(libc::SIGABRT), None)
    }
    fn clean() -> ExecOutcome {
        outcome(ExitClass::Ok, None, None)
    }

    fn cfg(attempts: u32, required: u32) -> ReproductionConfig {
        ReproductionConfig {
            attempts,
            required_successes: required,
            minimize: true,
            minimize_max_execs: 2000,
            use_oracle_binary: false,
        }
    }

    #[test]
    fn a_reliable_crash_reproduces_every_attempt() {
        let mut e = StubExecutor::new(|_, _| crash());
        let r = reproduce(&mut e, b"input", None, &cfg(5, 3)).unwrap();
        assert_eq!(r.record.attempts, 5);
        assert_eq!(r.record.successes, 5);
        assert_eq!(r.record.implied_status(), super::super::FindingStatus::Reproducible);
        assert_eq!(r.clean_runs, 0);
    }

    #[test]
    fn a_flaky_crash_is_counted_not_rounded_up() {
        // Crashes on every third call only.
        let mut e = StubExecutor::new(|_, i| if i % 3 == 0 { crash() } else { clean() });
        let r = reproduce(&mut e, b"input", None, &cfg(9, 5)).unwrap();
        assert_eq!(r.record.successes, 3, "should count exactly the crashing runs");
        assert_eq!(r.clean_runs, 6);
        assert_eq!(
            r.record.implied_status(),
            super::super::FindingStatus::Intermittent,
            "below the threshold must be intermittent, never reproducible"
        );
    }

    #[test]
    fn a_crash_that_never_recurs_is_unconfirmed() {
        let mut e = StubExecutor::new(|_, _| clean());
        let r = reproduce(&mut e, b"input", None, &cfg(5, 3)).unwrap();
        assert_eq!(r.record.successes, 0);
        assert_eq!(r.record.implied_status(), super::super::FindingStatus::Unconfirmed);
        assert!(r.dominant_signature.is_none());
    }

    #[test]
    fn only_the_expected_signature_counts_as_a_success() {
        // The candidate was a SIGABRT; the re-runs produce SIGSEGV instead.
        // That is a different failure and must not inflate this finding's rate.
        let expected = signature_for(&crash()).unwrap();
        let mut e = StubExecutor::new(|_, _| outcome(ExitClass::Crash, Some(libc::SIGSEGV), None));
        let r = reproduce(&mut e, b"input", Some(&expected), &cfg(5, 3)).unwrap();
        assert_eq!(r.record.successes, 0, "a different crash was counted as reproduction");
        assert!(r.dominant_signature.is_some(), "the other failure should still be recorded");
        assert_ne!(r.dominant_signature.unwrap().hash, expected.hash);
    }

    #[test]
    fn varying_symptoms_are_reported_separately() {
        // Alternating crash types: characteristic of memory corruption, and
        // worth surfacing rather than averaging away.
        let mut e = StubExecutor::new(|_, i| {
            if i % 2 == 0 {
                outcome(ExitClass::Crash, Some(libc::SIGABRT), None)
            } else {
                outcome(ExitClass::Crash, Some(libc::SIGSEGV), None)
            }
        });
        let r = reproduce(&mut e, b"input", None, &cfg(6, 3)).unwrap();
        assert!(!r.other_signatures.is_empty(), "a second symptom should be recorded");
        assert_eq!(r.other_signatures.len(), 1);
    }

    #[test]
    fn minimisation_requires_the_same_signature() {
        // The target crashes with the expected signature only while "BOOM" is
        // present; shorter inputs crash *differently*. A minimiser keyed on
        // "still crashes" would happily reduce to the wrong defect.
        let expected = signature_for(&crash()).unwrap();
        let mut e = StubExecutor::new(move |input, _| {
            if input.windows(4).any(|w| w == b"BOOM") {
                outcome(ExitClass::Crash, Some(libc::SIGABRT), None)
            } else {
                outcome(ExitClass::Crash, Some(libc::SIGSEGV), None)
            }
        });
        let (out, validated) =
            minimize_for_signature(&mut e, b"xxxxxBOOMyyyyy", &expected, &cfg(5, 3)).unwrap();
        assert_eq!(out.input, b"BOOM", "got {:?}", String::from_utf8_lossy(&out.input));
        assert!(validated, "minimised input should re-validate");
    }

    #[test]
    fn minimisation_reports_when_the_result_does_not_revalidate() {
        // A target that reproduces throughout reduction but not on the final
        // independent check. The finding must record that the minimised input
        // was not validated rather than implying it was.
        //
        // The clean-run threshold is calibrated rather than guessed: the same
        // reduction is first run against an always-reproducing stub to learn
        // how many executions it takes, so the failure lands exactly on the
        // closing re-validation however the minimiser's internals change.
        let expected = signature_for(&crash()).unwrap();
        let big = vec![b'A'; 64];

        let total_calls = {
            let mut e = StubExecutor::new(|_, _| crash());
            let (_, validated) =
                minimize_for_signature(&mut e, &big, &expected, &cfg(5, 3)).unwrap();
            assert!(validated, "control: an always-reproducing target must validate");
            e.exec_count()
        };
        assert!(total_calls >= 2, "expected at least a reduction and a re-validation");

        let last = total_calls - 1;
        let mut e = StubExecutor::new(move |_, i| if i >= last { clean() } else { crash() });
        let (_, validated) =
            minimize_for_signature(&mut e, &big, &expected, &cfg(5, 3)).unwrap();
        assert!(
            !validated,
            "re-validation failed but was reported as validated"
        );
    }

    #[test]
    fn minimisation_respects_its_execution_budget() {
        let expected = signature_for(&crash()).unwrap();
        let mut e = StubExecutor::new(|input, _| {
            if input.len() >= 500 {
                crash()
            } else {
                clean()
            }
        });
        let mut c = cfg(5, 3);
        c.minimize_max_execs = 30;
        let big = vec![b'A'; 4096];
        let (out, _) = minimize_for_signature(&mut e, &big, &expected, &c).unwrap();
        assert!(out.execs_used <= 30, "used {} executions", out.execs_used);
    }

    #[test]
    fn minimisation_does_not_shrink_what_it_cannot_reproduce() {
        // If the original input does not reproduce, reducing it would be
        // producing evidence for something never observed.
        let expected = signature_for(&crash()).unwrap();
        let mut e = StubExecutor::new(|_, _| clean());
        let original = b"important bytes".to_vec();
        let (out, validated) =
            minimize_for_signature(&mut e, &original, &expected, &cfg(5, 3)).unwrap();
        assert_eq!(out.input, original, "shrank an input that never reproduced");
        assert_eq!(out.stop, minimize::MinimizeStop::PredicateNeverHeld);
        assert!(!validated);
    }

    #[test]
    fn execution_errors_during_minimisation_surface() {
        struct FailingExecutor(ExecutorCapabilities);
        impl Executor for FailingExecutor {
            fn run(&mut self, _: &[u8]) -> Result<ExecOutcome> {
                Err(crate::error::Error::exec("stub", "target vanished"))
            }
            fn capabilities(&self) -> &ExecutorCapabilities {
                &self.0
            }
            fn exec_count(&self) -> u64 {
                0
            }
        }
        let expected = signature_for(&crash()).unwrap();
        let mut e = FailingExecutor(ExecutorCapabilities {
            backend: "failing".into(),
            edge_coverage: false,
            comparison_log: false,
            sanitizer_oracle: false,
            fork_server: false,
            memory_limit: false,
            limitations: Vec::new(),
        });
        let err = minimize_for_signature(&mut e, b"abc", &expected, &cfg(5, 3)).unwrap_err();
        assert_eq!(err.kind(), "execution_failed");
    }

    #[test]
    fn deduplication_matches_on_exact_signature_only() {
        let sig = signature_for(&crash()).unwrap();
        let id = FindingId::new();
        let existing = vec![(id.clone(), sig.hash.clone())];
        assert_eq!(deduplicate(&sig, &existing), DedupDecision::Duplicate(id));

        let other = signature_for(&outcome(ExitClass::Crash, Some(libc::SIGSEGV), None)).unwrap();
        assert_eq!(deduplicate(&other, &existing), DedupDecision::New);
        assert_eq!(deduplicate(&sig, &[]), DedupDecision::New);
    }

    #[test]
    fn sanitizer_faults_reproduce_and_minimise_together() {
        let expected =
            signature_for(&outcome(ExitClass::SanitizerFault, Some(libc::SIGABRT), Some("heap-buffer-overflow")))
                .unwrap();
        let mut e = StubExecutor::new(move |input, _| {
            if input.len() >= 4 {
                outcome(ExitClass::SanitizerFault, Some(libc::SIGABRT), Some("heap-buffer-overflow"))
            } else {
                clean()
            }
        });
        let r = reproduce(&mut e, b"AAAAAAAA", Some(&expected), &cfg(5, 3)).unwrap();
        assert_eq!(r.record.successes, 5);

        let (out, validated) =
            minimize_for_signature(&mut e, b"AAAAAAAA", &expected, &cfg(5, 3)).unwrap();
        assert_eq!(out.input.len(), 4, "should reduce to the minimum length that faults");
        assert!(validated);
    }
}
