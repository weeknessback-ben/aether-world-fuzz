//! The evidence engine: turning a suspected failure into a defensible finding.
//!
//! A crash observed once is a *candidate*, not a defect. This module runs the
//! pipeline that decides which it is, and records what was actually
//! established rather than what was hoped for:
//!
//! 1. detect a candidate failure and save its triggering input,
//! 2. assign a provisional signature,
//! 3. re-run under controlled conditions,
//! 4. record how many of those re-runs reproduced it,
//! 5. minimise the input while the *same* signature still occurs,
//! 6. re-validate the minimised input,
//! 7. deduplicate against existing findings,
//! 8. collect the evidence and produce a structured record.
//!
//! The rules that keep it honest:
//!
//! * A finding reaches `Reproducible` only if the configured number of re-runs
//!   actually reproduced it. Fewer, but more than zero, is `Intermittent` -
//!   never `Reproducible`.
//! * Minimisation requires the *same signature*, not merely another crash.
//!   Shrinking one defect into a different one would make the evidence wrong.
//! * The original input and its hash are always kept, even after minimisation,
//!   so a finding stays auditable.
//! * A crash is not called a vulnerability. Severity reflects what the evidence
//!   shows, and exploitability is never inferred.

pub mod report;
pub mod signature;
pub mod validate;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::exec::sanitizer::SanitizerReport;
use crate::exec::ExitClass;
use crate::hash::ContentHash;
use crate::ids::{CampaignId, FindingId, InputId};
use signature::Signature;

/// Lifecycle state of a finding. Transitions are checked, so a finding cannot
/// be marked reproducible without having gone through reproduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    /// Observed once; nothing established yet.
    Candidate,
    /// Reproduction in progress.
    Reproducing,
    /// Reproduced at least `required_successes` times out of `attempts`.
    Reproducible,
    /// Reproduced sometimes but below the required threshold.
    Intermittent,
    /// Re-runs never reproduced it.
    Unconfirmed,
    /// Attributable to the environment rather than the target, e.g. the
    /// harness itself failed to start.
    Environmental,
    /// Same signature as an existing finding.
    Duplicate,
    /// Closed, with a reason.
    Closed,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingStatus::Candidate => "candidate",
            FindingStatus::Reproducing => "reproducing",
            FindingStatus::Reproducible => "reproducible",
            FindingStatus::Intermittent => "intermittent",
            FindingStatus::Unconfirmed => "unconfirmed",
            FindingStatus::Environmental => "environmental",
            FindingStatus::Duplicate => "duplicate",
            FindingStatus::Closed => "closed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "candidate" => FindingStatus::Candidate,
            "reproducing" => FindingStatus::Reproducing,
            "reproducible" => FindingStatus::Reproducible,
            "intermittent" => FindingStatus::Intermittent,
            "unconfirmed" => FindingStatus::Unconfirmed,
            "environmental" => FindingStatus::Environmental,
            "duplicate" => FindingStatus::Duplicate,
            "closed" => FindingStatus::Closed,
            _ => return None,
        })
    }

    /// Whether this status represents an established defect. Only two do.
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            FindingStatus::Reproducible | FindingStatus::Intermittent
        )
    }

    /// Valid next states.
    ///
    /// The graph is deliberately restrictive: there is no edge from
    /// `Candidate` straight to `Reproducible`, so a finding cannot be declared
    /// reproducible without passing through reproduction.
    pub fn can_transition_to(&self, next: FindingStatus) -> bool {
        use FindingStatus::*;
        match self {
            Candidate => matches!(next, Reproducing | Duplicate | Environmental | Closed),
            Reproducing => matches!(
                next,
                Reproducible | Intermittent | Unconfirmed | Environmental | Duplicate | Closed
            ),
            // A confirmed finding may be re-validated, superseded as a
            // duplicate, or closed - but never silently downgraded.
            Reproducible | Intermittent => matches!(next, Reproducing | Duplicate | Closed),
            Unconfirmed => matches!(next, Reproducing | Closed | Duplicate),
            Environmental => matches!(next, Reproducing | Closed),
            Duplicate => matches!(next, Closed),
            Closed => false,
        }
    }
}

/// How confident the engine is, as a function of what was measured. Not a
/// severity, and not a guess about impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Reproduced every attempt.
    High,
    /// Reproduced at or above the threshold but not always.
    Medium,
    /// Reproduced below the threshold.
    Low,
    /// Not reproduced at all.
    None,
}

/// What the engine can say about severity.
///
/// Derived from the fault class alone. Memory corruption is more serious than
/// a hang, and that much the evidence supports; whether a given defect is
/// exploitable is not something a fuzzer can determine, so no variant claims
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Memory safety violation reported by a sanitizer.
    MemorySafety,
    /// Process terminated by a fault signal with no sanitizer detail.
    Crash,
    /// Target exceeded its deadline.
    Hang,
    /// A declared invariant was violated without a crash.
    InvariantViolation,
    /// Two implementations disagreed.
    BehaviouralDifference,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::MemorySafety => "memory-safety",
            Severity::Crash => "crash",
            Severity::Hang => "hang",
            Severity::InvariantViolation => "invariant-violation",
            Severity::BehaviouralDifference => "behavioural-difference",
        }
    }

    /// One sentence on what the evidence supports, and what it does not.
    ///
    /// Deliberately explicit about the limit: a report that says "memory
    /// corruption" and stops invites the reader to assume exploitability.
    pub fn evidence_note(&self) -> &'static str {
        match self {
            Severity::MemorySafety => {
                "A sanitizer reported a memory-safety violation. Whether it is \
                 exploitable has not been assessed and cannot be determined from \
                 this evidence."
            }
            Severity::Crash => {
                "The process terminated on a fault signal. The underlying cause has \
                 not been diagnosed; it may or may not be memory corruption."
            }
            Severity::Hang => {
                "The target exceeded its deadline. This may be an infinite loop, or \
                 simply work that needs longer than the configured timeout."
            }
            Severity::InvariantViolation => {
                "An operator-declared invariant did not hold. The target did not \
                 crash, so this is a correctness observation against the declared \
                 expectation."
            }
            Severity::BehaviouralDifference => {
                "Two implementations produced different output for the same input. \
                 Which one is correct has not been determined."
            }
        }
    }
}

/// The evidence collected for one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Content hash of the input that first triggered it. Always retained.
    pub trigger_hash: ContentHash,
    pub trigger_size: usize,
    /// Minimised input, when minimisation ran and succeeded.
    pub minimized_hash: Option<ContentHash>,
    pub minimized_size: Option<usize>,
    /// Command that reproduces it, as an argument vector - never a shell
    /// string, so it cannot be mis-copied into something that re-interprets
    /// metacharacters.
    pub reproduce_argv: Vec<String>,
    /// How the input is delivered.
    pub input_delivery: String,
    pub exit_class: String,
    pub signal: Option<i32>,
    pub exit_code: Option<i32>,
    pub sanitizer: Option<SanitizerReport>,
    /// Bounded excerpt of stderr.
    pub stderr_excerpt: String,
    pub stderr_truncated: bool,
    /// Target build identification, so a finding can be tied to what was tested.
    pub target_name: String,
    pub target_binary: String,
    pub target_build_id: Option<String>,
    /// Execution environment facts relevant to reproducing it.
    pub timeout_ms: u64,
    pub memory_limit_mb: u64,
    /// Limits that were requested but not enforced on this host.
    pub unenforced_limits: Vec<String>,
    pub campaign_seed: u64,
}

/// One finding record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub campaign_id: CampaignId,
    pub status: FindingStatus,
    pub signature: Signature,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Corpus input that triggered it.
    pub input_id: Option<InputId>,
    /// Strategy that produced the triggering input.
    pub discovered_by: Option<String>,
    pub reproduction: ReproductionRecord,
    pub evidence: Evidence,
    /// Finding this duplicates, when `status` is `Duplicate`.
    pub duplicate_of: Option<FindingId>,
    pub created_ms: u64,
    pub updated_ms: u64,
    /// Observations and caveats, in plain language. Facts only; hypotheses are
    /// marked as such.
    pub notes: Vec<String>,
}

/// What reproduction actually established.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReproductionRecord {
    pub attempts: u32,
    pub successes: u32,
    /// Required successes, recorded so a report shows the bar that was applied.
    pub required: u32,
    /// Whether the minimised input was re-validated after minimisation.
    pub minimized_validated: bool,
    /// Executions spent minimising.
    pub minimize_execs: u32,
    /// Whether the sanitizer oracle build was used.
    pub used_oracle_binary: bool,
}

impl ReproductionRecord {
    pub fn rate(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f64 / self.attempts as f64
        }
    }

    /// Status implied by the counts. The only place reproduction status is
    /// decided, so the threshold cannot be applied inconsistently.
    pub fn implied_status(&self) -> FindingStatus {
        if self.attempts == 0 {
            FindingStatus::Candidate
        } else if self.successes == 0 {
            FindingStatus::Unconfirmed
        } else if self.successes >= self.required {
            FindingStatus::Reproducible
        } else {
            FindingStatus::Intermittent
        }
    }

    pub fn confidence(&self) -> Confidence {
        if self.attempts == 0 || self.successes == 0 {
            Confidence::None
        } else if self.successes == self.attempts {
            Confidence::High
        } else if self.successes >= self.required {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}

impl Finding {
    /// Severity from the fault class.
    pub fn severity_for(class: ExitClass, sanitizer: Option<&SanitizerReport>) -> Severity {
        match (class, sanitizer) {
            (_, Some(_)) => Severity::MemorySafety,
            (ExitClass::Timeout, None) => Severity::Hang,
            _ => Severity::Crash,
        }
    }

    /// Move to a new status, refusing an invalid transition.
    pub fn transition(&mut self, next: FindingStatus) -> Result<()> {
        if !self.status.can_transition_to(next) {
            return Err(Error::InvalidTransition {
                from: self.status.as_str().to_string(),
                to: next.as_str().to_string(),
            });
        }
        self.status = next;
        self.updated_ms = crate::time::now_millis();
        Ok(())
    }

    /// Apply a reproduction result, setting status and confidence together so
    /// they cannot disagree.
    pub fn apply_reproduction(&mut self, record: ReproductionRecord) -> Result<()> {
        if self.status == FindingStatus::Candidate {
            self.transition(FindingStatus::Reproducing)?;
        }
        let implied = record.implied_status();
        self.confidence = record.confidence();
        self.reproduction = record;
        self.transition(implied)
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// One-line summary for CLI and MCP listings.
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} ({}/{} reproduced, confidence {:?})",
            self.status.as_str(),
            self.signature.label,
            self.reproduction.successes,
            self.reproduction.attempts,
            self.confidence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sanitizer::{SanitizerKind, SanitizerReport};

    fn evidence() -> Evidence {
        Evidence {
            trigger_hash: "ab".repeat(16),
            trigger_size: 8,
            minimized_hash: None,
            minimized_size: None,
            reproduce_argv: vec!["/bin/target".into()],
            input_delivery: "stdin".into(),
            exit_class: "crash".into(),
            signal: Some(libc::SIGABRT),
            exit_code: None,
            sanitizer: None,
            stderr_excerpt: String::new(),
            stderr_truncated: false,
            target_name: "demo".into(),
            target_binary: "/bin/target".into(),
            target_build_id: None,
            timeout_ms: 1000,
            memory_limit_mb: 512,
            unenforced_limits: Vec::new(),
            campaign_seed: 42,
        }
    }

    fn finding() -> Finding {
        Finding {
            id: FindingId::new(),
            campaign_id: CampaignId::new(),
            status: FindingStatus::Candidate,
            signature: Signature {
                hash: "deadbeef".into(),
                label: "crash: SIGABRT".into(),
                parts: signature::SignatureParts {
                    exit_class: "crash".into(),
                    signal: Some(libc::SIGABRT),
                    exit_code: None,
                    sanitizer_kind: None,
                    fault: None,
                    frames: Vec::new(),
                },
            },
            severity: Severity::Crash,
            confidence: Confidence::None,
            input_id: None,
            discovered_by: Some("havoc".into()),
            reproduction: ReproductionRecord::default(),
            evidence: evidence(),
            duplicate_of: None,
            created_ms: 0,
            updated_ms: 0,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_candidate_cannot_jump_straight_to_reproducible() {
        // The central guarantee: reproducibility has to be established, not
        // asserted.
        let mut f = finding();
        let e = f.transition(FindingStatus::Reproducible).unwrap_err();
        assert_eq!(e.kind(), "invalid_transition");
        assert_eq!(
            f.status,
            FindingStatus::Candidate,
            "status changed despite the error"
        );
    }

    #[test]
    fn the_normal_path_is_permitted() {
        let mut f = finding();
        f.transition(FindingStatus::Reproducing).unwrap();
        f.transition(FindingStatus::Reproducible).unwrap();
        assert!(f.status.is_confirmed());
    }

    #[test]
    fn closed_is_terminal() {
        let mut f = finding();
        f.transition(FindingStatus::Closed).unwrap();
        for next in [
            FindingStatus::Reproducing,
            FindingStatus::Reproducible,
            FindingStatus::Candidate,
            FindingStatus::Duplicate,
        ] {
            assert!(
                f.transition(next).is_err(),
                "closed finding accepted {next:?}"
            );
        }
    }

    #[test]
    fn reproduction_below_the_threshold_is_intermittent_never_reproducible() {
        let mut f = finding();
        f.apply_reproduction(ReproductionRecord {
            attempts: 5,
            successes: 2,
            required: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(f.status, FindingStatus::Intermittent);
        assert_eq!(f.confidence, Confidence::Low);
    }

    #[test]
    fn reproduction_at_the_threshold_is_reproducible() {
        let mut f = finding();
        f.apply_reproduction(ReproductionRecord {
            attempts: 5,
            successes: 3,
            required: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(f.status, FindingStatus::Reproducible);
        assert_eq!(f.confidence, Confidence::Medium);
    }

    #[test]
    fn full_reproduction_is_high_confidence() {
        let mut f = finding();
        f.apply_reproduction(ReproductionRecord {
            attempts: 5,
            successes: 5,
            required: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.reproduction.rate(), 1.0);
    }

    #[test]
    fn zero_successes_is_unconfirmed_and_not_a_defect() {
        let mut f = finding();
        f.apply_reproduction(ReproductionRecord {
            attempts: 5,
            successes: 0,
            required: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(f.status, FindingStatus::Unconfirmed);
        assert_eq!(f.confidence, Confidence::None);
        assert!(!f.status.is_confirmed());
    }

    #[test]
    fn implied_status_is_the_single_source_of_the_threshold() {
        let cases = [
            (0, 0, 3, FindingStatus::Candidate),
            (5, 0, 3, FindingStatus::Unconfirmed),
            (5, 1, 3, FindingStatus::Intermittent),
            (5, 3, 3, FindingStatus::Reproducible),
            (5, 5, 3, FindingStatus::Reproducible),
            (1, 1, 1, FindingStatus::Reproducible),
        ];
        for (attempts, successes, required, want) in cases {
            let r = ReproductionRecord {
                attempts,
                successes,
                required,
                ..Default::default()
            };
            assert_eq!(
                r.implied_status(),
                want,
                "{attempts}/{successes}/{required}"
            );
        }
    }

    #[test]
    fn severity_follows_the_fault_class() {
        let san = SanitizerReport {
            kind: SanitizerKind::Address,
            fault: "heap-buffer-overflow".into(),
            access: None,
            access_size: None,
            frames: vec![],
            summary: String::new(),
        };
        assert_eq!(
            Finding::severity_for(ExitClass::SanitizerFault, Some(&san)),
            Severity::MemorySafety
        );
        assert_eq!(
            Finding::severity_for(ExitClass::Crash, None),
            Severity::Crash
        );
        assert_eq!(
            Finding::severity_for(ExitClass::Timeout, None),
            Severity::Hang
        );
    }

    #[test]
    fn severity_notes_never_claim_exploitability() {
        for s in [
            Severity::MemorySafety,
            Severity::Crash,
            Severity::Hang,
            Severity::InvariantViolation,
            Severity::BehaviouralDifference,
        ] {
            let note = s.evidence_note();
            assert!(!note.is_empty());
            let lower = note.to_lowercase();
            // Affirmative claims only. A phrase like "whether it is
            // exploitable has not been assessed" is exactly what these notes
            // should say, so the check looks for assertions rather than for
            // the word itself.
            for forbidden in [
                "is exploitable.",
                "can be exploited",
                "allows an attacker",
                "attacker can",
                "is a vulnerability",
                "remote code execution",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{s:?} note claims too much: {note}"
                );
            }
        }
        // The memory-safety note must say explicitly that exploitability is
        // not assessed, since that is the one a reader will over-read.
        assert!(Severity::MemorySafety
            .evidence_note()
            .contains("not been assessed"));
    }

    #[test]
    fn status_strings_round_trip() {
        for s in [
            FindingStatus::Candidate,
            FindingStatus::Reproducing,
            FindingStatus::Reproducible,
            FindingStatus::Intermittent,
            FindingStatus::Unconfirmed,
            FindingStatus::Environmental,
            FindingStatus::Duplicate,
            FindingStatus::Closed,
        ] {
            assert_eq!(FindingStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(FindingStatus::parse("nonsense"), None);
    }

    #[test]
    fn only_two_statuses_count_as_confirmed() {
        assert!(FindingStatus::Reproducible.is_confirmed());
        assert!(FindingStatus::Intermittent.is_confirmed());
        for s in [
            FindingStatus::Candidate,
            FindingStatus::Reproducing,
            FindingStatus::Unconfirmed,
            FindingStatus::Environmental,
            FindingStatus::Duplicate,
            FindingStatus::Closed,
        ] {
            assert!(
                !s.is_confirmed(),
                "{s:?} must not count as an established defect"
            );
        }
    }

    #[test]
    fn the_original_input_is_retained_after_minimisation() {
        let mut f = finding();
        let original = f.evidence.trigger_hash.clone();
        f.evidence.minimized_hash = Some("cd".repeat(16));
        f.evidence.minimized_size = Some(4);
        assert_eq!(
            f.evidence.trigger_hash, original,
            "original input hash was lost"
        );
    }

    #[test]
    fn reproduce_command_is_an_argument_vector() {
        // A shell string could be mis-pasted into something that reinterprets
        // metacharacters from the input.
        let f = finding();
        assert!(!f.evidence.reproduce_argv.is_empty());
        for arg in &f.evidence.reproduce_argv {
            assert!(
                !arg.contains("&&"),
                "argv entry looks like a shell line: {arg}"
            );
            assert!(
                !arg.contains('|'),
                "argv entry looks like a shell line: {arg}"
            );
        }
    }

    #[test]
    fn summary_is_informative() {
        let mut f = finding();
        f.apply_reproduction(ReproductionRecord {
            attempts: 5,
            successes: 5,
            required: 3,
            ..Default::default()
        })
        .unwrap();
        let s = f.summary();
        assert!(s.contains("reproducible"), "{s}");
        assert!(s.contains("5/5"), "{s}");
    }
}
