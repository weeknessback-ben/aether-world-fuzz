//! Failure signatures: deciding when two failures are the same defect.
//!
//! Deduplication rests entirely on this. Too coarse and distinct defects are
//! merged, so a report shows one finding where there are three. Too fine and
//! one defect reported through twenty different call paths becomes twenty
//! findings, which is how a fuzzing report becomes unreadable.
//!
//! The signature is built only from parts that identify the *defect*, not the
//! run that happened to hit it:
//!
//! * Addresses, load offsets, PIDs and build paths are excluded. They change
//!   between builds and between machines, and including them would report the
//!   same defect as new after every recompile.
//! * Stack frames are included, but only the innermost few: the deep part of a
//!   stack is where the harness happened to call from, which varies with the
//!   input while the defect does not.
//! * The input is never part of the signature. Two different inputs reaching
//!   the same fault are the same defect.

use serde::{Deserialize, Serialize};

use crate::exec::sanitizer::SanitizerReport;
use crate::exec::{ExecOutcome, ExitClass};

/// How many innermost frames contribute. Three is enough to separate distinct
/// faults in the same function while staying insensitive to call depth.
const SIGNATURE_FRAME_DEPTH: usize = 3;

/// The components a signature was built from, kept so a report can explain
/// why two failures were treated as the same defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureParts {
    pub exit_class: String,
    pub signal: Option<i32>,
    pub exit_code: Option<i32>,
    pub sanitizer_kind: Option<String>,
    pub fault: Option<String>,
    pub frames: Vec<String>,
}

/// A failure signature and the evidence it was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Stable short hash, used as the deduplication key.
    pub hash: String,
    /// Human-readable one-line form, for reports and CLI output.
    pub label: String,
    pub parts: SignatureParts,
}

/// Build a signature from an execution outcome.
///
/// Returns `None` for an outcome that is not a failure: a clean exit or a
/// non-zero exit has nothing to deduplicate.
pub fn signature_for(outcome: &ExecOutcome) -> Option<Signature> {
    if !outcome.class.is_candidate_failure() {
        return None;
    }
    Some(match (&outcome.sanitizer, outcome.class) {
        (Some(report), _) => from_sanitizer(report, outcome),
        (None, ExitClass::Timeout) => from_timeout(),
        (None, _) => from_signal(outcome),
    })
}

fn from_sanitizer(report: &SanitizerReport, outcome: &ExecOutcome) -> Signature {
    let frames: Vec<String> = report
        .signature_frames(SIGNATURE_FRAME_DEPTH)
        .into_iter()
        .map(String::from)
        .collect();
    let parts = SignatureParts {
        exit_class: outcome.class.as_str().to_string(),
        // The signal is excluded for a sanitizer fault: the same defect can
        // abort or exit non-zero depending on the sanitizer's configuration.
        signal: None,
        exit_code: None,
        sanitizer_kind: Some(report.kind.as_str().to_string()),
        fault: Some(report.fault.clone()),
        frames: frames.clone(),
    };
    let mut keys: Vec<&str> = vec![report.kind.as_str(), &report.fault];
    keys.extend(frames.iter().map(String::as_str));
    // The access kind separates a read from a write at the same site, which
    // are usually different defects.
    if let Some(a) = &report.access {
        keys.push(a);
    }
    let hash = crate::hash::signature_hash(&keys);
    let label = if frames.is_empty() {
        format!("{}: {}", report.kind.as_str(), report.fault)
    } else {
        format!(
            "{}: {} in {}",
            report.kind.as_str(),
            report.fault,
            frames[0]
        )
    };
    Signature { hash, label, parts }
}

fn from_signal(outcome: &ExecOutcome) -> Signature {
    let sig = outcome.signal;
    let parts = SignatureParts {
        exit_class: outcome.class.as_str().to_string(),
        signal: sig,
        // The exit code is excluded when the process was signalled: there is
        // no meaningful code, and including None-vs-Some would split one
        // defect across two signatures.
        exit_code: if sig.is_some() {
            None
        } else {
            outcome.exit_code
        },
        sanitizer_kind: None,
        fault: None,
        frames: Vec::new(),
    };
    let signal_name = signal_name(sig);
    let code = outcome.exit_code.map(|c| c.to_string()).unwrap_or_default();
    let hash = crate::hash::signature_hash(&[
        outcome.class.as_str(),
        signal_name,
        if sig.is_some() { "" } else { &code },
    ]);
    Signature {
        hash,
        label: match sig {
            Some(s) => format!("crash: {} ({s})", signal_name),
            None => format!("crash: exit {code}"),
        },
        parts,
    }
}

fn from_timeout() -> Signature {
    // All timeouts share one signature. A hang is a hang: distinguishing them
    // by duration would produce a new finding on every run, since the duration
    // is just when the engine happened to give up.
    let parts = SignatureParts {
        exit_class: ExitClass::Timeout.as_str().to_string(),
        signal: None,
        exit_code: None,
        sanitizer_kind: None,
        fault: None,
        frames: Vec::new(),
    };
    Signature {
        hash: crate::hash::signature_hash(&["timeout"]),
        label: "timeout: target exceeded its deadline".to_string(),
        parts,
    }
}

fn signal_name(sig: Option<i32>) -> &'static str {
    match sig {
        Some(libc::SIGSEGV) => "SIGSEGV",
        Some(libc::SIGABRT) => "SIGABRT",
        Some(libc::SIGBUS) => "SIGBUS",
        Some(libc::SIGFPE) => "SIGFPE",
        Some(libc::SIGILL) => "SIGILL",
        Some(libc::SIGSYS) => "SIGSYS",
        Some(libc::SIGTRAP) => "SIGTRAP",
        Some(_) => "signal",
        None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sanitizer::SanitizerKind;
    use std::time::Duration;

    fn outcome(class: ExitClass, signal: Option<i32>, san: Option<SanitizerReport>) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: if signal.is_some() { None } else { Some(1) },
            signal,
            duration: Duration::from_millis(5),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: san,
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    fn report(fault: &str, frames: &[&str], access: Option<&str>) -> SanitizerReport {
        SanitizerReport {
            kind: SanitizerKind::Address,
            fault: fault.to_string(),
            access: access.map(String::from),
            access_size: Some(4),
            frames: frames.iter().map(|s| s.to_string()).collect(),
            summary: "summary".to_string(),
        }
    }

    #[test]
    fn non_failures_have_no_signature() {
        assert!(signature_for(&outcome(ExitClass::Ok, None, None)).is_none());
        assert!(signature_for(&outcome(ExitClass::NonZeroExit, None, None)).is_none());
        assert!(signature_for(&outcome(ExitClass::Killed, Some(libc::SIGKILL), None)).is_none());
    }

    #[test]
    fn identical_faults_share_a_signature() {
        let a = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["parse", "main"],
                Some("write"),
            )),
        ))
        .unwrap();
        let b = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["parse", "main"],
                Some("write"),
            )),
        ))
        .unwrap();
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn different_faults_get_different_signatures() {
        let oob = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-buffer-overflow", &["parse"], Some("write"))),
        ))
        .unwrap();
        let uaf = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-use-after-free", &["parse"], Some("write"))),
        ))
        .unwrap();
        assert_ne!(oob.hash, uaf.hash);
    }

    #[test]
    fn a_read_and_a_write_at_the_same_site_are_distinct() {
        let r = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-buffer-overflow", &["f"], Some("read"))),
        ))
        .unwrap();
        let w = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-buffer-overflow", &["f"], Some("write"))),
        ))
        .unwrap();
        assert_ne!(
            r.hash, w.hash,
            "a read and a write are usually different defects"
        );
    }

    #[test]
    fn deeper_call_stacks_do_not_split_one_defect() {
        // The same fault reached through different call depths: the innermost
        // frames identify it, the outer ones are where the harness called from.
        let shallow = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["memcpy", "copy", "parse"],
                Some("write"),
            )),
        ))
        .unwrap();
        let deep = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["memcpy", "copy", "parse", "handle", "dispatch", "main"],
                Some("write"),
            )),
        ))
        .unwrap();
        assert_eq!(
            shallow.hash, deep.hash,
            "call depth changed the signature; one defect would be reported twice"
        );
    }

    #[test]
    fn a_different_innermost_frame_is_a_different_defect() {
        let a = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["memcpy", "parse"],
                Some("write"),
            )),
        ))
        .unwrap();
        let b = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["strcpy", "parse"],
                Some("write"),
            )),
        ))
        .unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn sanitizer_signature_ignores_the_terminating_signal() {
        // The same defect aborts under one sanitizer configuration and exits
        // non-zero under another; both must dedupe together.
        let aborted = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-buffer-overflow", &["f"], Some("write"))),
        ))
        .unwrap();
        let exited = signature_for(&outcome(
            ExitClass::SanitizerFault,
            None,
            Some(report("heap-buffer-overflow", &["f"], Some("write"))),
        ))
        .unwrap();
        assert_eq!(aborted.hash, exited.hash);
    }

    #[test]
    fn signal_crashes_are_separated_by_signal() {
        let segv = signature_for(&outcome(ExitClass::Crash, Some(libc::SIGSEGV), None)).unwrap();
        let abrt = signature_for(&outcome(ExitClass::Crash, Some(libc::SIGABRT), None)).unwrap();
        assert_ne!(segv.hash, abrt.hash);
        assert!(segv.label.contains("SIGSEGV"), "{}", segv.label);
    }

    #[test]
    fn all_timeouts_share_one_signature() {
        // Otherwise every hang would be reported as a new finding, since the
        // duration is only when the engine gave up.
        let mut a = outcome(ExitClass::Timeout, None, None);
        a.duration = Duration::from_millis(1000);
        let mut b = outcome(ExitClass::Timeout, None, None);
        b.duration = Duration::from_millis(5000);
        assert_eq!(
            signature_for(&a).unwrap().hash,
            signature_for(&b).unwrap().hash
        );
    }

    #[test]
    fn signature_excludes_volatile_detail() {
        let s = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report(
                "heap-buffer-overflow",
                &["parse", "main"],
                Some("write"),
            )),
        ))
        .unwrap();
        // Nothing build- or run-specific may appear in the parts, or the same
        // defect would be reported as new after a rebuild.
        let serialised = serde_json::to_string(&s).unwrap();
        for volatile in ["0x", "/home/", "/tmp/", "pid"] {
            assert!(
                !serialised.contains(volatile),
                "signature retained volatile detail {volatile:?}: {serialised}"
            );
        }
    }

    #[test]
    fn labels_are_human_readable() {
        let s = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("heap-use-after-free", &["commit"], Some("read"))),
        ))
        .unwrap();
        assert_eq!(s.label, "AddressSanitizer: heap-use-after-free in commit");
    }

    #[test]
    fn frameless_sanitizer_reports_still_signature() {
        let s = signature_for(&outcome(
            ExitClass::SanitizerFault,
            Some(libc::SIGABRT),
            Some(report("memory-leak", &[], None)),
        ))
        .unwrap();
        assert!(!s.hash.is_empty());
        assert_eq!(s.label, "AddressSanitizer: memory-leak");
    }
}
