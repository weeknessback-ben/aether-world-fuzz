//! Target execution: the boundary between AETHER and the program under test.
//!
//! The [`Executor`] trait is what every backend implements, so the campaign
//! loop never knows whether it is driving an AETHER-instrumented binary, an
//! uninstrumented one, or a third-party engine through an adapter.
//!
//! Safety properties this layer is responsible for:
//!
//! * A target is launched from an explicit program path and an argument
//!   vector. No command string is ever handed to a shell, so a mutated input
//!   cannot become a shell metacharacter.
//! * Every run has a deadline, and exceeding it kills the whole process group,
//!   so a target that forks children cannot leak them.
//! * Captured output is bounded as it is read, not truncated afterwards, so a
//!   target that prints without end cannot exhaust memory.
//! * A sanitizer report is only believed when it arrives on stderr from a
//!   process that terminated abnormally.

pub mod adapters;
pub mod limits;
pub mod native;
pub mod sanitizer;
pub mod shm;

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::Result;
use sanitizer::SanitizerReport;

/// How a run ended. This is the engine's own classification, derived from the
/// wait status, the deadline, and the sanitizer oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitClass {
    /// Exited with status 0.
    Ok,
    /// Exited non-zero. A parser rejecting malformed input lands here: it is
    /// normal behaviour, not a defect.
    NonZeroExit,
    /// Terminated by a signal that indicates a fault.
    Crash,
    /// Killed because it exceeded its deadline.
    Timeout,
    /// Terminated by a signal AETHER sent for reasons other than a timeout,
    /// e.g. campaign cancellation. Never a finding.
    Killed,
    /// A sanitizer reported a fault on stderr and the process died abnormally.
    SanitizerFault,
}

impl ExitClass {
    /// Whether this outcome is worth offering to the evidence engine. Note
    /// that "interesting" is not "a bug": the evidence engine decides that.
    pub fn is_candidate_failure(&self) -> bool {
        matches!(
            self,
            ExitClass::Crash | ExitClass::SanitizerFault | ExitClass::Timeout
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExitClass::Ok => "ok",
            ExitClass::NonZeroExit => "non-zero-exit",
            ExitClass::Crash => "crash",
            ExitClass::Timeout => "timeout",
            ExitClass::Killed => "killed",
            ExitClass::SanitizerFault => "sanitizer-fault",
        }
    }
}

/// Everything observed about one execution.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub class: ExitClass,
    /// Exit code, when the process exited rather than being signalled.
    pub exit_code: Option<i32>,
    /// Terminating signal number, when signalled.
    pub signal: Option<i32>,
    pub duration: Duration,
    /// Bounded capture. `*_truncated` says whether output was dropped, so a
    /// report never implies it holds the complete log.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub sanitizer: Option<SanitizerReport>,
    /// Edge map for this run, already bucketed. `None` when the target carries
    /// no coverage instrumentation - distinct from a map that is all zeroes.
    pub coverage: Option<Box<[u8; shm::MAP_SIZE]>>,
    /// Comparison operands recorded this run, when the comparison log is on.
    pub cmp_entries: Vec<shm::CmpEntry>,
    /// Whether the comparison log filled up, in which case `cmp_entries` is a
    /// prefix rather than the complete set.
    pub cmp_overflowed: bool,
}

impl ExecOutcome {
    /// Count of touched map slots, or `None` when there is no coverage signal.
    /// A caller must distinguish "no instrumentation" from "zero edges"; this
    /// returning `Option` is what forces that.
    pub fn edge_count(&self) -> Option<u32> {
        self.coverage
            .as_ref()
            .map(|m| m.iter().filter(|b| **b != 0).count() as u32)
    }

    pub fn stderr_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

/// Classify a `waitpid` status together with AETHER's own knowledge of why the
/// run ended.
///
/// `timed_out` and `cancelled` come from the engine, not from the status: a
/// process we SIGKILLed on a deadline is a timeout, and the identical status
/// from a cancellation is not a finding.
pub fn classify(
    wait_status: i32,
    timed_out: bool,
    cancelled: bool,
    stderr: &[u8],
) -> (ExitClass, Option<i32>, Option<i32>, Option<SanitizerReport>) {
    if cancelled {
        return (ExitClass::Killed, None, None, None);
    }
    if timed_out {
        return (ExitClass::Timeout, None, None, None);
    }

    let exited = libc::WIFEXITED(wait_status);
    let signalled = libc::WIFSIGNALED(wait_status);
    let code = if exited {
        Some(libc::WEXITSTATUS(wait_status))
    } else {
        None
    };
    let sig = if signalled {
        Some(libc::WTERMSIG(wait_status))
    } else {
        None
    };

    // A sanitizer is only believed when the process actually died. A target
    // that printed a report-shaped banner and exited cleanly did not crash;
    // fixtures/noisy_output.c exists to keep this honest.
    let abnormal = signalled || code.map(|c| c != 0).unwrap_or(false);
    let report = if abnormal {
        sanitizer::parse(&String::from_utf8_lossy(stderr))
    } else {
        None
    };

    let class = if report.is_some() {
        ExitClass::SanitizerFault
    } else if let Some(s) = sig {
        // SIGABRT from a failed assertion, SIGSEGV, SIGBUS, SIGFPE and SIGILL
        // are faults. SIGKILL and SIGTERM are not: they came from outside.
        match s {
            libc::SIGABRT
            | libc::SIGSEGV
            | libc::SIGBUS
            | libc::SIGFPE
            | libc::SIGILL
            | libc::SIGSYS
            | libc::SIGTRAP => ExitClass::Crash,
            libc::SIGKILL | libc::SIGTERM | libc::SIGINT | libc::SIGHUP => ExitClass::Killed,
            _ => ExitClass::Crash,
        }
    } else if code == Some(0) {
        ExitClass::Ok
    } else {
        ExitClass::NonZeroExit
    };

    (class, code, sig, report)
}

/// What a backend can actually provide. Reported honestly: a campaign consults
/// this and records which signals were available rather than assuming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorCapabilities {
    pub backend: String,
    pub edge_coverage: bool,
    pub comparison_log: bool,
    pub sanitizer_oracle: bool,
    pub fork_server: bool,
    pub memory_limit: bool,
    /// Populated when a capability was requested but is unavailable here.
    pub limitations: Vec<String>,
}

/// One execution backend.
pub trait Executor: Send {
    /// Run the target once against `input`.
    fn run(&mut self, input: &[u8]) -> Result<ExecOutcome>;

    fn capabilities(&self) -> &ExecutorCapabilities;

    /// Total executions this executor has performed.
    fn exec_count(&self) -> u64;

    /// Release child processes and temporary state. Called on shutdown; also
    /// safe to call mid-campaign to force a fresh fork server.
    fn reset(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wait status the way the kernel encodes one.
    fn exited(code: i32) -> i32 {
        (code & 0xff) << 8
    }
    fn signalled(sig: i32) -> i32 {
        sig & 0x7f
    }

    #[test]
    fn clean_exit_is_ok() {
        let (c, code, sig, san) = classify(exited(0), false, false, b"");
        assert_eq!(c, ExitClass::Ok);
        assert_eq!(code, Some(0));
        assert_eq!(sig, None);
        assert!(san.is_none());
        assert!(!c.is_candidate_failure());
    }

    #[test]
    fn nonzero_exit_is_not_a_failure_candidate() {
        // A parser rejecting malformed input is the common case here.
        let (c, code, _, _) = classify(exited(2), false, false, b"");
        assert_eq!(c, ExitClass::NonZeroExit);
        assert_eq!(code, Some(2));
        assert!(!c.is_candidate_failure(), "a non-zero exit is not a defect");
    }

    #[test]
    fn fault_signals_are_crashes() {
        for sig in [
            libc::SIGSEGV,
            libc::SIGABRT,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGBUS,
        ] {
            let (c, _, s, _) = classify(signalled(sig), false, false, b"");
            assert_eq!(c, ExitClass::Crash, "signal {sig}");
            assert_eq!(s, Some(sig));
            assert!(c.is_candidate_failure());
        }
    }

    #[test]
    fn externally_sent_signals_are_not_crashes() {
        for sig in [libc::SIGKILL, libc::SIGTERM, libc::SIGINT] {
            let (c, _, _, _) = classify(signalled(sig), false, false, b"");
            assert_eq!(
                c,
                ExitClass::Killed,
                "signal {sig} must not read as a crash"
            );
            assert!(!c.is_candidate_failure());
        }
    }

    #[test]
    fn engine_knowledge_overrides_the_wait_status() {
        // Identical status; the difference is why we killed it.
        let st = signalled(libc::SIGKILL);
        assert_eq!(classify(st, true, false, b"").0, ExitClass::Timeout);
        assert_eq!(classify(st, false, true, b"").0, ExitClass::Killed);
        // Cancellation wins over a timeout: a cancelled run is never a finding.
        assert_eq!(classify(st, true, true, b"").0, ExitClass::Killed);
    }

    #[test]
    fn sanitizer_report_on_abnormal_exit_is_believed() {
        let err = b"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n    #0 0x1 in main /a.c:1\n";
        let (c, _, _, san) = classify(signalled(libc::SIGABRT), false, false, err);
        assert_eq!(c, ExitClass::SanitizerFault);
        assert_eq!(san.unwrap().fault, "heap-buffer-overflow");
    }

    #[test]
    fn sanitizer_banner_from_a_clean_exit_is_ignored() {
        // This is the fixtures/noisy_output.c case: the target prints a
        // convincing report and exits 0. Believing it would be a false
        // positive manufactured by the target itself.
        let err = b"==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x0\n";
        let (c, _, _, san) = classify(exited(0), false, false, err);
        assert_eq!(c, ExitClass::Ok);
        assert!(
            san.is_none(),
            "a clean exit must not yield a sanitizer finding"
        );
    }

    #[test]
    fn sanitizer_banner_with_nonzero_exit_is_believed() {
        // UBSan with -fno-sanitize-recover exits non-zero without a signal.
        let err = b"a.c:1:2: runtime error: signed integer overflow: 1 + 1\n";
        let (c, _, _, san) = classify(exited(1), false, false, err);
        assert_eq!(c, ExitClass::SanitizerFault);
        assert!(san.is_some());
    }

    #[test]
    fn candidate_failure_set_is_exactly_the_three_interesting_classes() {
        use ExitClass::*;
        for c in [Crash, SanitizerFault, Timeout] {
            assert!(c.is_candidate_failure(), "{c:?}");
        }
        for c in [Ok, NonZeroExit, Killed] {
            assert!(!c.is_candidate_failure(), "{c:?}");
        }
    }
}
