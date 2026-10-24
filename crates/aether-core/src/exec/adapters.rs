//! Adapters for third-party fuzzing engines.
//!
//! AETHER's own contribution is orchestration, not instrumentation, so where a
//! mature engine already provides execution and feedback it should be reused.
//! Each adapter declares what it needs and what it can supply, and
//! [`detect_all`] probes the host so `aether doctor` can report exactly which
//! backends are usable here and why the others are not.
//!
//! Two of the three adapters below are **interface-complete but unverified**:
//! this development host has neither AFL++ nor a clang with libFuzzer's
//! runtime, so their drive paths have never been exercised against a real
//! engine. That is recorded in [`AdapterStatus::verified`] and surfaced by
//! `aether doctor` rather than left for a reader to discover.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::Instrumentation;

/// Which backend an adapter drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// AETHER's own runtime: the only backend implemented end to end here.
    AetherNative,
    LibFuzzer,
    AflPlusPlus,
    /// Run an uninstrumented program; exit status and output only.
    BlackBox,
}

impl Backend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::AetherNative => "aether-native",
            Backend::LibFuzzer => "libfuzzer",
            Backend::AflPlusPlus => "aflplusplus",
            Backend::BlackBox => "black-box",
        }
    }

    pub fn from_instrumentation(i: Instrumentation) -> Self {
        match i {
            Instrumentation::AetherNative => Backend::AetherNative,
            Instrumentation::LibFuzzer => Backend::LibFuzzer,
            Instrumentation::AflPlusPlus => Backend::AflPlusPlus,
            Instrumentation::None => Backend::BlackBox,
        }
    }
}

/// The full declaration the specification asks every adapter to make.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDeclaration {
    pub backend: Backend,
    pub supported_target_types: Vec<String>,
    pub input_model: String,
    pub required_instrumentation: String,
    pub feedback_signals: Vec<String>,
    pub configuration: Vec<String>,
    pub outputs: Vec<String>,
    pub resource_limits: Vec<String>,
    pub failure_modes: Vec<String>,
    pub capability_limitations: Vec<String>,
}

/// Whether this host can actually use an adapter right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterStatus {
    pub backend: Backend,
    pub available: bool,
    /// Why it is unavailable, and what would make it available.
    pub reason: Option<String>,
    pub remedy: Option<String>,
    /// Tools found while probing, for the doctor report.
    pub discovered: Vec<String>,
    /// False when the adapter's drive path has never run against the real
    /// engine. An unverified adapter is not presented as a working feature.
    pub verified: bool,
}

/// Probe every adapter. Cheap enough to call from `aether doctor` and at
/// campaign start.
pub fn detect_all() -> Vec<AdapterStatus> {
    vec![
        detect_native(),
        detect_black_box(),
        detect_libfuzzer(),
        detect_aflpp(),
    ]
}

pub fn detect(backend: Backend) -> AdapterStatus {
    match backend {
        Backend::AetherNative => detect_native(),
        Backend::BlackBox => detect_black_box(),
        Backend::LibFuzzer => detect_libfuzzer(),
        Backend::AflPlusPlus => detect_aflpp(),
    }
}

fn detect_native() -> AdapterStatus {
    // The native backend needs a C compiler able to emit SanitizerCoverage
    // callbacks, plus a writable shared-memory directory.
    let mut discovered = Vec::new();
    let mut missing = Vec::new();

    let clang = which("clang");
    let gcc = which("gcc");
    if let Some(p) = &clang {
        discovered.push(format!("clang at {}", p.display()));
    }
    if let Some(p) = &gcc {
        discovered.push(format!("gcc at {}", p.display()));
    }
    if clang.is_none() && gcc.is_none() {
        missing.push("no clang or gcc to instrument a target with".to_string());
    }

    let shm_dir = Path::new("/dev/shm");
    if shm_dir.is_dir() {
        discovered.push("/dev/shm available for coverage regions".to_string());
    } else {
        discovered.push(format!(
            "/dev/shm absent; coverage regions fall back to {}",
            std::env::temp_dir().display()
        ));
    }

    AdapterStatus {
        backend: Backend::AetherNative,
        available: missing.is_empty(),
        reason: if missing.is_empty() {
            None
        } else {
            Some(missing.join("; "))
        },
        remedy: if missing.is_empty() {
            None
        } else {
            Some("install clang (preferred, enables the comparison log) or gcc".to_string())
        },
        discovered,
        verified: true,
    }
}

fn detect_black_box() -> AdapterStatus {
    // Running a program and reading its exit status needs nothing special.
    AdapterStatus {
        backend: Backend::BlackBox,
        available: true,
        reason: None,
        remedy: None,
        discovered: vec!["no instrumentation required".to_string()],
        verified: true,
    }
}

fn detect_libfuzzer() -> AdapterStatus {
    // A libFuzzer target is linked with -fsanitize=fuzzer, which needs
    // clang's own runtime archive. Probing for clang is not enough: this host
    // has clang but no libclang_rt.fuzzer, which is exactly the case that
    // would otherwise be reported as "available" and fail at build time.
    let clang = which("clang");
    let mut discovered = Vec::new();
    let runtime = clang.as_ref().and_then(|_| find_clang_runtime("fuzzer"));

    match (&clang, &runtime) {
        (Some(c), Some(r)) => {
            discovered.push(format!("clang at {}", c.display()));
            discovered.push(format!("libFuzzer runtime at {}", r.display()));
            AdapterStatus {
                backend: Backend::LibFuzzer,
                available: true,
                reason: None,
                remedy: None,
                discovered,
                // Never exercised against a real libFuzzer harness here.
                verified: false,
            }
        }
        (Some(c), None) => {
            discovered.push(format!("clang at {}", c.display()));
            AdapterStatus {
                backend: Backend::LibFuzzer,
                available: false,
                reason: Some(
                    "clang is installed but its libFuzzer runtime archive \
                     (libclang_rt.fuzzer-*.a) is not present, so -fsanitize=fuzzer \
                     cannot link"
                        .to_string(),
                ),
                remedy: Some(
                    "install the matching compiler-rt package, e.g. \
                     libclang-rt-<version>-dev on Debian/Ubuntu"
                        .to_string(),
                ),
                discovered,
                verified: false,
            }
        }
        (None, _) => AdapterStatus {
            backend: Backend::LibFuzzer,
            available: false,
            reason: Some("clang not found; libFuzzer requires clang".to_string()),
            remedy: Some("install clang and its compiler-rt runtime".to_string()),
            discovered,
            verified: false,
        },
    }
}

fn detect_aflpp() -> AdapterStatus {
    let fuzz = which("afl-fuzz");
    let cc = which("afl-clang-fast")
        .or_else(|| which("afl-cc"))
        .or_else(|| which("afl-gcc"));
    let mut discovered = Vec::new();
    if let Some(p) = &fuzz {
        discovered.push(format!("afl-fuzz at {}", p.display()));
    }
    if let Some(p) = &cc {
        discovered.push(format!("AFL++ compiler at {}", p.display()));
    }

    let mut missing = Vec::new();
    if fuzz.is_none() {
        missing.push("afl-fuzz not on PATH");
    }
    if cc.is_none() {
        missing.push("no afl-clang-fast / afl-cc / afl-gcc on PATH");
    }

    AdapterStatus {
        backend: Backend::AflPlusPlus,
        available: missing.is_empty(),
        reason: if missing.is_empty() {
            None
        } else {
            Some(missing.join("; "))
        },
        remedy: if missing.is_empty() {
            None
        } else {
            Some("install AFL++ (package aflplusplus, or build from source)".to_string())
        },
        discovered,
        verified: false,
    }
}

/// What each adapter declares. Static data, so the CLI and MCP layers can
/// report an adapter's contract without a host probe.
pub fn declaration(backend: Backend) -> AdapterDeclaration {
    match backend {
        Backend::AetherNative => AdapterDeclaration {
            backend,
            supported_target_types: vec![
                "local executable reading one input per run".into(),
                "local executable reading a newline-delimited command sequence".into(),
                "two executables compared differentially".into(),
            ],
            input_model: "one byte string per run on stdin, or a path substituted for @@".into(),
            required_instrumentation:
                "built with runtime/aether-cc: clang -fsanitize-coverage=trace-pc-guard,trace-cmp \
                 or gcc -fsanitize-coverage=trace-pc, linked against aether_rt.c"
                    .into(),
            feedback_signals: vec![
                "edge coverage (65536-slot map, AFL-style hit-count buckets)".into(),
                "comparison operands with constant-operand marking (clang only)".into(),
                "exit classification".into(),
                "sanitizer reports from stderr on abnormal termination".into(),
                "execution duration".into(),
            ],
            configuration: vec![
                "timeout_ms".into(),
                "memory_limit_mb".into(),
                "use_fork_server".into(),
                "input_mode".into(),
                "env (loader-affecting names refused)".into(),
            ],
            outputs: vec![
                "ExecOutcome with bounded stdout/stderr".into(),
                "bucketed edge map".into(),
                "comparison log".into(),
            ],
            resource_limits: vec![
                "RLIMIT_AS from memory_limit_mb".into(),
                "RLIMIT_FSIZE 64 MiB".into(),
                "RLIMIT_NPROC 256".into(),
                "RLIMIT_CORE 0".into(),
                "per-run deadline enforced by SIGKILL to the process group".into(),
            ],
            failure_modes: vec![
                "fork-server handshake absent: falls back to exec-per-run".into(),
                "coverage region ABI mismatch: refused, campaign stops".into(),
                "comparison log full: entries are a prefix, flagged by cmp_overflowed".into(),
            ],
            capability_limitations: vec![
                "gcc builds have no comparison log and coarser edges \
                 (return-address approximation)"
                    .into(),
                "a sanitizer build and a comparison-log build may need different compilers; \
                 configure oracle_binary to get both"
                    .into(),
                "no in-process persistent mode: one fork per input".into(),
            ],
        },
        Backend::BlackBox => AdapterDeclaration {
            backend,
            supported_target_types: vec!["any local executable".into()],
            input_model: "one byte string per run on stdin, or a path substituted for @@".into(),
            required_instrumentation: "none".into(),
            feedback_signals: vec![
                "exit classification".into(),
                "sanitizer reports from stderr, if the target happens to be a sanitizer build"
                    .into(),
                "execution duration".into(),
            ],
            configuration: vec![
                "timeout_ms".into(),
                "memory_limit_mb".into(),
                "input_mode".into(),
            ],
            outputs: vec!["ExecOutcome with bounded stdout/stderr, no coverage".into()],
            resource_limits: vec!["same rlimits as the native backend".into()],
            failure_modes: vec!["none specific to this adapter".into()],
            capability_limitations: vec![
                "no coverage, so coverage-guided and comparison-guided strategies are \
                 unavailable and corpus ranking loses its strongest signal"
                    .into(),
            ],
        },
        Backend::LibFuzzer => AdapterDeclaration {
            backend,
            supported_target_types: vec![
                "in-process harness exporting LLVMFuzzerTestOneInput".into()
            ],
            input_model: "a corpus directory of files; the engine owns the inner loop".into(),
            required_instrumentation: "clang -fsanitize=fuzzer[,address]".into(),
            feedback_signals: vec![
                "coverage counters reported by libFuzzer's own output".into(),
                "crash and OOM artifacts written to the artifact directory".into(),
            ],
            configuration: vec![
                "-max_total_time".into(),
                "-runs".into(),
                "-max_len".into(),
                "-timeout".into(),
                "-rss_limit_mb".into(),
                "-artifact_prefix".into(),
            ],
            outputs: vec![
                "artifact files for each crash".into(),
                "stderr progress lines parsed for coverage and execution counts".into(),
            ],
            resource_limits: vec!["-rss_limit_mb".into(), "-timeout".into()],
            failure_modes: vec![
                "harness exits immediately: usually a missing corpus directory".into(),
                "runtime archive absent at link time".into(),
            ],
            capability_limitations: vec![
                "libFuzzer owns the mutation loop, so AETHER's strategies cannot drive \
                 individual inputs; the adapter schedules bounded libFuzzer runs and \
                 harvests their corpus and artifacts instead"
                    .into(),
                "no per-input comparison log".into(),
                "INTERFACE ONLY on this host: the libFuzzer runtime is unavailable, so this \
                 adapter's drive path is unverified"
                    .into(),
            ],
        },
        Backend::AflPlusPlus => AdapterDeclaration {
            backend,
            supported_target_types: vec![
                "AFL++-instrumented executable reading stdin or a @@ path".into(),
            ],
            input_model: "a corpus directory of files; afl-fuzz owns the inner loop".into(),
            required_instrumentation: "afl-clang-fast / afl-cc / afl-gcc".into(),
            feedback_signals: vec![
                "AFL++ fuzzer_stats: edges found, executions, crash and hang counts".into(),
                "queue entries harvested as corpus inputs".into(),
            ],
            configuration: vec![
                "-i input dir".into(),
                "-o output dir".into(),
                "-V duration".into(),
                "-m memory limit".into(),
                "-t timeout".into(),
                "-x dictionary".into(),
            ],
            outputs: vec![
                "out/default/queue entries".into(),
                "out/default/crashes and hangs".into(),
                "out/default/fuzzer_stats".into(),
            ],
            resource_limits: vec!["-m".into(), "-t".into()],
            failure_modes: vec![
                "afl-fuzz refuses to start without a kernel core-pattern change".into(),
                "target not AFL-instrumented: afl-fuzz aborts with a fork-server error".into(),
            ],
            capability_limitations: vec![
                "AFL++ owns the mutation loop; AETHER schedules bounded runs and harvests \
                 the queue rather than driving single inputs"
                    .into(),
                "INTERFACE ONLY on this host: AFL++ is not installed, so this adapter's \
                 drive path is unverified"
                    .into(),
            ],
        },
    }
}

/// Look up an executable on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let c = dir.join(name);
        if is_executable(&c) {
            return Some(c);
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Find a clang runtime archive such as `libclang_rt.fuzzer-x86_64.a`.
///
/// `clang -print-runtime-dir` is authoritative but prints a directory that may
/// not exist, so the directory is checked for the archive itself.
fn find_clang_runtime(component: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("clang")
        .arg("-print-runtime-dir")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    if dir.as_os_str().is_empty() {
        return None;
    }
    let entries = std::fs::read_dir(&dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("libclang_rt.{component}")) && name.ends_with(".a") {
            return Some(e.path());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_backend_is_available_on_a_host_with_a_compiler() {
        let s = detect_native();
        assert!(s.available, "expected a C compiler: {:?}", s.reason);
        assert!(
            s.verified,
            "the native backend is the one that is actually exercised"
        );
    }

    #[test]
    fn black_box_backend_needs_nothing() {
        let s = detect_black_box();
        assert!(s.available);
        assert!(s.reason.is_none());
    }

    #[test]
    fn unavailable_adapters_explain_themselves_and_offer_a_remedy() {
        // Whatever this host has, an adapter reported unavailable must say why
        // and how to fix it; one reported available must not claim a reason.
        for s in detect_all() {
            if s.available {
                assert!(
                    s.reason.is_none(),
                    "{:?} available but gave a reason",
                    s.backend
                );
            } else {
                let r = s
                    .reason
                    .as_ref()
                    .unwrap_or_else(|| panic!("{:?} unavailable with no reason", s.backend));
                assert!(!r.is_empty());
                assert!(
                    s.remedy.is_some(),
                    "{:?} unavailable with no remedy",
                    s.backend
                );
            }
        }
    }

    #[test]
    fn third_party_adapters_are_marked_unverified() {
        // These adapters have never been driven against the real engines on
        // this host; the flag is what keeps the doctor report honest.
        assert!(!detect_libfuzzer().verified);
        assert!(!detect_aflpp().verified);
    }

    #[test]
    fn libfuzzer_detection_requires_the_runtime_not_just_clang() {
        let s = detect_libfuzzer();
        if which("clang").is_some() && find_clang_runtime("fuzzer").is_none() {
            assert!(
                !s.available,
                "clang without its runtime must not count as available"
            );
            let r = s.reason.unwrap();
            assert!(
                r.contains("libFuzzer runtime") || r.contains("libclang_rt"),
                "{r}"
            );
        }
    }

    #[test]
    fn every_backend_declares_a_full_contract() {
        for b in [
            Backend::AetherNative,
            Backend::BlackBox,
            Backend::LibFuzzer,
            Backend::AflPlusPlus,
        ] {
            let d = declaration(b);
            assert_eq!(d.backend, b);
            assert!(!d.supported_target_types.is_empty(), "{b:?}");
            assert!(!d.input_model.is_empty(), "{b:?}");
            assert!(!d.required_instrumentation.is_empty(), "{b:?}");
            assert!(!d.feedback_signals.is_empty(), "{b:?}");
            assert!(!d.outputs.is_empty(), "{b:?}");
            assert!(!d.resource_limits.is_empty(), "{b:?}");
            assert!(!d.failure_modes.is_empty(), "{b:?}");
            assert!(
                !d.capability_limitations.is_empty(),
                "{b:?} must state its limits"
            );
        }
    }

    #[test]
    fn backend_maps_from_instrumentation() {
        assert_eq!(
            Backend::from_instrumentation(Instrumentation::AetherNative),
            Backend::AetherNative
        );
        assert_eq!(
            Backend::from_instrumentation(Instrumentation::None),
            Backend::BlackBox
        );
    }

    #[test]
    fn which_finds_a_known_tool_and_misses_a_nonexistent_one() {
        assert!(which("sh").is_some());
        assert!(which("aether-definitely-not-a-real-tool").is_none());
    }
}
