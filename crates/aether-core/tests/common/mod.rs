//! Shared fixture support for integration tests.
//!
//! Fixtures are the C programs in `fixtures/`, compiled on demand with
//! `runtime/aether-cc`. They are built once per test binary into a cache
//! directory under the repository's `target/`, so the compile cost is paid
//! once rather than per test, and the binaries stay inspectable after a
//! failure.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// Repository root, found by walking up from this file's compile-time path.
pub fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // crates/aether-core
    p.pop(); // crates
    p.pop(); // repo root
    p
}

pub fn fixtures_dir() -> PathBuf {
    repo_root().join("fixtures")
}

pub fn aether_cc() -> PathBuf {
    repo_root().join("runtime").join("aether-cc")
}

fn cache_dir() -> PathBuf {
    let d = repo_root().join("target").join("fixture-bin");
    std::fs::create_dir_all(&d).expect("create fixture cache dir");
    d
}

/// How a fixture should be compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    /// clang, edge coverage plus the comparison log. The default.
    Instrumented,
    /// clang, coverage at -O0: the most sensitive coverage gradient.
    InstrumentedO0,
    /// gcc with AddressSanitizer and coverage. Used as a crash oracle.
    AsanOracle,
    /// No instrumentation at all, for the black-box path.
    Plain,
}

impl Build {
    fn suffix(&self) -> &'static str {
        match self {
            Build::Instrumented => "inst",
            Build::InstrumentedO0 => "inst0",
            Build::AsanOracle => "asan",
            Build::Plain => "plain",
        }
    }

    fn args(&self) -> Vec<&'static str> {
        match self {
            Build::Instrumented => vec![],
            Build::InstrumentedO0 => vec!["--opt", "-O0"],
            Build::AsanOracle => vec!["--cc", "gcc", "--sanitizer", "address"],
            Build::Plain => vec!["--no-instrument"],
        }
    }
}

static BUILD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Compile a fixture and return the binary path, reusing a cached build.
///
/// `stem` is the fixture file name without `.c`, e.g. `"crash_magic"`.
pub fn fixture(stem: &str, build: Build) -> PathBuf {
    let out = cache_dir().join(format!("{stem}.{}", build.suffix()));
    let src = fixtures_dir().join(format!("{stem}.c"));
    assert!(src.exists(), "no such fixture source: {}", src.display());

    // One compile at a time: tests run in parallel and would otherwise race
    // on the same output path.
    let lock = BUILD_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());

    if is_fresh(&out, &src) {
        return out;
    }

    let mut cmd = Command::new(aether_cc());
    cmd.args(build.args());
    cmd.arg("-o").arg(&out).arg(&src);
    let o = cmd.output().expect("run aether-cc");
    assert!(
        o.status.success(),
        "aether-cc failed for {stem} ({build:?}):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        out.exists(),
        "aether-cc reported success but produced no binary"
    );
    out
}

/// Is the cached binary newer than both the source and the runtime?
fn is_fresh(out: &Path, src: &Path) -> bool {
    let Ok(om) = std::fs::metadata(out).and_then(|m| m.modified()) else {
        return false;
    };
    for dep in [
        src.to_path_buf(),
        repo_root().join("runtime").join("aether_rt.c"),
        repo_root().join("runtime").join("aether_rt.h"),
        aether_cc(),
    ] {
        if let Ok(dm) = std::fs::metadata(&dep).and_then(|m| m.modified()) {
            if dm > om {
                return false;
            }
        }
    }
    true
}

/// A scratch directory that cleans itself up.
pub struct Scratch {
    pub path: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "aether-test-{}-{}-{}",
            tag,
            std::process::id(),
            aether_core::ids::CampaignId::new()
        ));
        std::fs::create_dir_all(&p).expect("create scratch dir");
        Scratch { path: p }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A minimal valid config for a fixture target, as TOML.
pub fn config_toml_for(binary: &Path, extra: &str) -> String {
    format!(
        r#"
schema_version = 1
[target]
name = "fixture"
kind = "executable"
binary = "{}"
timeout_ms = 2000
[campaign]
duration_secs = 5
{extra}
"#,
        binary.display()
    )
}

/// A config for a target with no instrumentation.
///
/// The default feedback provider list includes `edge-coverage`, which config
/// validation refuses on an uninstrumented target - correctly, since the
/// signal genuinely would not exist. An uninstrumented test target therefore
/// has to state the reduced provider set explicitly.
pub fn config_toml_uninstrumented(binary: &Path, extra_target: &str) -> String {
    format!(
        r#"
schema_version = 1
[target]
name = "fixture-plain"
kind = "executable"
binary = "{}"
timeout_ms = 2000
instrumentation = "none"
use_fork_server = false
{extra_target}
[campaign]
duration_secs = 5
[feedback]
providers = ["exit-class", "sanitizer"]
"#,
        binary.display()
    )
}
