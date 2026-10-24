//! Integration tests for the native execution backend, driven against the
//! real compiled fixtures in `fixtures/`.
//!
//! These cover the properties the rest of the engine depends on: that
//! coverage is real and responds to input quality, that the comparison log
//! reports the constants a target compares against, that a crash is detected
//! and a clean run is not, that a deadline is enforced and the process group
//! reaped, and that a target cannot flood the engine with output or fake a
//! sanitizer finding.

mod common;

use std::time::Duration;

use aether_core::config::{Config, InputMode, Instrumentation};
use aether_core::exec::native::{NativeExecutor, TargetSpec};
use aether_core::exec::{ExitClass, Executor};
use aether_core::scope::ScopePolicy;
use common::{config_toml_for, config_toml_uninstrumented, fixture, Build, Scratch};

/// Build an executor for a fixture, with the fork server as configured.
fn executor_for(stem: &str, build: Build, fork_server: bool, tag: &str) -> (NativeExecutor, Scratch) {
    let bin = fixture(stem, build);
    let extra = if fork_server { "" } else { "\nuse_fork_server = false" };
    // use_fork_server lives under [target]; splice it in there.
    let toml = if fork_server {
        config_toml_for(&bin, "")
    } else {
        config_toml_for(&bin, "").replace("timeout_ms = 2000", "timeout_ms = 2000\nuse_fork_server = false")
    };
    let _ = extra;
    let cfg = Config::from_toml_str(&toml).expect("fixture config should be valid");
    let scratch = Scratch::new(tag);
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 16 * 1024)
        .expect("spec from fixture config");
    let exec = NativeExecutor::new(spec, &scratch.path).expect("construct executor");
    (exec, scratch)
}

#[test]
fn fork_server_handshake_succeeds_on_an_instrumented_target() {
    let (exec, _s) = executor_for("coverage_ladder", Build::Instrumented, true, "fs-handshake");
    let caps = exec.capabilities();
    assert!(
        caps.fork_server,
        "fork server should be in use; limitations: {:?}",
        caps.limitations
    );
    assert!(caps.edge_coverage);
    assert!(caps.comparison_log);
}

#[test]
fn coverage_responds_to_input_quality() {
    // coverage_ladder unlocks one more block per correct prefix byte, so edge
    // counts must increase monotonically with a better prefix. This is the
    // property every coverage-guided strategy in the engine relies on.
    let (mut exec, _s) = executor_for("coverage_ladder", Build::InstrumentedO0, true, "cov-ladder");

    let mut counts = Vec::new();
    for prefix in ["", "A", "AE", "AET", "AETH", "AETHE", "AETHER"] {
        let out = exec.run(prefix.as_bytes()).expect("run");
        let edges = out.edge_count().expect("instrumented target must report coverage");
        counts.push(edges);
    }

    assert!(
        counts.windows(2).all(|w| w[1] >= w[0]),
        "edge counts must not decrease as the prefix improves: {counts:?}"
    );
    assert!(
        counts.last().unwrap() > counts.first().unwrap(),
        "a fully correct prefix must reach more edges than an empty input: {counts:?}"
    );
}

#[test]
fn coverage_is_per_run_not_cumulative() {
    // The engine resets the map before each run; without that, every input
    // would look like it reached everything the previous one did.
    let (mut exec, _s) = executor_for("coverage_ladder", Build::InstrumentedO0, true, "cov-reset");
    let good = exec.run(b"AETHER").unwrap().edge_count().unwrap();
    let bad = exec.run(b"zzzzzz").unwrap().edge_count().unwrap();
    assert!(bad < good, "coverage leaked between runs: good={good} bad={bad}");
}

#[test]
fn comparison_log_reports_the_constant_a_target_compares_against() {
    // crash_magic gates on 0xDEADBEEF. With a wrong input the comparison log
    // must surface that constant: this is what the cmplog-guided strategy
    // substitutes into the input instead of guessing 2^32 possibilities.
    let (mut exec, _s) = executor_for("crash_magic", Build::Instrumented, true, "cmplog");
    let out = exec.run(b"AAAAAAAA").expect("run");

    assert!(!out.cmp_entries.is_empty(), "expected comparison entries");
    let found = out
        .cmp_entries
        .iter()
        .any(|e| e.is_const && e.v0 == 0xDEAD_BEEF && e.width == 4);
    assert!(
        found,
        "comparison log should contain the 4-byte constant 0xDEADBEEF; got {:?}",
        out.cmp_entries
    );
}

#[test]
fn comparison_log_advances_with_the_input() {
    // Each gate passed should reveal the next gate's constant.
    let (mut exec, _s) = executor_for("crash_magic", Build::Instrumented, true, "cmplog-adv");

    let stage1 = exec.run(b"AAAAAAAA").unwrap();
    assert!(stage1.cmp_entries.iter().any(|e| e.v0 == 0xDEAD_BEEF));

    // Satisfy the magic; the next comparison is the 2-byte version 0x0203.
    let stage2 = exec.run(&[0xEF, 0xBE, 0xAD, 0xDE, b'A', b'A', b'A', b'A']).unwrap();
    assert!(
        stage2.cmp_entries.iter().any(|e| e.is_const && e.v0 == 0x0203 && e.width == 2),
        "expected the version constant after the magic matched: {:?}",
        stage2.cmp_entries
    );
}

#[test]
fn crash_is_detected_with_the_right_signal() {
    let (mut exec, _s) = executor_for("crash_magic", Build::Instrumented, true, "crash");
    let out = exec.run(&[0xEF, 0xBE, 0xAD, 0xDE, 0x03, 0x02, b'Z', b'!']).expect("run");
    assert_eq!(out.class, ExitClass::Crash, "stderr: {}", out.stderr_str());
    assert_eq!(out.signal, Some(libc::SIGABRT));
    assert!(out.class.is_candidate_failure());
}

#[test]
fn a_clean_target_never_reports_a_failure() {
    // always_ok is the false-positive control: no input may produce a finding.
    let (mut exec, _s) = executor_for("always_ok", Build::Instrumented, true, "clean");
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        b"hello".to_vec(),
        vec![0u8; 1024],
        vec![0xFF; 4096],
        (0..=255u8).collect(),
    ];
    for input in inputs {
        let out = exec.run(&input).expect("run");
        assert_eq!(out.class, ExitClass::Ok, "input len {} misclassified", input.len());
        assert!(!out.class.is_candidate_failure());
        assert!(out.sanitizer.is_none());
    }
}

#[test]
fn deadline_is_enforced_and_the_target_is_reaped() {
    // hang.c spins forever on input starting with 'H'.
    let bin = fixture("hang", Build::Instrumented);
    let toml = config_toml_for(&bin, "").replace("timeout_ms = 2000", "timeout_ms = 300");
    let cfg = Config::from_toml_str(&toml).unwrap();
    let scratch = Scratch::new("timeout");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &scratch.path).unwrap();

    let start = std::time::Instant::now();
    let out = exec.run(b"HANG").expect("run");
    let elapsed = start.elapsed();

    assert_eq!(out.class, ExitClass::Timeout);
    assert!(out.class.is_candidate_failure(), "a hang is worth investigating");
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout took {elapsed:?}; the deadline should have fired at 300ms"
    );

    // The executor must still be usable afterwards: a timeout cannot wedge it.
    let ok = exec.run(b"fine").expect("run after timeout");
    assert_eq!(ok.class, ExitClass::Ok);
}

#[test]
fn output_capture_is_bounded() {
    // noisy_output prints ~20k lines. The engine must keep a bounded prefix
    // and say that it truncated, rather than holding the whole stream.
    let bin = fixture("noisy_output", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let scratch = Scratch::new("noisy");
    let limit = 4096;
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), limit).unwrap();
    let mut exec = NativeExecutor::new(spec, &scratch.path).unwrap();

    let out = exec.run(b"x").expect("run");
    assert!(out.stdout.len() <= limit, "captured {} bytes", out.stdout.len());
    assert!(out.stdout_truncated, "truncation must be reported, not silent");
}

#[test]
fn a_target_cannot_fake_a_sanitizer_finding() {
    // noisy_output prints a convincing AddressSanitizer banner on stdout and
    // then exits cleanly. Treating that as a finding would let any target
    // manufacture false positives.
    let (mut exec, _s) = executor_for("noisy_output", Build::Instrumented, true, "fake-san");
    let out = exec.run(b"x").expect("run");
    assert!(
        out.sanitizer.is_none(),
        "a banner on stdout from a clean exit must not become a finding"
    );
    assert_ne!(out.class, ExitClass::SanitizerFault);
}

#[test]
fn sanitizer_oracle_detects_a_real_fault() {
    // The gcc+ASan build of heap_oob is the oracle build: the same input that
    // merely returns on the instrumented build must be reported here.
    let bin = fixture("heap_oob", Build::AsanOracle);
    let cfg = Config::from_toml_str(&config_toml_uninstrumented(&bin, ""))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cfg.target.instrumentation, Instrumentation::None);
    let scratch = Scratch::new("asan");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 32 * 1024).unwrap();
    let mut exec = NativeExecutor::new(spec, &scratch.path).unwrap();

    let out = exec.run(b"LEN\xff").expect("run");
    assert_eq!(
        out.class,
        ExitClass::SanitizerFault,
        "stderr was: {}",
        out.stderr_str()
    );
    let report = out.sanitizer.expect("a sanitizer report");
    assert!(
        report.fault.contains("overflow") || report.fault.contains("unknown-crash"),
        "unexpected fault {:?}",
        report.fault
    );
    assert!(!report.frames.is_empty(), "report should carry frames");
}

#[test]
fn exec_fallback_path_works_without_a_fork_server() {
    // A target with no AETHER runtime linked in cannot hand us a fork server;
    // the executor must fall back rather than fail, and say that it did.
    let bin = fixture("crash_magic", Build::Plain);
    let cfg = Config::from_toml_str(&config_toml_uninstrumented(&bin, "")).unwrap();
    let scratch = Scratch::new("plain");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &scratch.path).unwrap();

    assert!(!exec.capabilities().fork_server);
    assert!(!exec.capabilities().edge_coverage);
    assert!(exec
        .capabilities()
        .limitations
        .iter()
        .any(|l| l.contains("not instrumented")));

    // Still classifies correctly without any coverage.
    let crash = exec.run(&[0xEF, 0xBE, 0xAD, 0xDE, 0x03, 0x02, b'Z', b'!']).unwrap();
    assert_eq!(crash.class, ExitClass::Crash);
    assert!(crash.coverage.is_none(), "uninstrumented target must report no coverage, not zeroes");

    let ok = exec.run(b"AAAAAAAA").unwrap();
    assert_eq!(ok.class, ExitClass::NonZeroExit);
}

#[test]
fn input_is_passed_as_data_never_through_a_shell() {
    // Shell metacharacters, NUL bytes and path traversal in the *input* must
    // reach the target as bytes and nothing more.
    let (mut exec, _s) = executor_for("always_ok", Build::Instrumented, true, "shell-safe");
    let nasty: Vec<&[u8]> = vec![
        b"; rm -rf / #",
        b"$(touch /tmp/aether-should-not-exist)",
        b"`id`",
        b"../../../../etc/passwd",
        b"a\x00b|c>d<e&f",
        b"'\"\\",
    ];
    for input in nasty {
        let out = exec.run(input).expect("run");
        assert_eq!(out.class, ExitClass::Ok, "input {:?}", String::from_utf8_lossy(input));
    }
    assert!(
        !std::path::Path::new("/tmp/aether-should-not-exist").exists(),
        "command substitution in an input was executed"
    );
}

#[test]
fn large_inputs_are_handled() {
    let (mut exec, _s) = executor_for("always_ok", Build::Instrumented, true, "large");
    for size in [0usize, 1, 4096, 65_536, 1 << 20] {
        let out = exec.run(&vec![0x41; size]).expect("run");
        assert_eq!(out.class, ExitClass::Ok, "size {size}");
    }
}

#[test]
fn executor_survives_many_runs_without_leaking_children() {
    // A fork server that leaked a child per run would exhaust the process
    // table; 400 runs is enough to catch that against RLIMIT_NPROC of 256.
    let (mut exec, _s) = executor_for("coverage_ladder", Build::Instrumented, true, "many");
    for i in 0..400u32 {
        let input = i.to_le_bytes();
        exec.run(&input).unwrap_or_else(|e| panic!("run {i} failed: {e}"));
    }
    assert_eq!(exec.exec_count(), 400);
}

#[test]
fn reset_restarts_the_fork_server() {
    let (mut exec, _s) = executor_for("coverage_ladder", Build::Instrumented, true, "reset");
    exec.run(b"AETHER").unwrap();
    exec.reset().expect("reset should restart the fork server");
    assert!(exec.capabilities().fork_server);
    let out = exec.run(b"AETHER").expect("run after reset");
    assert!(out.edge_count().unwrap() > 0, "coverage lost after reset");
}

#[test]
fn file_arg_mode_delivers_input_through_the_placeholder() {
    // file_arg_reader reads argv[1], so this exercises @@ substitution. The
    // same input must get the same verdict as stdin delivery would, otherwise
    // a finding would depend on how the bytes were handed over.
    let bin = fixture("file_arg_reader", Build::Plain);
    let cfg = Config::from_toml_str(&config_toml_uninstrumented(
        &bin,
        "input_mode = \"file-arg\"\nargs = [\"@@\"]",
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cfg.target.input_mode, InputMode::FileArg);

    let scratch = Scratch::new("file-arg");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    assert!(!spec.use_fork_server, "file-arg mode cannot use the fork server");
    let mut exec = NativeExecutor::new(spec, &scratch.path).unwrap();

    // The crash input, delivered as a file path argument.
    let crash = exec.run(b"BOOM").expect("run");
    assert_eq!(crash.class, ExitClass::Crash, "stderr: {}", crash.stderr_str());

    // Non-crashing inputs still classify by exit code, which proves the file
    // really was re-written between runs rather than left stale.
    assert_eq!(exec.run(b"zebra").unwrap().exit_code, Some(2));
    assert_eq!(exec.run(b"apple").unwrap().exit_code, Some(0));
    assert_eq!(exec.run(b"").unwrap().exit_code, Some(1));
}

#[test]
fn fork_server_is_refused_for_file_arg_mode_at_config_time() {
    // The fork server rewinds an inherited stdin descriptor; a path argument
    // is fixed at exec time, so the combination cannot work and is rejected
    // during validation rather than failing mysteriously at run time.
    let bin = fixture("file_arg_reader", Build::Instrumented);
    let toml = config_toml_for(&bin, "").replace(
        "timeout_ms = 2000",
        "timeout_ms = 2000\ninput_mode = \"file-arg\"\nargs = [\"@@\"]",
    );
    let e = Config::from_toml_str(&toml).unwrap_err();
    assert!(e.to_string().contains("fork server requires"), "{e}");
}
