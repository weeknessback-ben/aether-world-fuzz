//! Throughput measurement, used to tune the execution path.
//!
//! Not an assertion-heavy test: it prints measurements so the numbers in
//! docs/BENCHMARKING.md come from this host rather than from guesswork. It
//! does assert the one property that must hold - that the fork server is
//! faster than exec-per-run - because if that inverts, the fork server is
//! costing more than it saves and should not be the default.
//!
//! Run with: cargo test -p aether-core --test perf_probe -- --nocapture

mod common;

use std::time::Instant;

use aether_core::config::Config;
use aether_core::exec::native::{NativeExecutor, TargetSpec};
use aether_core::exec::Executor;
use aether_core::scope::ScopePolicy;
use common::{config_toml_for, config_toml_uninstrumented, fixture, Build, Scratch};

/// Repetitions per configuration. This host is a shared VM whose run-to-run
/// variance was large enough to invert an A/B comparison, so each
/// configuration is measured several times and the median is reported.
const REPS: usize = 5;

fn measure(mut exec: NativeExecutor, runs: u32, label: &str) -> f64 {
    // Warm up so page faults and the first fork are not counted.
    for i in 0..50u32 {
        exec.run(&i.to_le_bytes()).unwrap();
    }

    let mut rates = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let start = Instant::now();
        for i in 0..runs {
            exec.run(&i.to_le_bytes()).unwrap();
        }
        rates.push(runs as f64 / start.elapsed().as_secs_f64());
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = rates[REPS / 2];
    let (lo, hi) = (rates[0], rates[REPS - 1]);
    println!(
        "  {label:<34} median {median:>8.0} exec/s  ({:>5.0} us/exec)  spread {lo:.0}..{hi:.0} (+/-{:.0}%)",
        1e6 / median,
        (hi - lo) / median * 50.0
    );
    median
}

#[test]
fn execution_throughput() {
    println!(
        "\n=== AETHER execution throughput ({} cores) ===",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(0)
    );

    let runs = 1200;

    // Fork server, instrumented, comparison log on.
    let bin = fixture("coverage_ladder", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s1 = Scratch::new("perf-fs");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let e = NativeExecutor::new(spec, &s1.path).unwrap();
    assert!(e.capabilities().fork_server, "expected the fork server");
    let fs_eps = measure(e, runs, "fork server + cov + cmplog");

    // Fork server, instrumented, comparison log off: isolates cmplog cost.
    let cfg2 = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s2 = Scratch::new("perf-fs-nocmp");
    let mut spec2 = TargetSpec::from_config(&cfg2.target, &ScopePolicy::default(), 4096).unwrap();
    spec2.cmplog = false;
    let e2 = NativeExecutor::new(spec2, &s2.path).unwrap();
    let fs_nocmp_eps = measure(e2, runs, "fork server + cov, no cmplog");

    // Exec per run, instrumented: the cost the fork server removes.
    let cfg3 = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s3 = Scratch::new("perf-exec");
    let mut spec3 = TargetSpec::from_config(&cfg3.target, &ScopePolicy::default(), 4096).unwrap();
    spec3.use_fork_server = false;
    let e3 = NativeExecutor::new(spec3, &s3.path).unwrap();
    assert!(!e3.capabilities().fork_server);
    let exec_eps = measure(e3, runs, "exec per run + cov");

    // Exec per run, no instrumentation: isolates instrumentation cost.
    let plain = fixture("coverage_ladder", Build::Plain);
    let cfg4 = Config::from_toml_str(&config_toml_uninstrumented(&plain, "")).unwrap();
    let s4 = Scratch::new("perf-plain");
    let spec4 = TargetSpec::from_config(&cfg4.target, &ScopePolicy::default(), 4096).unwrap();
    let e4 = NativeExecutor::new(spec4, &s4.path).unwrap();
    let plain_eps = measure(e4, runs, "exec per run, uninstrumented");

    // Scratch on tmpfs: the test case and the two log files are rewritten on
    // every execution, so where they live is part of the hot path.
    let tmpfs_eps = if std::path::Path::new("/dev/shm").is_dir() {
        let cfg5 = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
        let p = std::path::PathBuf::from("/dev/shm")
            .join(format!("aether-perf-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        let spec5 = TargetSpec::from_config(&cfg5.target, &ScopePolicy::default(), 4096).unwrap();
        let e5 = NativeExecutor::new(spec5, &p).unwrap();
        let r = measure(e5, runs, "fork server, scratch on tmpfs");
        let _ = std::fs::remove_dir_all(&p);
        Some(r)
    } else {
        None
    };

    println!(
        "\n  fork server speedup over exec-per-run: {:.2}x",
        fs_eps / exec_eps
    );
    if let Some(t) = tmpfs_eps {
        println!(
            "  tmpfs scratch vs default scratch:      {:+.1}%",
            (t - fs_eps) / fs_eps * 100.0
        );
    }
    println!(
        "  comparison log overhead:               {:.1}%",
        (fs_nocmp_eps - fs_eps) / fs_nocmp_eps * 100.0
    );
    println!(
        "  instrumentation overhead (exec path):  {:.1}%\n",
        (plain_eps - exec_eps) / plain_eps * 100.0
    );

    // The one thing that must hold: if the fork server were slower, it would
    // be costing more than it saves and should not be the default.
    assert!(
        fs_eps > exec_eps,
        "fork server ({fs_eps:.0}/s) is not faster than exec-per-run ({exec_eps:.0}/s)"
    );
}
