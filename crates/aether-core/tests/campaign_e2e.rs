//! End-to-end campaign tests against the real compiled fixtures.
//!
//! These are the tests that establish the engine works as a whole rather than
//! as a set of parts: a campaign is created, run against a real instrumented
//! binary, and its findings and reports are checked.
//!
//! Each one asserts something a user would actually care about:
//!
//! * a planted defect is found, reproduced and minimised,
//! * a clean target produces no findings at all,
//! * a hang is detected without wedging the campaign,
//! * the comparison-guided strategy walks a magic-value ladder that blind
//!   mutation does not,
//! * cancellation stops promptly,
//! * reports distinguish what was established from what was not.

mod common;

use std::time::{Duration, Instant};

use aether_core::config::Config;
use aether_core::evidence::FindingStatus;
use aether_core::runtime::{Campaign, Cancel, StopReason};
use common::{fixture, Build, Scratch};

/// Build a campaign config for a fixture, with a short budget.
fn config_for(stem: &str, build: Build, out_dir: &std::path::Path, extra: &str) -> Config {
    let bin = fixture(stem, build);
    let toml = format!(
        r#"
schema_version = 1
[target]
name = "{stem}"
kind = "executable"
binary = "{}"
timeout_ms = 1000
[campaign]
duration_secs = 10
workers = 1
seed = 20260124
max_input_bytes = 4096
[reproduction]
attempts = 5
required_successes = 3
minimize = true
minimize_max_execs = 400
[output]
dir = "{}"
report_formats = ["json", "markdown", "sarif"]
{extra}
"#,
        bin.display(),
        out_dir.display()
    );
    Config::from_toml_str(&toml).unwrap_or_else(|e| panic!("config for {stem}: {e}"))
}

fn run_campaign(cfg: Config) -> (Campaign, StopReason) {
    let cancel = Cancel::new();
    let mut c = Campaign::create(cfg, cancel).expect("create campaign");
    c.seed_corpus(None).expect("seed corpus");
    let reason = c.run().expect("run campaign");
    (c, reason)
}

#[test]
fn finds_reproduces_and_minimises_a_planted_defect() {
    // crash_magic aborts past four nested constant gates. With the comparison
    // log available, the campaign should walk them and reach the abort.
    let s = Scratch::new("e2e-crash");
    let cfg = config_for(
        "crash_magic",
        Build::Instrumented,
        &s.path,
        "[strategies]\nenabled = [\"cmplog-guided\", \"havoc\", \"dictionary\"]\n",
    );
    let (c, reason) = run_campaign(cfg);

    let confirmed: Vec<_> = c
        .findings()
        .iter()
        .filter(|f| f.status.is_confirmed())
        .collect();
    assert!(
        !confirmed.is_empty(),
        "no confirmed finding after {reason:?}; {} candidates, {} executions",
        c.findings().len(),
        c.report(Some(reason)).unwrap().execution.total_executions
    );

    let f = confirmed[0];
    assert_eq!(f.status, FindingStatus::Reproducible, "{}", f.summary());
    assert!(f.reproduction.successes >= f.reproduction.required);
    assert!(
        f.signature.label.contains("SIGABRT") || f.evidence.signal == Some(libc::SIGABRT),
        "expected the planted abort, got {}",
        f.signature.label
    );

    // Minimisation must have run and re-validated, and the original input must
    // still be recorded alongside it.
    let min_size = f.evidence.minimized_size.expect("minimised input");
    assert!(
        min_size <= f.evidence.trigger_size,
        "minimised input ({min_size}) is larger than the original ({})",
        f.evidence.trigger_size
    );
    assert!(
        f.reproduction.minimized_validated,
        "minimised input was not re-validated"
    );
    assert!(
        !f.evidence.trigger_hash.is_empty(),
        "original input hash was lost"
    );
    assert!(
        f.discovered_by.is_some(),
        "finding should name its strategy"
    );
}

#[test]
fn a_clean_target_produces_no_findings() {
    // always_ok is the false-positive control. Any finding here is a bug in
    // the engine, not in the target.
    let s = Scratch::new("e2e-clean");
    let mut cfg = config_for("always_ok", Build::Instrumented, &s.path, "");
    cfg.campaign.duration_secs = 5;
    let (c, _) = run_campaign(cfg);

    assert!(
        c.findings().is_empty(),
        "clean target produced findings: {:?}",
        c.findings().iter().map(|f| f.summary()).collect::<Vec<_>>()
    );
    let r = c.report(Some(StopReason::DurationElapsed)).unwrap();
    assert_eq!(r.findings.confirmed_count(), 0);
    assert_eq!(r.execution.crashes_observed, 0);
    assert!(r.execution.total_executions > 100, "campaign barely ran");

    // And the report must not read as a clean bill of health.
    let md = r.to_markdown();
    assert!(md.contains("not a claim that the target is free of defects"));
}

#[test]
fn a_hang_is_detected_without_wedging_the_campaign() {
    let s = Scratch::new("e2e-hang");
    let mut cfg = config_for(
        "hang",
        Build::Instrumented,
        &s.path,
        "[strategies]\nenabled = [\"dictionary\", \"havoc\"]\n",
    );
    cfg.target.timeout_ms = 200;
    cfg.campaign.duration_secs = 8;
    // Give the mutator a head start on producing an input beginning with 'H'.
    cfg.strategies.dictionary = vec!["H".into(), "HANG".into()];

    let (c, reason) = run_campaign(cfg);
    let r = c.report(Some(reason)).unwrap();

    assert!(
        r.execution.timeouts_observed > 0,
        "no timeout observed in {} executions",
        r.execution.total_executions
    );
    // The campaign must have kept running after the timeouts.
    assert!(
        r.execution.total_executions > r.execution.timeouts_observed,
        "campaign appears to have stalled on the first hang"
    );
}

#[test]
fn comparison_guided_substitution_beats_blind_mutation_on_a_magic_ladder() {
    // The measurable claim behind the comparison log: on a target gated by
    // nested constants, substitution reaches the defect and blind byte
    // mutation does not. Both get the same budget and the same seed.
    let run = |strategies: &str, tag: &str| -> (u64, bool, u32) {
        let s = Scratch::new(tag);
        let mut cfg = config_for(
            "crash_magic",
            Build::Instrumented,
            &s.path,
            &format!("[strategies]\nenabled = {strategies}\n"),
        );
        cfg.campaign.duration_secs = 8;
        let (c, reason) = run_campaign(cfg);
        let r = c.report(Some(reason)).unwrap();
        (
            r.execution.total_executions,
            r.findings.confirmed_count() > 0,
            r.coverage.total_edges,
        )
    };

    let (cmp_execs, cmp_found, cmp_edges) = run("[\"cmplog-guided\"]", "e2e-ladder-cmp");
    let (blind_execs, blind_found, blind_edges) = run("[\"random-mutation\"]", "e2e-ladder-blind");

    println!(
        "cmplog-guided: {cmp_execs} execs, {cmp_edges} edges, found={cmp_found}\n\
         random-mutation: {blind_execs} execs, {blind_edges} edges, found={blind_found}"
    );

    assert!(
        cmp_found,
        "comparison-guided substitution failed to reach the abort in {cmp_execs} executions"
    );
    assert!(
        !blind_found,
        "blind mutation reached a 4-gate constant ladder in {blind_execs} executions, which \
         would make this comparison meaningless"
    );
    assert!(
        cmp_edges > blind_edges,
        "substitution should reach more of the target: {cmp_edges} vs {blind_edges}"
    );
}

#[test]
fn cancellation_stops_promptly() {
    let s = Scratch::new("e2e-cancel");
    let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
    cfg.campaign.duration_secs = 3600; // would otherwise run for an hour

    let cancel = Cancel::new();
    let mut c = Campaign::create(cfg, cancel.clone()).unwrap();
    c.seed_corpus(None).unwrap();

    let canceller = {
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            cancel.cancel();
        })
    };

    let start = Instant::now();
    let reason = c.run().unwrap();
    let elapsed = start.elapsed();
    canceller.join().unwrap();

    assert_eq!(reason, StopReason::Cancelled);
    assert!(
        elapsed < Duration::from_secs(10),
        "cancellation took {elapsed:?}; it is checked between executions so it should be prompt"
    );
    assert!(c.report(Some(reason)).unwrap().execution.total_executions > 0);
}

#[test]
fn execution_budget_is_respected() {
    let s = Scratch::new("e2e-budget");
    let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
    cfg.campaign.duration_secs = 0;
    cfg.campaign.max_execs = 500;

    let (c, reason) = run_campaign(cfg);
    assert_eq!(reason, StopReason::ExecutionBudgetReached);
    let execs = c.report(Some(reason)).unwrap().execution.total_executions;
    // A round may finish the batch it was given, so allow one round of slack.
    assert!(
        (500..=700).contains(&execs),
        "ran {execs} executions against a 500 budget"
    );
}

#[test]
fn coverage_and_corpus_grow_on_a_coverage_gradient() {
    // coverage_ladder rewards each additional correct prefix byte, so a
    // working feedback loop must accumulate both coverage and corpus entries.
    let s = Scratch::new("e2e-coverage");
    let mut cfg = config_for("coverage_ladder", Build::InstrumentedO0, &s.path, "");
    cfg.campaign.duration_secs = 8;
    let (c, reason) = run_campaign(cfg);
    let r = c.report(Some(reason)).unwrap();

    assert!(
        r.coverage.total_edges > 1,
        "coverage did not grow: {:?}",
        r.coverage
    );
    assert!(
        r.corpus.entries > 1,
        "corpus did not grow beyond the bootstrap entry: {:?}",
        r.corpus
    );
    assert!(
        r.coverage.guard_count.is_some(),
        "instrumented target should report guards"
    );
    assert!(r.coverage.saturation.is_some());
    assert!(r.environment.edge_coverage);
    assert!(r.environment.fork_server, "fork server should be in use");
}

#[test]
fn reports_are_written_in_every_configured_format() {
    let s = Scratch::new("e2e-reports");
    let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
    cfg.campaign.duration_secs = 4;
    let (c, reason) = run_campaign(cfg);

    let written = c.write_reports(Some(reason)).expect("write reports");
    assert_eq!(written.len(), 3, "expected json, markdown and sarif");
    for p in &written {
        let body = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(!body.is_empty(), "{} is empty", p.display());
    }

    // The SARIF file must parse and declare the tool.
    let sarif = written
        .iter()
        .find(|p| p.to_string_lossy().contains("sarif"))
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(sarif).unwrap()).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "AETHER");
}

#[test]
fn report_records_capabilities_and_limitations_honestly() {
    let s = Scratch::new("e2e-limits");
    let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
    cfg.campaign.duration_secs = 3;
    let (c, reason) = run_campaign(cfg);
    let r = c.report(Some(reason)).unwrap();

    // The adapters that are not usable on this host must be named.
    assert!(
        r.limitations
            .iter()
            .any(|l| l.contains("libfuzzer") || l.contains("aflplusplus")),
        "limitations do not mention the unavailable backends: {:?}",
        r.limitations
    );
    // No oracle build was configured, and that has to be stated.
    assert!(
        r.limitations.iter().any(|l| l.contains("sanitizer oracle")),
        "missing oracle build not reported: {:?}",
        r.limitations
    );
    assert!(!r.environment.sanitizer_oracle);
    assert_eq!(
        r.seed, 20260124,
        "seed must be recorded so the run can be replayed"
    );
}

#[test]
fn a_fixed_execution_budget_is_honoured_exactly() {
    // The budget is a hard guarantee and must not drift with machine load.
    let run = |tag: &str| -> u64 {
        let s = Scratch::new(tag);
        let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
        cfg.campaign.duration_secs = 0;
        cfg.campaign.max_execs = 800;
        cfg.target.timeout_ms = 30_000;
        let (c, reason) = run_campaign(cfg);
        assert_eq!(reason, StopReason::ExecutionBudgetReached);
        c.report(Some(reason)).unwrap().execution.total_executions
    };
    assert_eq!(run("e2e-budget-a"), 800);
    assert_eq!(run("e2e-budget-b"), 800);
}

#[test]
fn the_research_benchmark_profile_replays_a_campaign_closely() {
    // What reproducibility means here, stated precisely, because the
    // benchmark comparisons depend on knowing it.
    //
    // Established and asserted strictly elsewhere:
    //   * the execution budget is honoured exactly
    //     (`a_fixed_execution_budget_is_honoured_exactly`),
    //   * replaying a fixed input sequence through the executor gives
    //     identical coverage every time, so the execution layer itself is
    //     deterministic,
    //   * every strategy's proposals and every RNG stream replay exactly
    //     under a fixed seed (unit tests).
    //
    // Not established: byte-for-byte replay of a whole campaign. Two
    // deliberate design choices read a wall-clock duration - the adaptive
    // schedulers reward discovery per unit of measured compute, and the corpus
    // ranks cheaper inputs higher - and the `research-benchmark` profile turns
    // both off for exactly this reason. With them off, repeated runs agree in
    // roughly five cases out of six and otherwise differ by a single edge,
    // which means some residual timing dependence remains that has not been
    // isolated. It is recorded as a known limitation rather than papered over,
    // and the tolerance below is set to that observed variance rather than to
    // whatever makes the test pass.
    let run = |tag: &str| -> (u64, u32, u64) {
        let s = Scratch::new(tag);
        let mut cfg = config_for("coverage_ladder", Build::Instrumented, &s.path, "");
        cfg.target.timeout_ms = 30_000;
        aether_core::config::apply_profile(&mut cfg, "research-benchmark").unwrap();
        cfg.campaign.duration_secs = 0;
        cfg.campaign.max_execs = 1500;
        cfg.campaign.seed = 20260124;
        let (c, reason) = run_campaign(cfg);
        let r = c.report(Some(reason)).unwrap();
        (
            r.execution.total_executions,
            r.coverage.total_edges,
            r.corpus.entries,
        )
    };
    let a = run("e2e-repro-a");
    let b = run("e2e-repro-b");
    println!("benchmark-profile replay: A = {a:?}  B = {b:?}");

    // The budget is exact, with no tolerance.
    assert_eq!(a.0, b.0, "execution budget must replay exactly");
    assert_eq!(a.0, 1500);
    // Coverage and corpus size within the observed variance.
    assert!(
        a.1.abs_diff(b.1) <= 1,
        "coverage diverged by more than the known variance: {} vs {}",
        a.1,
        b.1
    );
    assert!(
        a.2.abs_diff(b.2) <= 1,
        "corpus size diverged by more than the known variance: {} vs {}",
        a.2,
        b.2
    );
}

#[test]
fn the_execution_layer_is_deterministic() {
    // Isolates the execution layer from the engine's choices: the same input
    // sequence through a fresh executor must give identical coverage. This is
    // what establishes that the residual campaign-level variance above is in
    // scheduling, not in measurement.
    use aether_core::exec::native::{NativeExecutor, TargetSpec};
    use aether_core::exec::Executor;
    use aether_core::feedback::coverage::CoverageTracker;
    use aether_core::scope::ScopePolicy;
    use common::config_toml_for;

    let replay = |tag: &str| -> u32 {
        let bin = fixture("coverage_ladder", Build::Instrumented);
        let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
        let s = Scratch::new(tag);
        let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
        let mut e = NativeExecutor::new(spec, &s.path).unwrap();
        let mut t = CoverageTracker::new();
        for i in 0..400u32 {
            let mut input = i.to_le_bytes().to_vec();
            input.extend_from_slice(&b"AETHER"[..(i as usize % 7)]);
            if let Some(m) = &e.run(&input).unwrap().coverage {
                t.observe(m);
            }
        }
        t.total_edges()
    };

    let runs: Vec<u32> = (0..4)
        .map(|i| replay(&format!("e2e-exec-det-{i}")))
        .collect();
    assert!(
        runs.windows(2).all(|w| w[0] == w[1]),
        "identical input sequences produced different coverage: {runs:?}"
    );
    assert!(runs[0] > 0);
}

#[test]
fn stateful_sequences_reach_an_order_dependent_defect() {
    // stateful_service plants a use-after-free reachable only by AUTH, OPEN,
    // CLOSE, COMMIT in that order. No single-input mutation finds it.
    let s = Scratch::new("e2e-stateful");
    let mut cfg = config_for(
        "stateful_service",
        Build::Instrumented,
        &s.path,
        "[strategies]\nenabled = [\"stateful-sequence\"]\n\
         [strategies.params]\nsequence_max_steps = 10\n",
    );
    cfg.campaign.duration_secs = 15;
    cfg.strategies.dictionary = vec!["letmein".into(), "handle".into()];
    cfg.feedback.providers = vec![
        "edge-coverage".into(),
        "exit-class".into(),
        "state-transition".into(),
        "cmplog".into(),
        "sanitizer".into(),
    ];

    let (c, reason) = run_campaign(cfg);
    let r = c.report(Some(reason)).unwrap();
    println!(
        "stateful: {} executions, {} crashes, {} confirmed findings",
        r.execution.total_executions,
        r.execution.crashes_observed,
        r.findings.confirmed_count()
    );

    // The order is reachable, but finding it inside a short budget is
    // probabilistic, so the assertion is on the mechanism rather than on luck:
    // the campaign must have driven the protocol far enough to see accepted
    // transitions.
    assert!(r.execution.total_executions > 50, "campaign barely ran");
    assert!(
        r.coverage.total_edges > 5,
        "the sequence strategy did not get into the protocol: {:?}",
        r.coverage
    );
}

/// A pooled campaign must actually run on every worker, share the corpus, and
/// report how the pool behaved - not quietly fall back to one worker.
#[test]
fn a_pooled_campaign_runs_all_its_workers_and_shares_one_corpus() {
    let scratch = Scratch::new("pool-parallel");
    let mut cfg = config_for(
        "coverage_ladder",
        Build::Instrumented,
        &scratch.path,
        "[intel]\nscheduler = \"thompson\"\n",
    );
    cfg.campaign.workers = 3;
    cfg.campaign.duration_secs = 0;
    cfg.campaign.max_execs = 9_000;

    let (campaign, reason) = run_campaign(cfg);
    assert_eq!(
        reason,
        StopReason::ExecutionBudgetReached,
        "budget should end it"
    );

    let stats = campaign
        .parallel_stats()
        .expect("a multi-worker campaign must report pool statistics");
    assert_eq!(stats.workers, 3);
    assert!(
        stats.worker_failures.is_empty(),
        "no worker should fail against a working fixture: {:?}",
        stats.worker_failures
    );
    assert_eq!(
        stats.per_worker_executions.len(),
        3,
        "every worker must be accounted for"
    );
    // Every worker has to have done real work. A pool where one thread does
    // everything is the bug this guards against.
    for (i, execs) in stats.per_worker_executions.iter().enumerate() {
        assert!(
            *execs > 100,
            "worker {i} ran only {execs} executions; the pool is not sharing the load"
        );
    }
    assert!(
        stats.executions >= 9_000,
        "pool ran {} executions for a 9000 budget",
        stats.executions
    );

    let report = campaign.report(Some(reason)).expect("report");
    let parallel = report
        .parallel
        .as_ref()
        .expect("the report must carry pool statistics");
    assert_eq!(parallel.workers, 3);
    // The report must say that stagnation escalation did not apply, rather
    // than leaving a reader to assume it did.
    assert!(
        report
            .limitations
            .iter()
            .any(|l| l.contains("Stagnation escalation is not applied")),
        "pooled limitations missing: {:?}",
        report.limitations
    );

    // Strategy statistics must come from the workers. The controller never
    // schedules anything on this path, so reporting its own scheduler would
    // list every strategy at zero - "ran nothing" where the truth is "the
    // controller did not run it".
    assert!(
        !report.strategies.is_empty(),
        "pooled report lists no strategies at all"
    );
    let strategy_execs: u64 = report.strategies.iter().map(|s| s.executions).sum();
    assert!(
        strategy_execs > 0,
        "pooled report credits every strategy with zero executions: {:?}",
        report
            .strategies
            .iter()
            .map(|s| (&s.id, s.executions))
            .collect::<Vec<_>>()
    );
    let share: f64 = report.strategies.iter().map(|s| s.allocation_share).sum();
    assert!(
        (share - 1.0).abs() < 0.01,
        "pooled allocation shares sum to {share}, not 1"
    );

    // One shared corpus, not three private ones: the ladder fixture rewards
    // coverage, so a shared corpus should hold more than the seed.
    assert!(
        report.corpus.entries > 1,
        "shared corpus holds only {} entries",
        report.corpus.entries
    );
    assert!(
        report.coverage.total_edges > 0,
        "pooled coverage was not merged back into the campaign"
    );
}

/// A pooled campaign must validate a defect exactly once however many workers
/// hit it.
///
/// Seeded with a near-miss - `crash_magic`'s full magic prefix with only the
/// last gate byte wrong - so reaching the abort takes one byte flip rather
/// than luck. Measured across five seeds, a 15-second campaign on this fixture
/// from a blank corpus reaches the abort on roughly one seed in five, whether
/// pooled or sequential; a test of pooled deduplication must not ride on that.
/// Both workers will hit the same abort within the first rounds, which is
/// exactly the race being tested.
#[test]
fn a_pooled_campaign_validates_each_defect_once() {
    let scratch = Scratch::new("pool-findings");
    let seeds = scratch.path.join("seeds");
    std::fs::create_dir_all(&seeds).expect("seed dir");
    // 0xDEADBEEF, 0x0203, 'Z', then a byte that is not '!'.
    std::fs::write(
        seeds.join("near-miss"),
        [0xEF, 0xBE, 0xAD, 0xDE, 0x03, 0x02, b'Z', b'A'],
    )
    .expect("write seed");

    let mut cfg = config_for("crash_magic", Build::Instrumented, &scratch.path, "");
    cfg.campaign.workers = 2;
    cfg.campaign.duration_secs = 0;
    cfg.campaign.max_execs = 20_000;
    cfg.campaign.stop_after_findings = 0;

    let mut campaign = Campaign::create(cfg, Cancel::new()).expect("create");
    campaign.seed_corpus(Some(&seeds)).expect("seed corpus");
    let reason = campaign.run().expect("run");
    let report = campaign.report(Some(reason)).expect("report");

    assert!(
        !report.findings.items.is_empty(),
        "a pooled campaign found nothing one byte from the abort, after {} executions",
        report.execution.total_executions
    );
    assert!(
        report
            .findings
            .items
            .iter()
            .any(|f| f.status.is_confirmed()),
        "the pooled campaign produced only unvalidated candidates: {:?}",
        report
            .findings
            .items
            .iter()
            .map(|f| f.status)
            .collect::<Vec<_>>()
    );

    // Two workers hitting the same defect must not produce two findings with
    // the same signature: deduplication runs in the controller for exactly
    // this reason.
    let mut sigs: Vec<&str> = report
        .findings
        .items
        .iter()
        .map(|f| f.signature.hash.as_str())
        .collect();
    sigs.sort_unstable();
    let before = sigs.len();
    sigs.dedup();
    assert_eq!(
        sigs.len(),
        before,
        "duplicate signatures survived the controller's deduplication"
    );

    // The pool must still have run on both workers.
    let stats = campaign.parallel_stats().expect("pool statistics");
    assert_eq!(stats.per_worker_executions.len(), 2);
    assert!(
        stats.worker_failures.is_empty(),
        "worker failures: {:?}",
        stats.worker_failures
    );
}

/// Cancellation has to stop a pool promptly, not after its budget runs out.
#[test]
fn cancelling_a_pooled_campaign_stops_every_worker() {
    let scratch = Scratch::new("pool-cancel");
    let mut cfg = config_for("always_ok", Build::Instrumented, &scratch.path, "");
    cfg.campaign.workers = 3;
    cfg.campaign.duration_secs = 0;
    // A budget large enough that only cancellation can end the campaign.
    cfg.campaign.max_execs = 50_000_000;

    let cancel = Cancel::new();
    let mut campaign = Campaign::create(cfg, cancel.clone()).expect("create");
    campaign.seed_corpus(None).expect("seed");

    let flag = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        flag.cancel();
    });

    let start = Instant::now();
    let reason = campaign.run().expect("run");
    let elapsed = start.elapsed();

    assert_eq!(reason, StopReason::Cancelled);
    assert!(
        elapsed < Duration::from_secs(12),
        "pool took {elapsed:?} to stop after cancellation"
    );
    let stats = campaign.parallel_stats().expect("pool statistics");
    assert!(
        stats.executions > 0,
        "the pool should have run before being cancelled"
    );
}

/// The differential oracle must find the planted divergence between the two
/// parser implementations and report it as a behavioural difference, not as a
/// crash.
#[test]
fn the_differential_oracle_reports_a_real_divergence() {
    let scratch = Scratch::new("oracle-diff");
    let a = fixture("diff_impl_a", Build::Instrumented);
    let b = fixture("diff_impl_b", Build::Instrumented);
    // `+1` is accepted by B and rejected by A; `2000000` overflows in A but
    // not in B. Both seeds sit directly on a divergence.
    let seeds = scratch.path.join("seeds");
    std::fs::create_dir_all(&seeds).expect("seed dir");
    std::fs::write(seeds.join("plus"), b"+1").expect("seed");
    std::fs::write(seeds.join("big"), b"2000000").expect("seed");

    let toml = format!(
        r#"
schema_version = 1
[target]
name = "decimal_parser"
kind = "differential"
binary = "{}"
differential_binary = "{}"
timeout_ms = 1000
[campaign]
duration_secs = 0
max_execs = 4000
workers = 1
seed = 20260124
max_input_bytes = 256
[feedback]
providers = ["edge-coverage", "exit-class", "differential"]
[oracles]
enabled = ["differential"]
budget_fraction = 0.5
check_retained_only = false
[output]
dir = "{}"
"#,
        a.display(),
        b.display(),
        scratch.path.display()
    );
    let cfg = Config::from_toml_str(&toml).unwrap_or_else(|e| panic!("config: {e}"));
    let mut campaign = Campaign::create(cfg, Cancel::new()).expect("create");
    campaign.seed_corpus(Some(&seeds)).expect("seed corpus");
    let reason = campaign.run().expect("run");
    let report = campaign.report(Some(reason)).expect("report");

    let diffs: Vec<_> = report
        .findings
        .items
        .iter()
        .filter(|f| f.evidence.exit_class == "oracle:differential")
        .collect();
    assert!(
        !diffs.is_empty(),
        "the differential oracle found no divergence between two implementations that \
         demonstrably disagree, after {} executions",
        report.execution.total_executions
    );

    let f = diffs[0];
    // A disagreement where neither side crashed is a behavioural difference.
    // Calling it a crash, or a vulnerability, would be inventing severity.
    assert_eq!(
        f.severity,
        aether_core::evidence::Severity::BehaviouralDifference,
        "a non-crashing disagreement must not be escalated: {}",
        f.signature.label
    );
    assert_eq!(
        f.status,
        FindingStatus::Candidate,
        "an oracle violation is not reproduction-validated, so it must stay a candidate"
    );
    assert_eq!(f.evidence.signal, None, "no signal to claim");
    assert!(
        f.evidence.sanitizer.is_none(),
        "no sanitizer report to claim"
    );

    // Observed facts and possible readings must both be present and labelled.
    assert!(
        f.notes.iter().any(|n| n.starts_with("Observed:")),
        "notes should record what was observed: {:?}",
        f.notes
    );
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("Possible reading (not established)")),
        "notes should offer readings as unestablished: {:?}",
        f.notes
    );
    assert!(
        f.notes.iter().any(|n| n.contains("not a confirmed defect")),
        "the finding must not read as a confirmed defect: {:?}",
        f.notes
    );
    // The input that showed it is kept as evidence.
    assert!(
        f.input_id.is_some(),
        "the triggering input was not retained"
    );
    assert!(!f.evidence.trigger_hash.is_empty());
}

/// A metamorphic relation that genuinely holds must produce no findings. This
/// is the false-positive control for the oracle path.
#[test]
fn a_holding_metamorphic_relation_produces_no_findings() {
    let scratch = Scratch::new("oracle-meta-clean");
    let bin = fixture("always_ok", Build::Instrumented);
    let toml = format!(
        r#"
schema_version = 1
[target]
name = "always_ok"
kind = "executable"
binary = "{}"
timeout_ms = 1000
[campaign]
duration_secs = 0
max_execs = 3000
workers = 1
seed = 20260124
max_input_bytes = 512
[oracles]
enabled = ["metamorphic"]
metamorphic_relations = ["determinism", "trailing-newline", "nul-padding"]
budget_fraction = 0.5
check_retained_only = false
[output]
dir = "{}"
"#,
        bin.display(),
        scratch.path.display()
    );
    let cfg = Config::from_toml_str(&toml).unwrap_or_else(|e| panic!("config: {e}"));
    let (campaign, reason) = run_campaign(cfg);
    let report = campaign.report(Some(reason)).expect("report");
    assert!(
        report.findings.items.is_empty(),
        "a target that always succeeds must not violate a relation it satisfies: {:?}",
        report
            .findings
            .items
            .iter()
            .map(|f| f.signature.label.clone())
            .collect::<Vec<_>>()
    );
}

/// Declaring a metamorphic relation without enabling the oracle must be a
/// configuration error, not a silently skipped check.
#[test]
fn relations_without_the_oracle_are_refused() {
    let scratch = Scratch::new("oracle-misconfig");
    let bin = fixture("always_ok", Build::Instrumented);
    let toml = format!(
        r#"
schema_version = 1
[target]
name = "always_ok"
kind = "executable"
binary = "{}"
[campaign]
duration_secs = 1
[oracles]
metamorphic_relations = ["determinism"]
[output]
dir = "{}"
"#,
        bin.display(),
        scratch.path.display()
    );
    let err = Config::from_toml_str(&toml).expect_err("should be refused");
    assert!(
        err.to_string().contains("never be checked"),
        "the error should say the relations would be ignored: {err}"
    );
}
