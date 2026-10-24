//! Command implementations.
//!
//! Each function renders either human-readable text or JSON from the same
//! engine call, so the two views cannot disagree about what happened.

use std::path::Path;

use aether_core::config::{self, Config, InputMode, Instrumentation, TargetConfig, TargetKind};
use aether_core::corpus::Corpus;
use aether_core::error::{Error, Result};
use aether_core::evidence::report::CampaignReport;
use aether_core::exec::adapters;
use aether_core::exec::native::{NativeExecutor, TargetSpec};
use aether_core::exec::Executor;
use aether_core::ids::CampaignId;
use aether_core::query;
use aether_core::runtime::{Campaign, CampaignStatus, Cancel};
use aether_core::scope::ScopePolicy;

use crate::{EXIT_FINDINGS, EXIT_OK};

pub struct Ctx {
    pub json: bool,
    pub quiet: bool,
}

impl Ctx {
    fn say(&self, s: impl AsRef<str>) {
        if !self.quiet && !self.json {
            println!("{}", s.as_ref());
        }
    }

    fn emit(&self, value: serde_json::Value) {
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

pub fn doctor(ctx: &Ctx) -> Result<u8> {
    let adapters = adapters::detect_all();
    let limits = aether_core::exec::limits::ProcessLimits::from_config(512).probe();
    let (distributed, distributed_reason) = aether_core::runtime::worker::distributed_available();
    let cores = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(0);

    // A compiler able to emit the instrumentation is the one hard requirement.
    let usable = adapters.iter().any(|a| a.available && a.verified);

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": usable,
            "cpu_cores": cores,
            "backends": adapters,
            "limits": limits,
            "distributed": { "available": distributed, "reason": distributed_reason },
            "strategies": aether_core::strategy::ALL_STRATEGY_IDS,
            "profiles": config::PROFILE_NAMES,
            "schema_version": config::SCHEMA_VERSION,
        }));
        return Ok(if usable { EXIT_OK } else { crate::EXIT_ENGINE });
    }

    println!("AETHER environment check");
    println!("  CPU cores: {cores}");
    println!("  Config schema version: {}", config::SCHEMA_VERSION);
    println!();
    println!("Execution backends:");
    for a in &adapters {
        let mark = match (a.available, a.verified) {
            (true, true) => "ok",
            (true, false) => "untested",
            (false, _) => "unavailable",
        };
        println!("  [{mark:^11}] {}", a.backend.as_str());
        for d in &a.discovered {
            println!("                {d}");
        }
        if let Some(r) = &a.reason {
            println!("                reason: {r}");
        }
        if let Some(r) = &a.remedy {
            println!("                remedy: {r}");
        }
        if a.available && !a.verified {
            println!(
                "                note: interface-complete but never exercised against \
                 the real engine on this host"
            );
        }
    }
    println!();
    println!("Resource limits this host enforces:");
    println!(
        "  memory (RLIMIT_AS):  {}",
        yes_no(limits.memory_limit_enforced)
    );
    println!(
        "  core dumps disabled: {}",
        yes_no(limits.core_dumps_disabled)
    );
    println!(
        "  file size limited:   {}",
        yes_no(limits.file_size_limited)
    );
    println!(
        "  process count:       {}",
        yes_no(limits.process_count_limited)
    );
    for u in &limits.unenforced {
        println!("  not enforced: {u}");
    }
    println!();
    println!(
        "Distributed execution: {}",
        if distributed {
            "available"
        } else {
            "unavailable"
        }
    );
    if !distributed {
        println!("  {distributed_reason}");
    }
    println!();
    println!(
        "Strategies: {}",
        aether_core::strategy::ALL_STRATEGY_IDS.join(", ")
    );
    println!("Profiles:   {}", config::PROFILE_NAMES.join(", "));
    println!();
    if usable {
        println!("Ready. Build a target with runtime/aether-cc, then `aether campaign run`.");
    } else {
        println!("Not ready: no verified execution backend. Install clang or gcc.");
    }
    Ok(if usable { EXIT_OK } else { crate::EXIT_ENGINE })
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------------------
// target inspect
// ---------------------------------------------------------------------------

pub fn target_inspect(
    ctx: &Ctx,
    binary: &Path,
    input_mode: &str,
    args: &[String],
    timeout_ms: u64,
) -> Result<u8> {
    let mode = match input_mode {
        "file-arg" => InputMode::FileArg,
        _ => InputMode::Stdin,
    };
    // Probe as an instrumented target first; the executor reports honestly
    // when the fork server or the coverage region are not there.
    let target = TargetConfig {
        id: None,
        name: binary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".into()),
        kind: TargetKind::Executable,
        binary: binary.to_path_buf(),
        args: args.to_vec(),
        input_mode: mode,
        env: Default::default(),
        working_dir: None,
        timeout_ms,
        memory_limit_mb: 512,
        instrumentation: Instrumentation::AetherNative,
        oracle_binary: None,
        differential_binary: None,
        use_fork_server: mode == InputMode::Stdin,
    };
    target.validate()?;

    let scratch = std::env::temp_dir().join(format!("aether-inspect-{}", std::process::id()));
    let spec = TargetSpec::from_config(&target, &ScopePolicy::default(), 8192)?;
    let mut exec = NativeExecutor::new(spec, &scratch)?;

    // Probe with a few representative inputs rather than one, so a target that
    // rejects short input is not mistaken for one with no coverage.
    let probes: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"A".to_vec(),
        vec![0x41; 64],
        (0..=255u8).collect(),
    ];
    let mut classes = Vec::new();
    let mut max_edges = 0u32;
    let mut saw_cmp = 0usize;
    for p in &probes {
        let o = exec.run(p)?;
        if let Some(e) = o.edge_count() {
            max_edges = max_edges.max(e);
        }
        saw_cmp += o.cmp_entries.len();
        classes.push(serde_json::json!({
            "input_bytes": p.len(),
            "class": o.class.as_str(),
            "exit_code": o.exit_code,
            "signal": o.signal,
            "edges": o.edge_count(),
            "comparisons": o.cmp_entries.len(),
            "duration_micros": o.duration.as_micros(),
        }));
    }

    let caps = exec.capabilities();
    let guards = exec.shm_guard_count();
    let instrumented = caps.edge_coverage && guards.map(|g| g > 0).unwrap_or(false);
    let _ = std::fs::remove_dir_all(&scratch);

    // Only recommend strategies whose requirements this target actually meets.
    let mut recommended = vec![
        "havoc",
        "random-mutation",
        "boundary",
        "splice",
        "dictionary",
    ];
    if caps.comparison_log && saw_cmp > 0 {
        recommended.insert(0, "cmplog-guided");
    }
    if max_edges > 0 {
        recommended.push("evolutionary");
        recommended.push("structure-aware");
    }

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "binary": binary.display().to_string(),
            "instrumented": instrumented,
            "instrumentation_guards": guards,
            "fork_server": caps.fork_server,
            "edge_coverage": caps.edge_coverage,
            "comparison_log": caps.comparison_log && saw_cmp > 0,
            "max_edges_observed": max_edges,
            "comparisons_observed": saw_cmp,
            "probes": classes,
            "limitations": caps.limitations,
            "recommended_strategies": recommended,
        }));
        return Ok(EXIT_OK);
    }

    println!("Target: {}", binary.display());
    println!(
        "  Instrumented: {}{}",
        yes_no(instrumented),
        guards.map(|g| format!(" ({g} guards)")).unwrap_or_default()
    );
    println!("  Fork server:  {}", yes_no(caps.fork_server));
    println!("  Edge coverage: {}", yes_no(caps.edge_coverage));
    println!(
        "  Comparison log: {} ({saw_cmp} comparisons seen)",
        yes_no(caps.comparison_log)
    );
    if !instrumented {
        println!(
            "\n  This target reports no instrumentation. Rebuild it with \
             runtime/aether-cc to get coverage and comparison feedback; without them \
             only exit status is observable."
        );
    }
    println!("\n  Probe results:");
    for c in &classes {
        println!(
            "    {:>4} bytes -> {:<16} edges={:<6} comparisons={}",
            c["input_bytes"],
            c["class"].as_str().unwrap_or("?"),
            c["edges"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".into()),
            c["comparisons"]
        );
    }
    for l in &caps.limitations {
        println!("\n  Limitation: {l}");
    }
    println!("\n  Suggested strategies: {}", recommended.join(", "));
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// campaign
// ---------------------------------------------------------------------------

pub fn campaign_create(ctx: &Ctx, config_path: &Path) -> Result<u8> {
    let cfg = Config::load(config_path)?;
    let campaign = Campaign::create(cfg, Cancel::new())?;
    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "campaign_id": campaign.id.as_str(),
            "target": campaign.config().target.name,
        }));
    } else {
        ctx.say(format!("Campaign {} created and validated.", campaign.id));
        ctx.say(format!(
            "Run it with: aether campaign run --config {}",
            config_path.display()
        ));
    }
    Ok(EXIT_OK)
}

pub fn campaign_run(
    ctx: &Ctx,
    cfg: Config,
    seeds: Option<&Path>,
    resume: Option<&str>,
    fail_on_findings: bool,
) -> Result<u8> {
    let out_dir = cfg.output.dir.clone();
    let campaign_id_hint = CampaignId::new();
    let cancel = Cancel::with_sentinel(Campaign::cancel_file(&out_dir, campaign_id_hint.as_str()));

    let mut campaign = Campaign::create(cfg, cancel)?;
    // The sentinel path has to match the real campaign id, which is only known
    // after creation.
    let cancel = Cancel::with_sentinel(Campaign::cancel_file(&out_dir, campaign.id.as_str()));
    campaign.set_cancel(cancel);

    ctx.say(format!("Campaign {} starting.", campaign.id));
    let (added, dup, rejected) = campaign.seed_corpus(seeds)?;
    if seeds.is_some() {
        ctx.say(format!(
            "  seeds: {added} added, {dup} duplicates, {rejected} rejected"
        ));
    }
    if let Some(prev) = resume {
        if campaign.resume_from_checkpoint(prev)? {
            ctx.say(format!("  resumed learned state from {prev}"));
        } else {
            ctx.say(format!("  no checkpoint found for {prev}; starting fresh"));
        }
    }
    campaign.write_status_file()?;

    let reason = campaign.run()?;
    let report = campaign.report(Some(reason))?;
    let written = campaign.write_reports(Some(reason))?;

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "campaign_id": campaign.id.as_str(),
            "stop_reason": reason.as_str(),
            "executions": report.execution.total_executions,
            "executions_per_second": report.execution.executions_per_second,
            "edges": report.coverage.total_edges,
            "corpus_entries": report.corpus.entries,
            "findings": {
                "reproducible": report.findings.reproducible,
                "intermittent": report.findings.intermittent,
                "unconfirmed": report.findings.unconfirmed,
            },
            "reports": written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "limitations": report.limitations,
        }));
    } else {
        println!();
        println!("Campaign {} finished: {}", campaign.id, reason.as_str());
        println!(
            "  {} executions ({:.0}/s), {} edges, {} corpus entries",
            report.execution.total_executions,
            report.execution.executions_per_second,
            report.coverage.total_edges,
            report.corpus.entries
        );
        println!(
            "  findings: {} reproducible, {} intermittent, {} unconfirmed",
            report.findings.reproducible, report.findings.intermittent, report.findings.unconfirmed
        );
        for f in report
            .findings
            .items
            .iter()
            .filter(|f| f.status.is_confirmed())
        {
            println!("    {}", f.summary());
        }
        for p in &written {
            println!("  report: {}", p.display());
        }
    }

    // A non-zero exit on findings lets CI fail a build without parsing output.
    Ok(
        if fail_on_findings && report.findings.confirmed_count() > 0 {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

pub fn campaign_status(ctx: &Ctx, dir: &Path, campaign_id: Option<&str>) -> Result<u8> {
    let store = query::open_store(dir)?;
    let id = query::resolve_campaign(&store, campaign_id)?;
    let path = Campaign::status_file(dir, &id);
    let body =
        std::fs::read_to_string(&path).map_err(|_| Error::not_found("campaign status", &id))?;
    let status: CampaignStatus = serde_json::from_str(&body)?;

    if ctx.json {
        ctx.emit(serde_json::to_value(&status)?);
        return Ok(EXIT_OK);
    }
    println!("Campaign {} ({})", status.campaign_id, status.state);
    println!("  target:     {}", status.target_name);
    println!(
        "  elapsed:    {}",
        aether_core::time::format_duration_ms(status.elapsed_ms)
    );
    println!("  workers:    {}", status.workers);
    println!(
        "  executions: {} ({:.0}/s)",
        status.total_executions, status.executions_per_second
    );
    // "not measured" and zero are different things, and the display says which.
    println!(
        "  edges:      {}",
        status
            .total_edges
            .map(|e| e.to_string())
            .unwrap_or_else(|| "not measured (uninstrumented target)".into())
    );
    println!(
        "  saturation: {}",
        status
            .coverage_saturation
            .map(|s| format!("{:.1}%", s * 100.0))
            .unwrap_or_else(|| "not measurable".into())
    );
    println!("  corpus:     {}", status.corpus_entries);
    println!(
        "  findings:   {} confirmed, {} candidates",
        status.confirmed_findings, status.candidate_findings
    );
    println!("  phase:      {}", status.stagnation_phase);
    println!(
        "  progress:   {}",
        status
            .last_progress_ms
            .map(aether_core::time::format_rfc3339)
            .unwrap_or_else(|| "nothing discovered yet".into())
    );
    if !status.strategy_allocation.is_empty() {
        println!("  allocation:");
        let mut alloc = status.strategy_allocation.clone();
        alloc.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (name, share) in alloc.iter().take(6) {
            println!("    {:<22} {:>5.1}%", name, share * 100.0);
        }
    }
    Ok(EXIT_OK)
}

pub fn campaign_cancel(ctx: &Ctx, dir: &Path, campaign_id: &str) -> Result<u8> {
    let path = Campaign::cancel_file(dir, campaign_id);
    Cancel::request_via_file(&path)?;
    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "campaign_id": campaign_id,
            "sentinel": path.display().to_string(),
            "note": "the campaign stops at its next execution boundary",
        }));
    } else {
        ctx.say(format!(
            "Cancellation requested for {campaign_id}. It stops at the next execution boundary."
        ));
    }
    Ok(EXIT_OK)
}

pub fn campaign_list(ctx: &Ctx, dir: &Path, limit: usize) -> Result<u8> {
    let store = query::open_store(dir)?;
    let rows = query::list_campaigns(&store, limit)?;

    if ctx.json {
        ctx.emit(serde_json::json!({ "ok": true, "campaigns": rows }));
        return Ok(EXIT_OK);
    }
    if rows.is_empty() {
        println!("No campaigns in {}", dir.display());
        return Ok(EXIT_OK);
    }
    println!(
        "{:<24} {:<16} {:<12} {:>10} {:>8}  CREATED",
        "CAMPAIGN", "TARGET", "STATUS", "EXECS", "EDGES"
    );
    for r in &rows {
        println!(
            "{:<24} {:<16} {:<12} {:>10} {:>8}  {}",
            r.campaign_id,
            truncate(&r.target, 16),
            r.status,
            r.executions,
            r.edges,
            r.created_at
        );
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// corpus
// ---------------------------------------------------------------------------

pub fn corpus_stats(ctx: &Ctx, dir: &Path, campaign_id: Option<&str>) -> Result<u8> {
    let store = query::open_store(dir)?;
    let id = query::resolve_campaign(&store, campaign_id)?;
    let corpus = open_corpus(dir, &id)?;
    let stats = corpus.stats(&store)?;
    let top = corpus.top(&store, 10)?;

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "campaign_id": id,
            "stats": stats,
            "top_inputs": top.iter().map(|r| serde_json::json!({
                "input_id": r.id.as_str(),
                "content_hash": r.content_hash,
                "size_bytes": r.size_bytes,
                "score": r.score,
                "new_edges": r.new_edges,
                "strategy": r.strategy_id,
                "is_finding_evidence": r.finding_id.is_some(),
            })).collect::<Vec<_>>(),
        }));
        return Ok(EXIT_OK);
    }

    println!("Corpus for {id}");
    println!("  entries:            {}", stats.entries);
    println!("  distinct behaviours: {}", stats.distinct_behaviors);
    println!("  mean score:         {:.3}", stats.mean_score);
    println!("  input bytes:        {}", stats.total_input_bytes);
    println!(
        "  stored objects:     {} ({} bytes)",
        stats.store_objects, stats.store_bytes
    );
    println!(
        "  finding evidence:   {} (never evicted by retention)",
        stats.finding_inputs
    );
    if !top.is_empty() {
        println!("\n  Highest ranked:");
        println!(
            "    {:<22} {:>6} {:>8} {:>10}  STRATEGY",
            "INPUT", "BYTES", "EDGES", "SCORE"
        );
        for r in &top {
            println!(
                "    {:<22} {:>6} {:>8} {:>10.3}  {}",
                r.id.as_str(),
                r.size_bytes,
                r.new_edges,
                r.score,
                r.strategy_id.as_deref().unwrap_or("-")
            );
        }
    }
    Ok(EXIT_OK)
}

pub fn corpus_export(ctx: &Ctx, dir: &Path, campaign_id: &str, output: &Path) -> Result<u8> {
    let store = query::open_store(dir)?;
    let corpus = open_corpus(dir, campaign_id)?;
    let n = corpus.export(&store, output)?;
    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true, "exported": n, "output": output.display().to_string()
        }));
    } else {
        ctx.say(format!("Exported {n} inputs to {}", output.display()));
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

pub fn findings_list(
    ctx: &Ctx,
    dir: &Path,
    campaign_id: Option<&str>,
    status: Option<&str>,
    limit: usize,
) -> Result<u8> {
    let store = query::open_store(dir)?;
    let id = query::resolve_campaign(&store, campaign_id)?;
    let rows = query::list_findings(&store, &id, status, limit)?;

    if ctx.json {
        ctx.emit(serde_json::json!({ "ok": true, "campaign_id": id, "findings": rows }));
        return Ok(EXIT_OK);
    }
    if rows.is_empty() {
        println!("No findings for {id}.");
        println!(
            "This reflects this campaign under its budget and configuration; it is not a \
             claim that the target is free of defects."
        );
        return Ok(EXIT_OK);
    }
    println!(
        "{:<24} {:<14} {:<10} {:<22} CLASS",
        "FINDING", "STATUS", "REPRO", "FAULT"
    );
    for r in &rows {
        println!(
            "{:<24} {:<14} {:<10} {:<22} {}",
            r.finding_id,
            r.status,
            format!("{}/{}", r.repro_successes, r.repro_attempts),
            truncate(r.fault.as_deref().unwrap_or("-"), 22),
            r.exit_class
        );
    }
    Ok(EXIT_OK)
}

pub fn findings_show(ctx: &Ctx, dir: &Path, finding_id: &str) -> Result<u8> {
    let store = query::open_store(dir)?;
    let f = query::get_finding(&store, finding_id)?;
    let evidence = f.evidence.clone().unwrap_or(serde_json::Value::Null);

    if ctx.json {
        ctx.emit(serde_json::json!({ "ok": true, "finding": f }));
        return Ok(EXIT_OK);
    }

    println!("Finding {}", f.finding_id);
    println!("  campaign:  {}", f.campaign_id);
    println!("  status:    {}", f.status);
    println!("  signature: {}", f.signature);
    println!("  class:     {}", f.exit_class);
    if let Some(fault) = &f.fault {
        println!("  fault:     {fault}");
    }
    println!("  reproduced: {}/{}", f.repro_successes, f.repro_attempts);
    if let Some(argv) = evidence.get("reproduce_argv").and_then(|v| v.as_array()) {
        let cmd: Vec<String> = argv
            .iter()
            .map(|a| a.as_str().unwrap_or("").to_string())
            .collect();
        println!("  reproduce: {}", cmd.join(" "));
        println!(
            "    input delivered on {}",
            evidence["input_delivery"].as_str().unwrap_or("stdin")
        );
    }
    println!("  trigger input:   {}", f.trigger_hash);
    if let Some(h) = &f.minimized_hash {
        println!("  minimised input: {h}");
    }
    if let Some(san) = evidence.get("sanitizer") {
        if !san.is_null() {
            println!(
                "  sanitizer: {} {}",
                san["kind"].as_str().unwrap_or("?"),
                san["fault"].as_str().unwrap_or("?")
            );
        }
    }
    for n in &f.notes {
        println!("  note: {n}");
    }
    if let Some(arr) = evidence.get("unenforced_limits").and_then(|v| v.as_array()) {
        for l in arr {
            if let Some(s) = l.as_str() {
                println!("  caveat: {s}");
            }
        }
    }
    Ok(EXIT_OK)
}

pub fn findings_validate(
    ctx: &Ctx,
    dir: &Path,
    finding_id: &str,
    config_path: &Path,
    attempts: Option<u32>,
) -> Result<u8> {
    let mut cfg = Config::load(config_path)?;
    if let Some(a) = attempts {
        cfg.reproduction.attempts = a;
        cfg.reproduction.required_successes = cfg.reproduction.required_successes.min(a);
        cfg.reproduction.validate()?;
    }
    let (input, signature_hash) = load_finding_input(dir, finding_id)?;

    let scratch = std::env::temp_dir().join(format!("aether-validate-{}", std::process::id()));
    let spec = TargetSpec::from_config(&cfg.target, &cfg.scope, cfg.output.max_log_bytes)?;
    let mut exec = NativeExecutor::new(spec, &scratch)?;

    let outcome =
        aether_core::evidence::validate::reproduce(&mut exec, &input, None, &cfg.reproduction)?;
    let _ = std::fs::remove_dir_all(&scratch);

    let dominant = outcome.dominant_signature.as_ref();
    let same_defect = dominant.map(|s| s.hash == signature_hash).unwrap_or(false);
    let implied = outcome.record.implied_status();

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "finding_id": finding_id,
            "attempts": outcome.record.attempts,
            "successes": outcome.record.successes,
            "required": outcome.record.required,
            "implied_status": implied.as_str(),
            "clean_runs": outcome.clean_runs,
            "matches_recorded_signature": same_defect,
            "observed_signature": dominant.map(|s| s.label.clone()),
            "other_signatures": outcome.other_signatures.len(),
        }));
        return Ok(EXIT_OK);
    }

    println!("Validation of {finding_id}");
    println!(
        "  reproduced {}/{} attempts (threshold {})",
        outcome.record.successes, outcome.record.attempts, outcome.record.required
    );
    println!("  implied status: {}", implied.as_str());
    if outcome.clean_runs > 0 {
        println!("  {} run(s) did not fail at all", outcome.clean_runs);
    }
    match dominant {
        Some(s) if same_defect => println!("  same defect as recorded: {}", s.label),
        Some(s) => println!(
            "  DIFFERENT defect observed: {} (recorded signature was {signature_hash})",
            s.label
        ),
        None => println!("  no failure observed in any attempt"),
    }
    if !outcome.other_signatures.is_empty() {
        println!(
            "  {} other distinct signature(s) seen, which often indicates memory \
             corruption whose symptom varies between runs",
            outcome.other_signatures.len()
        );
    }
    Ok(EXIT_OK)
}

pub fn findings_minimize(
    ctx: &Ctx,
    dir: &Path,
    finding_id: &str,
    config_path: &Path,
) -> Result<u8> {
    let cfg = Config::load(config_path)?;
    let (input, _) = load_finding_input(dir, finding_id)?;

    let scratch = std::env::temp_dir().join(format!("aether-minimize-{}", std::process::id()));
    let spec = TargetSpec::from_config(&cfg.target, &cfg.scope, cfg.output.max_log_bytes)?;
    let mut exec = NativeExecutor::new(spec, &scratch)?;

    // Minimise toward whatever the input currently does, re-derived rather
    // than trusted from the record: the target may have been rebuilt since.
    let first = exec.run(&input)?;
    let Some(signature) = aether_core::evidence::signature::signature_for(&first) else {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(Error::target(
            "minimisation",
            "the recorded input no longer produces a failure against this target, so there \
             is nothing to minimise toward",
        ));
    };
    let (outcome, validated) = aether_core::evidence::validate::minimize_for_signature(
        &mut exec,
        &input,
        &signature,
        &cfg.reproduction,
    )?;
    let _ = std::fs::remove_dir_all(&scratch);

    let out_path = dir.join(format!("{finding_id}.min"));
    std::fs::write(&out_path, &outcome.input).map_err(|e| Error::io(&out_path, e))?;

    if ctx.json {
        ctx.emit(serde_json::json!({
            "ok": true,
            "finding_id": finding_id,
            "original_bytes": outcome.original_len,
            "minimized_bytes": outcome.input.len(),
            "reduction": outcome.reduction_ratio(),
            "executions_used": outcome.execs_used,
            "stop_reason": format!("{:?}", outcome.stop),
            "revalidated": validated,
            "signature": signature.label,
            "output": out_path.display().to_string(),
        }));
        return Ok(EXIT_OK);
    }
    println!("Minimised {finding_id}");
    println!(
        "  {} -> {} bytes ({:.0}% smaller)",
        outcome.original_len,
        outcome.input.len(),
        outcome.reduction_ratio() * 100.0
    );
    println!("  executions used: {}", outcome.execs_used);
    println!("  stopped because: {:?}", outcome.stop);
    println!(
        "  re-validated: {}{}",
        yes_no(validated),
        if validated {
            ""
        } else {
            "  <- the result could not be confirmed"
        }
    );
    println!("  written to: {}", out_path.display());
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

pub fn report_generate(
    ctx: &Ctx,
    dir: &Path,
    campaign_id: Option<&str>,
    format: &str,
    output: Option<&Path>,
) -> Result<u8> {
    let store = query::open_store(dir)?;
    let id = query::resolve_campaign(&store, campaign_id)?;
    // Reports are written when a campaign stops; regenerating a different
    // format from stored metadata alone would omit what only the live
    // campaign held, so the stored JSON report is the source.
    let json_path = dir.join(&id).join("report.json");
    let body = std::fs::read_to_string(&json_path).map_err(|_| {
        Error::not_found(
            "campaign report",
            format!(
                "{id} (expected {}; a report is written when a campaign stops)",
                json_path.display()
            ),
        )
    })?;
    let report: CampaignReport = serde_json::from_str(&body)?;
    let rendered = report.render(format)?;

    match output {
        Some(p) => {
            std::fs::write(p, &rendered).map_err(|e| Error::io(p, e))?;
            if ctx.json {
                ctx.emit(serde_json::json!({
                    "ok": true, "format": format, "output": p.display().to_string()
                }));
            } else {
                ctx.say(format!("Wrote {} report to {}", format, p.display()));
            }
        }
        None => println!("{rendered}"),
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

pub fn benchmark_list(ctx: &Ctx) -> Result<u8> {
    let experiments = aether_core::bench::EXPERIMENTS;
    if ctx.json {
        ctx.emit(serde_json::json!({ "ok": true, "experiments": experiments }));
        return Ok(EXIT_OK);
    }
    println!("Benchmark experiments:");
    for e in experiments {
        println!("  {}  {}", e.id, e.title);
        println!("      {}", e.description);
        if !e.implemented {
            println!("      NOT IMPLEMENTED: {}", e.unimplemented_reason);
        }
    }
    Ok(EXIT_OK)
}

pub fn benchmark_run(
    ctx: &Ctx,
    experiment: &str,
    config_path: Option<&Path>,
    trials: u32,
    duration: u64,
    output: Option<&Path>,
) -> Result<u8> {
    let cfg = match config_path {
        Some(p) => Config::load(p)?,
        None => {
            return Err(Error::config(
                "benchmark",
                "a benchmark needs --config naming the target to run against",
            ))
        }
    };
    let results = aether_core::bench::run_experiment(experiment, cfg, trials, duration)?;
    let json = serde_json::to_string_pretty(&results)?;

    if let Some(p) = output {
        std::fs::write(p, &json).map_err(|e| Error::io(p, e))?;
    }
    if ctx.json {
        println!("{json}");
        return Ok(EXIT_OK);
    }

    println!("{}", results.render_table());
    if let Some(p) = output {
        println!("\nRaw metrics written to {}", p.display());
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

pub fn init(ctx: &Ctx, profile: &str, binary: Option<&Path>, output: Option<&Path>) -> Result<u8> {
    let bin = binary
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "./build/target".to_string());
    let base = format!(
        r#"# AETHER campaign configuration
schema_version = {}

[target]
name = "my-target"
kind = "executable"
# Build this with runtime/aether-cc to get coverage and comparison feedback.
binary = "{bin}"
input_mode = "stdin"
timeout_ms = 1000
memory_limit_mb = 512
instrumentation = "aether-native"
# A second build under a sanitizer. The campaign loop uses `binary`; the
# evidence engine re-runs candidates here for a stronger crash oracle.
# oracle_binary = "./build/target-asan"

[campaign]
duration_secs = 60
workers = 1
seed = 20260124
max_input_bytes = 65536

[scope]
# Local execution only. A network target additionally needs an explicit host
# list, an authorization note and a rate limit; supplying an address is not
# authorization to test it.
allow_local_execution = true
allow_network_targets = false

[strategies]
# Empty means every strategy whose requirements this target meets.
enabled = []
dictionary = []

[feedback]
providers = ["edge-coverage", "exit-class", "cmplog", "sanitizer"]

[intel]
scheduler = "thompson"
round_budget = 64

[reproduction]
attempts = 5
required_successes = 3
minimize = true

[output]
dir = ".aether"
report_formats = ["json", "markdown"]
"#,
        config::SCHEMA_VERSION
    );

    // Validate what is emitted, with the profile applied, so the example is
    // never something the engine would reject. The binary may not exist yet,
    // so only the schema is checked here, not the target itself.
    let mut cfg = Config::from_toml_str(&base)?;
    config::apply_profile(&mut cfg, profile)?;
    cfg.validate()?;
    let rendered = format!("{base}\n# Profile applied: {profile}\n");

    match output {
        Some(p) => {
            std::fs::write(p, &rendered).map_err(|e| Error::io(p, e))?;
            ctx.say(format!("Wrote example configuration to {}", p.display()));
            if ctx.json {
                ctx.emit(serde_json::json!({
                    "ok": true, "output": p.display().to_string(), "profile": profile
                }));
            }
        }
        None => println!("{rendered}"),
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn open_corpus(dir: &Path, campaign_id: &str) -> Result<Corpus> {
    let id = CampaignId::from_string(campaign_id);
    id.validate()?;
    Corpus::open(
        &dir.join(campaign_id),
        id,
        Default::default(),
        100_000,
        config::MAX_INPUT_BYTES,
    )
}

/// Read a finding's triggering input, preferring the minimised form.
fn load_finding_input(dir: &Path, finding_id: &str) -> Result<(Vec<u8>, String)> {
    let store = query::open_store(dir)?;
    let f = query::get_finding(&store, finding_id)?;
    let corpus = open_corpus(dir, &f.campaign_id)?;
    let hash = f.minimized_hash.as_deref().unwrap_or(&f.trigger_hash);
    // Fall back to the original if the minimised object is gone: the original
    // is always retained, which is what makes a finding auditable.
    let bytes = corpus
        .get_bytes(hash)
        .or_else(|_| corpus.get_bytes(&f.trigger_hash))?;
    Ok((bytes, f.signature))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
}
