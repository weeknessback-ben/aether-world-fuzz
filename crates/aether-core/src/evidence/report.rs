//! Report generation: JSON, Markdown, SARIF and machine-readable benchmark output.
//!
//! Reports are where a campaign's results meet a reader, so the structure
//! enforces the distinction the rest of the engine maintains:
//!
//! * **Observed facts** - what was measured, with the numbers.
//! * **Unconfirmed observations** - candidates that did not reproduce, listed
//!   as such rather than quietly dropped or quietly counted.
//! * **Limitations** - signals that were unavailable, limits the host did not
//!   enforce, capabilities that were not exercised.
//!
//! A report never claims exploitability, never calls a crash a vulnerability,
//! and never reports a metric that was not measured: an unavailable signal is
//! `null`, which is not the same as zero.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::feedback::coverage::CoverageSummary;
use crate::intel::IntelSnapshot;

use super::{Finding, FindingStatus};

/// Everything a report is built from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub schema_version: u32,
    pub campaign_id: String,
    pub target_name: String,
    pub target_binary: String,
    pub profile: Option<String>,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: u64,
    pub seed: u64,

    pub execution: ExecutionStats,
    pub coverage: CoverageSummary,
    pub corpus: crate::corpus::CorpusStats,
    pub findings: FindingsSummary,
    pub strategies: Vec<StrategyReport>,
    pub intelligence: Option<IntelSnapshot>,

    /// Capabilities, with what was and was not available.
    pub environment: EnvironmentReport,
    /// Everything that limits how far the results can be taken.
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub total_executions: u64,
    pub executions_per_second: f64,
    pub crashes_observed: u64,
    pub timeouts_observed: u64,
    pub clean_runs: u64,
    /// `None` when the target is uninstrumented, so a reader can tell "not
    /// measurable" from "zero".
    pub mean_exec_micros: Option<f64>,
    pub last_progress_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    /// Reproduced at or above the configured threshold.
    pub reproducible: u32,
    /// Reproduced sometimes, below the threshold.
    pub intermittent: u32,
    /// Observed once and never reproduced. Listed, not counted as defects.
    pub unconfirmed: u32,
    pub duplicates: u32,
    pub environmental: u32,
    /// Still being validated when the report was produced.
    pub in_progress: u32,
    pub items: Vec<Finding>,
}

impl FindingsSummary {
    /// Findings the report asserts as established defects.
    pub fn confirmed_count(&self) -> u32 {
        self.reproducible + self.intermittent
    }

    pub fn from_findings(findings: Vec<Finding>) -> Self {
        let mut s = FindingsSummary {
            reproducible: 0,
            intermittent: 0,
            unconfirmed: 0,
            duplicates: 0,
            environmental: 0,
            in_progress: 0,
            items: Vec::new(),
        };
        for f in &findings {
            match f.status {
                FindingStatus::Reproducible => s.reproducible += 1,
                FindingStatus::Intermittent => s.intermittent += 1,
                FindingStatus::Unconfirmed => s.unconfirmed += 1,
                FindingStatus::Duplicate => s.duplicates += 1,
                FindingStatus::Environmental => s.environmental += 1,
                FindingStatus::Candidate | FindingStatus::Reproducing => s.in_progress += 1,
                FindingStatus::Closed => {}
            }
        }
        s.items = findings;
        s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyReport {
    pub id: String,
    pub rounds: u32,
    pub executions: u64,
    pub new_edges: u64,
    pub findings: u32,
    /// Share of total rounds. The scheduler's decision, as a number.
    pub allocation_share: f64,
    /// Exploration value per millisecond of compute: the quantity the
    /// scheduler was maximising.
    pub value_per_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentReport {
    pub backend: String,
    pub fork_server: bool,
    pub edge_coverage: bool,
    pub comparison_log: bool,
    pub sanitizer_oracle: bool,
    pub memory_limit_enforced: bool,
    pub workers: u32,
    pub cpu_cores: usize,
    /// Signals requested but unavailable, with reasons.
    pub unavailable_signals: Vec<(String, String)>,
    /// Strategies dropped because the target could not support them.
    pub skipped_strategies: Vec<(String, String)>,
}

impl CampaignReport {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::from)
    }

    /// Compact machine-readable form for benchmark aggregation. Flat, so a
    /// benchmark run over many campaigns can be loaded as a table.
    pub fn to_bench_json(&self) -> Result<String> {
        let v = serde_json::json!({
            "campaign_id": self.campaign_id,
            "target": self.target_name,
            "profile": self.profile,
            "seed": self.seed,
            "duration_ms": self.duration_ms,
            "total_executions": self.execution.total_executions,
            "executions_per_second": self.execution.executions_per_second,
            "total_edges": self.coverage.total_edges,
            "guard_count": self.coverage.guard_count,
            "saturation": self.coverage.saturation,
            "corpus_entries": self.corpus.entries,
            "distinct_behaviors": self.corpus.distinct_behaviors,
            "findings_reproducible": self.findings.reproducible,
            "findings_intermittent": self.findings.intermittent,
            "findings_unconfirmed": self.findings.unconfirmed,
            "crashes_observed": self.execution.crashes_observed,
            "timeouts_observed": self.execution.timeouts_observed,
            "workers": self.environment.workers,
            "fork_server": self.environment.fork_server,
            "edge_coverage": self.environment.edge_coverage,
            "comparison_log": self.environment.comparison_log,
            "strategies": self.strategies.iter().map(|s| serde_json::json!({
                "id": s.id,
                "rounds": s.rounds,
                "executions": s.executions,
                "new_edges": s.new_edges,
                "findings": s.findings,
                "allocation_share": s.allocation_share,
                "value_per_ms": s.value_per_ms,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string(&v).map_err(Error::from)
    }

    /// Human-readable Markdown.
    ///
    /// Section order is deliberate: what was established, then what was not,
    /// then what limits the whole thing. A reader who stops after the first
    /// section still has an accurate picture.
    pub fn to_markdown(&self) -> String {
        let mut m = String::new();
        m.push_str(&format!("# AETHER campaign report: {}\n\n", self.target_name));
        m.push_str(&format!("- Campaign: `{}`\n", self.campaign_id));
        m.push_str(&format!("- Target: `{}`\n", self.target_binary));
        if let Some(p) = &self.profile {
            m.push_str(&format!("- Profile: `{p}`\n"));
        }
        m.push_str(&format!("- Status: {}\n", self.status));
        m.push_str(&format!("- Started: {}\n", self.started_at));
        if let Some(f) = &self.finished_at {
            m.push_str(&format!("- Finished: {f}\n"));
        }
        m.push_str(&format!(
            "- Duration: {}\n",
            crate::time::format_duration_ms(self.duration_ms)
        ));
        m.push_str(&format!("- Random seed: `{}` (replays this campaign)\n\n", self.seed));

        // --- Findings ---
        m.push_str("## Findings\n\n");
        if self.findings.confirmed_count() == 0 {
            m.push_str(
                "No reproducible findings. This is a statement about this campaign under \
                 this budget and configuration, not a claim that the target is free of \
                 defects.\n\n",
            );
        } else {
            m.push_str(&format!(
                "{} reproducible, {} intermittent.\n\n",
                self.findings.reproducible, self.findings.intermittent
            ));
        }

        let confirmed: Vec<&Finding> =
            self.findings.items.iter().filter(|f| f.status.is_confirmed()).collect();
        for f in &confirmed {
            m.push_str(&format!("### {} — {}\n\n", f.id, f.signature.label));
            m.push_str(&format!("- Status: **{}**\n", f.status.as_str()));
            m.push_str(&format!("- Class: {}\n", f.severity.as_str()));
            m.push_str(&format!("- Confidence: {:?}\n", f.confidence));
            m.push_str(&format!(
                "- Reproduced: {}/{} attempts (threshold {})\n",
                f.reproduction.successes, f.reproduction.attempts, f.reproduction.required
            ));
            if let Some(s) = &f.discovered_by {
                m.push_str(&format!("- Found by strategy: `{s}`\n"));
            }
            m.push_str(&format!("- Triggering input: `{}` ({} bytes)\n",
                f.evidence.trigger_hash, f.evidence.trigger_size));
            if let (Some(h), Some(sz)) = (&f.evidence.minimized_hash, f.evidence.minimized_size) {
                m.push_str(&format!("- Minimised input: `{h}` ({sz} bytes"));
                if f.reproduction.minimized_validated {
                    m.push_str(", re-validated)\n");
                } else {
                    m.push_str(", **not** re-validated)\n");
                }
            }
            m.push_str(&format!(
                "- Reproduce with: `{}` reading the input on {}\n",
                f.evidence.reproduce_argv.join(" "),
                f.evidence.input_delivery
            ));
            if let Some(san) = &f.evidence.sanitizer {
                m.push_str(&format!(
                    "- Sanitizer: {} — {}\n",
                    san.kind.as_str(),
                    san.fault
                ));
                if !san.frames.is_empty() {
                    m.push_str(&format!("- Frames: `{}`\n", san.frames.join("` <- `")));
                }
            }
            // The evidence note is what keeps a reader from over-reading the
            // class as a severity rating.
            m.push_str(&format!("\n> {}\n", f.severity.evidence_note()));
            if !f.notes.is_empty() {
                m.push_str("\nNotes:\n");
                for n in &f.notes {
                    m.push_str(&format!("- {n}\n"));
                }
            }
            m.push('\n');
        }

        // --- Unconfirmed ---
        let unconfirmed: Vec<&Finding> = self
            .findings
            .items
            .iter()
            .filter(|f| f.status == FindingStatus::Unconfirmed)
            .collect();
        if !unconfirmed.is_empty() {
            m.push_str("## Unconfirmed observations\n\n");
            m.push_str(
                "Observed once but not reproduced. These are recorded for completeness and \
                 are **not** established defects.\n\n",
            );
            for f in unconfirmed {
                m.push_str(&format!(
                    "- `{}` {} — 0/{} attempts reproduced\n",
                    f.id, f.signature.label, f.reproduction.attempts
                ));
            }
            m.push('\n');
        }

        // --- Measurements ---
        m.push_str("## Measurements\n\n");
        m.push_str("| Metric | Value |\n| --- | --- |\n");
        m.push_str(&format!("| Executions | {} |\n", self.execution.total_executions));
        m.push_str(&format!(
            "| Executions per second | {:.0} |\n",
            self.execution.executions_per_second
        ));
        m.push_str(&format!("| Edges reached | {} |\n", self.coverage.total_edges));
        m.push_str(&format!(
            "| Instrumented guards | {} |\n",
            self.coverage
                .guard_count
                .map(|g| g.to_string())
                .unwrap_or_else(|| "not reported".into())
        ));
        m.push_str(&format!(
            "| Coverage saturation | {} |\n",
            self.coverage
                .saturation
                .map(|s| format!("{:.1}%", s * 100.0))
                .unwrap_or_else(|| "not measurable".into())
        ));
        m.push_str(&format!("| Corpus entries | {} |\n", self.corpus.entries));
        m.push_str(&format!(
            "| Distinct behaviours | {} |\n",
            self.corpus.distinct_behaviors
        ));
        m.push_str(&format!("| Crashes observed | {} |\n", self.execution.crashes_observed));
        m.push_str(&format!("| Timeouts observed | {} |\n", self.execution.timeouts_observed));
        m.push('\n');

        // --- Strategies ---
        if !self.strategies.is_empty() {
            m.push_str("## Strategy allocation\n\n");
            m.push_str(
                "What the scheduler actually chose, and what each strategy returned. \
                 `value/ms` is the quantity it was maximising.\n\n",
            );
            m.push_str(
                "| Strategy | Rounds | Share | Executions | New edges | Findings | value/ms |\n\
                 | --- | --- | --- | --- | --- | --- | --- |\n",
            );
            for s in &self.strategies {
                m.push_str(&format!(
                    "| `{}` | {} | {:.1}% | {} | {} | {} | {:.3} |\n",
                    s.id,
                    s.rounds,
                    s.allocation_share * 100.0,
                    s.executions,
                    s.new_edges,
                    s.findings,
                    s.value_per_ms
                ));
            }
            m.push('\n');
        }

        // --- Environment ---
        m.push_str("## Environment and capabilities\n\n");
        let e = &self.environment;
        m.push_str(&format!("- Backend: `{}`\n", e.backend));
        m.push_str(&format!("- Workers: {} (host has {} cores)\n", e.workers, e.cpu_cores));
        for (label, on) in [
            ("Fork server", e.fork_server),
            ("Edge coverage", e.edge_coverage),
            ("Comparison log", e.comparison_log),
            ("Sanitizer oracle", e.sanitizer_oracle),
            ("Memory limit enforced", e.memory_limit_enforced),
        ] {
            m.push_str(&format!("- {label}: {}\n", if on { "yes" } else { "no" }));
        }
        if !e.unavailable_signals.is_empty() {
            m.push_str("\nSignals requested but unavailable:\n");
            for (id, reason) in &e.unavailable_signals {
                m.push_str(&format!("- `{id}`: {reason}\n"));
            }
        }
        if !e.skipped_strategies.is_empty() {
            m.push_str("\nStrategies not used:\n");
            for (id, reason) in &e.skipped_strategies {
                m.push_str(&format!("- `{id}`: {reason}\n"));
            }
        }
        m.push('\n');

        // --- Limitations ---
        m.push_str("## Limitations\n\n");
        if self.limitations.is_empty() {
            m.push_str("None recorded beyond the capability notes above.\n");
        } else {
            for l in &self.limitations {
                m.push_str(&format!("- {l}\n"));
            }
        }
        m.push('\n');
        m
    }

    /// SARIF 2.1.0, for static-analysis and security-reporting tooling.
    ///
    /// Only confirmed findings become results: a SARIF consumer treats every
    /// result as an issue, so emitting unconfirmed ones would manufacture
    /// false positives in whatever system ingests this.
    pub fn to_sarif(&self) -> Result<String> {
        let rules: Vec<serde_json::Value> = [
            ("AETHER-MEMORY-SAFETY", "Memory-safety violation reported by a sanitizer", "error"),
            ("AETHER-CRASH", "Process terminated on a fault signal", "error"),
            ("AETHER-HANG", "Target exceeded its execution deadline", "warning"),
            ("AETHER-INVARIANT", "Operator-declared invariant violated", "warning"),
            ("AETHER-DIFFERENTIAL", "Implementations disagreed on the same input", "warning"),
        ]
        .iter()
        .map(|(id, desc, level)| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": desc },
                "defaultConfiguration": { "level": level },
            })
        })
        .collect();

        let results: Vec<serde_json::Value> = self
            .findings
            .items
            .iter()
            .filter(|f| f.status.is_confirmed())
            .map(|f| {
                let rule = match f.severity {
                    super::Severity::MemorySafety => "AETHER-MEMORY-SAFETY",
                    super::Severity::Crash => "AETHER-CRASH",
                    super::Severity::Hang => "AETHER-HANG",
                    super::Severity::InvariantViolation => "AETHER-INVARIANT",
                    super::Severity::BehaviouralDifference => "AETHER-DIFFERENTIAL",
                };
                let frames: Vec<serde_json::Value> = f
                    .evidence
                    .sanitizer
                    .as_ref()
                    .map(|s| {
                        s.frames
                            .iter()
                            .map(|fr| {
                                serde_json::json!({
                                    "location": {
                                        "logicalLocations": [{ "name": fr, "kind": "function" }]
                                    }
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                serde_json::json!({
                    "ruleId": rule,
                    "level": match f.severity {
                        super::Severity::MemorySafety | super::Severity::Crash => "error",
                        _ => "warning",
                    },
                    "message": {
                        "text": format!(
                            "{}. Reproduced {}/{} attempts. {}",
                            f.signature.label,
                            f.reproduction.successes,
                            f.reproduction.attempts,
                            f.severity.evidence_note()
                        )
                    },
                    "partialFingerprints": {
                        "aetherSignature/v1": f.signature.hash,
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.evidence.target_binary }
                        }
                    }],
                    "stacks": if frames.is_empty() {
                        serde_json::Value::Array(vec![])
                    } else {
                        serde_json::json!([{ "frames": frames }])
                    },
                    "properties": {
                        "status": f.status.as_str(),
                        "confidence": format!("{:?}", f.confidence),
                        "triggerInputHash": f.evidence.trigger_hash,
                        "minimizedInputHash": f.evidence.minimized_hash,
                        "reproduceArgv": f.evidence.reproduce_argv,
                        "exploitabilityAssessed": false,
                    },
                })
            })
            .collect();

        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AETHER",
                        "informationUri": "https://github.com/weeknessback-ben/self-aware_fuzz",
                        "version": env!("CARGO_PKG_VERSION"),
                        "rules": rules,
                    }
                },
                "invocations": [{
                    "executionSuccessful": true,
                    "startTimeUtc": self.started_at,
                    "endTimeUtc": self.finished_at,
                    "properties": {
                        "campaignId": self.campaign_id,
                        "seed": self.seed,
                        "totalExecutions": self.execution.total_executions,
                        "limitations": self.limitations,
                    }
                }],
                "results": results,
            }]
        });
        serde_json::to_string_pretty(&sarif).map_err(Error::from)
    }

    /// Render in the named format.
    pub fn render(&self, format: &str) -> Result<String> {
        match format {
            "json" => self.to_json(),
            "markdown" => Ok(self.to_markdown()),
            "sarif" => self.to_sarif(),
            "bench-json" => self.to_bench_json(),
            other => Err(Error::config(
                "report format",
                format!("unknown format {other:?}; expected json, markdown, sarif or bench-json"),
            )),
        }
    }

    /// Conventional file extension for a format.
    pub fn extension(format: &str) -> &'static str {
        match format {
            "markdown" => "md",
            "sarif" => "sarif.json",
            "bench-json" => "bench.json",
            _ => "json",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::signature::{Signature, SignatureParts};
    use crate::evidence::{Confidence, Evidence, ReproductionRecord, Severity};
    use crate::ids::{CampaignId, FindingId};

    fn finding(status: FindingStatus, severity: Severity) -> Finding {
        Finding {
            id: FindingId::from_string("fnd-0000000000000001"),
            campaign_id: CampaignId::from_string("cmp-0000000000000001"),
            status,
            signature: Signature {
                hash: "abcd1234".into(),
                label: "AddressSanitizer: heap-buffer-overflow in parse".into(),
                parts: SignatureParts {
                    exit_class: "sanitizer-fault".into(),
                    signal: None,
                    exit_code: None,
                    sanitizer_kind: Some("AddressSanitizer".into()),
                    fault: Some("heap-buffer-overflow".into()),
                    frames: vec!["parse".into()],
                },
            },
            severity,
            confidence: Confidence::High,
            input_id: None,
            discovered_by: Some("cmplog-guided".into()),
            reproduction: ReproductionRecord {
                attempts: 5,
                successes: 5,
                required: 3,
                minimized_validated: true,
                minimize_execs: 42,
                used_oracle_binary: true,
            },
            evidence: Evidence {
                trigger_hash: "aa".repeat(16),
                trigger_size: 64,
                minimized_hash: Some("bb".repeat(16)),
                minimized_size: Some(8),
                reproduce_argv: vec!["/bin/target".into()],
                input_delivery: "stdin".into(),
                exit_class: "sanitizer-fault".into(),
                signal: Some(libc::SIGABRT),
                exit_code: None,
                sanitizer: Some(crate::exec::sanitizer::SanitizerReport {
                    kind: crate::exec::sanitizer::SanitizerKind::Address,
                    fault: "heap-buffer-overflow".into(),
                    access: Some("write".into()),
                    access_size: Some(255),
                    frames: vec!["memset".into(), "main".into()],
                    summary: "SUMMARY: AddressSanitizer".into(),
                }),
                stderr_excerpt: "==1==ERROR: AddressSanitizer".into(),
                stderr_truncated: false,
                target_name: "heap_oob".into(),
                target_binary: "/bin/target".into(),
                target_build_id: None,
                timeout_ms: 1000,
                memory_limit_mb: 512,
                unenforced_limits: vec!["RLIMIT_AS not applied to a sanitizer build".into()],
                campaign_seed: 42,
            },
            duplicate_of: None,
            created_ms: 1_700_000_000_000,
            updated_ms: 1_700_000_001_000,
            notes: vec!["Found while walking the magic-value ladder.".into()],
        }
    }

    fn report(findings: Vec<Finding>) -> CampaignReport {
        CampaignReport {
            schema_version: 1,
            campaign_id: "cmp-0000000000000001".into(),
            target_name: "heap_oob".into(),
            target_binary: "/bin/target".into(),
            profile: Some("quick-local".into()),
            status: "completed".into(),
            started_at: "2026-10-24T10:00:00.000Z".into(),
            finished_at: Some("2026-10-24T10:01:00.000Z".into()),
            duration_ms: 60_000,
            seed: 42,
            execution: ExecutionStats {
                total_executions: 180_000,
                executions_per_second: 3000.0,
                crashes_observed: 12,
                timeouts_observed: 1,
                clean_runs: 179_987,
                mean_exec_micros: Some(308.0),
                last_progress_at: Some("2026-10-24T10:00:45.000Z".into()),
            },
            coverage: CoverageSummary { total_edges: 142, guard_count: Some(190), saturation: Some(0.747) },
            corpus: crate::corpus::CorpusStats {
                entries: 230,
                mean_score: 0.41,
                total_input_bytes: 18_000,
                distinct_behaviors: 17,
                finding_inputs: 1,
                store_bytes: 20_000,
                store_objects: 230,
            },
            findings: FindingsSummary::from_findings(findings),
            strategies: vec![StrategyReport {
                id: "cmplog-guided".into(),
                rounds: 40,
                executions: 2560,
                new_edges: 88,
                findings: 1,
                allocation_share: 0.55,
                value_per_ms: 1.42,
            }],
            intelligence: None,
            environment: EnvironmentReport {
                backend: "aether-native".into(),
                fork_server: true,
                edge_coverage: true,
                comparison_log: true,
                sanitizer_oracle: true,
                memory_limit_enforced: false,
                workers: 2,
                cpu_cores: 4,
                unavailable_signals: vec![("state-transition".into(), "target emits no status codes".into())],
                skipped_strategies: vec![("grammar".into(), "no grammar supplied".into())],
            },
            limitations: vec!["AFL++ adapter unavailable on this host".into()],
        }
    }

    #[test]
    fn json_round_trips() {
        let r = report(vec![finding(FindingStatus::Reproducible, Severity::MemorySafety)]);
        let j = r.to_json().unwrap();
        let back: CampaignReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back.campaign_id, r.campaign_id);
        assert_eq!(back.findings.reproducible, 1);
        assert_eq!(back.seed, 42);
    }

    #[test]
    fn findings_are_counted_by_status() {
        let s = FindingsSummary::from_findings(vec![
            finding(FindingStatus::Reproducible, Severity::MemorySafety),
            finding(FindingStatus::Intermittent, Severity::Crash),
            finding(FindingStatus::Unconfirmed, Severity::Crash),
            finding(FindingStatus::Duplicate, Severity::Crash),
            finding(FindingStatus::Candidate, Severity::Crash),
        ]);
        assert_eq!(s.reproducible, 1);
        assert_eq!(s.intermittent, 1);
        assert_eq!(s.unconfirmed, 1);
        assert_eq!(s.duplicates, 1);
        assert_eq!(s.in_progress, 1);
        assert_eq!(s.confirmed_count(), 2, "only reproducible and intermittent are confirmed");
    }

    #[test]
    fn markdown_separates_confirmed_from_unconfirmed() {
        let r = report(vec![
            finding(FindingStatus::Reproducible, Severity::MemorySafety),
            finding(FindingStatus::Unconfirmed, Severity::Crash),
        ]);
        let m = r.to_markdown();
        let findings_at = m.find("## Findings").unwrap();
        let unconfirmed_at = m.find("## Unconfirmed observations").unwrap();
        assert!(findings_at < unconfirmed_at, "confirmed findings must come first");
        assert!(
            m.contains("**not** established defects"),
            "unconfirmed section must say plainly that these are not defects"
        );
    }

    #[test]
    fn markdown_never_claims_exploitability() {
        let r = report(vec![finding(FindingStatus::Reproducible, Severity::MemorySafety)]);
        let m = r.to_markdown().to_lowercase();
        // Affirmative claims only: the disclaimer legitimately contains the
        // word "exploitable", which is the point of it.
        for forbidden in [
            "is exploitable.",
            "can be exploited",
            "allows an attacker",
            "attacker can",
            "remote code execution",
            "critical vulnerability",
        ] {
            assert!(!m.contains(forbidden), "report over-claims: found {forbidden:?}");
        }
        assert!(
            m.contains("not been assessed"),
            "a memory-safety finding must carry the exploitability caveat"
        );
    }

    #[test]
    fn markdown_states_when_nothing_was_found_without_claiming_safety() {
        let r = report(Vec::new());
        let m = r.to_markdown();
        assert!(m.contains("No reproducible findings"));
        assert!(
            m.contains("not a claim that the target is free of defects"),
            "an empty result must not read as a clean bill of health"
        );
    }

    #[test]
    fn markdown_distinguishes_unmeasurable_from_zero() {
        let mut r = report(Vec::new());
        r.coverage = CoverageSummary { total_edges: 0, guard_count: None, saturation: None };
        let m = r.to_markdown();
        assert!(m.contains("not reported"), "a missing guard count must not render as 0");
        assert!(m.contains("not measurable"), "missing saturation must not render as 0%");
    }

    #[test]
    fn markdown_reports_unvalidated_minimisation_explicitly() {
        let mut f = finding(FindingStatus::Reproducible, Severity::MemorySafety);
        f.reproduction.minimized_validated = false;
        let m = report(vec![f]).to_markdown();
        assert!(
            m.contains("**not** re-validated"),
            "an unvalidated minimised input must be flagged"
        );
    }

    #[test]
    fn markdown_lists_capability_gaps() {
        let m = report(Vec::new()).to_markdown();
        assert!(m.contains("state-transition"), "unavailable signals must be listed");
        assert!(m.contains("no grammar supplied"), "skipped strategies must be listed");
        assert!(m.contains("AFL++ adapter unavailable"), "limitations must be listed");
        assert!(m.contains("Memory limit enforced: no"));
    }

    #[test]
    fn sarif_is_valid_and_contains_only_confirmed_findings() {
        let r = report(vec![
            finding(FindingStatus::Reproducible, Severity::MemorySafety),
            finding(FindingStatus::Unconfirmed, Severity::Crash),
            finding(FindingStatus::Candidate, Severity::Crash),
        ]);
        let s = r.to_sarif().unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "AETHER");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            1,
            "only the reproducible finding may become a SARIF result"
        );
        assert_eq!(results[0]["ruleId"], "AETHER-MEMORY-SAFETY");
        assert_eq!(results[0]["level"], "error");
        // A fingerprint lets a consumer dedupe across runs.
        assert_eq!(results[0]["partialFingerprints"]["aetherSignature/v1"], "abcd1234");
        // And the exploitability caveat has to survive into SARIF too.
        assert_eq!(results[0]["properties"]["exploitabilityAssessed"], false);
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("not been assessed"));
    }

    #[test]
    fn sarif_declares_every_rule_it_uses() {
        let r = report(vec![
            finding(FindingStatus::Reproducible, Severity::MemorySafety),
            finding(FindingStatus::Intermittent, Severity::Hang),
        ]);
        let v: serde_json::Value = serde_json::from_str(&r.to_sarif().unwrap()).unwrap();
        let declared: Vec<String> = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        for res in v["runs"][0]["results"].as_array().unwrap() {
            let used = res["ruleId"].as_str().unwrap();
            assert!(declared.contains(&used.to_string()), "rule {used} not declared");
        }
    }

    #[test]
    fn bench_json_is_flat_and_machine_readable() {
        let r = report(vec![finding(FindingStatus::Reproducible, Severity::MemorySafety)]);
        let v: serde_json::Value = serde_json::from_str(&r.to_bench_json().unwrap()).unwrap();
        assert_eq!(v["total_executions"], 180_000);
        assert_eq!(v["findings_reproducible"], 1);
        assert_eq!(v["seed"], 42);
        assert_eq!(v["total_edges"], 142);
        assert!(v["strategies"].as_array().unwrap().len() == 1);
        // Unmeasurable values must stay null rather than becoming zero.
        let mut r2 = report(Vec::new());
        r2.coverage.guard_count = None;
        let v2: serde_json::Value = serde_json::from_str(&r2.to_bench_json().unwrap()).unwrap();
        assert!(v2["guard_count"].is_null());
    }

    #[test]
    fn render_dispatches_and_rejects_unknown_formats() {
        let r = report(Vec::new());
        for f in ["json", "markdown", "sarif", "bench-json"] {
            assert!(!r.render(f).unwrap().is_empty(), "{f} produced nothing");
        }
        assert!(r.render("pdf").is_err());
    }

    #[test]
    fn extensions_are_conventional() {
        assert_eq!(CampaignReport::extension("markdown"), "md");
        assert_eq!(CampaignReport::extension("sarif"), "sarif.json");
        assert_eq!(CampaignReport::extension("bench-json"), "bench.json");
        assert_eq!(CampaignReport::extension("json"), "json");
    }
}
