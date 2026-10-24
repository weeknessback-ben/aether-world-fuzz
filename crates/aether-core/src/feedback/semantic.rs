//! Semantic feedback: signals beyond control-flow coverage.
//!
//! Each provider here documents, in [`ProviderDescription`], how its
//! measurement is obtained, what it cannot see, and what it costs. That is not
//! decoration: these signals are weaker and more easily fooled than edge
//! coverage, and a campaign that treats them as equally authoritative will
//! chase noise.
//!
//! The honest limits, stated once:
//!
//! * **Nothing here infers program state.** A provider observes only what the
//!   target chose to emit. `StateTransitionProvider` tracks transitions
//!   between *observed response classes*, which correlate with internal state
//!   in a protocol that reports status - and say nothing about one that does
//!   not.
//! * **Timing is not used as a defect oracle.** Wall-clock differences on a
//!   shared machine are dominated by scheduling noise. Duration is recorded as
//!   a *cost*, never as evidence.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::exec::{ExecOutcome, ExitClass};

/// Whether a provider can actually produce its signal for this target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    /// Present but producing nothing useful, with the reason.
    Degraded(String),
    /// Cannot work against this target, with the reason.
    Unavailable(String),
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available)
    }
}

/// A provider's self-description, surfaced by `aether doctor` and recorded in
/// campaign metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDescription {
    pub id: String,
    /// How the measurement is actually obtained.
    pub method: String,
    /// What the provider cannot observe.
    pub limitations: Vec<String>,
    /// Cost of collecting it, in plain terms.
    pub cost: String,
}

/// What one provider made of one execution.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderOutcome {
    /// Unweighted novelty in `[0, 1]`.
    pub novelty: f64,
    /// Named sub-signals, for reporting and for the scheduler's context.
    pub signals: Vec<(String, f64)>,
    /// A declared invariant was violated. This is a candidate finding even
    /// when the process exited cleanly.
    pub invariant_violated: Option<String>,
    /// Response status codes parsed from the target's output, in order.
    /// Carried through so the stateful strategy can learn which command
    /// transitions were accepted without parsing the output a second time.
    pub response_codes: Vec<u32>,
}

impl ProviderOutcome {
    pub fn none() -> Self {
        Self::default()
    }
    pub fn novel(novelty: f64) -> Self {
        ProviderOutcome {
            novelty: novelty.clamp(0.0, 1.0),
            ..Default::default()
        }
    }
}

/// Context handed to a provider for one execution.
pub struct Observation<'a> {
    pub input: &'a [u8],
    pub outcome: &'a ExecOutcome,
}

/// A source of feedback other than the raw edge map.
pub trait SemanticProvider: Send {
    fn id(&self) -> &'static str;
    fn availability(&self) -> Availability;
    fn describe(&self) -> ProviderDescription;
    fn observe(&mut self, obs: &Observation<'_>) -> ProviderOutcome;
}

// ---------------------------------------------------------------------------
// Exit classification
// ---------------------------------------------------------------------------

/// Novelty from the coarsest signal every target has: how it terminated.
///
/// Works with no instrumentation at all, which makes it the fallback that
/// keeps a black-box target from having no feedback whatsoever.
#[derive(Default)]
pub struct ExitClassProvider {
    seen: HashSet<(u8, Option<i32>, Option<i32>)>,
}

impl SemanticProvider for ExitClassProvider {
    fn id(&self) -> &'static str {
        "exit-class"
    }

    fn availability(&self) -> Availability {
        Availability::Available
    }

    fn describe(&self) -> ProviderDescription {
        ProviderDescription {
            id: self.id().to_string(),
            method: "exit status and terminating signal, as reported by waitpid".into(),
            limitations: vec![
                "extremely coarse: a parser with one error path for every malformed \
                 input produces a single class"
                    .into(),
                "says nothing about which code ran".into(),
            ],
            cost: "free; already collected for every execution".into(),
        }
    }

    fn observe(&mut self, obs: &Observation<'_>) -> ProviderOutcome {
        let key = (
            obs.outcome.class as u8,
            obs.outcome.exit_code,
            obs.outcome.signal,
        );
        let novel = self.seen.insert(key);
        ProviderOutcome {
            novelty: if novel { 1.0 } else { 0.0 },
            signals: vec![("distinct_exit_classes".into(), self.seen.len() as f64)],
            invariant_violated: None,
            response_codes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response-class transitions
// ---------------------------------------------------------------------------

/// Novelty from newly observed transitions between response classes.
///
/// A line-oriented service that answers each command with a status code lets
/// an ordered pair of consecutive codes stand in for a state transition. This
/// is a proxy, not a reading of the target's state machine: see the
/// limitations in [`SemanticProvider::describe`].
pub struct StateTransitionProvider {
    seen_transitions: HashSet<(u32, u32)>,
    seen_states: HashSet<u32>,
    max_tracked: usize,
}

impl Default for StateTransitionProvider {
    fn default() -> Self {
        StateTransitionProvider {
            seen_transitions: HashSet::new(),
            seen_states: HashSet::new(),
            max_tracked: 100_000,
        }
    }
}

impl StateTransitionProvider {
    /// Extract response classes from output: a leading 3-digit status code per
    /// line, as line-oriented protocols conventionally emit.
    fn classes(output: &[u8]) -> Vec<u32> {
        let text = String::from_utf8_lossy(output);
        let mut out = Vec::new();
        for line in text.lines() {
            let t = line.trim_start();
            let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() == 3 {
                if let Ok(code) = digits.parse::<u32>() {
                    out.push(code);
                }
            }
        }
        out
    }
}

impl SemanticProvider for StateTransitionProvider {
    fn id(&self) -> &'static str {
        "state-transition"
    }

    fn availability(&self) -> Availability {
        Availability::Available
    }

    fn describe(&self) -> ProviderDescription {
        ProviderDescription {
            id: self.id().to_string(),
            method: "ordered pairs of consecutive three-digit status codes parsed from \
                     the target's stdout"
                .into(),
            limitations: vec![
                "a proxy for state, not a reading of it: the provider sees only what the \
                 target prints"
                    .into(),
                "produces nothing for a target that does not emit status codes; such a \
                 target reports Degraded rather than a fabricated signal"
                    .into(),
                "output is captured up to output.max_log_bytes, so a very long session \
                 is observed only in part"
                    .into(),
            ],
            cost: "one pass over captured stdout per execution".into(),
        }
    }

    fn observe(&mut self, obs: &Observation<'_>) -> ProviderOutcome {
        let codes = Self::classes(&obs.outcome.stdout);
        if codes.is_empty() {
            return ProviderOutcome::none();
        }
        if self.seen_transitions.len() >= self.max_tracked {
            return ProviderOutcome::none();
        }

        let mut new_states = 0u32;
        let mut new_transitions = 0u32;
        for c in &codes {
            if self.seen_states.insert(*c) {
                new_states += 1;
            }
        }
        for pair in codes.windows(2) {
            if self.seen_transitions.insert((pair[0], pair[1])) {
                new_transitions += 1;
            }
        }

        // A new transition is the stronger signal: it means a sequence reached
        // a combination not previously produced.
        let novelty = if new_transitions > 0 {
            1.0
        } else if new_states > 0 {
            0.5
        } else {
            0.0
        };
        ProviderOutcome {
            novelty,
            signals: vec![
                ("new_transitions".into(), new_transitions as f64),
                (
                    "distinct_transitions".into(),
                    self.seen_transitions.len() as f64,
                ),
                ("sequence_length".into(), codes.len() as f64),
            ],
            invariant_violated: None,
            response_codes: codes,
        }
    }
}

// ---------------------------------------------------------------------------
// Declared invariants
// ---------------------------------------------------------------------------

/// A condition the operator declares must always hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub rule: InvariantRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum InvariantRule {
    /// Output must never contain this byte string.
    StdoutMustNotContain { needle: String },
    /// Output must contain it whenever the process exits successfully.
    StdoutMustContainOnSuccess { needle: String },
    /// The process must never exit with this code.
    ExitCodeForbidden { code: i32 },
    /// Output must not exceed this many bytes, as a cheap resource-use check.
    StdoutMaxBytes { max: usize },
}

/// Checks declared invariants and reports violations.
///
/// A violation is a candidate finding independent of exit status: a target
/// that answers wrongly but exits 0 is still wrong. The engine's own crash
/// oracles cannot see that; only a declared expectation can.
pub struct InvariantProvider {
    invariants: Vec<Invariant>,
    violated: HashSet<String>,
}

impl InvariantProvider {
    pub fn new(invariants: Vec<Invariant>) -> Self {
        InvariantProvider {
            invariants,
            violated: HashSet::new(),
        }
    }
}

impl SemanticProvider for InvariantProvider {
    fn id(&self) -> &'static str {
        "invariant"
    }

    fn availability(&self) -> Availability {
        if self.invariants.is_empty() {
            Availability::Unavailable("no invariants declared in configuration".into())
        } else {
            Availability::Available
        }
    }

    fn describe(&self) -> ProviderDescription {
        ProviderDescription {
            id: self.id().to_string(),
            method: "operator-declared rules evaluated against captured output and exit status"
                .into(),
            limitations: vec![
                "only checks what was declared; it cannot discover an expectation".into(),
                "evaluated against bounded output capture, so a rule about the tail of a \
                 very long output may not be checkable"
                    .into(),
            ],
            cost: "one scan of captured stdout per declared rule per execution".into(),
        }
    }

    fn observe(&mut self, obs: &Observation<'_>) -> ProviderOutcome {
        let stdout = &obs.outcome.stdout;
        for inv in &self.invariants {
            let broken = match &inv.rule {
                InvariantRule::StdoutMustNotContain { needle } => {
                    contains(stdout, needle.as_bytes())
                }
                InvariantRule::StdoutMustContainOnSuccess { needle } => {
                    obs.outcome.class == ExitClass::Ok && !contains(stdout, needle.as_bytes())
                }
                InvariantRule::ExitCodeForbidden { code } => obs.outcome.exit_code == Some(*code),
                InvariantRule::StdoutMaxBytes { max } => {
                    // Only trustworthy when the capture was complete.
                    !obs.outcome.stdout_truncated && stdout.len() > *max
                }
            };
            if broken {
                let first = self.violated.insert(inv.name.clone());
                return ProviderOutcome {
                    // Only the first violation of a given invariant is novel;
                    // repeats of the same one must not look like progress.
                    novelty: if first { 1.0 } else { 0.0 },
                    signals: vec![("invariants_violated".into(), self.violated.len() as f64)],
                    invariant_violated: Some(inv.name.clone()),
                    response_codes: Vec::new(),
                };
            }
        }
        ProviderOutcome::none()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn outcome(class: ExitClass, code: Option<i32>, stdout: &[u8]) -> ExecOutcome {
        ExecOutcome {
            class,
            exit_code: code,
            signal: None,
            duration: Duration::from_millis(1),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            sanitizer: None,
            coverage: None,
            cmp_entries: Vec::new(),
            cmp_overflowed: false,
        }
    }

    fn observe(p: &mut dyn SemanticProvider, o: &ExecOutcome) -> ProviderOutcome {
        p.observe(&Observation {
            input: b"",
            outcome: o,
        })
    }

    #[test]
    fn exit_class_novelty_fires_once_per_distinct_class() {
        let mut p = ExitClassProvider::default();
        let a = outcome(ExitClass::Ok, Some(0), b"");
        assert_eq!(observe(&mut p, &a).novelty, 1.0);
        assert_eq!(observe(&mut p, &a).novelty, 0.0, "a repeat is not novel");

        let b = outcome(ExitClass::NonZeroExit, Some(3), b"");
        assert_eq!(observe(&mut p, &b).novelty, 1.0);
        // Same class, different code: still a distinct observation.
        let c = outcome(ExitClass::NonZeroExit, Some(4), b"");
        assert_eq!(observe(&mut p, &c).novelty, 1.0);
    }

    #[test]
    fn exit_class_works_with_no_instrumentation() {
        let p = ExitClassProvider::default();
        assert!(
            p.availability().is_available(),
            "must be the black-box fallback"
        );
    }

    #[test]
    fn state_transitions_parse_status_codes() {
        assert_eq!(
            StateTransitionProvider::classes(b"230 ok\n250 opened\n200 written\n"),
            vec![230, 250, 200]
        );
        // Not three digits, or not leading: ignored.
        assert!(StateTransitionProvider::classes(b"ok\nerror 42\n12 x\n1234 y\n").is_empty());
    }

    #[test]
    fn new_transition_outranks_a_new_state_alone() {
        let mut p = StateTransitionProvider::default();
        // First sequence: new states and new transitions.
        let first = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"230 a\n250 b\n"));
        assert_eq!(first.novelty, 1.0);

        // Exactly the same sequence again: nothing new.
        let repeat = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"230 a\n250 b\n"));
        assert_eq!(repeat.novelty, 0.0);

        // Same states, reversed order: a transition never seen before.
        let reordered = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"250 b\n230 a\n"));
        assert_eq!(
            reordered.novelty, 1.0,
            "order matters: this is the signal a stateful strategy needs"
        );
    }

    #[test]
    fn state_provider_reports_nothing_for_a_silent_target() {
        let mut p = StateTransitionProvider::default();
        let r = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"no codes here"));
        assert_eq!(r, ProviderOutcome::none(), "must not fabricate a signal");
    }

    #[test]
    fn state_provider_is_bounded() {
        let mut p = StateTransitionProvider {
            max_tracked: 4,
            ..Default::default()
        };
        for i in 100..200u32 {
            let s = format!("{i} x\n{} y\n", i + 1);
            observe(&mut p, &outcome(ExitClass::Ok, Some(0), s.as_bytes()));
        }
        assert!(
            p.seen_transitions.len() <= 8,
            "got {}",
            p.seen_transitions.len()
        );
    }

    #[test]
    fn invariant_provider_is_unavailable_without_declarations() {
        let p = InvariantProvider::new(Vec::new());
        assert!(!p.availability().is_available());
        match p.availability() {
            Availability::Unavailable(r) => assert!(r.contains("no invariants")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_output_is_detected_on_a_clean_exit() {
        // The point of invariants: a target that answers wrongly but exits 0.
        let mut p = InvariantProvider::new(vec![Invariant {
            name: "no-internal-error".into(),
            rule: InvariantRule::StdoutMustNotContain {
                needle: "INTERNAL".into(),
            },
        }]);
        let r = observe(
            &mut p,
            &outcome(ExitClass::Ok, Some(0), b"result: INTERNAL ERROR"),
        );
        assert_eq!(r.invariant_violated.as_deref(), Some("no-internal-error"));
        assert_eq!(r.novelty, 1.0);

        // Repeat of the same violation is not new progress.
        let again = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"INTERNAL again"));
        assert_eq!(again.novelty, 0.0);
        assert!(
            again.invariant_violated.is_some(),
            "still a violation, just not novel"
        );

        // Clean output: no violation.
        let ok = observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"fine"));
        assert!(ok.invariant_violated.is_none());
    }

    #[test]
    fn must_contain_on_success_only_applies_to_success() {
        let mut p = InvariantProvider::new(vec![Invariant {
            name: "ok-marker".into(),
            rule: InvariantRule::StdoutMustContainOnSuccess {
                needle: "OK".into(),
            },
        }]);
        // Successful but missing the marker: a violation.
        assert!(observe(&mut p, &outcome(ExitClass::Ok, Some(0), b"hmm"))
            .invariant_violated
            .is_some());
        // Failed exit, marker absent: not a violation of this rule.
        let mut p2 = InvariantProvider::new(vec![Invariant {
            name: "ok-marker".into(),
            rule: InvariantRule::StdoutMustContainOnSuccess {
                needle: "OK".into(),
            },
        }]);
        assert!(
            observe(&mut p2, &outcome(ExitClass::NonZeroExit, Some(1), b"hmm"))
                .invariant_violated
                .is_none()
        );
    }

    #[test]
    fn forbidden_exit_code_is_detected() {
        let mut p = InvariantProvider::new(vec![Invariant {
            name: "no-77".into(),
            rule: InvariantRule::ExitCodeForbidden { code: 77 },
        }]);
        assert!(
            observe(&mut p, &outcome(ExitClass::NonZeroExit, Some(77), b""))
                .invariant_violated
                .is_some()
        );
        assert!(
            observe(&mut p, &outcome(ExitClass::NonZeroExit, Some(1), b""))
                .invariant_violated
                .is_none()
        );
    }

    #[test]
    fn size_invariant_is_not_judged_on_truncated_output() {
        // Claiming a size violation from a bounded capture would be reporting
        // the engine's own truncation as a target defect.
        let mut p = InvariantProvider::new(vec![Invariant {
            name: "output-bounded".into(),
            rule: InvariantRule::StdoutMaxBytes { max: 4 },
        }]);
        let mut o = outcome(ExitClass::Ok, Some(0), b"way too long");
        o.stdout_truncated = true;
        assert!(
            observe(&mut p, &o).invariant_violated.is_none(),
            "a truncated capture cannot establish a size violation"
        );

        o.stdout_truncated = false;
        assert!(observe(&mut p, &o).invariant_violated.is_some());
    }

    #[test]
    fn every_provider_describes_its_method_limits_and_cost() {
        let providers: Vec<Box<dyn SemanticProvider>> = vec![
            Box::new(ExitClassProvider::default()),
            Box::new(StateTransitionProvider::default()),
            Box::new(InvariantProvider::new(Vec::new())),
        ];
        for p in &providers {
            let d = p.describe();
            assert!(!d.method.is_empty(), "{} has no method", d.id);
            assert!(!d.limitations.is_empty(), "{} claims no limitations", d.id);
            assert!(!d.cost.is_empty(), "{} states no cost", d.id);
        }
    }
}
