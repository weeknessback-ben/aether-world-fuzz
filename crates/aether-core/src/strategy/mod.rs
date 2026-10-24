//! Input generation strategies.
//!
//! A strategy proposes candidate inputs and learns from what they did. The
//! campaign loop knows only this trait, so a strategy can be added without
//! touching the execution loop or the scheduler.
//!
//! Strategies declare their requirements through [`StrategyCapabilities`].
//! The registry refuses to build one whose requirements the target does not
//! meet - a comparison-guided strategy against an uninstrumented binary would
//! otherwise run forever proposing nothing useful.
//!
//! Differential and metamorphic testing are deliberately *not* strategies:
//! neither generates input. They are oracles, and live in [`crate::oracle`].

pub mod cmpguided;
pub mod dictionary;
pub mod evolutionary;
pub mod grammar;
pub mod mutate;
pub mod stateful;
pub mod structure;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::exec::shm::CmpEntry;
use crate::feedback::Feedback;
use crate::ids::InputId;
use crate::rng::Rng;

/// A corpus entry offered to a strategy as a mutation base.
#[derive(Debug, Clone)]
pub struct Base {
    pub id: InputId,
    pub bytes: Vec<u8>,
    /// Comparisons recorded the last time this input ran, when available.
    /// This is what the comparison-guided strategy substitutes from.
    pub cmp_entries: Vec<CmpEntry>,
}

/// One proposed input.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub bytes: Vec<u8>,
    /// Corpus entry this was derived from, for provenance.
    pub parent: Option<InputId>,
    /// Operator or production that made it, for per-operator accounting.
    pub note: String,
}

impl Candidate {
    pub fn new(bytes: Vec<u8>) -> Self {
        Candidate {
            bytes,
            parent: None,
            note: String::new(),
        }
    }

    pub fn from_base(bytes: Vec<u8>, base: &Base, note: impl Into<String>) -> Self {
        Candidate {
            bytes,
            parent: Some(base.id.clone()),
            note: note.into(),
        }
    }
}

/// What one proposed candidate achieved.
#[derive(Debug, Clone)]
pub struct CandidateResult {
    pub note: String,
    pub feedback: Feedback,
    /// Whether the input was kept in the corpus.
    pub retained: bool,
}

/// What a strategy needs and what it produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyCapabilities {
    pub id: String,
    /// Needs edge coverage to make decisions.
    pub requires_coverage: bool,
    /// Needs the comparison log.
    pub requires_cmplog: bool,
    /// Needs a grammar in configuration.
    pub requires_grammar: bool,
    /// Needs at least one corpus entry to mutate.
    pub requires_corpus: bool,
    /// Produces newline-delimited command sequences rather than opaque bytes.
    pub produces_sequences: bool,
    pub description: String,
}

/// Everything a strategy is given at initialisation.
pub struct StrategyContext<'a> {
    pub seed: u64,
    pub max_input_bytes: usize,
    pub dictionary: &'a [Vec<u8>],
    pub grammar_text: Option<&'a str>,
    pub params: &'a BTreeMap<String, toml::Value>,
    pub coverage_available: bool,
    pub cmplog_available: bool,
}

impl StrategyContext<'_> {
    /// Read an integer parameter, falling back to a default.
    pub fn param_u64(&self, key: &str, default: u64) -> u64 {
        self.params
            .get(key)
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok())
            .unwrap_or(default)
    }

    pub fn param_f64(&self, key: &str, default: f64) -> f64 {
        self.params
            .get(key)
            .and_then(|v| v.as_float())
            .unwrap_or(default)
    }
}

/// One input-generation strategy.
pub trait Strategy: Send {
    fn id(&self) -> &'static str;
    fn capabilities(&self) -> StrategyCapabilities;

    /// Prepare for a campaign. Returning an error here keeps a strategy that
    /// cannot work from being scheduled at all.
    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()>;

    /// Propose up to `budget` candidates, drawing on `bases`.
    ///
    /// May return fewer, including none - for example a corpus-dependent
    /// strategy given an empty corpus. The scheduler treats an empty proposal
    /// as a round that produced nothing, not as an error.
    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate>;

    /// Learn from the previous round.
    fn observe(&mut self, results: &[CandidateResult]);

    fn export_state(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    fn restore_state(&mut self, _state: serde_json::Value) -> Result<()> {
        Ok(())
    }
}

/// Every strategy id this build knows.
pub const ALL_STRATEGY_IDS: &[&str] = &[
    "random-mutation",
    "havoc",
    "boundary",
    "splice",
    "dictionary",
    "cmplog-guided",
    "grammar",
    "structure-aware",
    "evolutionary",
    "stateful-sequence",
];

/// Build a strategy by id.
pub fn build(id: &str) -> Result<Box<dyn Strategy>> {
    Ok(match id {
        "random-mutation" => Box::new(RandomMutation::default()),
        "havoc" => Box::new(Havoc::default()),
        "boundary" => Box::new(Boundary::default()),
        "splice" => Box::new(Splice::default()),
        "dictionary" => Box::new(dictionary::DictionaryStrategy::default()),
        "cmplog-guided" => Box::new(cmpguided::CmpGuided::default()),
        "grammar" => Box::new(grammar::GrammarStrategy::default()),
        "structure-aware" => Box::new(structure::StructureAware::default()),
        "evolutionary" => Box::new(evolutionary::Evolutionary::default()),
        "stateful-sequence" => Box::new(stateful::StatefulSequence::default()),
        other => {
            return Err(Error::config(
                "strategies.enabled",
                format!(
                    "unknown strategy {other:?}; known: {}",
                    ALL_STRATEGY_IDS.join(", ")
                ),
            ))
        }
    })
}

/// The usable strategies, plus `(id, reason)` for each one left out.
pub type BuiltStrategies = (Vec<Box<dyn Strategy>>, Vec<(String, String)>);

/// Build the requested strategies, dropping any whose requirements this target
/// cannot meet.
///
/// Returns the usable strategies plus a list of `(id, reason)` for those left
/// out, so a campaign can report which strategies were unavailable rather than
/// silently running a smaller set than asked for.
pub fn build_all(requested: &[String], ctx: &StrategyContext<'_>) -> Result<BuiltStrategies> {
    let ids: Vec<String> = if requested.is_empty() {
        ALL_STRATEGY_IDS.iter().map(|s| s.to_string()).collect()
    } else {
        requested.to_vec()
    };

    let mut built = Vec::new();
    let mut skipped = Vec::new();

    for id in &ids {
        let mut s = build(id)?;
        let caps = s.capabilities();

        if caps.requires_coverage && !ctx.coverage_available {
            skipped.push((
                id.clone(),
                "needs edge coverage; target is not instrumented".into(),
            ));
            continue;
        }
        if caps.requires_cmplog && !ctx.cmplog_available {
            skipped.push((
                id.clone(),
                "needs the comparison log, which this target's instrumentation does not \
                 provide (gcc builds have no trace-cmp)"
                    .into(),
            ));
            continue;
        }
        if caps.requires_grammar && ctx.grammar_text.is_none() {
            skipped.push((id.clone(), "needs strategies.grammar_file to be set".into()));
            continue;
        }

        match s.initialize(ctx) {
            Ok(()) => built.push(s),
            Err(e) => skipped.push((id.clone(), e.to_string())),
        }
    }

    if built.is_empty() {
        return Err(Error::config(
            "strategies.enabled",
            format!(
                "no usable strategy for this target; skipped: {}",
                skipped
                    .iter()
                    .map(|(i, r)| format!("{i} ({r})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    Ok((built, skipped))
}

// ---------------------------------------------------------------------------
// Random mutation
// ---------------------------------------------------------------------------

/// One mutation operator per candidate, chosen uniformly.
///
/// The simplest useful strategy, and the control that stacked and
/// structure-aware mutation are measured against.
#[derive(Default)]
pub struct RandomMutation {
    max_len: usize,
    /// Per-operator success accounting, reported in campaign metadata.
    wins: BTreeMap<String, u32>,
}

impl Strategy for RandomMutation {
    fn id(&self) -> &'static str {
        "random-mutation"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "a single byte-level mutation operator per candidate".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let base = &bases[rng.below(bases.len())];
            let mut buf = base.bytes.clone();
            let op = mutate::Operator::ALL[rng.below(mutate::Operator::ALL.len())];
            if mutate::apply(op, &mut buf, rng, self.max_len) {
                out.push(Candidate::from_base(buf, base, op.as_str()));
            }
        }
        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        for r in results {
            if r.feedback.is_interesting() {
                *self.wins.entry(r.note.clone()).or_insert(0) += 1;
            }
        }
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({ "operator_wins": self.wins })
    }
}

// ---------------------------------------------------------------------------
// Havoc
// ---------------------------------------------------------------------------

/// Stacked mutation: several operators per candidate.
///
/// Stacking is what reaches defects needing two coordinated changes, such as a
/// length field adjusted together with the payload it describes.
pub struct Havoc {
    max_len: usize,
    max_stack: u32,
    /// Adapted from observed success: a target that rewards bigger changes
    /// gets them. Bounded so it cannot run away.
    stack_floor: u32,
    recent_wins: u32,
    recent_total: u32,
}

impl Default for Havoc {
    fn default() -> Self {
        Havoc {
            max_len: 65_536,
            max_stack: 5,
            stack_floor: 1,
            recent_wins: 0,
            recent_total: 0,
        }
    }
}

impl Strategy for Havoc {
    fn id(&self) -> &'static str {
        "havoc"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "stacked byte-level mutation with an adaptive stack size".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.max_stack = ctx.param_u64("havoc_max_stack", 5).clamp(1, 10) as u32;
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let base = &bases[rng.below(bases.len())];
            let mut buf = base.bytes.clone();
            let stack = self.max_stack.max(self.stack_floor);
            let applied = mutate::havoc(&mut buf, rng, self.max_len, stack);
            if applied > 0 && buf != base.bytes {
                out.push(Candidate::from_base(buf, base, format!("havoc-{applied}")));
            }
        }
        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        self.recent_total += results.len() as u32;
        self.recent_wins += results
            .iter()
            .filter(|r| r.feedback.is_interesting())
            .count() as u32;
        if self.recent_total >= 256 {
            let rate = self.recent_wins as f64 / self.recent_total as f64;
            // A low hit rate means small edits are not landing; reach further.
            // A high one means the current size is working; keep it.
            if rate < 0.01 {
                self.stack_floor = (self.stack_floor + 1).min(self.max_stack);
            } else if rate > 0.10 {
                self.stack_floor = self.stack_floor.saturating_sub(1).max(1);
            }
            self.recent_total = 0;
            self.recent_wins = 0;
        }
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({ "stack_floor": self.stack_floor, "max_stack": self.max_stack })
    }

    fn restore_state(&mut self, state: serde_json::Value) -> Result<()> {
        if let Some(v) = state.get("stack_floor").and_then(|v| v.as_u64()) {
            self.stack_floor = (v as u32).clamp(1, 10);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Boundary
// ---------------------------------------------------------------------------

/// Boundary-value mutation: writes integer limits and extreme lengths.
///
/// Separated from random mutation so its contribution can be measured on its
/// own, since length and limit handling is where a large share of real
/// memory-safety defects sit.
#[derive(Default)]
pub struct Boundary {
    max_len: usize,
}

impl Strategy for Boundary {
    fn id(&self) -> &'static str {
        "boundary"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "integer limits, off-by-ones and extreme lengths".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for i in 0..budget {
            let base = &bases[rng.below(bases.len())];
            let mut buf = base.bytes.clone();
            // Alternate between writing a boundary value and taking the input
            // itself to a length extreme.
            let note = if i % 3 == 2 {
                if rng.bool_with(0.5) {
                    buf.clear();
                    "length-zero"
                } else {
                    let room = self.max_len.saturating_sub(buf.len());
                    if room > 0 {
                        let fill = if buf.is_empty() {
                            0x41
                        } else {
                            buf[buf.len() - 1]
                        };
                        buf.extend(std::iter::repeat(fill).take(room));
                    }
                    "length-max"
                }
            } else if mutate::interesting_value(&mut buf, rng) {
                "interesting-value"
            } else {
                continue;
            };
            if buf.len() > self.max_len {
                buf.truncate(self.max_len);
            }
            out.push(Candidate::from_base(buf, base, note));
        }
        out
    }

    fn observe(&mut self, _results: &[CandidateResult]) {}
}

// ---------------------------------------------------------------------------
// Splice
// ---------------------------------------------------------------------------

/// Combine two corpus entries at a cut point.
///
/// Crossover between inputs that reached different parts of the target can
/// produce one that reaches both, which single-input mutation cannot do.
#[derive(Default)]
pub struct Splice {
    max_len: usize,
}

impl Strategy for Splice {
    fn id(&self) -> &'static str {
        "splice"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "crossover between two corpus entries".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        // Needs two distinct entries to combine.
        if bases.len() < 2 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let a = &bases[rng.below(bases.len())];
            let b = &bases[rng.below(bases.len())];
            if a.id == b.id || a.bytes.is_empty() || b.bytes.is_empty() {
                continue;
            }
            let cut_a = rng.below(a.bytes.len() + 1);
            let cut_b = rng.below(b.bytes.len() + 1);
            let mut buf = Vec::with_capacity(cut_a + (b.bytes.len() - cut_b));
            buf.extend_from_slice(&a.bytes[..cut_a]);
            buf.extend_from_slice(&b.bytes[cut_b..]);
            if buf.is_empty() || buf == a.bytes || buf == b.bytes {
                continue;
            }
            if buf.len() > self.max_len {
                buf.truncate(self.max_len);
            }
            out.push(Candidate::from_base(buf, a, "splice"));
        }
        out
    }

    fn observe(&mut self, _results: &[CandidateResult]) {}
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    pub fn ctx<'a>(
        dict: &'a [Vec<u8>],
        grammar: Option<&'a str>,
        params: &'a BTreeMap<String, toml::Value>,
    ) -> StrategyContext<'a> {
        StrategyContext {
            seed: 42,
            max_input_bytes: 4096,
            dictionary: dict,
            grammar_text: grammar,
            params,
            coverage_available: true,
            cmplog_available: true,
        }
    }

    pub fn bases(data: &[&[u8]]) -> Vec<Base> {
        data.iter()
            .map(|d| Base {
                id: InputId::new(),
                bytes: d.to_vec(),
                cmp_entries: Vec::new(),
            })
            .collect()
    }

    pub fn result(note: &str, interesting: bool) -> CandidateResult {
        let mut fb = Feedback::default();
        if interesting {
            fb.novelty = 1.0;
        }
        CandidateResult {
            note: note.to_string(),
            feedback: fb,
            retained: interesting,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn every_known_strategy_builds() {
        for id in ALL_STRATEGY_IDS {
            let s = build(id).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(s.id(), *id);
            let caps = s.capabilities();
            assert_eq!(caps.id, *id);
            assert!(!caps.description.is_empty(), "{id} has no description");
        }
    }

    #[test]
    fn unknown_strategy_is_refused() {
        let e = match build("telepathy") {
            Ok(_) => panic!("an unknown strategy id must not build"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("unknown strategy"), "{e}");
    }

    #[test]
    fn requirements_filter_the_registry_with_reasons() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        // No coverage and no comparison log: coverage- and cmplog-dependent
        // strategies must be dropped with an explanation, not silently.
        let mut c = ctx(&dict, None, &params);
        c.coverage_available = false;
        c.cmplog_available = false;

        let (built, skipped) = match build_all(&[], &c) {
            Ok(v) => v,
            Err(e) => panic!("build_all failed: {e}"),
        };
        assert!(!built.is_empty(), "byte-level strategies should still work");
        assert!(
            skipped
                .iter()
                .any(|(id, r)| id == "cmplog-guided" && r.contains("comparison log")),
            "skipped: {skipped:?}"
        );
        assert!(
            skipped
                .iter()
                .any(|(id, r)| id == "grammar" && r.contains("grammar_file")),
            "skipped: {skipped:?}"
        );
        for (_, reason) in &skipped {
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn no_usable_strategy_is_an_error_not_an_empty_run() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut c = ctx(&dict, None, &params);
        c.cmplog_available = false;
        let e = match build_all(&["cmplog-guided".to_string()], &c) {
            Ok(_) => panic!("expected an error when no strategy is usable"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("no usable strategy"), "{e}");
    }

    #[test]
    fn corpus_dependent_strategies_propose_nothing_without_a_corpus() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut rng = Rng::from_seed(1);
        for id in ["random-mutation", "havoc", "boundary", "splice"] {
            let mut s = build(id).unwrap();
            s.initialize(&c).unwrap();
            assert!(
                s.propose(16, &[], &mut rng).is_empty(),
                "{id} invented candidates from an empty corpus"
            );
        }
    }

    #[test]
    fn mutation_strategies_produce_candidates_within_the_ceiling() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 64;
        let b = bases(&[b"hello world this is a base input", b"another base"]);
        let mut rng = Rng::from_seed(7);

        for id in ["random-mutation", "havoc", "boundary", "splice"] {
            let mut s = build(id).unwrap();
            s.initialize(&c).unwrap();
            let cands = s.propose(32, &b, &mut rng);
            assert!(
                !cands.is_empty(),
                "{id} proposed nothing from a two-entry corpus"
            );
            for cand in &cands {
                assert!(cand.bytes.len() <= 64, "{id} exceeded the ceiling");
                assert!(!cand.note.is_empty(), "{id} did not label its operator");
                assert!(cand.parent.is_some(), "{id} lost provenance");
            }
        }
    }

    #[test]
    fn splice_needs_two_distinct_entries() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut s = Splice::default();
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(3);
        assert!(s.propose(8, &bases(&[b"only one"]), &mut rng).is_empty());
        assert!(!s
            .propose(8, &bases(&[b"first one", b"second one"]), &mut rng)
            .is_empty());
    }

    #[test]
    fn splice_output_combines_both_parents() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut s = Splice::default();
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(11);
        let b = bases(&[b"AAAAAAAA", b"BBBBBBBB"]);
        let cands = s.propose(64, &b, &mut rng);
        assert!(
            cands
                .iter()
                .any(|c| c.bytes.contains(&b'A') && c.bytes.contains(&b'B')),
            "splice never mixed the two parents"
        );
    }

    #[test]
    fn havoc_stack_floor_rises_when_nothing_lands() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut h = Havoc::default();
        h.initialize(&c).unwrap();
        let before = h.stack_floor;
        // A long run of fruitless results should make it reach further.
        let fruitless: Vec<CandidateResult> = (0..300).map(|_| result("havoc-1", false)).collect();
        h.observe(&fruitless);
        assert!(h.stack_floor > before, "stack floor did not adapt upward");
    }

    #[test]
    fn havoc_state_round_trips() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut h = Havoc::default();
        h.initialize(&c).unwrap();
        h.observe(
            &(0..300)
                .map(|_| result("havoc-1", false))
                .collect::<Vec<_>>(),
        );
        let state = h.export_state();

        let mut h2 = Havoc::default();
        h2.initialize(&c).unwrap();
        h2.restore_state(state).unwrap();
        assert_eq!(h2.stack_floor, h.stack_floor);
    }

    #[test]
    fn strategies_are_reproducible_for_a_fixed_seed() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let b = bases(&[b"reproducible base input", b"second base"]);
        for id in ["random-mutation", "havoc", "boundary", "splice"] {
            let run = || {
                let mut s = build(id).unwrap();
                s.initialize(&c).unwrap();
                let mut rng = Rng::from_seed(1234);
                s.propose(16, &b, &mut rng)
                    .into_iter()
                    .map(|c| c.bytes)
                    .collect::<Vec<_>>()
            };
            assert_eq!(run(), run(), "{id} is not reproducible under a fixed seed");
        }
    }

    #[test]
    fn random_mutation_records_which_operators_pay_off() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let c = ctx(&dict, None, &params);
        let mut s = RandomMutation::default();
        s.initialize(&c).unwrap();
        s.observe(&[
            result("bit-flip", true),
            result("bit-flip", true),
            result("insert", false),
        ]);
        let state = s.export_state();
        assert_eq!(state["operator_wins"]["bit-flip"], 2);
        assert!(state["operator_wins"].get("insert").is_none());
    }

    #[test]
    fn boundary_reaches_both_length_extremes() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 32;
        let mut s = Boundary::default();
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(5);
        let cands = s.propose(200, &bases(&[b"some base"]), &mut rng);
        assert!(
            cands.iter().any(|x| x.bytes.is_empty()),
            "never tried an empty input"
        );
        assert!(
            cands.iter().any(|x| x.bytes.len() == 32),
            "never tried the maximum length"
        );
    }
}
