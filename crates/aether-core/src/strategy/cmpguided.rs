//! Comparison-guided mutation (input-to-state substitution).
//!
//! This is the strategy that makes magic-value gates tractable. When the
//! target runs `if (magic != 0xDEADBEEF)`, the instrumentation reports both
//! operands. Finding the input-side operand's bytes in the input and
//! overwriting them with the constant turns a 2^32 search into one execution.
//!
//! The effect is measured, not assumed: `fixtures/crash_magic.c` has four
//! nested constant gates, and the integration suite checks that this strategy
//! walks them while blind mutation does not.
//!
//! It needs the comparison log, so it is unavailable on a gcc-instrumented
//! target (gcc has no `trace-cmp`). The registry drops it with that reason
//! rather than letting it run and propose nothing.

use crate::error::Result;
use crate::feedback::cmplog::{CmpTokenStore, Substitution};
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

pub struct CmpGuided {
    max_len: usize,
    store: CmpTokenStore,
    /// Substitutions proposed per base, bounded so one base with a huge
    /// comparison log cannot consume a whole round's budget.
    max_subs_per_base: usize,
    applied: u64,
    productive: u64,
}

impl Default for CmpGuided {
    fn default() -> Self {
        CmpGuided {
            max_len: 65_536,
            store: CmpTokenStore::new(4096),
            max_subs_per_base: 8,
            applied: 0,
            productive: 0,
        }
    }
}

impl CmpGuided {
    /// Write `sub` into a copy of `input`, extending it if the substitution
    /// runs past the end.
    fn apply_substitution(input: &[u8], sub: &Substitution, max_len: usize) -> Option<Vec<u8>> {
        let end = sub.offset.checked_add(sub.bytes.len())?;
        if sub.offset > input.len() || end > max_len {
            return None;
        }
        let mut out = input.to_vec();
        if end > out.len() {
            out.resize(end, 0);
        }
        out[sub.offset..end].copy_from_slice(&sub.bytes);
        if out == input {
            return None;
        }
        Some(out)
    }
}

impl Strategy for CmpGuided {
    fn id(&self) -> &'static str {
        "cmplog-guided"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: true,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "substitutes constants the target compared against into the \
                          input at the offset the compared bytes came from; grows the \
                          input first when the target has not yet reached a comparison"
                .into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.max_subs_per_base = ctx.param_u64("cmplog_max_subs_per_base", 8).clamp(1, 64) as usize;
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);

        // Pass 1: located substitutions. These are the high-value proposals,
        // because the offset is derived from an actual comparison rather than
        // guessed at.
        for base in bases {
            if out.len() >= budget as usize {
                break;
            }
            if base.cmp_entries.is_empty() {
                continue;
            }
            self.store.observe(&base.cmp_entries);
            let subs =
                self.store
                    .substitutions_for(&base.bytes, &base.cmp_entries, self.max_subs_per_base);
            for sub in subs {
                if out.len() >= budget as usize {
                    break;
                }
                if let Some(bytes) = Self::apply_substitution(&base.bytes, &sub, self.max_len) {
                    self.applied += 1;
                    out.push(Candidate::from_base(bytes, base, "substitute"));
                }
            }
        }

        // Pass 2: constants seen anywhere in the campaign, written at an
        // offset chosen at random. Weaker than a located substitution, but it
        // covers the case where the input-side operand was transformed before
        // the comparison and so cannot be found in the input.
        let ranked = self.store.ranked();
        if !ranked.is_empty() {
            // Prefer frequently-seen constants: a value the target keeps
            // comparing against is likelier to be a real gate.
            let pool = ranked.len().div_ceil(3).max(1);
            while out.len() < budget as usize {
                let base = &bases[rng.below(bases.len())];
                let (token, _) = &ranked[rng.below(pool)];
                let enc = token.candidate_encodings();
                let bytes = &enc[rng.below(enc.len())];

                // Grow the base when the constant does not fit. A short seed
                // cannot hold an eight-byte magic value, and refusing to place
                // it would leave the strategy unable to act on what it knows -
                // which is exactly the situation a one-byte bootstrap seed
                // against a length-checked target produces.
                let mut buf = base.bytes.clone();
                if buf.len() < bytes.len() {
                    let want = (bytes.len() * 2).min(self.max_len).max(bytes.len());
                    while buf.len() < want {
                        buf.push(rng.byte());
                    }
                }
                if buf.len() < bytes.len() || buf.len() > self.max_len {
                    break;
                }
                let at = rng.below(buf.len() - bytes.len() + 1);
                let sub = Substitution { offset: at, bytes: bytes.clone() };
                match Self::apply_substitution(&buf, &sub, self.max_len) {
                    Some(b) => out.push(Candidate::from_base(b, base, "place-constant")),
                    // The write would be a no-op on this base; try another
                    // rather than abandoning the pass.
                    None => continue,
                }
            }
        }

        // Pass 3, the fallback: nothing could be placed, so grow and perturb
        // the base to get the target far enough to perform a comparison at
        // all. Without it the strategy can stall indefinitely on a target
        // whose first check rejects short input before comparing anything,
        // and never acquire the data it exists to exploit.
        if out.is_empty() {
            for _ in 0..budget {
                let base = &bases[rng.below(bases.len())];
                let mut buf = base.bytes.clone();
                let want = rng.between(8, 64).min(self.max_len);
                while buf.len() < want {
                    buf.push(rng.byte());
                }
                super::mutate::havoc(&mut buf, rng, self.max_len, 2);
                if buf.is_empty() || buf == base.bytes {
                    continue;
                }
                out.push(Candidate::from_base(buf, base, "bootstrap-reach-comparison"));
            }
        }

        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        for r in results {
            if r.note == "substitute" && r.feedback.is_interesting() {
                self.productive += 1;
            }
        }
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "tokens_known": self.store.len(),
            "comparison_sites": self.store.distinct_sites(),
            "substitutions_applied": self.applied,
            "substitutions_productive": self.productive,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::exec::shm::CmpEntry;
    use crate::ids::InputId;
    use std::collections::BTreeMap;

    fn base_with(bytes: &[u8], entries: Vec<CmpEntry>) -> Base {
        Base { id: InputId::new(), bytes: bytes.to_vec(), cmp_entries: entries }
    }

    fn entry(v0: u64, v1: u64, width: u8) -> CmpEntry {
        CmpEntry { v0, v1, pc_hash: 7, width, is_const: true }
    }

    fn strategy() -> CmpGuided {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut s = CmpGuided::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();
        s
    }

    #[test]
    fn declares_that_it_needs_the_comparison_log() {
        assert!(strategy().capabilities().requires_cmplog);
    }

    #[test]
    fn substitutes_the_constant_at_the_located_offset() {
        // The crash_magic case: input holds 0x41414141, target wants 0xDEADBEEF.
        let mut s = strategy();
        let mut rng = Rng::from_seed(1);
        let b = base_with(b"AAAArest", vec![entry(0xDEAD_BEEF, 0x4141_4141, 4)]);
        let cands = s.propose(8, &[b], &mut rng);

        assert!(
            cands.iter().any(|c| c.bytes.starts_with(&[0xEF, 0xBE, 0xAD, 0xDE])),
            "no candidate placed the little-endian constant at offset 0: {:?}",
            cands.iter().map(|c| hex(&c.bytes)).collect::<Vec<_>>()
        );
        assert!(cands.iter().any(|c| c.note == "substitute"));
    }

    #[test]
    fn walks_a_nested_gate_ladder_one_stage_at_a_time() {
        // Each stage's comparison log reveals only the next constant, exactly
        // as the real fixture behaves. The strategy must make progress at
        // every stage rather than needing all constants at once.
        let mut s = strategy();
        let mut rng = Rng::from_seed(2);

        // Stage 1: magic.
        let b1 = base_with(b"AAAAAAAA", vec![entry(0xDEAD_BEEF, 0x4141_4141, 4)]);
        let c1 = s.propose(8, &[b1], &mut rng);
        let after1 = c1
            .iter()
            .find(|c| c.bytes.starts_with(&[0xEF, 0xBE, 0xAD, 0xDE]))
            .expect("stage 1 substitution");

        // Stage 2: with the magic satisfied, the version constant appears.
        let b2 = base_with(&after1.bytes, vec![entry(0x0203, 0x4141, 2)]);
        let c2 = s.propose(8, &[b2], &mut rng);
        assert!(
            c2.iter().any(|c| c.bytes.len() >= 6 && c.bytes[4..6] == [0x03, 0x02]),
            "stage 2 did not place the version constant: {:?}",
            c2.iter().map(|c| hex(&c.bytes)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn handles_a_single_byte_gate() {
        let mut s = strategy();
        let mut rng = Rng::from_seed(3);
        let b = base_with(b"xAy", vec![entry(0x5A, 0x41, 1)]);
        let cands = s.propose(8, &[b], &mut rng);
        assert!(
            cands.iter().any(|c| c.bytes.contains(&0x5A)),
            "single-byte constant was never placed"
        );
    }

    #[test]
    fn bootstraps_when_the_target_has_not_reached_a_comparison_yet() {
        // A one-byte seed against a target with a length check ahead of its
        // magic check yields no operands. Without a bootstrap path the
        // strategy would propose nothing for the whole campaign and never
        // acquire the data it exists to exploit.
        let mut s = strategy();
        let mut rng = Rng::from_seed(20);
        let b = base_with(b"\0", Vec::new());
        let cands = s.propose(16, &[b], &mut rng);

        assert!(!cands.is_empty(), "strategy starved itself with no comparison data");
        assert!(cands.iter().all(|c| c.note == "bootstrap-reach-comparison"));
        assert!(cands.iter().all(|c| c.bytes.len() > 1), "bootstrap must grow the seed");
        assert!(
            cands.iter().any(|c| c.bytes.len() >= 8),
            "bootstrap should grow the input past a minimum-length check"
        );
    }

    #[test]
    fn bootstrap_stops_once_constants_are_known() {
        let mut s = strategy();
        let mut rng = Rng::from_seed(21);
        // Teach it one constant; it should now place that rather than bootstrap.
        s.store.observe(&[entry(0xCAFE_BABE, 0x1111_1111, 4)]);
        let cands = s.propose(8, &[base_with(b"zzzzzzzz", Vec::new())], &mut rng);
        assert!(!cands.is_empty());
        assert!(
            cands.iter().all(|c| c.note != "bootstrap-reach-comparison"),
            "should exploit the known constant rather than bootstrap"
        );
    }

    #[test]
    fn grows_a_short_base_to_fit_a_wider_constant() {
        // The case that stalled a real campaign: a one-byte seed against a
        // target whose first check is `n < 8`. That check is itself an
        // instrumented comparison, so the strategy learns the constant 8 as an
        // eight-byte value - which cannot be written into a one-byte input.
        // Refusing to place it left the strategy proposing nothing for 9,000
        // consecutive rounds while executing once in total.
        let mut s = strategy();
        let mut rng = Rng::from_seed(22);
        let b = base_with(b"\0", vec![entry(8, 0, 8)]);
        let cands = s.propose(16, &[b], &mut rng);

        assert!(!cands.is_empty(), "strategy stalled on a base too short for the constant");
        assert!(
            cands.iter().any(|c| c.bytes.len() >= 8),
            "should have grown the base to fit an eight-byte constant: {:?}",
            cands.iter().map(|c| c.bytes.len()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn proposes_nothing_without_a_corpus() {
        let mut s = strategy();
        let mut rng = Rng::from_seed(4);
        assert!(s.propose(8, &[], &mut rng).is_empty());
    }

    #[test]
    fn falls_back_to_placing_known_constants_when_the_operand_cannot_be_located() {
        // The input-side operand is not present in the input, so there is no
        // offset to substitute at; the strategy should still try placing the
        // constant rather than give up.
        let mut s = strategy();
        let mut rng = Rng::from_seed(5);
        // First, teach it a constant.
        s.store.observe(&[entry(0xCAFE_BABE, 0x1111_1111, 4)]);
        let b = base_with(b"zzzzzzzzzzzz", Vec::new());
        let cands = s.propose(8, &[b], &mut rng);
        assert!(!cands.is_empty(), "should fall back to placing the constant");
        assert!(cands.iter().all(|c| c.note == "place-constant"));
        assert!(
            cands.iter().any(|c| c.bytes.windows(4).any(|w| w == [0xBE, 0xBA, 0xFE, 0xCA])),
            "fallback never wrote the constant"
        );
    }

    #[test]
    fn respects_the_budget_and_the_length_ceiling() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 8;
        let mut s = CmpGuided::default();
        s.initialize(&c).unwrap();

        let entries: Vec<CmpEntry> =
            (0..200).map(|i| entry(0x1000 + i, 0x4141_4141, 4)).collect();
        let b = base_with(b"AAAAAAAA", entries);
        let mut rng = Rng::from_seed(6);
        let cands = s.propose(5, &[b], &mut rng);
        assert!(cands.len() <= 5, "budget exceeded: {}", cands.len());
        for cand in &cands {
            assert!(cand.bytes.len() <= 8);
        }
    }

    #[test]
    fn never_proposes_an_unchanged_input() {
        let mut s = strategy();
        let mut rng = Rng::from_seed(7);
        // Constant already equals what is in the input.
        let b = base_with(&[0xEF, 0xBE, 0xAD, 0xDE], vec![entry(0xDEAD_BEEF, 0xDEAD_BEEF, 4)]);
        for c in s.propose(8, &[b.clone()], &mut rng) {
            assert_ne!(c.bytes, b.bytes, "proposed an identical input");
        }
    }

    #[test]
    fn reports_its_accounting() {
        let mut s = strategy();
        let mut rng = Rng::from_seed(8);
        let b = base_with(b"AAAAAAAA", vec![entry(0xDEAD_BEEF, 0x4141_4141, 4)]);
        s.propose(4, &[b], &mut rng);
        s.observe(&[result("substitute", true), result("substitute", false)]);
        let st = s.export_state();
        assert!(st["substitutions_applied"].as_u64().unwrap() > 0);
        assert_eq!(st["substitutions_productive"], 1);
        assert!(st["tokens_known"].as_u64().unwrap() > 0);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
