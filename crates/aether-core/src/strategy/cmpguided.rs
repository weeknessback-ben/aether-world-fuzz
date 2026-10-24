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
                          input at the offset the compared bytes came from"
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

        // Pass 2: constants seen anywhere in the campaign, written at random
        // offsets. Weaker, but it covers the case where the input-side operand
        // was transformed before the comparison and so cannot be located.
        let ranked = self.store.ranked();
        while out.len() < budget as usize && !ranked.is_empty() {
            let base = &bases[rng.below(bases.len())];
            if base.bytes.is_empty() {
                break;
            }
            // Prefer frequently-seen constants: sample from the top third.
            let pool = ranked.len().div_ceil(3).max(1);
            let (token, _) = &ranked[rng.below(pool)];
            let enc = token.candidate_encodings();
            let bytes = &enc[rng.below(enc.len())];
            if bytes.len() > base.bytes.len() {
                break;
            }
            let at = rng.below(base.bytes.len() - bytes.len() + 1);
            let sub = Substitution { offset: at, bytes: bytes.clone() };
            if let Some(b) = Self::apply_substitution(&base.bytes, &sub, self.max_len) {
                out.push(Candidate::from_base(b, base, "place-constant"));
            } else {
                break;
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
