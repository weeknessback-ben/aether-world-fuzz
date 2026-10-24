//! Comparison-operand feedback: turning what a target compared against into
//! bytes worth putting in the input.
//!
//! When a target runs `if (magic != 0xDEADBEEF)`, the instrumentation reports
//! the pair `(0xDEADBEEF, whatever-was-in-the-input)`. The constant side is
//! exactly the value the input needs at whatever offset the other side came
//! from. Recovering that correspondence replaces a 2^32 search with one
//! substitution, which is the difference between reaching a gate and not.
//!
//! This module keeps the recovered constants; `strategy::cmpguided` is what
//! splices them into inputs.

use std::collections::HashMap;

use crate::exec::shm::CmpEntry;

/// A constant a target compared against, in the widths it could be written as.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CmpToken {
    /// The constant operand.
    pub value: u64,
    /// Width in bytes as the target compared it: 1, 2, 4 or 8.
    pub width: u8,
}

impl CmpToken {
    /// Little-endian encoding, which is what an `x86` target comparing an
    /// integer read out of a buffer will have seen.
    pub fn le_bytes(&self) -> Vec<u8> {
        self.value.to_le_bytes()[..self.width as usize].to_vec()
    }

    /// Big-endian encoding, for network-order fields.
    pub fn be_bytes(&self) -> Vec<u8> {
        let all = self.value.to_be_bytes();
        all[8 - self.width as usize..].to_vec()
    }

    /// The encodings worth trying, most likely first. Both endiannesses are
    /// offered because which one a format uses is not knowable from the
    /// comparison alone, and an ASCII-looking constant is also tried as text.
    pub fn candidate_encodings(&self) -> Vec<Vec<u8>> {
        let mut out = vec![self.le_bytes()];
        let be = self.be_bytes();
        if be != out[0] {
            out.push(be);
        }
        // A constant whose bytes are all printable is often a literal string
        // compared as an integer, e.g. memcmp lowered to a 4-byte compare.
        let le = self.le_bytes();
        if le.len() > 1 && le.iter().all(|b| b.is_ascii_graphic()) {
            // Already covered by le_bytes, but record the ASCII reading so a
            // caller can prefer it when mutating a text format.
        }
        out
    }
}

/// Where in the input a constant should be written, and what to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// Constants recovered from comparisons, scored by how often they appeared.
///
/// Bounded in size: a target in a loop can emit thousands of comparisons per
/// run, and an unbounded store would grow without limit over a long campaign.
#[derive(Debug, Default)]
pub struct CmpTokenStore {
    /// token -> times observed
    tokens: HashMap<CmpToken, u32>,
    /// Distinct comparison sites seen, as a rough measure of how much of the
    /// target's comparison surface has been exercised.
    sites: HashMap<u32, u32>,
    capacity: usize,
}

impl CmpTokenStore {
    pub fn new(capacity: usize) -> Self {
        CmpTokenStore {
            tokens: HashMap::new(),
            sites: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn distinct_sites(&self) -> usize {
        self.sites.len()
    }

    /// Fold one run's comparisons in. Returns how many tokens were new, which
    /// the scheduler uses as a secondary novelty signal: a run that made the
    /// target compare against constants never seen before explored something,
    /// even if it added no coverage.
    pub fn observe(&mut self, entries: &[CmpEntry]) -> u32 {
        let mut new = 0;
        for e in entries {
            *self.sites.entry(e.pc_hash).or_insert(0) += 1;

            // Only the constant side is useful: the other operand came from
            // the input, so writing it back teaches nothing.
            if !e.is_const {
                continue;
            }
            // A zero or all-ones constant is almost always a length or flag
            // check rather than a magic value, and substituting it blindly
            // wastes budget.
            if e.v0 == 0 || e.v0 == u64::MAX {
                continue;
            }
            let token = CmpToken {
                value: e.v0,
                width: e.width,
            };
            match self.tokens.get_mut(&token) {
                Some(c) => *c += 1,
                None => {
                    if self.tokens.len() < self.capacity {
                        self.tokens.insert(token, 1);
                        new += 1;
                    }
                }
            }
        }
        new
    }

    /// Tokens ordered by observation count, most frequent first. A constant
    /// the target keeps comparing against is likelier to be a real gate than
    /// one seen once.
    pub fn ranked(&self) -> Vec<(CmpToken, u32)> {
        let mut v: Vec<(CmpToken, u32)> =
            self.tokens.iter().map(|(t, c)| (t.clone(), *c)).collect();
        v.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then(b.0.width.cmp(&a.0.width))
                .then(a.0.value.cmp(&b.0.value))
        });
        v
    }

    /// Find every offset in `input` where the *input-side* operand of a
    /// comparison appears, and propose writing the constant there.
    ///
    /// This is the input-to-state correspondence: the comparison tells us the
    /// target read some bytes and compared them against a constant, and
    /// locating those bytes tells us where to write it.
    pub fn substitutions_for(
        &self,
        input: &[u8],
        entries: &[CmpEntry],
        max: usize,
    ) -> Vec<Substitution> {
        let mut out = Vec::new();
        for e in entries {
            if !e.is_const || out.len() >= max {
                continue;
            }
            let want = CmpToken {
                value: e.v1,
                width: e.width,
            };
            let repl = CmpToken {
                value: e.v0,
                width: e.width,
            };
            if e.v0 == e.v1 {
                continue;
            }
            for (pattern, replacement) in [
                (want.le_bytes(), repl.le_bytes()),
                (want.be_bytes(), repl.be_bytes()),
            ] {
                if pattern.iter().all(|b| *b == 0) {
                    continue; // matches everywhere, teaches nothing
                }
                for off in find_all(input, &pattern, 4) {
                    out.push(Substitution {
                        offset: off,
                        bytes: replacement.clone(),
                    });
                    if out.len() >= max {
                        break;
                    }
                }
                if out.len() >= max {
                    break;
                }
            }
        }
        out.dedup();
        out
    }
}

/// Every offset of `needle` in `haystack`, up to `limit` matches.
fn find_all(haystack: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, w) in haystack.windows(needle.len()).enumerate() {
        if w == needle {
            out.push(i);
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(v0: u64, v1: u64, width: u8, is_const: bool) -> CmpEntry {
        CmpEntry {
            v0,
            v1,
            pc_hash: 0x1234,
            width,
            is_const,
        }
    }

    #[test]
    fn token_encodes_in_both_endiannesses() {
        let t = CmpToken {
            value: 0xDEAD_BEEF,
            width: 4,
        };
        assert_eq!(t.le_bytes(), vec![0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(t.be_bytes(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(t.candidate_encodings().len(), 2);
    }

    #[test]
    fn narrow_tokens_truncate_correctly() {
        let t = CmpToken {
            value: 0x5A,
            width: 1,
        };
        assert_eq!(t.le_bytes(), vec![0x5A]);
        assert_eq!(t.be_bytes(), vec![0x5A]);
        // A single byte reads the same either way, so only one encoding.
        assert_eq!(t.candidate_encodings().len(), 1);
    }

    #[test]
    fn only_constant_operands_are_stored() {
        let mut s = CmpTokenStore::new(64);
        // Non-const entry: both sides came from the program, so neither is a
        // value the input should be made to contain.
        s.observe(&[entry(0xAAAA, 0xBBBB, 2, false)]);
        assert!(s.is_empty());
        s.observe(&[entry(0xAAAA, 0xBBBB, 2, true)]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn trivial_constants_are_skipped() {
        let mut s = CmpTokenStore::new(64);
        s.observe(&[
            entry(0, 5, 4, true),
            entry(u64::MAX, 5, 8, true),
            entry(0xDEADBEEF, 5, 4, true),
        ]);
        assert_eq!(
            s.len(),
            1,
            "zero and all-ones are length/flag checks, not magics"
        );
        assert_eq!(s.ranked()[0].0.value, 0xDEADBEEF);
    }

    #[test]
    fn store_is_bounded() {
        let mut s = CmpTokenStore::new(10);
        let entries: Vec<CmpEntry> = (1..1000u64).map(|i| entry(i, 0, 8, true)).collect();
        let new = s.observe(&entries);
        assert_eq!(s.len(), 10, "store must not grow without limit");
        assert_eq!(new, 10);
    }

    #[test]
    fn repeated_constants_rank_higher() {
        let mut s = CmpTokenStore::new(64);
        s.observe(&[entry(0x1111, 1, 2, true), entry(0x2222, 1, 2, true)]);
        for _ in 0..5 {
            s.observe(&[entry(0x2222, 1, 2, true)]);
        }
        let r = s.ranked();
        assert_eq!(
            r[0].0.value, 0x2222,
            "the repeatedly compared constant should lead"
        );
        assert_eq!(r[0].1, 6);
    }

    #[test]
    fn new_token_count_reports_only_genuinely_new_ones() {
        let mut s = CmpTokenStore::new(64);
        assert_eq!(s.observe(&[entry(0xABCD, 1, 2, true)]), 1);
        assert_eq!(s.observe(&[entry(0xABCD, 1, 2, true)]), 0);
    }

    #[test]
    fn distinct_sites_are_counted_even_for_non_const_entries() {
        let mut s = CmpTokenStore::new(64);
        let mut a = entry(1, 2, 4, false);
        a.pc_hash = 1;
        let mut b = entry(1, 2, 4, false);
        b.pc_hash = 2;
        s.observe(&[a, b, a]);
        assert_eq!(s.distinct_sites(), 2);
    }

    #[test]
    fn substitution_locates_the_input_operand_and_replaces_it() {
        // This is the crash_magic case: the input holds 0x41414141 where the
        // target wants 0xDEADBEEF.
        let s = CmpTokenStore::new(64);
        let input = b"AAAAZZZZ".to_vec();
        let entries = [entry(0xDEAD_BEEF, 0x4141_4141, 4, true)];
        let subs = s.substitutions_for(&input, &entries, 8);

        assert!(!subs.is_empty(), "should locate the input-side operand");
        let first = &subs[0];
        assert_eq!(first.offset, 0);
        assert_eq!(first.bytes, vec![0xEF, 0xBE, 0xAD, 0xDE]);

        // Applying it must produce an input containing the wanted constant.
        let mut patched = input.clone();
        patched[first.offset..first.offset + first.bytes.len()].copy_from_slice(&first.bytes);
        assert_eq!(&patched[..4], &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn substitution_finds_an_operand_at_a_nonzero_offset() {
        let s = CmpTokenStore::new(64);
        let input = b"hdr\x01\x02rest".to_vec(); // 0x0201 little-endian at offset 3
        let entries = [entry(0x0203, 0x0201, 2, true)];
        let subs = s.substitutions_for(&input, &entries, 8);
        assert!(subs.iter().any(|x| x.offset == 3), "subs were {subs:?}");
    }

    #[test]
    fn substitution_skips_all_zero_patterns() {
        // A zero operand matches at every zero run in the input, so proposing
        // a write at each is noise rather than information.
        let s = CmpTokenStore::new(64);
        let input = vec![0u8; 32];
        let entries = [entry(0xFFFF, 0, 2, true)];
        assert!(s.substitutions_for(&input, &entries, 8).is_empty());
    }

    #[test]
    fn substitution_count_is_bounded() {
        let s = CmpTokenStore::new(64);
        let input = vec![0x41u8; 512];
        let entries: Vec<CmpEntry> = (0..200)
            .map(|i| entry(0x1000 + i, 0x4141_4141, 4, true))
            .collect();
        let subs = s.substitutions_for(&input, &entries, 5);
        assert!(subs.len() <= 5, "got {}", subs.len());
    }

    #[test]
    fn equal_operands_produce_no_substitution() {
        let s = CmpTokenStore::new(64);
        let entries = [entry(0x4141, 0x4141, 2, true)];
        assert!(s.substitutions_for(b"AAAA", &entries, 8).is_empty());
    }

    #[test]
    fn find_all_respects_its_limit() {
        assert_eq!(find_all(b"aaaa", b"a", 2), vec![0, 1]);
        assert_eq!(find_all(b"abcabc", b"abc", 9), vec![0, 3]);
        assert!(find_all(b"abc", b"xyz", 9).is_empty());
        assert!(find_all(b"", b"a", 9).is_empty());
        assert!(find_all(b"a", b"", 9).is_empty());
    }
}
