//! Dictionary-driven mutation.
//!
//! Inserts and overwrites with tokens the target is known to care about:
//! format magics, keywords, delimiters. A random mutation will essentially
//! never produce the string `"TLV1"`, so for a format-driven target a
//! dictionary is the difference between parsing and being rejected at byte 0.
//!
//! Tokens come from configuration, from a dictionary file in the AFL format,
//! and from a small set of structural delimiters that are useful across text
//! formats.

use crate::error::{Error, Result};
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

/// Delimiters and markers that matter in most text and wire formats. Included
/// by default because a target that parses *anything* structured tends to
/// branch on at least some of them.
const STRUCTURAL_TOKENS: &[&[u8]] = &[
    b"\0", b"\n", b"\r\n", b"\t", b" ", b"{", b"}", b"[", b"]", b"(", b")", b"<", b">", b"\"",
    b"'", b"=", b":", b";", b",", b".", b"/", b"\\", b"-", b"+", b"%", b"&", b"?", b"#", b"|",
    b"../", b"%00", b"%s", b"%n", b"\\x00",
];

#[derive(Default)]
pub struct DictionaryStrategy {
    tokens: Vec<Vec<u8>>,
    max_len: usize,
    /// Per-token success counts: a token that keeps finding things is worth
    /// trying more often than one that never has.
    token_wins: Vec<u32>,
    token_tries: Vec<u32>,
}

impl DictionaryStrategy {
    /// Parse an AFL-style dictionary: `name="token"` or a bare `"token"`,
    /// with `#` comments. Escapes `\\`, `\"` and `\xNN` are honoured.
    pub fn parse_dictionary(text: &str) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Take whatever is inside the first pair of double quotes.
            let Some(start) = line.find('"') else { continue };
            let body = &line[start + 1..];
            let Some(end) = find_unescaped_quote(body) else {
                return Err(Error::config(
                    "strategies.dictionary_file",
                    format!("line {}: unterminated quoted token", lineno + 1),
                ));
            };
            let token = unescape(&body[..end]);
            if !token.is_empty() {
                out.push(token);
            }
        }
        Ok(out)
    }

    fn pick_token(&mut self, rng: &mut Rng) -> Option<usize> {
        if self.tokens.is_empty() {
            return None;
        }
        // Weight by observed success, with a floor so an untried token is
        // still reachable. Without the floor the strategy would lock onto
        // whichever token happened to win first.
        let weights: Vec<f64> = (0..self.tokens.len())
            .map(|i| {
                let tries = self.token_tries[i] as f64;
                let wins = self.token_wins[i] as f64;
                0.25 + if tries > 0.0 { wins / tries * 4.0 } else { 0.75 }
            })
            .collect();
        rng.weighted_index(&weights)
    }
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        match b[i + 1] {
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'x' if i + 3 < b.len() => {
                let hex = &s[i + 2..i + 4];
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 4;
                    }
                    Err(_) => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 2;
            }
        }
    }
    out
}

impl Strategy for DictionaryStrategy {
    fn id(&self) -> &'static str {
        "dictionary"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "inserts and overwrites with target-specific tokens".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.tokens = ctx.dictionary.to_vec();
        if ctx.param_u64("dictionary_include_structural", 1) != 0 {
            for t in STRUCTURAL_TOKENS {
                self.tokens.push(t.to_vec());
            }
        }
        // Deduplicate: a token listed twice would get twice the budget.
        self.tokens.sort();
        self.tokens.dedup();
        self.token_wins = vec![0; self.tokens.len()];
        self.token_tries = vec![0; self.tokens.len()];
        if self.tokens.is_empty() {
            return Err(Error::config(
                "strategies.dictionary",
                "no tokens available; provide strategies.dictionary or a dictionary_file",
            ));
        }
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let base = &bases[rng.below(bases.len())];
            let Some(ti) = self.pick_token(rng) else { break };
            let token = self.tokens[ti].clone();
            self.token_tries[ti] += 1;

            let mut buf = base.bytes.clone();
            // Insert keeps surrounding structure; overwrite replaces a field
            // in place. Both matter: one grows a record, the other changes a
            // keyword without shifting offsets.
            let note = if rng.bool_with(0.5) || buf.is_empty() {
                let at = rng.below(buf.len() + 1);
                if buf.len() + token.len() > self.max_len {
                    continue;
                }
                buf.splice(at..at, token.iter().copied());
                format!("insert:{ti}")
            } else {
                let at = rng.below(buf.len());
                let end = (at + token.len()).min(buf.len());
                buf[at..end].copy_from_slice(&token[..end - at]);
                format!("overwrite:{ti}")
            };
            if buf != base.bytes {
                out.push(Candidate::from_base(buf, base, note));
            }
        }
        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        for r in results {
            if !r.feedback.is_interesting() {
                continue;
            }
            // note is "insert:<index>" or "overwrite:<index>".
            if let Some(idx) = r.note.rsplit(':').next().and_then(|s| s.parse::<usize>().ok()) {
                if idx < self.token_wins.len() {
                    self.token_wins[idx] += 1;
                }
            }
        }
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "token_count": self.tokens.len(),
            "wins": self.token_wins,
            "tries": self.token_tries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn parses_afl_dictionary_format() {
        let text = r#"
# a comment
magic="TLV1"
kw_if="if"
"bare"
hex="\x41\x42"
esc="a\"b"
newline="a\nb"
"#;
        let t = DictionaryStrategy::parse_dictionary(text).unwrap();
        assert!(t.contains(&b"TLV1".to_vec()));
        assert!(t.contains(&b"if".to_vec()));
        assert!(t.contains(&b"bare".to_vec()));
        assert!(t.contains(&b"AB".to_vec()), "hex escapes: {t:?}");
        assert!(t.contains(&b"a\"b".to_vec()), "quote escape: {t:?}");
        assert!(t.contains(&b"a\nb".to_vec()), "newline escape: {t:?}");
    }

    #[test]
    fn unterminated_token_is_an_error_with_a_line_number() {
        let e = DictionaryStrategy::parse_dictionary("good=\"ok\"\nbad=\"oops\n").unwrap_err();
        assert!(e.to_string().contains("line 2"), "{e}");
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let t = DictionaryStrategy::parse_dictionary("# nothing\n\n   \n").unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn structural_tokens_make_the_strategy_usable_with_no_configured_dictionary() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let params = BTreeMap::new();
        let mut s = DictionaryStrategy::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();
        assert!(s.tokens.len() >= STRUCTURAL_TOKENS.len());
    }

    #[test]
    fn structural_tokens_can_be_turned_off_leaving_nothing_to_do() {
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        let e = s.initialize(&ctx(&dict, None, &params)).unwrap_err();
        assert!(e.to_string().contains("no tokens available"), "{e}");
    }

    #[test]
    fn tokens_are_deduplicated() {
        let dict = vec![b"TLV1".to_vec(), b"TLV1".to_vec(), b"{".to_vec()];
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();
        assert_eq!(s.tokens.len(), 2, "duplicate tokens would get double the budget");
    }

    #[test]
    fn proposed_inputs_contain_the_tokens() {
        let dict = vec![b"TLV1".to_vec()];
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();

        let mut rng = Rng::from_seed(3);
        let cands = s.propose(64, &bases(&[b"........................"]), &mut rng);
        assert!(!cands.is_empty());
        assert!(
            cands.iter().any(|c| c.bytes.windows(4).any(|w| w == b"TLV1")),
            "no candidate contained the configured token"
        );
    }

    #[test]
    fn respects_the_length_ceiling() {
        let dict = vec![vec![0x41; 32]];
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 16;
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(4);
        for cand in s.propose(64, &bases(&[b"0123456789"]), &mut rng) {
            assert!(cand.bytes.len() <= 16, "got {} bytes", cand.bytes.len());
        }
    }

    #[test]
    fn successful_tokens_are_tried_more_often() {
        let dict = vec![b"AAA".to_vec(), b"BBB".to_vec()];
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();
        let winner = s.tokens.iter().position(|t| t == b"AAA").unwrap();

        // Credit the winning token repeatedly.
        for _ in 0..50 {
            s.token_tries[winner] += 1;
            s.observe(&[result(&format!("insert:{winner}"), true)]);
        }
        // The loser is tried but never pays off.
        let loser = 1 - winner;
        s.token_tries[loser] += 50;

        let mut rng = Rng::from_seed(9);
        let mut winner_picks = 0;
        for _ in 0..400 {
            if s.pick_token(&mut rng) == Some(winner) {
                winner_picks += 1;
            }
        }
        assert!(
            winner_picks > 220,
            "successful token picked only {winner_picks}/400 times"
        );
    }

    #[test]
    fn untried_tokens_remain_reachable() {
        // Without a floor on the weight, one early winner would starve the
        // rest of the dictionary forever.
        let dict: Vec<Vec<u8>> = (0..10).map(|i| vec![b'a' + i as u8; 3]).collect();
        let mut params = BTreeMap::new();
        params.insert("dictionary_include_structural".into(), toml::Value::Integer(0));
        let mut s = DictionaryStrategy::default();
        s.initialize(&ctx(&dict, None, &params)).unwrap();
        s.token_tries[0] = 100;
        s.token_wins[0] = 100;

        let mut rng = Rng::from_seed(2);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            if let Some(i) = s.pick_token(&mut rng) {
                seen.insert(i);
            }
        }
        assert!(seen.len() >= 9, "only {} of 10 tokens were ever picked", seen.len());
    }
}
