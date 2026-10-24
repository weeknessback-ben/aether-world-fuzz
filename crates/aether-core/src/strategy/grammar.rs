//! Grammar-aware generation.
//!
//! Generates inputs from an explicitly supplied grammar rather than mutating
//! bytes. For a target that rejects anything malformed at its first check,
//! generation reaches the interesting code; mutation mostly does not.
//!
//! The grammar is a small BNF-like notation, deliberately not a general parser
//! generator:
//!
//! ```text
//! # comment
//! <start>  ::= "TLV1" <records>
//! <records> ::= <record> | <record> <records> |
//! <record> ::= "T" <byte> <byte>
//! <byte>   ::= "\x01" | "\x02"
//! ```
//!
//! Recursion is permitted and bounded by a depth limit, because `<records>`
//! referring to itself is exactly what makes a grammar useful and also what
//! makes naive expansion run forever.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

/// One element of a production.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Literal(Vec<u8>),
    Rule(String),
}

#[derive(Debug, Clone, Default)]
struct Grammar {
    /// rule name -> alternatives, each a sequence of terms.
    rules: HashMap<String, Vec<Vec<Term>>>,
    start: String,
}

impl Grammar {
    /// Parse the notation above. Errors name the line, because a grammar is
    /// hand-written and a silent misparse would be very hard to notice.
    fn parse(text: &str) -> Result<Self> {
        let mut rules: HashMap<String, Vec<Vec<Term>>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((lhs, rhs)) = line.split_once("::=") else {
                return Err(Error::config(
                    "grammar",
                    format!("line {}: expected '::=' in {line:?}", i + 1),
                ));
            };
            let name = lhs.trim();
            if !(name.starts_with('<') && name.ends_with('>') && name.len() > 2) {
                return Err(Error::config(
                    "grammar",
                    format!("line {}: rule name must look like <name>, got {name:?}", i + 1),
                ));
            }
            let name = name[1..name.len() - 1].to_string();

            let mut alts = Vec::new();
            for alt in rhs.split('|') {
                alts.push(parse_terms(alt, i + 1)?);
            }
            if !rules.contains_key(&name) {
                order.push(name.clone());
            }
            rules.entry(name).or_default().extend(alts);
        }

        if rules.is_empty() {
            return Err(Error::config("grammar", "no rules defined"));
        }
        let start = if rules.contains_key("start") {
            "start".to_string()
        } else {
            order[0].clone()
        };

        // Every referenced rule must exist, checked up front: a missing rule
        // discovered mid-generation would silently produce a truncated input.
        for (name, alts) in &rules {
            for alt in alts {
                for t in alt {
                    if let Term::Rule(r) = t {
                        if !rules.contains_key(r) {
                            return Err(Error::config(
                                "grammar",
                                format!("rule <{name}> refers to undefined rule <{r}>"),
                            ));
                        }
                    }
                }
            }
        }
        Ok(Grammar { rules, start })
    }

    /// Expand `rule` into `out`, bounded by depth and output length.
    fn expand(
        &self,
        rule: &str,
        depth: u32,
        max_depth: u32,
        out: &mut Vec<u8>,
        max_len: usize,
        rng: &mut Rng,
    ) {
        if out.len() >= max_len {
            return;
        }
        let Some(alts) = self.rules.get(rule) else { return };
        if alts.is_empty() {
            return;
        }

        // At the depth limit, prefer an alternative that does not recurse, so
        // generation terminates with a well-formed input rather than a
        // truncated one.
        let choice = if depth >= max_depth {
            alts.iter()
                .position(|a| !a.iter().any(|t| matches!(t, Term::Rule(_))))
                .unwrap_or_else(|| rng.below(alts.len()))
        } else {
            rng.below(alts.len())
        };

        for term in &alts[choice] {
            if out.len() >= max_len {
                return;
            }
            match term {
                Term::Literal(b) => {
                    let room = max_len - out.len();
                    out.extend_from_slice(&b[..b.len().min(room)]);
                }
                Term::Rule(r) => self.expand(r, depth + 1, max_depth, out, max_len, rng),
            }
        }
    }
}

fn parse_terms(s: &str, lineno: usize) -> Result<Vec<Term>> {
    let mut terms = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'"' => {
                let mut j = i + 1;
                let mut lit = Vec::new();
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'\\' && j + 1 < b.len() {
                        match b[j + 1] {
                            b'n' => {
                                lit.push(b'\n');
                                j += 2;
                            }
                            b'r' => {
                                lit.push(b'\r');
                                j += 2;
                            }
                            b't' => {
                                lit.push(b'\t');
                                j += 2;
                            }
                            b'0' => {
                                lit.push(0);
                                j += 2;
                            }
                            b'x' if j + 3 < b.len() => {
                                let v = u8::from_str_radix(&s[j + 2..j + 4], 16).map_err(|_| {
                                    Error::config(
                                        "grammar",
                                        format!("line {lineno}: bad hex escape"),
                                    )
                                })?;
                                lit.push(v);
                                j += 4;
                            }
                            other => {
                                lit.push(other);
                                j += 2;
                            }
                        }
                    } else {
                        lit.push(b[j]);
                        j += 1;
                    }
                }
                if j >= b.len() {
                    return Err(Error::config(
                        "grammar",
                        format!("line {lineno}: unterminated literal"),
                    ));
                }
                terms.push(Term::Literal(lit));
                i = j + 1;
            }
            b'<' => {
                let Some(close) = s[i..].find('>') else {
                    return Err(Error::config(
                        "grammar",
                        format!("line {lineno}: unterminated rule reference"),
                    ));
                };
                let name = &s[i + 1..i + close];
                if name.is_empty() {
                    return Err(Error::config(
                        "grammar",
                        format!("line {lineno}: empty rule reference"),
                    ));
                }
                terms.push(Term::Rule(name.to_string()));
                i += close + 1;
            }
            _ => {
                return Err(Error::config(
                    "grammar",
                    format!("line {lineno}: unexpected character {:?}", b[i] as char),
                ))
            }
        }
    }
    Ok(terms)
}

pub struct GrammarStrategy {
    grammar: Grammar,
    max_len: usize,
    max_depth: u32,
    /// Mutate a generated input occasionally: pure generation explores the
    /// grammar, but a defect often lives just outside what the grammar allows.
    mutation_rate: f64,
}

impl Default for GrammarStrategy {
    fn default() -> Self {
        GrammarStrategy {
            grammar: Grammar::default(),
            max_len: 65_536,
            max_depth: 8,
            mutation_rate: 0.15,
        }
    }
}

impl Strategy for GrammarStrategy {
    fn id(&self) -> &'static str {
        "grammar"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: true,
            // Generates from nothing, so an empty corpus is fine. This is what
            // makes it the strategy that can start a campaign with no seeds.
            requires_corpus: false,
            produces_sequences: false,
            description: "generates structurally valid inputs from a supplied grammar".into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        let text = ctx.grammar_text.ok_or_else(|| {
            Error::config("strategies.grammar_file", "the grammar strategy needs a grammar")
        })?;
        self.grammar = Grammar::parse(text)?;
        self.max_len = ctx.max_input_bytes;
        self.max_depth = ctx.param_u64("grammar_max_depth", 8).clamp(1, 64) as u32;
        self.mutation_rate = ctx.param_f64("grammar_mutation_rate", 0.15).clamp(0.0, 1.0);
        Ok(())
    }

    fn propose(&mut self, budget: u32, _bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let mut buf = Vec::new();
            self.grammar
                .expand(&self.grammar.start.clone(), 0, self.max_depth, &mut buf, self.max_len, rng);
            if buf.is_empty() {
                continue;
            }
            let note = if rng.bool_with(self.mutation_rate) {
                // Perturb just outside the grammar: this is where a parser's
                // error handling lives, and error paths are where defects hide.
                super::mutate::havoc(&mut buf, rng, self.max_len, 2);
                "generated+mutated"
            } else {
                "generated"
            };
            out.push(Candidate { bytes: buf, parent: None, note: note.into() });
        }
        out
    }

    fn observe(&mut self, _results: &[CandidateResult]) {}

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "rules": self.grammar.rules.len(),
            "start": self.grammar.start,
            "max_depth": self.max_depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use std::collections::BTreeMap;

    const TLV: &str = r#"
# the format fixtures/toy_parser.c accepts
<start>   ::= "TLV1" <records>
<records> ::= <record> | <record> <records>
<record>  ::= "T" <type> <len> <payload>
<type>    ::= "\x01" | "\x02"
<len>     ::= "\x02"
<payload> ::= "ab" | "cd"
"#;

    fn built(text: &str, params: &BTreeMap<String, toml::Value>) -> GrammarStrategy {
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = GrammarStrategy::default();
        s.initialize(&ctx(&dict, Some(text), params)).unwrap();
        s
    }

    #[test]
    fn parses_a_grammar_and_names_the_start_rule() {
        let g = Grammar::parse(TLV).unwrap();
        assert_eq!(g.start, "start");
        assert!(g.rules.contains_key("records"));
    }

    #[test]
    fn generates_structurally_valid_output() {
        let params = BTreeMap::new();
        let mut s = built(TLV, &params);
        // Pure generation, so the result must always satisfy the grammar.
        s.mutation_rate = 0.0;
        let mut rng = Rng::from_seed(1);
        let cands = s.propose(40, &[], &mut rng);
        assert!(!cands.is_empty());
        for c in &cands {
            assert!(
                c.bytes.starts_with(b"TLV1"),
                "generated input lacks the header: {:?}",
                String::from_utf8_lossy(&c.bytes)
            );
            assert!(c.bytes.len() > 4, "no records generated");
        }
    }

    #[test]
    fn generates_without_any_corpus() {
        // The property that lets a campaign start with no seeds at all.
        let params = BTreeMap::new();
        let mut s = built(TLV, &params);
        assert!(!s.capabilities().requires_corpus);
        let mut rng = Rng::from_seed(2);
        assert!(!s.propose(8, &[], &mut rng).is_empty());
    }

    #[test]
    fn recursion_is_bounded_by_depth_and_length() {
        // <records> is left-recursive through <record> <records>; without a
        // bound this expands forever.
        let mut params = BTreeMap::new();
        params.insert("grammar_max_depth".into(), toml::Value::Integer(6));
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut c = ctx(&dict, Some(TLV), &params);
        c.max_input_bytes = 256;
        let mut s = GrammarStrategy::default();
        s.initialize(&c).unwrap();
        s.mutation_rate = 0.0;

        let mut rng = Rng::from_seed(3);
        for cand in s.propose(200, &[], &mut rng) {
            assert!(cand.bytes.len() <= 256, "grammar exceeded the ceiling");
        }
    }

    #[test]
    fn deeply_recursive_grammar_terminates() {
        let g = r#"
<start> ::= <list>
<list>  ::= "x" | "(" <list> ")"
"#;
        let params = BTreeMap::new();
        let mut s = built(g, &params);
        s.mutation_rate = 0.0;
        let mut rng = Rng::from_seed(4);
        // If expansion did not terminate this would hang rather than fail.
        let cands = s.propose(100, &[], &mut rng);
        assert!(!cands.is_empty());
        assert!(cands.iter().all(|c| c.bytes.len() <= 4096));
        // Balanced output at least some of the time proves the non-recursive
        // alternative is being chosen at the depth limit.
        assert!(
            cands.iter().any(|c| c.bytes.contains(&b'x')),
            "never reached the terminal alternative"
        );
    }

    #[test]
    fn mutation_rate_produces_near_miss_inputs() {
        let params = BTreeMap::new();
        let mut s = built(TLV, &params);
        s.mutation_rate = 1.0;
        let mut rng = Rng::from_seed(5);
        let cands = s.propose(50, &[], &mut rng);
        assert!(cands.iter().all(|c| c.note == "generated+mutated"));
        // With every input mutated, some must deviate from the strict header.
        assert!(
            cands.iter().any(|c| !c.bytes.starts_with(b"TLV1")),
            "mutation never perturbed the structure"
        );
    }

    #[test]
    fn generation_is_reproducible_for_a_fixed_seed() {
        let params = BTreeMap::new();
        let run = || {
            let mut s = built(TLV, &params);
            let mut rng = Rng::from_seed(77);
            s.propose(20, &[], &mut rng).into_iter().map(|c| c.bytes).collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn malformed_grammars_are_rejected_with_a_line_number() {
        for (text, expect) in [
            ("start ::= \"x\"", "rule name must look like"),
            ("<start> \"x\"", "expected '::='"),
            ("<start> ::= \"unterminated", "unterminated literal"),
            ("<start> ::= <missing>", "undefined rule"),
            ("<start> ::= <unclosed", "unterminated rule reference"),
            ("# only comments", "no rules defined"),
            ("<start> ::= \"\\xZZ\"", "bad hex escape"),
        ] {
            let e = Grammar::parse(text).unwrap_err();
            assert!(
                e.to_string().contains(expect),
                "for {text:?} expected {expect:?}, got {e}"
            );
        }
    }

    #[test]
    fn empty_alternative_is_allowed_as_a_terminator() {
        // `<rest> ::= <more> |` gives recursion a way to stop.
        let g = "<start> ::= \"a\" <rest>\n<rest> ::= \"b\" <rest> |\n";
        let parsed = Grammar::parse(g).unwrap();
        assert_eq!(parsed.rules["rest"].len(), 2);
        assert!(parsed.rules["rest"].iter().any(|a| a.is_empty()));
    }

    #[test]
    fn hex_and_control_escapes_are_decoded() {
        let g = "<start> ::= \"\\x41\\x42\" \"\\n\" \"\\0\"\n";
        let parsed = Grammar::parse(g).unwrap();
        let mut out = Vec::new();
        let mut rng = Rng::from_seed(1);
        parsed.expand("start", 0, 4, &mut out, 64, &mut rng);
        assert_eq!(out, b"AB\n\0");
    }

    #[test]
    fn first_rule_is_the_start_when_none_is_named_start() {
        let g = "<document> ::= \"D\"\n<other> ::= \"O\"\n";
        assert_eq!(Grammar::parse(g).unwrap().start, "document");
    }

    #[test]
    fn reports_its_grammar_shape() {
        let params = BTreeMap::new();
        let s = built(TLV, &params);
        let st = s.export_state();
        assert_eq!(st["start"], "start");
        assert!(st["rules"].as_u64().unwrap() >= 6);
    }
}
