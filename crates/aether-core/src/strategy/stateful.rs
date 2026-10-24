//! Stateful sequence generation.
//!
//! Some defects are not reachable by any single input: they need a particular
//! *order* of operations. `fixtures/stateful_service.c` plants exactly that
//! case - its use-after-free needs `AUTH`, `OPEN`, `CLOSE`, `COMMIT` in that
//! order, and no amount of mutating one command reaches it.
//!
//! A test case here is a sequence of commands, serialised newline-delimited.
//! The strategy learns which transitions the target accepts from the status
//! codes it answers with, and biases generation toward sequences that get
//! further into the protocol rather than being rejected at the first step.

use std::collections::HashMap;

use crate::error::Result;
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

/// One command template. `{arg}` is replaced with a generated argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTemplate {
    pub name: String,
    pub template: String,
    pub takes_arg: bool,
}

impl CommandTemplate {
    fn render(&self, rng: &mut Rng, args: &[Vec<u8>]) -> Vec<u8> {
        if !self.takes_arg {
            return self.template.as_bytes().to_vec();
        }
        let arg = if args.is_empty() {
            random_token(rng)
        } else {
            args[rng.below(args.len())].clone()
        };
        let mut out = Vec::with_capacity(self.template.len() + arg.len());
        let bytes = self.template.as_bytes();
        match self.template.find("{arg}") {
            Some(pos) => {
                out.extend_from_slice(&bytes[..pos]);
                out.extend_from_slice(&arg);
                out.extend_from_slice(&bytes[pos + 5..]);
            }
            None => {
                out.extend_from_slice(bytes);
                out.push(b' ');
                out.extend_from_slice(&arg);
            }
        }
        out
    }
}

fn random_token(rng: &mut Rng) -> Vec<u8> {
    let n = rng.between(1, 12);
    (0..n).map(|_| b'a' + (rng.below(26) as u8)).collect()
}

/// Default command set, derived from the stateful fixture's protocol. Real
/// use supplies its own through `strategies.params`.
fn default_commands() -> Vec<CommandTemplate> {
    vec![
        CommandTemplate { name: "AUTH".into(), template: "AUTH {arg}".into(), takes_arg: true },
        CommandTemplate { name: "OPEN".into(), template: "OPEN {arg}".into(), takes_arg: true },
        CommandTemplate { name: "WRITE".into(), template: "WRITE {arg}".into(), takes_arg: true },
        CommandTemplate { name: "CLOSE".into(), template: "CLOSE".into(), takes_arg: false },
        CommandTemplate { name: "COMMIT".into(), template: "COMMIT".into(), takes_arg: false },
        CommandTemplate { name: "QUIT".into(), template: "QUIT".into(), takes_arg: false },
    ]
}

pub struct StatefulSequence {
    commands: Vec<CommandTemplate>,
    /// Argument values worth reusing; seeded from the dictionary, since a
    /// protocol token such as a valid password is exactly the sort of thing a
    /// dictionary carries.
    args: Vec<Vec<u8>>,
    max_len: usize,
    min_steps: usize,
    max_steps: usize,
    /// Observed (from, to) command-index pairs that were followed by an
    /// accepted response, used to bias generation toward viable orders.
    accepted_pairs: HashMap<(usize, usize), u32>,
    /// Longest accepted prefix seen, as a progress measure.
    deepest_accepted: usize,
}

impl Default for StatefulSequence {
    fn default() -> Self {
        StatefulSequence {
            commands: default_commands(),
            args: Vec::new(),
            max_len: 65_536,
            min_steps: 2,
            max_steps: 8,
            accepted_pairs: HashMap::new(),
            deepest_accepted: 0,
        }
    }
}

impl StatefulSequence {
    /// Serialise a sequence of command indices into an input.
    fn render(&self, steps: &[usize], rng: &mut Rng) -> Vec<u8> {
        let mut out = Vec::new();
        for &i in steps {
            if i >= self.commands.len() {
                continue;
            }
            let line = self.commands[i].render(rng, &self.args);
            if out.len() + line.len() + 1 > self.max_len {
                break;
            }
            out.extend_from_slice(&line);
            out.push(b'\n');
        }
        out
    }

    /// Pick the next command, biased toward transitions already seen to be
    /// accepted after `prev`. Keeps a floor of randomness so an unexplored
    /// transition remains reachable.
    fn next_step(&self, prev: Option<usize>, rng: &mut Rng) -> usize {
        let n = self.commands.len();
        if n == 0 {
            return 0;
        }
        let Some(prev) = prev else { return rng.below(n) };
        let weights: Vec<f64> = (0..n)
            .map(|to| {
                let seen = self.accepted_pairs.get(&(prev, to)).copied().unwrap_or(0) as f64;
                // The constant is the exploration floor: without it the
                // strategy would only ever repeat orders it already knows,
                // and could never discover a new one.
                0.5 + seen.min(20.0)
            })
            .collect();
        rng.weighted_index(&weights).unwrap_or_else(|| rng.below(n))
    }

    /// Record which transitions the target accepted, read from status codes.
    ///
    /// A 2xx or 3xx reply is taken as acceptance, matching the convention the
    /// fixture and most line protocols follow. This is a proxy for the
    /// target's state machine, not a reading of it.
    fn learn_from_codes(&mut self, steps: &[usize], codes: &[u32]) {
        let mut depth = 0;
        for (i, code) in codes.iter().enumerate() {
            let accepted = (200..400).contains(code);
            if accepted {
                depth = i + 1;
                if i > 0 && i < steps.len() {
                    *self.accepted_pairs.entry((steps[i - 1], steps[i])).or_insert(0) += 1;
                }
            }
        }
        self.deepest_accepted = self.deepest_accepted.max(depth);
    }

    /// Parse leading three-digit status codes from a response.
    pub fn parse_codes(output: &[u8]) -> Vec<u32> {
        String::from_utf8_lossy(output)
            .lines()
            .filter_map(|l| {
                let d: String = l.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
                if d.len() == 3 {
                    d.parse().ok()
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Strategy for StatefulSequence {
    fn id(&self) -> &'static str {
        "stateful-sequence"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            // Generates sequences from its command set, so it can start with
            // no corpus at all.
            requires_corpus: false,
            produces_sequences: true,
            description: "generates ordered command sequences and learns which \
                          transitions the target accepts"
                .into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.min_steps = ctx.param_u64("sequence_min_steps", 2).clamp(1, 64) as usize;
        self.max_steps = ctx
            .param_u64("sequence_max_steps", 8)
            .clamp(self.min_steps as u64, 256) as usize;

        // Commands may be supplied as a TOML array of strings.
        if let Some(toml::Value::Array(items)) = ctx.params.get("sequence_commands") {
            let mut cmds = Vec::new();
            for item in items {
                if let Some(s) = item.as_str() {
                    let name =
                        s.split_whitespace().next().unwrap_or(s).trim_end_matches(':').to_string();
                    cmds.push(CommandTemplate {
                        name,
                        template: s.to_string(),
                        takes_arg: s.contains("{arg}"),
                    });
                }
            }
            if !cmds.is_empty() {
                self.commands = cmds;
            }
        }
        // Dictionary tokens make good protocol arguments.
        self.args = ctx.dictionary.to_vec();
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        let mut out = Vec::with_capacity(budget as usize);
        for i in 0..budget {
            // Occasionally extend an existing sequence rather than generating
            // a fresh one: a long accepted prefix is expensive to rediscover.
            if !bases.is_empty() && i % 4 == 3 {
                let base = &bases[rng.below(bases.len())];
                if !base.bytes.is_empty() && base.bytes.len() < self.max_len {
                    let mut buf = base.bytes.clone();
                    if !buf.ends_with(b"\n") {
                        buf.push(b'\n');
                    }
                    let step = self.next_step(None, rng);
                    let line = self.commands[step].render(rng, &self.args);
                    if buf.len() + line.len() + 1 <= self.max_len {
                        buf.extend_from_slice(&line);
                        buf.push(b'\n');
                        out.push(Candidate::from_base(buf, base, "extend-sequence"));
                        continue;
                    }
                }
            }

            let steps_n = rng.between(self.min_steps, self.max_steps);
            let mut steps = Vec::with_capacity(steps_n);
            let mut prev = None;
            for _ in 0..steps_n {
                let s = self.next_step(prev, rng);
                steps.push(s);
                prev = Some(s);
            }
            let bytes = self.render(&steps, rng);
            if bytes.is_empty() {
                continue;
            }
            // The step indices travel in the note so `observe` can learn which
            // transitions the response codes correspond to.
            let note = format!(
                "sequence:{}",
                steps.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
            );
            out.push(Candidate { bytes, parent: None, note });
        }
        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        for r in results {
            let Some(spec) = r.note.strip_prefix("sequence:") else { continue };
            let steps: Vec<usize> =
                spec.split(',').filter_map(|s| s.parse().ok()).collect();
            if steps.is_empty() {
                continue;
            }
            // Prefer the target's own status codes: they say which specific
            // steps were accepted, where a retained flag only says the whole
            // sequence was interesting.
            if !r.feedback.response_codes.is_empty() {
                self.learn_from_codes(&steps, &r.feedback.response_codes);
                continue;
            }
            // No status codes available (a target that does not answer that
            // way): fall back to crediting the sequence as a whole.
            let transitions =
                r.feedback.components.get("state-transition").copied().unwrap_or(0.0);
            if transitions > 0.0 || r.retained {
                for pair in steps.windows(2) {
                    *self.accepted_pairs.entry((pair[0], pair[1])).or_insert(0) += 1;
                }
                self.deepest_accepted = self.deepest_accepted.max(steps.len());
            }
        }
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "commands": self.commands.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
            "accepted_transitions": self.accepted_pairs.len(),
            "deepest_accepted": self.deepest_accepted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use std::collections::BTreeMap;

    fn built(params: &BTreeMap<String, toml::Value>, dict: &[Vec<u8>]) -> StatefulSequence {
        let mut s = StatefulSequence::default();
        s.initialize(&ctx(dict, None, params)).unwrap();
        s
    }

    #[test]
    fn generates_newline_delimited_command_sequences() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        let mut rng = Rng::from_seed(1);
        let cands = s.propose(32, &[], &mut rng);
        assert!(!cands.is_empty(), "should generate without any corpus");
        for c in &cands {
            let text = String::from_utf8_lossy(&c.bytes);
            assert!(text.ends_with('\n'), "sequence not newline terminated: {text:?}");
            let lines: Vec<&str> = text.lines().collect();
            assert!(lines.len() >= 2, "expected at least min_steps lines: {text:?}");
            for l in lines {
                let cmd = l.split_whitespace().next().unwrap_or("");
                assert!(
                    s.commands.iter().any(|c| c.name == cmd),
                    "generated an unknown command {cmd:?}"
                );
            }
        }
    }

    #[test]
    fn declares_that_it_produces_sequences() {
        let caps = StatefulSequence::default().capabilities();
        assert!(caps.produces_sequences);
        assert!(!caps.requires_corpus);
    }

    #[test]
    fn can_reach_the_order_the_fixture_requires() {
        // fixtures/stateful_service.c needs AUTH, OPEN, CLOSE, COMMIT in that
        // order. Generation must be able to produce it; if it cannot, the
        // strategy could never find the planted defect.
        let params = BTreeMap::new();
        let dict = vec![b"letmein".to_vec()];
        let mut s = built(&params, &dict);
        let mut rng = Rng::from_seed(2);

        let mut found = false;
        for _ in 0..200 {
            for c in s.propose(64, &[], &mut rng) {
                let text = String::from_utf8_lossy(&c.bytes);
                let cmds: Vec<&str> = text
                    .lines()
                    .map(|l| l.split_whitespace().next().unwrap_or(""))
                    .collect();
                // Look for the required order as a subsequence.
                let want = ["AUTH", "OPEN", "CLOSE", "COMMIT"];
                let mut wi = 0;
                for cmd in &cmds {
                    if wi < want.len() && *cmd == want[wi] {
                        wi += 1;
                    }
                }
                if wi == want.len() {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(found, "never generated the AUTH/OPEN/CLOSE/COMMIT order");
    }

    #[test]
    fn dictionary_tokens_are_used_as_arguments() {
        let params = BTreeMap::new();
        let dict = vec![b"letmein".to_vec()];
        let mut s = built(&params, &dict);
        let mut rng = Rng::from_seed(3);
        let cands = s.propose(100, &[], &mut rng);
        assert!(
            cands.iter().any(|c| c.bytes.windows(7).any(|w| w == b"letmein")),
            "the dictionary token was never used as an argument"
        );
    }

    #[test]
    fn learns_accepted_transitions_from_status_codes() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        assert_eq!(s.accepted_pairs.len(), 0);

        // 230 and 250 are acceptances; 550 is a rejection.
        s.learn_from_codes(&[0, 1, 2], &[230, 250, 550]);
        assert!(
            s.accepted_pairs.contains_key(&(0, 1)),
            "accepted transition was not recorded: {:?}",
            s.accepted_pairs
        );
        assert_eq!(s.deepest_accepted, 2);
    }

    #[test]
    fn rejections_alone_teach_nothing() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        s.learn_from_codes(&[0, 1, 2], &[550, 550, 500]);
        assert!(s.accepted_pairs.is_empty());
        assert_eq!(s.deepest_accepted, 0);
    }

    #[test]
    fn parses_status_codes() {
        assert_eq!(
            StatefulSequence::parse_codes(b"230 ok\n550 bad state\nnot a code\n"),
            vec![230, 550]
        );
        assert!(StatefulSequence::parse_codes(b"no codes at all").is_empty());
    }

    #[test]
    fn learned_transitions_bias_generation_without_eliminating_exploration() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        // Teach it strongly that 0 -> 1 works.
        for _ in 0..100 {
            *s.accepted_pairs.entry((0, 1)).or_insert(0) += 1;
        }
        let mut rng = Rng::from_seed(4);
        let mut after_zero = std::collections::HashMap::new();
        for _ in 0..2000 {
            *after_zero.entry(s.next_step(Some(0), &mut rng)).or_insert(0) += 1;
        }
        let one = *after_zero.get(&1).unwrap_or(&0);
        assert!(one > 600, "learned transition chosen only {one}/2000 times");
        assert!(
            after_zero.len() >= 5,
            "exploration collapsed: only {} distinct next steps",
            after_zero.len()
        );
    }

    #[test]
    fn custom_command_set_is_honoured() {
        let mut params = BTreeMap::new();
        params.insert(
            "sequence_commands".into(),
            toml::Value::Array(vec![
                toml::Value::String("LOGIN {arg}".into()),
                toml::Value::String("LOGOUT".into()),
            ]),
        );
        let dict: Vec<Vec<u8>> = Vec::new();
        let s = built(&params, &dict);
        assert_eq!(s.commands.len(), 2);
        assert_eq!(s.commands[0].name, "LOGIN");
        assert!(s.commands[0].takes_arg);
        assert!(!s.commands[1].takes_arg);
    }

    #[test]
    fn respects_the_length_ceiling() {
        let mut params = BTreeMap::new();
        params.insert("sequence_max_steps".into(), toml::Value::Integer(200));
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = StatefulSequence::default();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 48;
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(5);
        for cand in s.propose(64, &[], &mut rng) {
            assert!(cand.bytes.len() <= 48, "got {} bytes", cand.bytes.len());
        }
    }

    #[test]
    fn extends_an_existing_sequence() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        let mut rng = Rng::from_seed(6);
        let b = bases(&[b"AUTH letmein\nOPEN f\n"]);
        let cands = s.propose(32, &b, &mut rng);
        let extended: Vec<&Candidate> =
            cands.iter().filter(|c| c.note == "extend-sequence").collect();
        assert!(!extended.is_empty(), "never extended the base sequence");
        for c in extended {
            assert!(
                c.bytes.starts_with(b"AUTH letmein\nOPEN f\n"),
                "extension lost the accepted prefix"
            );
            assert!(c.parent.is_some());
        }
    }

    #[test]
    fn observe_prefers_real_status_codes_over_the_retained_flag() {
        // The target answered 230 (accepted), 250 (accepted), 550 (rejected),
        // so only the first transition should be learned - even though the
        // result was retained, which the fallback would have credited wholly.
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        let mut fb = crate::feedback::Feedback::default();
        fb.response_codes = vec![230, 250, 550];
        s.observe(&[CandidateResult {
            note: "sequence:0,1,2".into(),
            feedback: fb,
            retained: true,
        }]);
        assert!(s.accepted_pairs.contains_key(&(0, 1)), "{:?}", s.accepted_pairs);
        assert!(
            !s.accepted_pairs.contains_key(&(1, 2)),
            "credited a transition the target rejected: {:?}",
            s.accepted_pairs
        );
    }

    #[test]
    fn observe_credits_transitions_from_feedback() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = built(&params, &dict);
        let mut fb = crate::feedback::Feedback::default();
        fb.components.insert("state-transition".into(), 1.0);
        s.observe(&[CandidateResult {
            note: "sequence:0,1,2".into(),
            feedback: fb,
            retained: false,
        }]);
        assert!(s.accepted_pairs.contains_key(&(0, 1)));
        assert!(s.accepted_pairs.contains_key(&(1, 2)));
        assert_eq!(s.deepest_accepted, 3);
    }

    #[test]
    fn is_reproducible_for_a_fixed_seed() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let run = || {
            let mut s = built(&params, &dict);
            let mut rng = Rng::from_seed(888);
            s.propose(20, &[], &mut rng).into_iter().map(|c| c.bytes).collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
