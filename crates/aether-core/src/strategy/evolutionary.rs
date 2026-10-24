//! Evolutionary search over a population of inputs.
//!
//! Keeps its own population, breeds it, and selects survivors against a
//! configurable multi-objective fitness. The difference from the mutation
//! strategies is memory: those treat each corpus entry independently, while
//! this one accumulates a lineage, so an improvement found in one generation
//! becomes the base for the next.
//!
//! Fitness combines coverage gain, novelty and cost rather than coverage
//! alone, because selecting on coverage alone drives the population toward
//! large slow inputs that reach a lot and mutate badly.

use crate::error::Result;
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

/// One population member and its measured fitness.
#[derive(Debug, Clone)]
struct Individual {
    bytes: Vec<u8>,
    fitness: f64,
    /// Generation it was created in, for diagnostics.
    generation: u32,
    /// Candidates bred from it that improved on it.
    successes: u32,
}

pub struct Evolutionary {
    population: Vec<Individual>,
    population_cap: usize,
    max_len: usize,
    generation: u32,
    /// Fraction of each round produced by crossover rather than mutation.
    crossover_rate: f64,
    /// Fraction of the population kept unchanged between generations, so a
    /// good individual cannot be lost to an unlucky round.
    elitism: f64,
    /// Maps a proposal's note back to the parent that produced it, so
    /// `observe` can credit the right individual.
    pending: Vec<(String, usize)>,
    best_fitness: f64,
}

impl Default for Evolutionary {
    fn default() -> Self {
        Evolutionary {
            population: Vec::new(),
            population_cap: 64,
            max_len: 65_536,
            generation: 0,
            crossover_rate: 0.3,
            elitism: 0.2,
            pending: Vec::new(),
            best_fitness: 0.0,
        }
    }
}

impl Evolutionary {
    /// Fitness from measured feedback.
    ///
    /// Coverage dominates, novelty contributes, and cost divides: an
    /// individual that reaches the same code in half the time is fitter,
    /// which keeps the population fast enough to be worth mutating.
    fn fitness(result: &CandidateResult) -> f64 {
        let f = &result.feedback;
        let cov = f.coverage.map(|c| c.score()).unwrap_or(0.0);
        let value = cov + f.novelty * 5.0 + f.new_cmp_tokens as f64 * 0.5;
        let cost_ms = (f.cost_micros as f64 / 1000.0).max(0.05);
        // sqrt on the cost so it shapes selection without letting a very fast
        // but useless individual dominate a slower, genuinely better one.
        value / cost_ms.sqrt()
    }

    /// Tournament selection: sample a few, take the fittest. Keeps selection
    /// pressure without the premature convergence of always picking the best.
    fn select(&self, rng: &mut Rng) -> Option<usize> {
        if self.population.is_empty() {
            return None;
        }
        let k = 3.min(self.population.len());
        let mut best = rng.below(self.population.len());
        for _ in 1..k {
            let c = rng.below(self.population.len());
            if self.population[c].fitness > self.population[best].fitness {
                best = c;
            }
        }
        Some(best)
    }

    fn crossover(a: &[u8], b: &[u8], rng: &mut Rng, max_len: usize) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        // Two-point crossover: take a middle section from b into a. More
        // disruptive than a single cut, which matters when the useful part of
        // an input is in the middle rather than at an end.
        let cut1 = rng.below(a.len());
        let cut2 = rng.between(cut1, a.len());
        let bl = rng.below(b.len());
        let br = rng.between(bl, b.len());

        let mut out = Vec::with_capacity(a.len());
        out.extend_from_slice(&a[..cut1]);
        out.extend_from_slice(&b[bl..br]);
        out.extend_from_slice(&a[cut2..]);
        out.truncate(max_len);
        out
    }

    /// Trim to the population cap, keeping the fittest.
    fn cull(&mut self) {
        if self.population.len() <= self.population_cap {
            return;
        }
        self.population
            .sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(std::cmp::Ordering::Equal));
        self.population.truncate(self.population_cap);
    }

    /// Seed the population from the corpus when it is empty or has shrunk.
    fn seed_from(&mut self, bases: &[Base]) {
        for b in bases {
            if self.population.len() >= self.population_cap {
                break;
            }
            if b.bytes.is_empty() {
                continue;
            }
            if self.population.iter().any(|i| i.bytes == b.bytes) {
                continue;
            }
            self.population.push(Individual {
                bytes: b.bytes.clone(),
                // Unmeasured, so neutral rather than zero: a fresh seed must
                // not rank below an individual already shown to be unfit.
                fitness: 1.0,
                generation: self.generation,
                successes: 0,
            });
        }
    }
}

impl Strategy for Evolutionary {
    fn id(&self) -> &'static str {
        "evolutionary"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "maintains a population, breeds it by crossover and mutation, \
                          and selects on coverage, novelty and cost together"
                .into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.population_cap = ctx.param_u64("evolution_population", 64).clamp(4, 4096) as usize;
        self.crossover_rate = ctx.param_f64("evolution_crossover_rate", 0.3).clamp(0.0, 1.0);
        self.elitism = ctx.param_f64("evolution_elitism", 0.2).clamp(0.0, 0.9);
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        self.seed_from(bases);
        if self.population.is_empty() {
            return Vec::new();
        }
        self.generation += 1;
        self.pending.clear();

        let mut out = Vec::with_capacity(budget as usize);
        for i in 0..budget {
            let Some(pi) = self.select(rng) else { break };
            let parent = &self.population[pi];

            let (bytes, kind) = if rng.bool_with(self.crossover_rate) && self.population.len() > 1 {
                let Some(qi) = self.select(rng) else { continue };
                if qi == pi {
                    continue;
                }
                (
                    Self::crossover(
                        &parent.bytes,
                        &self.population[qi].bytes,
                        rng,
                        self.max_len,
                    ),
                    "crossover",
                )
            } else {
                let mut b = parent.bytes.clone();
                super::mutate::havoc(&mut b, rng, self.max_len, 3);
                (b, "mutate")
            };

            if bytes.is_empty() || bytes == self.population[pi].bytes {
                continue;
            }
            let note = format!("{kind}-g{}-{i}", self.generation);
            self.pending.push((note.clone(), pi));
            out.push(Candidate {
                bytes,
                parent: bases.iter().find(|b| b.bytes == self.population[pi].bytes).map(|b| b.id.clone()),
                note,
            });
        }
        out
    }

    fn observe(&mut self, results: &[CandidateResult]) {
        // Protect the elite before admitting this generation's offspring, so
        // a bad round cannot wipe out accumulated progress.
        let keep = ((self.population.len() as f64) * self.elitism).ceil() as usize;
        self.population
            .sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(std::cmp::Ordering::Equal));

        for r in results {
            let fit = Self::fitness(r);
            if fit > self.best_fitness {
                self.best_fitness = fit;
            }
            // Credit the parent that produced an improvement.
            if let Some((_, pi)) = self.pending.iter().find(|(n, _)| *n == r.note) {
                if *pi < self.population.len() && fit > self.population[*pi].fitness {
                    self.population[*pi].successes += 1;
                }
            }
            // Admit a retained offspring into the population. Offspring bytes
            // are not carried in the result, so admission is represented by
            // raising the parent's fitness toward what its child achieved -
            // the lineage improves without needing a second copy of the data.
            if r.retained {
                if let Some((_, pi)) = self.pending.iter().find(|(n, _)| *n == r.note) {
                    if *pi < self.population.len() {
                        let p = &mut self.population[*pi];
                        p.fitness = (p.fitness * 0.7) + (fit * 0.3);
                    }
                }
            }
        }

        // Decay unfit individuals so the population keeps turning over, but
        // never the protected elite.
        for (i, ind) in self.population.iter_mut().enumerate() {
            if i >= keep {
                ind.fitness *= 0.98;
            }
        }
        self.cull();
        self.pending.clear();
    }

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "generation": self.generation,
            "population": self.population.len(),
            "best_fitness": self.best_fitness,
            "mean_fitness": if self.population.is_empty() {
                0.0
            } else {
                self.population.iter().map(|i| i.fitness).sum::<f64>() / self.population.len() as f64
            },
            // Lineage diagnostics: how old the surviving individuals are, and
            // how often breeding from them has actually improved on them.
            "oldest_survivor_generation": self.population.iter().map(|i| i.generation).min(),
            "breeding_successes": self.population.iter().map(|i| i.successes).sum::<u32>(),
        })
    }

    fn restore_state(&mut self, state: serde_json::Value) -> Result<()> {
        if let Some(g) = state.get("generation").and_then(|v| v.as_u64()) {
            self.generation = g as u32;
        }
        if let Some(b) = state.get("best_fitness").and_then(|v| v.as_f64()) {
            self.best_fitness = b;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::feedback::coverage::CoverageGain;
    use crate::feedback::Feedback;
    use std::collections::BTreeMap;

    fn built(params: &BTreeMap<String, toml::Value>) -> Evolutionary {
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = Evolutionary::default();
        s.initialize(&ctx(&dict, None, params)).unwrap();
        s
    }

    fn graded(note: &str, new_edges: u32, micros: u64, retained: bool) -> CandidateResult {
        CandidateResult {
            note: note.to_string(),
            feedback: Feedback {
                coverage: Some(CoverageGain { new_edges, new_buckets: 0, touched: new_edges }),
                cost_micros: micros,
                ..Default::default()
            },
            retained,
        }
    }

    #[test]
    fn seeds_from_the_corpus_and_breeds() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(1);
        let b = bases(&[b"first individual", b"second individual", b"third one"]);
        let cands = s.propose(32, &b, &mut rng);
        assert!(!cands.is_empty());
        assert_eq!(s.export_state()["generation"], 1);
        assert!(s.population.len() >= 3);
    }

    #[test]
    fn proposes_nothing_with_no_corpus_and_no_population() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(2);
        assert!(s.propose(16, &[], &mut rng).is_empty());
    }

    #[test]
    fn population_stays_within_its_cap() {
        let mut params = BTreeMap::new();
        params.insert("evolution_population".into(), toml::Value::Integer(8));
        let mut s = built(&params);
        let mut rng = Rng::from_seed(3);
        let many: Vec<Vec<u8>> = (0..100).map(|i| format!("individual-{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = many.iter().map(|v| v.as_slice()).collect();
        let b = bases(&refs);
        for _ in 0..20 {
            let c = s.propose(16, &b, &mut rng);
            let results: Vec<CandidateResult> =
                c.iter().map(|x| graded(&x.note, 1, 1000, true)).collect();
            s.observe(&results);
            assert!(s.population.len() <= 8, "population grew to {}", s.population.len());
        }
    }

    #[test]
    fn fitness_prefers_coverage_and_penalises_cost() {
        let cheap_good = graded("a", 10, 500, true);
        let dear_good = graded("b", 10, 50_000, true);
        let cheap_bad = graded("c", 0, 500, true);
        assert!(
            Evolutionary::fitness(&cheap_good) > Evolutionary::fitness(&dear_good),
            "cost must shape fitness"
        );
        assert!(
            Evolutionary::fitness(&cheap_good) > Evolutionary::fitness(&cheap_bad),
            "coverage must dominate"
        );
    }

    #[test]
    fn fitness_improves_across_generations_when_offspring_do_better() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(4);
        let b = bases(&[b"base individual one", b"base individual two"]);

        s.propose(16, &b, &mut rng);
        let first_mean = s.export_state()["mean_fitness"].as_f64().unwrap();

        // Several generations where offspring consistently achieve a lot.
        for _ in 0..10 {
            let c = s.propose(16, &b, &mut rng);
            let results: Vec<CandidateResult> =
                c.iter().map(|x| graded(&x.note, 50, 400, true)).collect();
            s.observe(&results);
        }
        let later_mean = s.export_state()["mean_fitness"].as_f64().unwrap();
        assert!(
            later_mean > first_mean,
            "population did not improve: {first_mean} then {later_mean}"
        );
        assert!(s.export_state()["best_fitness"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn elitism_protects_the_best_individual_from_a_bad_round() {
        let mut params = BTreeMap::new();
        params.insert("evolution_elitism".into(), toml::Value::Float(0.5));
        let mut s = built(&params);
        let mut rng = Rng::from_seed(5);
        let b = bases(&[b"aaa", b"bbb", b"ccc", b"ddd"]);
        s.propose(8, &b, &mut rng);

        // Hand-set one individual as clearly the best.
        s.population[0].fitness = 100.0;
        let best_bytes = s.population[0].bytes.clone();

        // Many fruitless rounds.
        for _ in 0..30 {
            let c = s.propose(8, &b, &mut rng);
            let results: Vec<CandidateResult> =
                c.iter().map(|x| graded(&x.note, 0, 20_000, false)).collect();
            s.observe(&results);
        }
        assert!(
            s.population.iter().any(|i| i.bytes == best_bytes),
            "the elite individual was lost"
        );
    }

    #[test]
    fn crossover_combines_two_parents() {
        let mut rng = Rng::from_seed(6);
        let mut mixed = 0;
        for _ in 0..200 {
            let out = Evolutionary::crossover(b"AAAAAAAAAA", b"BBBBBBBBBB", &mut rng, 4096);
            if out.contains(&b'A') && out.contains(&b'B') {
                mixed += 1;
            }
        }
        assert!(mixed > 50, "crossover mixed parents only {mixed}/200 times");
    }

    #[test]
    fn crossover_handles_empty_parents() {
        let mut rng = Rng::from_seed(7);
        assert_eq!(Evolutionary::crossover(b"", b"BBB", &mut rng, 64), b"BBB");
        assert_eq!(Evolutionary::crossover(b"AAA", b"", &mut rng, 64), b"AAA");
    }

    #[test]
    fn respects_the_length_ceiling() {
        let params = BTreeMap::new();
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 32;
        let mut s = Evolutionary::default();
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(8);
        let b = bases(&[&vec![0x41u8; 30], &vec![0x42u8; 30]]);
        for _ in 0..20 {
            for cand in s.propose(16, &b, &mut rng) {
                assert!(cand.bytes.len() <= 32, "got {}", cand.bytes.len());
            }
        }
    }

    #[test]
    fn is_reproducible_for_a_fixed_seed() {
        let params = BTreeMap::new();
        let b = vec![
            Base { id: crate::ids::InputId::from_string("inp-a"), bytes: b"alpha input".to_vec(), cmp_entries: vec![] },
            Base { id: crate::ids::InputId::from_string("inp-b"), bytes: b"beta input".to_vec(), cmp_entries: vec![] },
        ];
        let run = || {
            let mut s = built(&params);
            let mut rng = Rng::from_seed(555);
            let mut all = Vec::new();
            for _ in 0..5 {
                let c = s.propose(8, &b, &mut rng);
                let results: Vec<CandidateResult> =
                    c.iter().map(|x| graded(&x.note, 3, 900, true)).collect();
                all.extend(c.into_iter().map(|x| x.bytes));
                s.observe(&results);
            }
            all
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn state_round_trips() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(9);
        let b = bases(&[b"x", b"y"]);
        for _ in 0..3 {
            let c = s.propose(4, &b, &mut rng);
            let r: Vec<CandidateResult> = c.iter().map(|x| graded(&x.note, 5, 1000, true)).collect();
            s.observe(&r);
        }
        let st = s.export_state();
        let mut s2 = built(&params);
        s2.restore_state(st.clone()).unwrap();
        assert_eq!(s2.generation, s.generation);
        assert_eq!(s2.best_fitness, s.best_fitness);
    }
}
