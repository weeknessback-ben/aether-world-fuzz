//! Multi-objective corpus ranking.
//!
//! An input's worth as an exploration seed is not one number the engine can
//! read off; it is a trade-off between how much coverage it contributed, how
//! unusual its behaviour was, how cheap it is to run, and how much it
//! duplicates what the corpus already holds.
//!
//! Two properties this module is built around:
//!
//! * **Every component is normalised to `[0, 1]` before weighting.** Raw
//!   values live on wildly different scales - edge counts in the hundreds,
//!   durations in microseconds, sizes in kilobytes - and combining them
//!   unnormalised would let whichever happens to be largest dominate
//!   regardless of the configured weights.
//! * **Exploration rank is not finding confidence.** A high score means
//!   "promising to mutate", never "likely to contain a defect". An input that
//!   reproduces a finding is marked as such and protected from eviction
//!   separately, by [`InputRecord::finding_id`].

use serde::{Deserialize, Serialize};

use crate::config::CorpusWeights;

/// The measurements a score is computed from, as raw values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreInputs {
    /// Edges this input reached for the first time when it was added.
    pub new_edges: u32,
    /// Slots it touches at all, a proxy for how much of the target it drives.
    pub touched_edges: u32,
    /// Semantic novelty recorded when it was added, already in `[0, 1]`.
    pub novelty: f64,
    /// Mean execution time in microseconds.
    pub exec_micros: u64,
    /// Length in bytes.
    pub size_bytes: usize,
    /// Descendants of this input that themselves found something new. The
    /// direct measure of whether mutating it has paid off.
    pub productive_children: u32,
    /// Descendants tried in total, productive or not.
    pub total_children: u32,
    /// How many other corpus entries share its behaviour signature.
    pub signature_siblings: u32,
    /// New response-class transitions it produced.
    pub state_transitions: u32,
}

impl Default for ScoreInputs {
    fn default() -> Self {
        ScoreInputs {
            new_edges: 0,
            touched_edges: 0,
            novelty: 0.0,
            exec_micros: 1000,
            size_bytes: 0,
            productive_children: 0,
            total_children: 0,
            signature_siblings: 0,
            state_transitions: 0,
        }
    }
}

/// Corpus-wide maxima, needed to normalise each component.
///
/// Maintained incrementally by the corpus rather than recomputed per scoring
/// pass: at corpus sizes of tens of thousands, rescanning to find a maximum on
/// every insert would dominate the cost of inserting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreNorms {
    pub max_new_edges: u32,
    pub max_touched_edges: u32,
    pub max_exec_micros: u64,
    pub max_size_bytes: usize,
    pub max_state_transitions: u32,
    pub corpus_size: u32,
}

impl ScoreNorms {
    /// Fold one input's measurements in.
    ///
    /// Returns true when a maximum moved. That matters because every score is
    /// relative to these maxima: an input scored against an older, smaller
    /// maximum is not comparable to one scored against the new value, so the
    /// corpus rescores its existing entries when this returns true. Without
    /// that, the first input added would hold a coverage component of 1.0
    /// forever and outrank genuinely better inputs added later.
    pub fn observe(&mut self, s: &ScoreInputs) -> bool {
        let mut moved = false;
        if s.new_edges > self.max_new_edges {
            self.max_new_edges = s.new_edges;
            moved = true;
        }
        if s.touched_edges > self.max_touched_edges {
            self.max_touched_edges = s.touched_edges;
            moved = true;
        }
        if s.exec_micros > self.max_exec_micros {
            self.max_exec_micros = s.exec_micros;
            moved = true;
        }
        if s.size_bytes > self.max_size_bytes {
            self.max_size_bytes = s.size_bytes;
            moved = true;
        }
        if s.state_transitions > self.max_state_transitions {
            self.max_state_transitions = s.state_transitions;
            moved = true;
        }
        self.corpus_size = self.corpus_size.saturating_add(1);
        moved
    }
}

/// A score with its components kept, so a report can explain a ranking rather
/// than just assert one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub total: f64,
    pub coverage: f64,
    pub novelty: f64,
    pub diversity: f64,
    pub mutation_productivity: f64,
    /// Already inverted: cheap inputs score high.
    pub cost: f64,
    /// Already inverted: non-redundant inputs score high.
    pub redundancy: f64,
    pub state_transitions: f64,
}

/// Normalise `v` against `max`, returning 0 when no maximum is known yet.
fn ratio(v: f64, max: f64) -> f64 {
    if max <= 0.0 {
        0.0
    } else {
        (v / max).clamp(0.0, 1.0)
    }
}

/// Compute an input's exploration score.
pub fn score(inputs: &ScoreInputs, norms: &ScoreNorms, weights: &CorpusWeights) -> Score {
    let coverage = ratio(inputs.new_edges as f64, norms.max_new_edges as f64);
    let novelty = inputs.novelty.clamp(0.0, 1.0);

    // Diversity: reaching a broad slice of the target is more useful as a
    // mutation base than reaching a narrow one.
    let diversity = ratio(inputs.touched_edges as f64, norms.max_touched_edges as f64);

    // Mutation productivity: the share of this input's descendants that found
    // something. Untried inputs get a neutral 0.5 rather than 0, so a new
    // entry is not ranked below one already shown to be unproductive.
    let mutation_productivity = if inputs.total_children == 0 {
        0.5
    } else {
        (inputs.productive_children as f64 / inputs.total_children as f64).clamp(0.0, 1.0)
    };

    // Cost, inverted: a fast, small input yields more executions per second of
    // budget. Time dominates, size is a secondary tiebreak.
    let time_cost = ratio(inputs.exec_micros as f64, norms.max_exec_micros as f64);
    let size_cost = ratio(inputs.size_bytes as f64, norms.max_size_bytes as f64);
    let cost = 1.0 - (time_cost * 0.75 + size_cost * 0.25);

    // Redundancy, inverted: an input whose behaviour many others share adds
    // little. Decays hyperbolically, so the first few siblings matter most.
    let redundancy = 1.0 / (1.0 + inputs.signature_siblings as f64);

    let state_transitions =
        ratio(inputs.state_transitions as f64, norms.max_state_transitions as f64);

    let terms = [
        (weights.coverage, coverage),
        (weights.novelty, novelty),
        (weights.diversity, diversity),
        (weights.mutation_productivity, mutation_productivity),
        (weights.execution_cost, cost),
        (weights.redundancy, redundancy),
        (weights.state_transitions, state_transitions),
    ];
    let weight_sum: f64 = terms.iter().map(|(w, _)| *w).sum();
    // Normalising by the weight sum keeps the total in [0, 1] whatever
    // weights are configured, so scores stay comparable across campaigns
    // with different weightings.
    let total = if weight_sum > 0.0 {
        terms.iter().map(|(w, v)| w * v).sum::<f64>() / weight_sum
    } else {
        0.0
    };

    Score {
        total,
        coverage,
        novelty,
        diversity,
        mutation_productivity,
        cost,
        redundancy,
        state_transitions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norms() -> ScoreNorms {
        ScoreNorms {
            max_new_edges: 100,
            max_touched_edges: 500,
            max_exec_micros: 10_000,
            max_size_bytes: 4096,
            max_state_transitions: 20,
            corpus_size: 50,
        }
    }

    #[test]
    fn score_stays_in_unit_interval_for_any_weighting() {
        let n = norms();
        let extremes = [
            ScoreInputs::default(),
            ScoreInputs {
                new_edges: 100,
                touched_edges: 500,
                novelty: 1.0,
                exec_micros: 0,
                size_bytes: 0,
                productive_children: 10,
                total_children: 10,
                signature_siblings: 0,
                state_transitions: 20,
            },
            ScoreInputs {
                new_edges: u32::MAX,
                touched_edges: u32::MAX,
                novelty: 99.0,
                exec_micros: u64::MAX,
                size_bytes: usize::MAX,
                productive_children: 5,
                total_children: 1,
                signature_siblings: u32::MAX,
                state_transitions: u32::MAX,
            },
        ];
        let weightings = [
            CorpusWeights::default(),
            CorpusWeights {
                coverage: 0.0,
                novelty: 0.0,
                diversity: 0.0,
                mutation_productivity: 0.0,
                execution_cost: 1.0,
                redundancy: 0.0,
                state_transitions: 0.0,
            },
            CorpusWeights {
                coverage: 1000.0,
                novelty: 1000.0,
                diversity: 1000.0,
                mutation_productivity: 1000.0,
                execution_cost: 1000.0,
                redundancy: 1000.0,
                state_transitions: 1000.0,
            },
        ];
        for s in &extremes {
            for w in &weightings {
                let r = score(s, &n, w);
                assert!(
                    (0.0..=1.0).contains(&r.total) && r.total.is_finite(),
                    "total {} out of range for {s:?}",
                    r.total
                );
            }
        }
    }

    #[test]
    fn more_coverage_scores_higher() {
        let n = norms();
        let w = CorpusWeights::default();
        let low = score(&ScoreInputs { new_edges: 1, ..Default::default() }, &n, &w);
        let high = score(&ScoreInputs { new_edges: 80, ..Default::default() }, &n, &w);
        assert!(high.total > low.total, "{} vs {}", high.total, low.total);
        assert!(high.coverage > low.coverage);
    }

    #[test]
    fn cheaper_inputs_score_higher_all_else_equal() {
        let n = norms();
        let w = CorpusWeights::default();
        let fast = score(
            &ScoreInputs { new_edges: 10, exec_micros: 100, ..Default::default() },
            &n,
            &w,
        );
        let slow = score(
            &ScoreInputs { new_edges: 10, exec_micros: 10_000, ..Default::default() },
            &n,
            &w,
        );
        assert!(fast.total > slow.total);
        assert!(fast.cost > slow.cost, "cost must be inverted: cheap is good");
    }

    #[test]
    fn redundant_inputs_score_lower() {
        let n = norms();
        let w = CorpusWeights::default();
        let unique = score(
            &ScoreInputs { new_edges: 10, signature_siblings: 0, ..Default::default() },
            &n,
            &w,
        );
        let common = score(
            &ScoreInputs { new_edges: 10, signature_siblings: 30, ..Default::default() },
            &n,
            &w,
        );
        assert!(unique.total > common.total);
        assert!(unique.redundancy > common.redundancy);
    }

    #[test]
    fn untried_inputs_are_not_penalised_against_unproductive_ones() {
        // A brand-new entry has no track record. Scoring it 0 would rank it
        // below an input already shown to be a dead end, which would stop the
        // corpus ever trying it.
        let n = norms();
        let w = CorpusWeights::default();
        let untried = score(&ScoreInputs { total_children: 0, ..Default::default() }, &n, &w);
        let barren = score(
            &ScoreInputs { total_children: 40, productive_children: 0, ..Default::default() },
            &n,
            &w,
        );
        assert!(untried.mutation_productivity > barren.mutation_productivity);
        assert_eq!(untried.mutation_productivity, 0.5);
    }

    #[test]
    fn productive_inputs_outrank_barren_ones() {
        let n = norms();
        let w = CorpusWeights::default();
        let good = score(
            &ScoreInputs { total_children: 10, productive_children: 8, ..Default::default() },
            &n,
            &w,
        );
        let bad = score(
            &ScoreInputs { total_children: 10, productive_children: 0, ..Default::default() },
            &n,
            &w,
        );
        assert!(good.total > bad.total);
    }

    #[test]
    fn weights_actually_select_the_objective() {
        let n = norms();
        // Weighted on cost alone, a cheap input with no coverage must beat an
        // expensive one with lots of it.
        let cost_only = CorpusWeights {
            coverage: 0.0,
            novelty: 0.0,
            diversity: 0.0,
            mutation_productivity: 0.0,
            execution_cost: 1.0,
            redundancy: 0.0,
            state_transitions: 0.0,
        };
        let cheap_useless =
            ScoreInputs { new_edges: 0, exec_micros: 10, ..Default::default() };
        let dear_useful =
            ScoreInputs { new_edges: 100, exec_micros: 10_000, ..Default::default() };
        assert!(
            score(&cheap_useless, &n, &cost_only).total
                > score(&dear_useful, &n, &cost_only).total
        );
        // And with coverage weighted alone, the ordering inverts.
        let cov_only = CorpusWeights {
            coverage: 1.0,
            novelty: 0.0,
            diversity: 0.0,
            mutation_productivity: 0.0,
            execution_cost: 0.0,
            redundancy: 0.0,
            state_transitions: 0.0,
        };
        assert!(
            score(&dear_useful, &n, &cov_only).total
                > score(&cheap_useless, &n, &cov_only).total
        );
    }

    #[test]
    fn empty_norms_do_not_produce_nan() {
        // At the very start of a campaign nothing has been measured yet.
        let n = ScoreNorms::default();
        let r = score(&ScoreInputs { new_edges: 5, ..Default::default() }, &n, &CorpusWeights::default());
        assert!(r.total.is_finite(), "got {}", r.total);
        assert_eq!(r.coverage, 0.0, "no maximum known yet means no relative coverage");
    }

    #[test]
    fn norms_track_maxima_and_report_movement() {
        let mut n = ScoreNorms::default();
        assert!(n.observe(&ScoreInputs { new_edges: 5, exec_micros: 100, ..Default::default() }));
        assert!(n.observe(&ScoreInputs { new_edges: 50, exec_micros: 10, ..Default::default() }));
        assert_eq!(n.max_new_edges, 50);
        assert_eq!(n.max_exec_micros, 100);
        assert_eq!(n.corpus_size, 2);
        // Nothing exceeds a current maximum: no rescore needed.
        assert!(!n.observe(&ScoreInputs { new_edges: 1, exec_micros: 1, ..Default::default() }));
        assert_eq!(n.corpus_size, 3);
    }
}
