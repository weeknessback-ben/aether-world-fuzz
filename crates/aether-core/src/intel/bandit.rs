//! Adaptive strategy selection as a contextual multi-armed bandit.
//!
//! Each strategy is an arm. A round hands one strategy a bounded execution
//! budget; what that round discovered, divided by what it cost, is the reward.
//! The scheduler updates its estimate and chooses again.
//!
//! Design points that matter:
//!
//! * **Reward is value per unit of compute**, not raw coverage. A strategy
//!   that finds twice as much while costing five times as much is a worse use
//!   of a fixed budget, and a scheduler optimising raw coverage would pick it.
//! * **Context matters.** Which strategy is productive changes over a
//!   campaign: byte mutation early while the corpus is thin, comparison-guided
//!   substitution once gates are being hit, structure-aware once a format is
//!   established. Estimates are therefore kept per discretised context, not
//!   globally.
//! * **No arm is ever fully starved.** A selection floor and a minimum trial
//!   count keep a slow starter from being eliminated on noise, which is the
//!   failure mode of a naive greedy scheduler.
//! * **Every decision is recorded** with the numbers behind it, so a report
//!   can show why a strategy was chosen rather than asserting that it was.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::SchedulerKind;
use crate::rng::Rng;

/// Discretised campaign state. Coarse on purpose: a finer context would split
/// the evidence across too many buckets to learn anything from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Context {
    /// 0 = progressing, 1 = slowing, 2 = stagnant.
    pub progress: u8,
    /// Corpus size bucket: 0 = empty/tiny, 1 = small, 2 = large.
    pub corpus: u8,
    /// Coverage saturation bucket: 0 = low, 1 = medium, 2 = high, 3 = unknown.
    pub saturation: u8,
}

impl Context {
    pub fn new(
        stagnant_rounds: u32,
        stagnation_threshold: u32,
        corpus_size: u64,
        saturation: Option<f64>,
    ) -> Self {
        let progress = if stagnant_rounds == 0 {
            0
        } else if stagnant_rounds < stagnation_threshold {
            1
        } else {
            2
        };
        let corpus = match corpus_size {
            0..=4 => 0,
            5..=500 => 1,
            _ => 2,
        };
        let saturation = match saturation {
            None => 3,
            Some(s) if s < 0.33 => 0,
            Some(s) if s < 0.66 => 1,
            Some(_) => 2,
        };
        Context {
            progress,
            corpus,
            saturation,
        }
    }

    /// Context used before anything has been measured.
    pub fn initial() -> Self {
        Context {
            progress: 0,
            corpus: 0,
            saturation: 3,
        }
    }
}

/// Running statistics for one arm in one context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArmStats {
    pub rounds: u32,
    pub executions: u64,
    /// Rounds that produced any new discovery. The Beta posterior's successes.
    pub productive_rounds: u32,
    /// Sum of per-round value, for the mean-reward estimate.
    pub value_sum: f64,
    pub cost_micros: u64,
    pub new_edges: u64,
    pub findings: u32,
}

impl ArmStats {
    /// Fold another arm's statistics into this one.
    ///
    /// Used to aggregate a worker pool, where each worker runs its own
    /// scheduler: the sums are additive, so the campaign-wide figures are the
    /// real totals rather than one worker's view of them.
    pub fn absorb(&mut self, other: &ArmStats) {
        self.rounds = self.rounds.saturating_add(other.rounds);
        self.executions = self.executions.saturating_add(other.executions);
        self.productive_rounds = self
            .productive_rounds
            .saturating_add(other.productive_rounds);
        self.value_sum += other.value_sum;
        self.cost_micros = self.cost_micros.saturating_add(other.cost_micros);
        self.new_edges = self.new_edges.saturating_add(other.new_edges);
        self.findings = self.findings.saturating_add(other.findings);
    }

    /// Mean value per millisecond of compute. The quantity being maximised.
    pub fn value_per_ms(&self) -> f64 {
        let ms = (self.cost_micros as f64 / 1000.0).max(1.0);
        self.value_sum / ms
    }

    /// Share of rounds that discovered anything.
    pub fn success_rate(&self) -> f64 {
        if self.rounds == 0 {
            0.0
        } else {
            self.productive_rounds as f64 / self.rounds as f64
        }
    }
}

/// What one round achieved, fed back to the scheduler.
#[derive(Debug, Clone, Copy)]
pub struct RoundOutcome {
    pub executions: u64,
    /// Exploration value: coverage gain plus weighted novelty.
    pub value: f64,
    pub cost_micros: u64,
    pub new_edges: u64,
    pub findings: u32,
}

impl RoundOutcome {
    pub fn produced_anything(&self) -> bool {
        self.value > 0.0 || self.new_edges > 0 || self.findings > 0
    }
}

/// One recorded decision, with the evidence behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub round: u64,
    pub strategy: String,
    pub context: Context,
    /// Why this arm: the sampled or computed score per arm.
    pub scores: Vec<(String, f64)>,
    pub reason: String,
}

/// The adaptive scheduler.
pub struct Scheduler {
    kind: SchedulerKind,
    arms: Vec<String>,
    /// (context, arm index) -> statistics.
    stats: HashMap<(Context, usize), ArmStats>,
    /// Aggregate per arm, used as a prior when a context is new.
    global: Vec<ArmStats>,
    round: u64,
    round_budget: u32,
    min_rounds: u32,
    selection_floor: f64,
    /// Decisions kept for reporting, bounded.
    decisions: Vec<Decision>,
    max_decisions: usize,
    /// Round-robin cursor.
    cursor: usize,
    /// What the *other* workers in a pool have learned, folded into the global
    /// prior for selection only.
    ///
    /// Each worker in a pooled campaign runs its own scheduler, so on its own
    /// it sees `1/workers` of the rounds. Measured on `toy_parser`, a worker in
    /// a four-worker 25-second campaign got about 240 rounds per arm spread
    /// over nine contexts - too few to tell a ten-times-better arm from an
    /// average one, so allocation stayed near uniform however good the
    /// posterior.
    ///
    /// Round outcomes are cheap to share: there is one per round, not one per
    /// execution. This holds the peers' contribution separately from
    /// `global`, so publishing and absorbing cannot double-count a worker's
    /// own rounds.
    peer_global: Vec<ArmStats>,
    /// Highest per-ms value seen, used to normalise reward into [0, 1].
    ///
    /// Starts at zero, meaning "nothing measured yet", and is raised by the
    /// first observation. It must **not** start at 1.0: value per millisecond
    /// is target-dependent and on a fast target sits far below 1, so a scale
    /// that starts at 1 and only ever rises never adapts, and every arm's
    /// normalised magnitude stays near zero. See `thompson` for what that
    /// cost.
    value_scale: f64,
}

impl Scheduler {
    pub fn new(
        kind: SchedulerKind,
        arms: Vec<String>,
        round_budget: u32,
        min_rounds: u32,
        selection_floor: f64,
    ) -> Self {
        let n = arms.len();
        Scheduler {
            kind,
            arms,
            stats: HashMap::new(),
            global: vec![ArmStats::default(); n],
            round: 0,
            round_budget: round_budget.max(1),
            min_rounds,
            selection_floor: selection_floor.clamp(0.0, 0.5),
            decisions: Vec::new(),
            max_decisions: 512,
            cursor: 0,
            peer_global: vec![ArmStats::default(); n],
            value_scale: 0.0,
        }
    }

    pub fn arms(&self) -> &[String] {
        &self.arms
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn round_budget(&self) -> u32 {
        self.round_budget
    }

    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    pub fn global_stats(&self) -> &[ArmStats] {
        &self.global
    }

    pub fn stats_for(&self, ctx: Context, arm: usize) -> ArmStats {
        self.stats.get(&(ctx, arm)).cloned().unwrap_or_default()
    }

    /// Choose the arm for the next round.
    pub fn select(&mut self, ctx: Context, rng: &mut Rng) -> usize {
        self.round += 1;
        if self.arms.is_empty() {
            return 0;
        }

        // Every arm gets `min_rounds` trials before any can be passed over.
        // Without this an arm that happened to start badly would be written
        // off before there was evidence to write it off on.
        if let Some(i) = self.under_trialled(ctx) {
            self.record(ctx, i, Vec::new(), "minimum trials not yet met");
            return i;
        }

        let (chosen, scores, reason) = match self.kind {
            SchedulerKind::Thompson => self.thompson(ctx, rng),
            SchedulerKind::Ucb1 => self.ucb1(ctx),
            SchedulerKind::Static => {
                // Equal fixed shares: the baseline adaptive scheduling is
                // measured against in Experiment B.
                let i = rng.below(self.arms.len());
                (i, Vec::new(), "static uniform allocation".to_string())
            }
            SchedulerKind::RoundRobin => {
                let i = self.cursor % self.arms.len();
                self.cursor += 1;
                (i, Vec::new(), "round robin".to_string())
            }
        };

        // Selection floor: occasionally pick uniformly regardless of the
        // posterior, so no enabled arm is ever permanently starved.
        if self.selection_floor > 0.0 && rng.bool_with(self.selection_floor) {
            let i = rng.below(self.arms.len());
            self.record(ctx, i, scores, "exploration floor");
            return i;
        }

        self.record(ctx, chosen, scores, &reason);
        chosen
    }

    fn under_trialled(&self, ctx: Context) -> Option<usize> {
        (0..self.arms.len())
            .find(|&i| self.stats.get(&(ctx, i)).map(|s| s.rounds).unwrap_or(0) < self.min_rounds)
    }

    /// Thompson Sampling over per-arm Beta posteriors, scaled by observed
    /// value per unit cost.
    ///
    /// The Beta posterior models "will this arm discover anything this
    /// round?"; multiplying by normalised value-per-millisecond turns that
    /// into "how much discovery per unit of compute should I expect?". Drawing
    /// a sample rather than taking the mean is what provides exploration: an
    /// arm with little evidence has a wide posterior and will sometimes sample
    /// high, which is precisely when it should be tried again.
    fn thompson(&self, ctx: Context, rng: &mut Rng) -> (usize, Vec<(String, f64)>, String) {
        let mut scores = Vec::with_capacity(self.arms.len());
        let mut best = 0usize;
        let mut best_score = f64::NEG_INFINITY;

        for i in 0..self.arms.len() {
            let s = self.effective_stats(ctx, i);
            // Beta(1 + successes, 1 + failures): a uniform prior, so an
            // untried arm samples anywhere in [0, 1].
            let alpha = 1.0 + s.productive_rounds as f64;
            let beta = 1.0 + (s.rounds.saturating_sub(s.productive_rounds)) as f64;
            let p = rng.beta(alpha, beta);

            // Scale by value per millisecond, normalised against the best
            // seen so far, so the two factors are comparable.
            //
            // The normalisation has to be against the best *observed* rate,
            // not a fixed constant. Value per millisecond depends entirely on
            // the target: measured on `toy_parser` the best arm managed 0.027,
            // so dividing by a scale of 1.0 left every magnitude near zero and
            // the `0.25 +` floor below then flattened a 4.6x real difference
            // into 1.06x. The scheduler became almost blind to how much an arm
            // discovers and selected on the binary productive-or-not rate
            // alone, which separates arms far less. See docs/DECISIONS.md D19.
            let magnitude = if s.rounds == 0 || self.value_scale <= 0.0 {
                // Unmeasured: assume mid-range rather than zero, or an untried
                // arm could never win however good its Beta draw.
                0.5
            } else {
                (s.value_per_ms() / self.value_scale).clamp(0.0, 1.0)
            };
            let score = p * (0.25 + 0.75 * magnitude);
            scores.push((self.arms[i].clone(), score));
            if score > best_score {
                best_score = score;
                best = i;
            }
        }
        (
            best,
            scores,
            format!("highest Thompson sample ({best_score:.4})"),
        )
    }

    /// UCB1 with cost normalisation.
    fn ucb1(&self, ctx: Context) -> (usize, Vec<(String, f64)>, String) {
        let total_rounds: u32 = (0..self.arms.len())
            .map(|i| self.effective_stats(ctx, i).rounds)
            .sum();
        let total = (total_rounds.max(1)) as f64;

        let mut scores = Vec::with_capacity(self.arms.len());
        let mut best = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        for i in 0..self.arms.len() {
            let s = self.effective_stats(ctx, i);
            let mean = if s.rounds == 0 {
                0.5
            } else {
                (s.value_per_ms() / self.value_scale).clamp(0.0, 1.0)
            };
            // The exploration term shrinks as an arm accumulates evidence.
            let bonus = if s.rounds == 0 {
                f64::INFINITY
            } else {
                (2.0 * total.ln() / s.rounds as f64).sqrt()
            };
            let score = mean + bonus;
            scores.push((
                self.arms[i].clone(),
                if score.is_finite() { score } else { 1e9 },
            ));
            if score > best_score {
                best_score = score;
                best = i;
            }
        }
        (best, scores, "highest UCB1 bound".to_string())
    }

    /// Statistics for a context, falling back to the arm's global record when
    /// this context has little evidence of its own. A brand-new context would
    /// otherwise discard everything already learned about an arm.
    fn effective_stats(&self, ctx: Context, arm: usize) -> ArmStats {
        // The prior is this worker's own history plus whatever its peers have
        // published. In a single-worker campaign the peer term is empty and
        // this is exactly the global prior.
        let mut prior = self.global[arm].clone();
        prior.absorb(&self.peer_global[arm]);

        // Always blend context-specific evidence with the discounted prior -
        // never switch to context-only evidence.
        //
        // This used to switch: once a `(context, arm)` cell had `min_rounds`
        // rounds it was used alone and the prior was discarded. With 36
        // possible contexts that is far too early. Measured on `toy_parser`,
        // a worker's cells held about 25 rounds each at a roughly 2% rate of
        // productive rounds, so a cell saw zero or one productive round -
        // noise - and every other context's evidence, and every peer
        // worker's, was thrown away. The prior is a shrinkage term, which is
        // what a contextual bandit with sparse per-context data needs.
        //
        // The prior is discounted to a quarter because evidence from other
        // contexts is weaker evidence about this one. It includes this
        // context's own rounds, so those count 1.25 times rather than once;
        // that is a property of using the global total as a shrinkage prior
        // and does not change the ordering between arms.
        let s = self.stats.get(&(ctx, arm)).cloned().unwrap_or_default();
        ArmStats {
            rounds: s.rounds + prior.rounds / 4,
            executions: s.executions,
            productive_rounds: s.productive_rounds + prior.productive_rounds / 4,
            value_sum: s.value_sum + prior.value_sum / 4.0,
            cost_micros: s.cost_micros + prior.cost_micros / 4,
            new_edges: s.new_edges,
            findings: s.findings,
        }
    }

    /// This worker's own per-arm totals, for publishing to a pool.
    pub fn global_totals(&self) -> &[ArmStats] {
        &self.global
    }

    /// Adopt the pool's totals as the peer prior.
    ///
    /// `pool` is the sum of every worker's totals, this one included, so this
    /// worker's own contribution is subtracted out - otherwise its rounds
    /// would be counted twice and the posterior would be more confident than
    /// the evidence supports. The pool's best observed value rate is adopted
    /// too, so one worker finding a high-value arm fixes the normalisation for
    /// all of them at once.
    pub fn absorb_pool_totals(&mut self, pool: &[ArmStats], pool_value_scale: f64) {
        for (i, total) in pool.iter().enumerate().take(self.peer_global.len()) {
            let own = &self.global[i];
            self.peer_global[i] = ArmStats {
                rounds: total.rounds.saturating_sub(own.rounds),
                executions: total.executions.saturating_sub(own.executions),
                productive_rounds: total
                    .productive_rounds
                    .saturating_sub(own.productive_rounds),
                value_sum: (total.value_sum - own.value_sum).max(0.0),
                cost_micros: total.cost_micros.saturating_sub(own.cost_micros),
                new_edges: total.new_edges.saturating_sub(own.new_edges),
                findings: total.findings.saturating_sub(own.findings),
            };
        }
        if pool_value_scale > self.value_scale {
            self.value_scale = pool_value_scale;
        }
    }

    /// Highest value-per-millisecond this scheduler has observed, for a pool
    /// to share. Zero means nothing measured yet.
    pub fn value_scale(&self) -> f64 {
        self.value_scale
    }

    fn record(&mut self, ctx: Context, arm: usize, scores: Vec<(String, f64)>, reason: &str) {
        if self.decisions.len() >= self.max_decisions {
            // Keep the most recent window; a long campaign must not accumulate
            // decisions without bound.
            self.decisions.drain(..self.max_decisions / 2);
        }
        self.decisions.push(Decision {
            round: self.round,
            strategy: self.arms.get(arm).cloned().unwrap_or_default(),
            context: ctx,
            scores,
            reason: reason.to_string(),
        });
    }

    /// Fold a round's result into the estimates.
    pub fn update(&mut self, ctx: Context, arm: usize, outcome: RoundOutcome) {
        if arm >= self.arms.len() {
            return;
        }
        for s in [
            self.stats.entry((ctx, arm)).or_default(),
            &mut self.global[arm],
        ] {
            s.rounds += 1;
            s.executions += outcome.executions;
            s.value_sum += outcome.value;
            s.cost_micros += outcome.cost_micros;
            s.new_edges += outcome.new_edges;
            s.findings += outcome.findings;
            if outcome.produced_anything() {
                s.productive_rounds += 1;
            }
        }

        // Track the best observed value rate so reward normalisation adapts to
        // the target instead of assuming a scale.
        let rate = {
            let s = &self.global[arm];
            s.value_per_ms()
        };
        if rate > self.value_scale {
            self.value_scale = rate;
        }
    }

    /// Current allocation share per arm, for status output.
    pub fn allocation(&self) -> Vec<(String, f64)> {
        let total: u32 = self.global.iter().map(|s| s.rounds).sum();
        if total == 0 {
            return self.arms.iter().map(|a| (a.clone(), 0.0)).collect();
        }
        self.arms
            .iter()
            .zip(&self.global)
            .map(|(a, s)| (a.clone(), s.rounds as f64 / total as f64))
            .collect()
    }

    pub fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "round": self.round,
            "value_scale": self.value_scale,
            "arms": self.arms,
            "global": self.global,
        })
    }

    pub fn restore_state(&mut self, v: &serde_json::Value) {
        if let Some(r) = v.get("round").and_then(|x| x.as_u64()) {
            self.round = r;
        }
        if let Some(s) = v.get("value_scale").and_then(|x| x.as_f64()) {
            self.value_scale = s.max(1e-9);
        }
        if let Some(arr) = v.get("global").and_then(|x| x.as_array()) {
            for (i, item) in arr.iter().enumerate() {
                if i < self.global.len() {
                    if let Ok(s) = serde_json::from_value::<ArmStats>(item.clone()) {
                        self.global[i] = s;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arms() -> Vec<String> {
        vec!["good".into(), "bad".into(), "middling".into()]
    }

    fn sched(kind: SchedulerKind) -> Scheduler {
        Scheduler::new(kind, arms(), 32, 2, 0.0)
    }

    /// The scheduler must exploit an arm that is genuinely better, and must do
    /// so at the *absolute* value rates a real target produces.
    ///
    /// This is a regression test for a measured defect: `value_scale` was
    /// initialised to 1.0 and only ever raised, so on a target whose best
    /// value per millisecond was 0.027 the normalisation never adapted. Every
    /// arm's magnitude term stayed near zero, the `0.25 +` floor flattened a
    /// 4.6x real difference into 1.06x, and over 4000 rounds the best arm's
    /// share fell to 0.05 - worse than uniform. The scale is now set by the
    /// first observation, and this test fails if it is ever pinned again.
    #[test]
    fn thompson_exploits_the_better_arm_at_realistic_value_rates() {
        // Deliberately small: these are the magnitudes a fast target gives,
        // and they are what the old normalisation could not see.
        const SCALE: f64 = 0.001;
        let mut s = Scheduler::new(SchedulerKind::Thompson, arms(), 64, 2, 0.0);
        let mut rng = Rng::from_seed(20260124);
        let ctx = Context {
            progress: 0,
            corpus: 1,
            saturation: 1,
        };
        let mut picks = [0u32; 3];

        for _ in 0..4000 {
            let arm = s.select(ctx, &mut rng);
            picks[arm] += 1;
            // Arm 0 is worth ten times arm 1 and arm 2 per unit of compute,
            // at the same cost and the same chance of being productive.
            let productive = rng.below(100) < 20;
            let value = if productive {
                match arm {
                    0 => 10.0 * SCALE,
                    _ => 1.0 * SCALE,
                }
            } else {
                0.0
            };
            s.update(
                ctx,
                arm,
                RoundOutcome {
                    executions: 64,
                    value,
                    cost_micros: 20_000,
                    new_edges: u64::from(productive),
                    findings: 0,
                },
            );
        }

        let total: u32 = picks.iter().sum();
        let best = f64::from(picks[0]) / f64::from(total);
        assert!(
            best > 0.5,
            "the ten-times-better arm took only {best:.2} of rounds; the scheduler is not              exploiting it (shares: {:?})",
            picks.map(|p| f64::from(p) / f64::from(total))
        );
        // Exploitation must not become starvation: the others still get tried.
        assert!(
            picks[1] > 0 && picks[2] > 0,
            "no arm may be starved entirely: {picks:?}"
        );
    }

    #[test]
    fn the_value_scale_adapts_to_the_target_rather_than_assuming_one() {
        let mut s = Scheduler::new(SchedulerKind::Thompson, arms(), 64, 1, 0.0);
        let ctx = Context::initial();
        assert_eq!(
            s.value_scale, 0.0,
            "nothing is measured yet, which is not the same as a scale of one"
        );
        s.update(
            ctx,
            0,
            RoundOutcome {
                executions: 64,
                value: 0.05,
                cost_micros: 10_000,
                new_edges: 1,
                findings: 0,
            },
        );
        // 0.05 over 10 ms is 0.005 per ms. The scale must now be that, not 1.0.
        assert!(
            (s.value_scale - 0.005).abs() < 1e-9,
            "scale should follow the observed rate, got {}",
            s.value_scale
        );
    }

    /// Reward profile: arm 0 is productive and cheap, arm 1 finds nothing,
    /// arm 2 is productive but expensive.
    fn simulate(arm: usize) -> RoundOutcome {
        match arm {
            0 => RoundOutcome {
                executions: 32,
                value: 10.0,
                cost_micros: 1_000,
                new_edges: 5,
                findings: 0,
            },
            1 => RoundOutcome {
                executions: 32,
                value: 0.0,
                cost_micros: 1_000,
                new_edges: 0,
                findings: 0,
            },
            _ => RoundOutcome {
                executions: 32,
                value: 10.0,
                cost_micros: 50_000,
                new_edges: 5,
                findings: 0,
            },
        }
    }

    #[test]
    fn context_buckets_are_coarse_and_distinguish_unknown_saturation() {
        let c = Context::new(0, 10, 0, None);
        assert_eq!(c.progress, 0);
        assert_eq!(c.corpus, 0);
        assert_eq!(c.saturation, 3, "unknown saturation must not read as low");

        assert_eq!(Context::new(5, 10, 100, Some(0.5)).progress, 1);
        assert_eq!(Context::new(20, 10, 100, Some(0.5)).progress, 2);
        assert_eq!(Context::new(0, 10, 1000, Some(0.9)).corpus, 2);
        assert_eq!(Context::new(0, 10, 1000, Some(0.9)).saturation, 2);
    }

    #[test]
    fn every_arm_gets_its_minimum_trials_first() {
        let mut s = sched(SchedulerKind::Thompson);
        let mut rng = Rng::from_seed(1);
        let ctx = Context::initial();
        let mut counts = vec![0u32; 3];
        // 3 arms x 2 minimum rounds = 6 selections before any preference.
        for _ in 0..6 {
            let a = s.select(ctx, &mut rng);
            counts[a] += 1;
            s.update(ctx, a, simulate(a));
        }
        assert_eq!(
            counts,
            vec![2, 2, 2],
            "minimum trials were not spread evenly"
        );
    }

    #[test]
    fn thompson_converges_on_the_productive_cheap_arm() {
        let mut s = sched(SchedulerKind::Thompson);
        let mut rng = Rng::from_seed(2);
        let ctx = Context::initial();
        for _ in 0..400 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        let alloc = s.allocation();
        let good = alloc.iter().find(|(n, _)| n == "good").unwrap().1;
        let bad = alloc.iter().find(|(n, _)| n == "bad").unwrap().1;
        let mid = alloc.iter().find(|(n, _)| n == "middling").unwrap().1;

        assert!(
            good > 0.5,
            "productive arm got only {:.0}% of rounds",
            good * 100.0
        );
        assert!(
            good > bad * 3.0,
            "unproductive arm not de-prioritised: {good:.3} vs {bad:.3}"
        );
        assert!(
            good > mid,
            "the expensive arm with equal value should lose on cost: {good:.3} vs {mid:.3}"
        );
    }

    #[test]
    fn reward_is_value_per_cost_not_raw_value() {
        // Arms 0 and 2 produce identical value; 2 costs fifty times as much.
        // A scheduler maximising raw value would split evenly between them.
        let mut s = sched(SchedulerKind::Thompson);
        let mut rng = Rng::from_seed(3);
        let ctx = Context::initial();
        for _ in 0..400 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        let cheap = s.stats_for(ctx, 0);
        let dear = s.stats_for(ctx, 2);
        assert!(
            cheap.rounds > dear.rounds * 2,
            "cost was not accounted for: cheap {} rounds, expensive {} rounds",
            cheap.rounds,
            dear.rounds
        );
        assert!(cheap.value_per_ms() > dear.value_per_ms());
    }

    #[test]
    fn ucb1_also_converges_on_the_best_arm() {
        let mut s = sched(SchedulerKind::Ucb1);
        let mut rng = Rng::from_seed(4);
        let ctx = Context::initial();
        for _ in 0..400 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        let alloc = s.allocation();
        let good = alloc.iter().find(|(n, _)| n == "good").unwrap().1;
        let bad = alloc.iter().find(|(n, _)| n == "bad").unwrap().1;
        assert!(good > bad, "UCB1 did not prefer the productive arm");
    }

    #[test]
    fn the_selection_floor_keeps_every_arm_reachable() {
        // Without a floor, an arm whose posterior collapses is never tried
        // again even if the target changes character later in the campaign.
        let mut s = Scheduler::new(SchedulerKind::Thompson, arms(), 32, 1, 0.2);
        let mut rng = Rng::from_seed(5);
        let ctx = Context::initial();
        for _ in 0..600 {
            let a = s.select(ctx, &mut rng);
            // Arm 1 never produces anything at all.
            s.update(ctx, a, simulate(a));
        }
        let bad = s.stats_for(ctx, 1);
        assert!(
            bad.rounds > 20,
            "starved arm got only {} rounds",
            bad.rounds
        );
    }

    #[test]
    fn static_allocation_does_not_adapt() {
        // The control for Experiment B: it must stay roughly uniform even
        // when one arm is obviously better.
        let mut s = sched(SchedulerKind::Static);
        let mut rng = Rng::from_seed(6);
        let ctx = Context::initial();
        for _ in 0..600 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        for (name, share) in s.allocation() {
            assert!(
                (0.25..=0.42).contains(&share),
                "{name} got {share:.3}; static allocation should stay near 1/3"
            );
        }
    }

    #[test]
    fn round_robin_is_exactly_even() {
        let mut s = sched(SchedulerKind::RoundRobin);
        let mut rng = Rng::from_seed(7);
        let ctx = Context::initial();
        // Past the minimum-trial phase, selection must cycle.
        for _ in 0..6 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        let seq: Vec<usize> = (0..6).map(|_| s.select(ctx, &mut rng)).collect();
        assert_eq!(seq, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn context_specific_learning_is_kept_separate() {
        // Arm 0 is good in one context, arm 1 in another. A global-only
        // scheduler would average these into indifference.
        let mut s = Scheduler::new(SchedulerKind::Thompson, arms(), 32, 2, 0.0);
        let mut rng = Rng::from_seed(8);
        let early = Context {
            progress: 0,
            corpus: 0,
            saturation: 0,
        };
        let late = Context {
            progress: 2,
            corpus: 2,
            saturation: 2,
        };

        for _ in 0..200 {
            let a = s.select(early, &mut rng);
            let out = if a == 0 { simulate(0) } else { simulate(1) };
            s.update(early, a, out);

            let b = s.select(late, &mut rng);
            let out = if b == 1 { simulate(0) } else { simulate(1) };
            s.update(late, b, out);
        }
        assert!(
            s.stats_for(early, 0).rounds > s.stats_for(early, 1).rounds,
            "early context did not learn arm 0"
        );
        assert!(
            s.stats_for(late, 1).rounds > s.stats_for(late, 0).rounds,
            "late context did not learn arm 1"
        );
    }

    #[test]
    fn a_new_context_inherits_the_global_prior() {
        let mut s = Scheduler::new(SchedulerKind::Thompson, arms(), 32, 2, 0.0);
        let mut rng = Rng::from_seed(9);
        let a_ctx = Context::initial();
        for _ in 0..200 {
            let a = s.select(a_ctx, &mut rng);
            s.update(a_ctx, a, simulate(a));
        }
        // A context never seen before should still start from what is known.
        let fresh = Context {
            progress: 2,
            corpus: 2,
            saturation: 1,
        };
        let inherited = s.effective_stats(fresh, 0);
        assert!(
            inherited.rounds > 0,
            "global prior was discarded for a new context"
        );
    }

    #[test]
    fn decisions_are_recorded_with_their_evidence_and_stay_bounded() {
        let mut s = sched(SchedulerKind::Thompson);
        let mut rng = Rng::from_seed(10);
        let ctx = Context::initial();
        for _ in 0..3000 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        assert!(
            s.decisions().len() <= 512,
            "decision log grew to {}",
            s.decisions().len()
        );
        let d = s.decisions().last().unwrap();
        assert!(!d.strategy.is_empty());
        assert!(!d.reason.is_empty());
        assert!(
            !d.scores.is_empty(),
            "a Thompson decision should carry per-arm scores"
        );
    }

    #[test]
    fn state_round_trips() {
        let mut s = sched(SchedulerKind::Thompson);
        let mut rng = Rng::from_seed(11);
        let ctx = Context::initial();
        for _ in 0..50 {
            let a = s.select(ctx, &mut rng);
            s.update(ctx, a, simulate(a));
        }
        let state = s.export_state();

        let mut s2 = sched(SchedulerKind::Thompson);
        s2.restore_state(&state);
        assert_eq!(s2.round(), s.round());
        assert_eq!(s2.global_stats()[0].rounds, s.global_stats()[0].rounds);
        assert_eq!(
            s2.global_stats()[0].value_sum,
            s.global_stats()[0].value_sum
        );
    }

    #[test]
    fn selection_is_reproducible_for_a_fixed_seed() {
        let run = || {
            let mut s = sched(SchedulerKind::Thompson);
            let mut rng = Rng::from_seed(4242);
            let ctx = Context::initial();
            (0..100)
                .map(|_| {
                    let a = s.select(ctx, &mut rng);
                    s.update(ctx, a, simulate(a));
                    a
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn an_empty_arm_set_does_not_panic() {
        let mut s = Scheduler::new(SchedulerKind::Thompson, Vec::new(), 8, 1, 0.1);
        let mut rng = Rng::from_seed(12);
        assert_eq!(s.select(Context::initial(), &mut rng), 0);
        s.update(Context::initial(), 0, simulate(0));
    }
}
