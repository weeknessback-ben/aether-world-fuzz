//! Stagnation detection with hysteresis.
//!
//! A campaign that has stopped discovering anything should change what it is
//! doing. Detecting that reliably is harder than it looks: discovery is bursty,
//! so a naive "no new coverage for N rounds" test fires constantly during
//! normal operation and makes the scheduler thrash between strategies.
//!
//! Three mechanisms keep this stable:
//!
//! * **A sliding window**, so one quiet round does not count as stagnation.
//! * **Hysteresis**: the threshold to *enter* stagnation is stricter than the
//!   threshold to leave it. Without the gap, a campaign hovering at the
//!   boundary would oscillate in and out on every round.
//! * **A minimum dwell time** after any state change, so a response has time
//!   to take effect before the detector reconsiders.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Discovering at a healthy rate.
    Progressing,
    /// Discovery has slowed but has not stopped.
    Slowing,
    /// Nothing new for a sustained period.
    Stagnant,
}

/// What the detector suggests doing about it. Advice, not a command: the
/// campaign decides, and records the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Response {
    /// Keep going.
    Continue,
    /// Let the scheduler weight exploration higher.
    DiversifyStrategies,
    /// Draw mutation bases from a different part of the corpus.
    ResampleCorpus,
    /// Try generation rather than mutation, where available.
    PreferGeneration,
    /// Spend budget on constraint solving for a blocking comparison.
    EscalateToConstraintSolving,
    /// Nothing left to try: report rather than churn.
    ReportNoProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagnationState {
    pub phase: Phase,
    /// Consecutive rounds with no discovery.
    pub barren_rounds: u32,
    /// Rounds since the phase last changed.
    pub rounds_in_phase: u32,
    /// Discovery rate over the window, in discoveries per round.
    pub window_rate: f64,
    /// Escalations already applied, so the detector stops suggesting more.
    pub escalation_level: u8,
}

pub struct StagnationDetector {
    /// Rounds considered for the rate estimate.
    window: usize,
    /// 1 if the round discovered something, 0 otherwise.
    history: VecDeque<u8>,
    /// Consecutive barren rounds needed to enter stagnation.
    enter_threshold: u32,
    /// Window discovery rate needed to leave it. Deliberately above zero: the
    /// gap between this and `enter_threshold` is the hysteresis band.
    recovery_ratio: f64,
    /// Rounds a phase must persist before it can change again.
    min_dwell: u32,
    phase: Phase,
    barren_rounds: u32,
    rounds_in_phase: u32,
    escalation_level: u8,
    /// Phase changes, for diagnostics.
    transitions: Vec<(u64, Phase)>,
    round: u64,
}

impl StagnationDetector {
    pub fn new(enter_threshold: u32, recovery_ratio: f64) -> Self {
        let enter = enter_threshold.max(2);
        StagnationDetector {
            // The window spans at least the entry threshold, so the rate
            // estimate covers the same span the entry test looks at.
            window: (enter as usize * 2).clamp(8, 512),
            history: VecDeque::new(),
            enter_threshold: enter,
            recovery_ratio: recovery_ratio.clamp(0.0, 1.0),
            min_dwell: (enter / 4).max(2),
            phase: Phase::Progressing,
            barren_rounds: 0,
            rounds_in_phase: 0,
            escalation_level: 0,
            transitions: Vec::new(),
            round: 0,
        }
    }

    pub fn state(&self) -> StagnationState {
        StagnationState {
            phase: self.phase,
            barren_rounds: self.barren_rounds,
            rounds_in_phase: self.rounds_in_phase,
            window_rate: self.window_rate(),
            escalation_level: self.escalation_level,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn barren_rounds(&self) -> u32 {
        self.barren_rounds
    }

    pub fn transitions(&self) -> &[(u64, Phase)] {
        &self.transitions
    }

    fn window_rate(&self) -> f64 {
        if self.history.is_empty() {
            return 1.0;
        }
        self.history.iter().map(|v| *v as f64).sum::<f64>() / self.history.len() as f64
    }

    /// Record a round and get the current advice.
    pub fn observe(&mut self, discovered: bool) -> Response {
        self.round += 1;
        self.history.push_back(u8::from(discovered));
        if self.history.len() > self.window {
            self.history.pop_front();
        }

        if discovered {
            self.barren_rounds = 0;
        } else {
            self.barren_rounds += 1;
        }
        self.rounds_in_phase += 1;

        let rate = self.window_rate();
        let next = self.next_phase(rate);

        if next != self.phase && self.rounds_in_phase >= self.min_dwell {
            // A phase change resets the escalation ladder only when things
            // improve; worsening keeps the ladder so responses keep climbing.
            if matches!(next, Phase::Progressing) {
                self.escalation_level = 0;
            }
            self.phase = next;
            self.rounds_in_phase = 0;
            self.transitions.push((self.round, next));
        }

        self.advice()
    }

    fn next_phase(&self, rate: f64) -> Phase {
        match self.phase {
            // Entering stagnation needs a sustained barren run.
            Phase::Progressing | Phase::Slowing => {
                if self.barren_rounds >= self.enter_threshold {
                    Phase::Stagnant
                } else if self.barren_rounds >= self.enter_threshold / 2 {
                    Phase::Slowing
                } else if rate > self.recovery_ratio {
                    Phase::Progressing
                } else {
                    self.phase
                }
            }
            // Leaving it needs the window rate to clear the recovery ratio,
            // which is a higher bar than simply not being barren. This gap is
            // the hysteresis that stops oscillation.
            Phase::Stagnant => {
                if rate > self.recovery_ratio {
                    Phase::Progressing
                } else {
                    Phase::Stagnant
                }
            }
        }
    }

    /// Advice for the current phase, climbing the escalation ladder each time
    /// stagnation persists past the dwell time.
    fn advice(&mut self) -> Response {
        match self.phase {
            Phase::Progressing => Response::Continue,
            Phase::Slowing => Response::DiversifyStrategies,
            Phase::Stagnant => {
                if self.rounds_in_phase < self.min_dwell {
                    // Give the last response time to work before escalating.
                    return self.response_for_level(self.escalation_level);
                }
                if self.escalation_level < 4 {
                    self.escalation_level += 1;
                    self.rounds_in_phase = 0;
                }
                self.response_for_level(self.escalation_level)
            }
        }
    }

    fn response_for_level(&self, level: u8) -> Response {
        // Cheapest responses first; constraint solving is expensive, so it is
        // only reached after the cheap options have been tried and failed.
        match level {
            0 | 1 => Response::DiversifyStrategies,
            2 => Response::ResampleCorpus,
            3 => Response::PreferGeneration,
            4 => Response::EscalateToConstraintSolving,
            _ => Response::ReportNoProgress,
        }
    }

    /// Exhausted the ladder with no recovery.
    pub fn is_exhausted(&self) -> bool {
        self.phase == Phase::Stagnant && self.escalation_level >= 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_progressing() {
        let d = StagnationDetector::new(10, 0.15);
        assert_eq!(d.phase(), Phase::Progressing);
        assert_eq!(d.state().barren_rounds, 0);
    }

    #[test]
    fn steady_discovery_never_declares_stagnation() {
        let mut d = StagnationDetector::new(10, 0.15);
        for _ in 0..500 {
            assert_eq!(d.observe(true), Response::Continue);
        }
        assert_eq!(d.phase(), Phase::Progressing);
    }

    #[test]
    fn a_sustained_barren_run_declares_stagnation() {
        let mut d = StagnationDetector::new(10, 0.15);
        for _ in 0..40 {
            d.observe(false);
        }
        assert_eq!(d.phase(), Phase::Stagnant);
        assert!(d.state().barren_rounds >= 10);
    }

    #[test]
    fn one_quiet_round_is_not_stagnation() {
        let mut d = StagnationDetector::new(10, 0.15);
        for _ in 0..20 {
            d.observe(true);
        }
        assert_eq!(d.observe(false), Response::Continue);
        assert_eq!(d.phase(), Phase::Progressing);
    }

    #[test]
    fn bursty_discovery_does_not_thrash_the_phase() {
        // Real campaigns discover in bursts. A detector that flipped phase on
        // every gap would make the scheduler change strategy constantly.
        let mut d = StagnationDetector::new(12, 0.15);
        for cycle in 0..40 {
            // One discovery then four quiet rounds: a 20% rate, above the
            // recovery ratio, so this is healthy progress.
            d.observe(true);
            for _ in 0..4 {
                d.observe(false);
            }
            assert_ne!(
                d.phase(),
                Phase::Stagnant,
                "declared stagnation during bursty but healthy progress (cycle {cycle})"
            );
        }
        assert!(
            d.transitions().len() < 10,
            "phase changed {} times during steady bursty progress",
            d.transitions().len()
        );
    }

    #[test]
    fn hysteresis_prevents_oscillation_at_the_boundary() {
        // Alternating discovery sits exactly at the kind of rate that would
        // make a thresholdless detector flip every round.
        let mut d = StagnationDetector::new(8, 0.15);
        for _ in 0..200 {
            d.observe(true);
            d.observe(false);
            d.observe(false);
        }
        assert!(
            d.transitions().len() <= 4,
            "phase oscillated {} times at the boundary",
            d.transitions().len()
        );
    }

    #[test]
    fn recovery_requires_clearing_the_recovery_ratio_not_merely_one_hit() {
        let mut d = StagnationDetector::new(8, 0.30);
        for _ in 0..40 {
            d.observe(false);
        }
        assert_eq!(d.phase(), Phase::Stagnant);

        // A single discovery must not be enough to declare recovery.
        d.observe(true);
        assert_eq!(
            d.phase(),
            Phase::Stagnant,
            "one discovery cleared stagnation; the hysteresis band is not working"
        );

        // Sustained discovery does clear it.
        for _ in 0..40 {
            d.observe(true);
        }
        assert_eq!(d.phase(), Phase::Progressing);
    }

    #[test]
    fn escalation_climbs_from_cheap_to_expensive_responses() {
        let mut d = StagnationDetector::new(8, 0.15);
        let mut seen = Vec::new();
        for _ in 0..200 {
            let r = d.observe(false);
            if seen.last() != Some(&r) {
                seen.push(r);
            }
        }
        // Diversifying is cheap; constraint solving is not, so it must come
        // last rather than being suggested immediately.
        let div = seen.iter().position(|r| *r == Response::DiversifyStrategies);
        let solve = seen.iter().position(|r| *r == Response::EscalateToConstraintSolving);
        assert!(div.is_some(), "never suggested the cheap response: {seen:?}");
        assert!(solve.is_some(), "never escalated to constraint solving: {seen:?}");
        assert!(div < solve, "escalated to solving before trying cheap options: {seen:?}");
    }

    #[test]
    fn escalation_terminates_rather_than_churning() {
        let mut d = StagnationDetector::new(6, 0.15);
        for _ in 0..500 {
            d.observe(false);
        }
        assert!(d.is_exhausted());
        assert_eq!(d.state().escalation_level, 4);
        // At the top of the ladder the advice stops changing, so the campaign
        // reports a lack of progress rather than cycling forever.
        let a = d.observe(false);
        let b = d.observe(false);
        assert_eq!(a, b);
    }

    #[test]
    fn recovery_resets_the_escalation_ladder() {
        let mut d = StagnationDetector::new(8, 0.15);
        for _ in 0..100 {
            d.observe(false);
        }
        assert!(d.state().escalation_level > 0);
        for _ in 0..60 {
            d.observe(true);
        }
        assert_eq!(d.phase(), Phase::Progressing);
        assert_eq!(d.state().escalation_level, 0, "ladder not reset after recovery");
    }

    #[test]
    fn window_rate_reflects_recent_history_only() {
        let mut d = StagnationDetector::new(8, 0.15);
        for _ in 0..100 {
            d.observe(true);
        }
        assert!(d.state().window_rate > 0.9);
        for _ in 0..100 {
            d.observe(false);
        }
        assert!(
            d.state().window_rate < 0.1,
            "old history still dominates: {}",
            d.state().window_rate
        );
    }

    #[test]
    fn slowing_is_reported_before_full_stagnation() {
        let mut d = StagnationDetector::new(20, 0.15);
        let mut saw_slowing = false;
        for _ in 0..15 {
            if d.observe(false) == Response::DiversifyStrategies && d.phase() == Phase::Slowing {
                saw_slowing = true;
            }
        }
        assert!(saw_slowing, "went straight to stagnant without reporting a slowdown");
    }
}
