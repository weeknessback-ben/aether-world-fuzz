//! Global coverage state and novelty detection.
//!
//! One [`CoverageTracker`] per campaign holds the union of everything seen so
//! far, as a "virgin" map in AFL's sense: a slot still holding `0xff` has
//! never been reached in any bucket. Deciding novelty against that map, rather
//! than against a count of distinct edges, is what makes the signal stable -
//! a loop running a different number of times collapses into the same bucket
//! and is correctly reported as *not* new.

use serde::{Deserialize, Serialize};

use crate::exec::shm::MAP_SIZE;

/// What a single execution contributed to the campaign's coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoverageGain {
    /// Slots reached for the first time in any bucket.
    pub new_edges: u32,
    /// Slots already reached, but in a higher hit-count bucket than before.
    /// A weaker signal than a new edge, but still forward progress.
    pub new_buckets: u32,
    /// Slots this run touched, new or not.
    pub touched: u32,
}

impl CoverageGain {
    /// Did this run reach anything the campaign had not reached before?
    pub fn is_novel(&self) -> bool {
        self.new_edges > 0 || self.new_buckets > 0
    }

    /// A single scalar for ranking and for the scheduler's reward signal.
    ///
    /// A new edge is weighted an order of magnitude above a new bucket: both
    /// are progress, but reaching previously unreachable code is the one worth
    /// spending budget to repeat.
    pub fn score(&self) -> f64 {
        self.new_edges as f64 * 10.0 + self.new_buckets as f64
    }
}

/// Campaign-wide coverage accumulator.
pub struct CoverageTracker {
    /// `0xff` in a slot means no bucket of that slot has been seen. Bits are
    /// cleared as buckets are observed.
    virgin: Box<[u8; MAP_SIZE]>,
    /// Union of every bucket seen, for reporting total reach.
    seen: Box<[u8; MAP_SIZE]>,
    total_edges: u32,
    guard_count: Option<u32>,
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageTracker {
    pub fn new() -> Self {
        CoverageTracker {
            virgin: Box::new([0xff; MAP_SIZE]),
            seen: Box::new([0; MAP_SIZE]),
            total_edges: 0,
            guard_count: None,
        }
    }

    /// Record how many guards the target registered, so coverage can be
    /// reported as a fraction of what is reachable at all.
    pub fn set_guard_count(&mut self, guards: u32) {
        self.guard_count = Some(guards);
    }

    pub fn guard_count(&self) -> Option<u32> {
        self.guard_count
    }

    /// Distinct map slots reached across the whole campaign.
    pub fn total_edges(&self) -> u32 {
        self.total_edges
    }

    /// Fraction of the target's registered guards reached, when the guard
    /// count is known. `None` rather than a fabricated percentage otherwise.
    pub fn saturation(&self) -> Option<f64> {
        match self.guard_count {
            Some(g) if g > 0 => Some((self.total_edges as f64 / g as f64).min(1.0)),
            _ => None,
        }
    }

    /// Evaluate a run's bucketed map without changing campaign state.
    ///
    /// Used when a decision has to be made before committing - for example,
    /// checking whether a candidate is worth keeping while other workers are
    /// still reporting.
    pub fn evaluate(&self, map: &[u8; MAP_SIZE]) -> CoverageGain {
        let mut gain = CoverageGain::default();
        for (i, &cur) in map.iter().enumerate() {
            if cur == 0 {
                continue;
            }
            gain.touched += 1;
            let virgin = self.virgin[i];
            if virgin & cur != 0 {
                // At least one bucket bit here is untouched.
                if self.seen[i] == 0 {
                    gain.new_edges += 1;
                } else {
                    gain.new_buckets += 1;
                }
            }
        }
        gain
    }

    /// Evaluate and fold the run into campaign state.
    pub fn observe(&mut self, map: &[u8; MAP_SIZE]) -> CoverageGain {
        let mut gain = CoverageGain::default();
        for (i, &cur) in map.iter().enumerate() {
            if cur == 0 {
                continue;
            }
            gain.touched += 1;
            let virgin = self.virgin[i];
            if virgin & cur != 0 {
                let first_time = self.seen[i] == 0;
                if first_time {
                    gain.new_edges += 1;
                    self.total_edges += 1;
                } else {
                    gain.new_buckets += 1;
                }
                self.virgin[i] = virgin & !cur;
                self.seen[i] |= cur;
            }
        }
        gain
    }

    /// Union of buckets seen, for persistence and for merging campaigns.
    pub fn seen_map(&self) -> &[u8; MAP_SIZE] {
        &self.seen
    }

    /// Restore from a persisted map, e.g. when resuming a campaign.
    pub fn restore(&mut self, seen: &[u8; MAP_SIZE], guard_count: Option<u32>) {
        self.seen.copy_from_slice(seen);
        self.total_edges = 0;
        for i in 0..MAP_SIZE {
            self.virgin[i] = !seen[i];
            if seen[i] != 0 {
                self.total_edges += 1;
            }
        }
        self.guard_count = guard_count;
    }

    /// Fold another tracker's reach into this one, for corpus or worker
    /// synchronisation. Returns how many edges were new here.
    pub fn merge(&mut self, other: &CoverageTracker) -> u32 {
        let mut new = 0;
        for i in 0..MAP_SIZE {
            let add = other.seen[i];
            if add == 0 {
                continue;
            }
            if self.seen[i] == 0 {
                new += 1;
                self.total_edges += 1;
            }
            self.seen[i] |= add;
            self.virgin[i] &= !add;
        }
        new
    }
}

/// A compact, serialisable summary for status output and reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageSummary {
    pub total_edges: u32,
    /// `None` when the target did not report a guard count, so a consumer can
    /// tell "not measurable" from "zero".
    pub guard_count: Option<u32>,
    pub saturation: Option<f64>,
}

impl From<&CoverageTracker> for CoverageSummary {
    fn from(t: &CoverageTracker) -> Self {
        CoverageSummary {
            total_edges: t.total_edges(),
            guard_count: t.guard_count(),
            saturation: t.saturation(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_with(slots: &[(usize, u8)]) -> Box<[u8; MAP_SIZE]> {
        let mut m = Box::new([0u8; MAP_SIZE]);
        for (i, v) in slots {
            m[*i] = *v;
        }
        m
    }

    #[test]
    fn first_observation_is_all_new() {
        let mut t = CoverageTracker::new();
        let g = t.observe(&map_with(&[(1, 1), (2, 1), (3, 4)]));
        assert_eq!(g.new_edges, 3);
        assert_eq!(g.new_buckets, 0);
        assert_eq!(g.touched, 3);
        assert!(g.is_novel());
        assert_eq!(t.total_edges(), 3);
    }

    #[test]
    fn repeating_the_same_coverage_is_not_novel() {
        let mut t = CoverageTracker::new();
        let m = map_with(&[(1, 1), (2, 2)]);
        t.observe(&m);
        let g = t.observe(&m);
        assert_eq!(g.new_edges, 0);
        assert_eq!(g.new_buckets, 0);
        assert_eq!(g.touched, 2, "touched still counts the slots");
        assert!(!g.is_novel(), "identical coverage must not look like progress");
    }

    #[test]
    fn a_higher_hit_bucket_is_weaker_progress_than_a_new_edge() {
        let mut t = CoverageTracker::new();
        t.observe(&map_with(&[(5, 1)]));
        // Same slot, higher bucket: progress, but not a new edge.
        let g = t.observe(&map_with(&[(5, 8)]));
        assert_eq!(g.new_edges, 0);
        assert_eq!(g.new_buckets, 1);
        assert!(g.is_novel());
        assert_eq!(t.total_edges(), 1, "the slot was already counted");
        assert!(
            CoverageGain { new_edges: 1, new_buckets: 0, touched: 1 }.score()
                > CoverageGain { new_edges: 0, new_buckets: 1, touched: 1 }.score()
        );
    }

    #[test]
    fn evaluate_does_not_mutate_state() {
        let t = CoverageTracker::new();
        let m = map_with(&[(7, 1)]);
        let a = t.evaluate(&m);
        let b = t.evaluate(&m);
        assert_eq!(a, b, "evaluate must be side-effect free");
        assert_eq!(t.total_edges(), 0);
    }

    #[test]
    fn saturation_is_none_without_a_guard_count() {
        let mut t = CoverageTracker::new();
        t.observe(&map_with(&[(1, 1)]));
        assert_eq!(t.saturation(), None, "must not invent a percentage");
        t.set_guard_count(4);
        assert_eq!(t.saturation(), Some(0.25));
    }

    #[test]
    fn saturation_is_clamped_to_one() {
        // The edge map is a hash of (prev, cur) pairs, so touched slots can
        // exceed the guard count; a fraction above 1.0 would be nonsense.
        let mut t = CoverageTracker::new();
        for i in 0..10 {
            t.observe(&map_with(&[(i, 1)]));
        }
        t.set_guard_count(3);
        assert_eq!(t.saturation(), Some(1.0));
    }

    #[test]
    fn restore_round_trips() {
        let mut a = CoverageTracker::new();
        a.observe(&map_with(&[(1, 1), (9, 8), (300, 2)]));
        a.set_guard_count(50);

        let mut b = CoverageTracker::new();
        b.restore(a.seen_map(), a.guard_count());
        assert_eq!(b.total_edges(), a.total_edges());
        assert_eq!(b.guard_count(), Some(50));
        // And the restored tracker must agree about what is novel.
        assert!(!b.observe(&map_with(&[(1, 1)])).is_novel());
        assert!(b.observe(&map_with(&[(2, 1)])).is_novel());
    }

    #[test]
    fn merge_unions_reach_and_counts_only_what_is_new() {
        let mut a = CoverageTracker::new();
        a.observe(&map_with(&[(1, 1), (2, 1)]));
        let mut b = CoverageTracker::new();
        b.observe(&map_with(&[(2, 1), (3, 1)]));

        let new = a.merge(&b);
        assert_eq!(new, 1, "only slot 3 was new to a");
        assert_eq!(a.total_edges(), 3);
        assert!(!a.observe(&map_with(&[(3, 1)])).is_novel());
    }

    #[test]
    fn empty_map_contributes_nothing() {
        let mut t = CoverageTracker::new();
        let g = t.observe(&Box::new([0u8; MAP_SIZE]));
        assert_eq!(g, CoverageGain::default());
        assert!(!g.is_novel());
    }

    #[test]
    fn summary_distinguishes_unmeasurable_from_zero() {
        let t = CoverageTracker::new();
        let s = CoverageSummary::from(&t);
        assert_eq!(s.total_edges, 0);
        assert_eq!(s.guard_count, None, "no guard count is not a guard count of zero");
        assert_eq!(s.saturation, None);
    }
}
