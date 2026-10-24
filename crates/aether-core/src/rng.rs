//! Reproducible randomness.
//!
//! Every stochastic decision in a campaign - mutation choices, bandit
//! sampling, corpus sampling - draws from a [`Rng`] seeded from the campaign
//! seed. Each worker derives its own stream from `(campaign_seed, worker_id)`
//! so a campaign with a fixed seed and a fixed worker count replays
//! identically, which is what makes the benchmark comparisons meaningful.

use rand::{Rng as _, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[derive(Clone)]
pub struct Rng {
    inner: ChaCha8Rng,
}

impl Rng {
    pub fn from_seed(seed: u64) -> Self {
        Rng { inner: ChaCha8Rng::seed_from_u64(seed) }
    }

    /// Derive an independent stream for a sub-component. Deterministic in
    /// `(seed, label, index)`, so adding a worker does not perturb the streams
    /// the existing workers draw from.
    pub fn derive(seed: u64, label: &str, index: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(&seed.to_le_bytes());
        h.update(label.as_bytes());
        h.update(&index.to_le_bytes());
        let d = h.finalize();
        let mut s = [0u8; 8];
        s.copy_from_slice(&d.as_bytes()[..8]);
        Rng { inner: ChaCha8Rng::seed_from_u64(u64::from_le_bytes(s)) }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.inner.gen()
    }

    /// Uniform in `0..n`. Returns 0 when `n == 0` so callers can skip a bounds
    /// check on an empty collection.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }

    /// Inclusive range.
    pub fn between(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo { lo } else { lo + self.below(hi - lo + 1) }
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub fn bool_with(&mut self, probability: f64) -> bool {
        self.unit() < probability
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Standard normal via Box-Muller. Used by the Thompson Sampling posterior
    /// for continuous reward arms.
    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(f64::MIN_POSITIVE);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Gamma(shape, 1) by Marsaglia-Tsang, for Beta sampling.
    fn gamma(&mut self, shape: f64) -> f64 {
        if shape < 1.0 {
            let u = self.unit().max(f64::MIN_POSITIVE);
            return self.gamma(shape + 1.0) * u.powf(1.0 / shape);
        }
        let d = shape - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();
        loop {
            let x = self.normal();
            let v = 1.0 + c * x;
            if v <= 0.0 {
                continue;
            }
            let v3 = v * v * v;
            let u = self.unit().max(f64::MIN_POSITIVE);
            if u.ln() < 0.5 * x * x + d - d * v3 + d * v3.ln() {
                return d * v3;
            }
        }
    }

    /// Beta(a, b). This is the draw that makes Thompson Sampling work: each
    /// strategy's success posterior is sampled once per selection round.
    pub fn beta(&mut self, a: f64, b: f64) -> f64 {
        let a = a.max(1e-6);
        let b = b.max(1e-6);
        let x = self.gamma(a);
        let y = self.gamma(b);
        if x + y <= 0.0 { 0.5 } else { x / (x + y) }
    }

    /// Pick an index with probability proportional to its weight. Returns
    /// `None` only when the slice is empty or every weight is non-positive.
    pub fn weighted_index(&mut self, weights: &[f64]) -> Option<usize> {
        let total: f64 = weights.iter().filter(|w| **w > 0.0).sum();
        if total <= 0.0 {
            return None;
        }
        let mut point = self.unit() * total;
        for (i, w) in weights.iter().enumerate() {
            if *w <= 0.0 {
                continue;
            }
            point -= w;
            if point <= 0.0 {
                return Some(i);
            }
        }
        weights.iter().rposition(|w| *w > 0.0)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_replays_identically() {
        let a: Vec<u64> = { let mut r = Rng::from_seed(42); (0..64).map(|_| r.next_u64()).collect() };
        let b: Vec<u64> = { let mut r = Rng::from_seed(42); (0..64).map(|_| r.next_u64()).collect() };
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::from_seed(1);
        let mut b = Rng::from_seed(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn derived_streams_are_independent_and_stable() {
        let a1: Vec<u64> = { let mut r = Rng::derive(7, "worker", 0); (0..8).map(|_| r.next_u64()).collect() };
        let a2: Vec<u64> = { let mut r = Rng::derive(7, "worker", 0); (0..8).map(|_| r.next_u64()).collect() };
        let b: Vec<u64> = { let mut r = Rng::derive(7, "worker", 1); (0..8).map(|_| r.next_u64()).collect() };
        assert_eq!(a1, a2, "derived stream must be reproducible");
        assert_ne!(a1, b, "different worker indices must not share a stream");
    }

    #[test]
    fn below_and_between_stay_in_range() {
        let mut r = Rng::from_seed(9);
        for _ in 0..2000 {
            assert!(r.below(10) < 10);
            assert_eq!(r.below(0), 0);
            let v = r.between(5, 9);
            assert!((5..=9).contains(&v));
            assert_eq!(r.between(3, 3), 3);
        }
    }

    #[test]
    fn beta_stays_in_unit_interval_and_tracks_shape() {
        let mut r = Rng::from_seed(11);
        let mut high = 0.0f64;
        let mut low = 0.0f64;
        for _ in 0..400 {
            let h = r.beta(20.0, 2.0);
            let l = r.beta(2.0, 20.0);
            assert!((0.0..=1.0).contains(&h));
            assert!((0.0..=1.0).contains(&l));
            high += h;
            low += l;
        }
        // Beta(20,2) concentrates near 1, Beta(2,20) near 0.
        assert!(high / 400.0 > 0.75, "mean was {}", high / 400.0);
        assert!(low / 400.0 < 0.25, "mean was {}", low / 400.0);
    }

    #[test]
    fn weighted_index_respects_zero_weights() {
        let mut r = Rng::from_seed(3);
        for _ in 0..500 {
            let i = r.weighted_index(&[0.0, 1.0, 0.0]).unwrap();
            assert_eq!(i, 1);
        }
        assert_eq!(r.weighted_index(&[]), None);
        assert_eq!(r.weighted_index(&[0.0, 0.0]), None);
    }

    #[test]
    fn unit_stays_in_range() {
        let mut r = Rng::from_seed(5);
        for _ in 0..5000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }
}
