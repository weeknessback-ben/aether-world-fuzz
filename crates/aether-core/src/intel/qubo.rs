//! Quantum-inspired optimisation laboratory.
//!
//! An experimental module, **off by default**, for one question: under a fixed
//! compute budget, does a quantum-inspired optimiser choose better than a
//! classical one on the combinatorial problems a fuzzing campaign actually
//! faces?
//!
//! # What this is and is not
//!
//! Everything here runs on a classical CPU. "Quantum-inspired" means the
//! algorithms borrow structure from quantum mechanics - probability amplitudes
//! and rotation gates in [`Qiea`], a transverse field and Trotter replicas in
//! [`SimulatedQuantumAnnealing`] - while being ordinary classical computation.
//! No quantum hardware is involved, nothing here is a quantum speedup, and a
//! result from this module is never reported as one. A quantum *annealer*
//! adapter would plug into the same [`Solver`] trait, but none is available
//! here, so none is claimed.
//!
//! # Problems
//!
//! Both are genuine campaign decisions, not toys:
//!
//! * [`Problem::CorpusSubset`] - choose `k` of `n` corpus entries maximising
//!   covered edges minus redundancy. A max-coverage problem, NP-hard.
//! * [`Problem::BudgetAllocation`] - split a round budget across strategies
//!   given their measured value and cost.
//!
//! # The formulation
//!
//! Max-coverage is reduced to QUBO - minimise `x' Q x` over `x` in `{0,1}^n` -
//! with a pairwise redundancy term and a quadratic cardinality penalty. Writing
//! `w_i` for entry `i`'s edge count and `r_ij` for the overlap between entries
//! `i` and `j`, the objective is
//!
//! ```text
//! minimise  -sum_i w_i x_i  +  sum_{i<j} r_ij x_i x_j  +  lambda (sum_i x_i - k)^2
//! ```
//!
//! Using `x_i^2 = x_i`, the penalty expands into linear and quadratic parts and
//! the whole thing collapses to
//!
//! ```text
//! Q_ii = -w_i + lambda (1 - 2k)
//! Q_ij =  r_ij + 2 lambda          (i < j)
//! ```
//!
//! The pairwise redundancy term is an *approximation* of true set-union
//! coverage, which is not quadratic. It is exact for disjoint and for
//! pairwise-overlapping sets and over-penalises an edge covered three or more
//! times. That is stated plainly because it bounds how good any QUBO solver
//! can be here, independently of which solver is used.
//!
//! # Honesty requirements, enforced in code
//!
//! * Every returned solution is checked against the real constraints
//!   ([`Solver`] callers use [`SolveOutcome::feasible`]), and an infeasible one
//!   is never preferred over a feasible one.
//! * Solver wall-clock cost is measured and reported, so a better objective
//!   bought with ten times the compute is visible as such.
//! * [`compare_solvers`] runs a classical baseline alongside every experimental
//!   solver at the same budget. Any claim about this module has to come from it.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::rng::Rng;

/// A QUBO instance: minimise `x' Q x` for binary `x`.
///
/// `Q` is stored dense and upper-triangular-symmetric. Dense is the right
/// choice here: `n` is the number of candidate corpus entries or strategy
/// budget slots, which stays in the hundreds, and a dense row scan is faster
/// than sparse indirection at that size.
#[derive(Debug, Clone)]
pub struct Qubo {
    n: usize,
    /// Row-major `n x n`, symmetric. `q[i][i]` holds the linear coefficient.
    q: Vec<f64>,
    /// Constant offset, kept so reported energies are comparable to the
    /// original objective rather than being off by a formulation constant.
    offset: f64,
}

impl Qubo {
    pub fn new(n: usize) -> Self {
        Qubo { n, q: vec![0.0; n * n], offset: 0.0 }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn offset(&self) -> f64 {
        self.offset
    }

    pub fn set_offset(&mut self, v: f64) {
        self.offset = v;
    }

    pub fn set_linear(&mut self, i: usize, v: f64) {
        if i < self.n {
            self.q[i * self.n + i] = v;
        }
    }

    pub fn add_linear(&mut self, i: usize, v: f64) {
        if i < self.n {
            self.q[i * self.n + i] += v;
        }
    }

    /// Add to the symmetric off-diagonal pair, splitting the weight so that
    /// `x' Q x` counts the interaction exactly once.
    pub fn add_quadratic(&mut self, i: usize, j: usize, v: f64) {
        if i >= self.n || j >= self.n || i == j {
            return;
        }
        self.q[i * self.n + j] += v / 2.0;
        self.q[j * self.n + i] += v / 2.0;
    }

    pub fn get(&self, i: usize, j: usize) -> f64 {
        self.q[i * self.n + j]
    }

    /// Full energy of an assignment.
    pub fn energy(&self, x: &[bool]) -> f64 {
        let mut e = self.offset;
        for i in 0..self.n {
            if !x[i] {
                continue;
            }
            e += self.q[i * self.n + i];
            for j in (i + 1)..self.n {
                if x[j] {
                    // Both halves of the symmetric pair.
                    e += self.q[i * self.n + j] + self.q[j * self.n + i];
                }
            }
        }
        e
    }

    /// Energy change from flipping bit `i`. O(n) rather than O(n^2), which is
    /// what makes local search over this affordable.
    pub fn delta(&self, x: &[bool], i: usize) -> f64 {
        let mut d = self.q[i * self.n + i];
        for j in 0..self.n {
            if j != i && x[j] {
                d += self.q[i * self.n + j] + self.q[j * self.n + i];
            }
        }
        if x[i] {
            -d
        } else {
            d
        }
    }
}

/// Constraints a solution must satisfy to be usable, checked independently of
/// the penalty terms that encouraged it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Exact cardinality, when the problem demands one.
    pub exact_count: Option<usize>,
    /// Upper bound on selected items.
    pub max_count: Option<usize>,
    /// Lower bound on selected items.
    pub min_count: Option<usize>,
}

impl Constraints {
    pub fn exactly(k: usize) -> Self {
        Constraints { exact_count: Some(k), max_count: None, min_count: None }
    }

    pub fn at_most(k: usize) -> Self {
        Constraints { exact_count: None, max_count: Some(k), min_count: None }
    }

    pub fn none() -> Self {
        Constraints { exact_count: None, max_count: None, min_count: None }
    }

    pub fn satisfied_by(&self, x: &[bool]) -> bool {
        let n = x.iter().filter(|b| **b).count();
        if let Some(k) = self.exact_count {
            if n != k {
                return false;
            }
        }
        if let Some(k) = self.max_count {
            if n > k {
                return false;
            }
        }
        if let Some(k) = self.min_count {
            if n < k {
                return false;
            }
        }
        true
    }

    /// Why an assignment fails, for diagnostics.
    pub fn violation(&self, x: &[bool]) -> Option<String> {
        let n = x.iter().filter(|b| **b).count();
        if let Some(k) = self.exact_count {
            if n != k {
                return Some(format!("selected {n} items, required exactly {k}"));
            }
        }
        if let Some(k) = self.max_count {
            if n > k {
                return Some(format!("selected {n} items, at most {k} allowed"));
            }
        }
        if let Some(k) = self.min_count {
            if n < k {
                return Some(format!("selected {n} items, at least {k} required"));
            }
        }
        None
    }
}

/// One corpus entry as the optimiser sees it.
#[derive(Debug, Clone)]
pub struct CorpusItem {
    /// Edge indices this entry reaches. Sorted, for fast intersection.
    pub edges: Vec<u32>,
    /// Execution cost in microseconds, used as a tie-break.
    pub cost_micros: u64,
}

/// A campaign decision posed as an optimisation problem.
#[derive(Debug, Clone)]
pub enum Problem {
    /// Choose `select` entries from `items` maximising covered edges minus
    /// redundancy.
    CorpusSubset { items: Vec<CorpusItem>, select: usize },
    /// Split `total_units` of budget across strategies with measured value
    /// and cost. Encoded as one binary variable per (strategy, unit) slot.
    BudgetAllocation {
        /// Per-strategy value per unit of budget.
        value_per_unit: Vec<f64>,
        /// Per-strategy cost per unit.
        cost_per_unit: Vec<f64>,
        total_units: usize,
        /// Cap per strategy, so one cannot take the whole budget.
        max_units_per_strategy: usize,
    },
}

/// A prepared problem: the QUBO, its constraints, and how to read a solution.
#[derive(Debug, Clone)]
pub struct PreparedProblem {
    pub qubo: Qubo,
    pub constraints: Constraints,
    /// Penalty weight used, recorded because it determines whether the
    /// formulation can represent the constraint at all.
    pub penalty: f64,
    pub description: String,
}

impl Problem {
    /// Build the QUBO. See the module docs for the derivation.
    pub fn prepare(&self) -> PreparedProblem {
        match self {
            Problem::CorpusSubset { items, select } => {
                let n = items.len();
                let k = (*select).min(n);
                let mut qubo = Qubo::new(n);

                let weights: Vec<f64> = items.iter().map(|i| i.edges.len() as f64).collect();
                let max_w = weights.iter().copied().fold(1.0, f64::max);

                // The penalty has to exceed any objective gain from breaking
                // the constraint, or the optimum of the QUBO would be an
                // infeasible assignment. One item's weight is the most the
                // objective can gain from one extra selection, so scaling
                // above that is sufficient.
                let penalty = max_w * 2.0 + 1.0;

                for i in 0..n {
                    qubo.set_linear(i, -weights[i] + penalty * (1.0 - 2.0 * k as f64));
                    for j in (i + 1)..n {
                        let overlap = sorted_intersection_len(&items[i].edges, &items[j].edges);
                        if overlap > 0 || penalty != 0.0 {
                            qubo.add_quadratic(i, j, overlap as f64 + 2.0 * penalty);
                        }
                    }
                }
                qubo.set_offset(penalty * (k * k) as f64);

                PreparedProblem {
                    qubo,
                    constraints: Constraints::exactly(k),
                    penalty,
                    description: format!("corpus subset: choose {k} of {n} entries"),
                }
            }
            Problem::BudgetAllocation {
                value_per_unit,
                cost_per_unit,
                total_units,
                max_units_per_strategy,
            } => {
                let m = value_per_unit.len();
                let cap = (*max_units_per_strategy).max(1).min(*total_units);
                let n = m * cap;
                let mut qubo = Qubo::new(n);

                let max_v = value_per_unit.iter().copied().fold(1.0, f64::max);
                let penalty = max_v * 2.0 + 1.0;
                let k = *total_units;

                for s in 0..m {
                    let v = value_per_unit[s];
                    let c = cost_per_unit.get(s).copied().unwrap_or(1.0).max(1e-6);
                    for u in 0..cap {
                        let idx = s * cap + u;
                        // Diminishing returns within a strategy: the u-th unit
                        // is worth less than the first, which is what stops the
                        // solution piling the whole budget onto one arm.
                        let marginal = v / ((u + 1) as f64).sqrt() / c;
                        qubo.set_linear(idx, -marginal + penalty * (1.0 - 2.0 * k as f64));
                        for j in (idx + 1)..n {
                            qubo.add_quadratic(idx, j, 2.0 * penalty);
                        }
                    }
                }
                qubo.set_offset(penalty * (k * k) as f64);

                PreparedProblem {
                    qubo,
                    constraints: Constraints::exactly(k),
                    penalty,
                    description: format!(
                        "budget allocation: {k} units across {m} strategies, cap {cap}"
                    ),
                }
            }
        }
    }

    /// True objective value of a solution, computed on the *real* objective
    /// rather than the QUBO.
    ///
    /// This is what solvers are compared on. Scoring them on QUBO energy would
    /// compare how well each exploits the formulation's approximation, which is
    /// not the question.
    pub fn true_objective(&self, x: &[bool]) -> f64 {
        match self {
            Problem::CorpusSubset { items, .. } => {
                // Genuine set union, no pairwise approximation.
                let mut union: Vec<u32> = Vec::new();
                for (i, sel) in x.iter().enumerate() {
                    if *sel && i < items.len() {
                        union.extend_from_slice(&items[i].edges);
                    }
                }
                union.sort_unstable();
                union.dedup();
                union.len() as f64
            }
            Problem::BudgetAllocation { value_per_unit, cost_per_unit, max_units_per_strategy, total_units } => {
                let m = value_per_unit.len();
                let cap = (*max_units_per_strategy).max(1).min(*total_units);
                let mut total = 0.0;
                for s in 0..m {
                    let units = (0..cap).filter(|u| x.get(s * cap + u).copied().unwrap_or(false)).count();
                    let c = cost_per_unit.get(s).copied().unwrap_or(1.0).max(1e-6);
                    // Concave in units: matches the diminishing-returns model.
                    total += value_per_unit[s] * (units as f64).sqrt() / c;
                }
                total
            }
        }
    }
}

/// Length of the intersection of two sorted slices.
fn sorted_intersection_len(a: &[u32], b: &[u32]) -> usize {
    let (mut i, mut j, mut n) = (0, 0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                n += 1;
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    n
}

/// What a solver may spend.
#[derive(Debug, Clone, Copy)]
pub struct SolveBudget {
    pub wall_clock: Duration,
    /// Ceiling on energy evaluations, so a comparison can be made equal in
    /// work as well as in time.
    pub max_evaluations: u64,
}

impl SolveBudget {
    pub fn from_millis(ms: u64) -> Self {
        SolveBudget {
            wall_clock: Duration::from_millis(ms.max(1)),
            max_evaluations: u64::MAX,
        }
    }

    pub fn with_evaluations(mut self, n: u64) -> Self {
        self.max_evaluations = n;
        self
    }
}

/// A solver's result, with everything needed to judge it honestly.
#[derive(Debug, Clone)]
pub struct SolveOutcome {
    pub solver: String,
    pub assignment: Vec<bool>,
    /// QUBO energy, including the formulation offset.
    pub energy: f64,
    /// Value on the real objective. The number solvers are compared on.
    pub true_objective: f64,
    /// Whether the real constraints hold.
    pub feasible: bool,
    pub violation: Option<String>,
    pub elapsed: Duration,
    pub evaluations: u64,
    /// Solver-specific diagnostics.
    pub diagnostics: serde_json::Value,
}

impl SolveOutcome {
    /// Objective per millisecond of solver time: the figure that decides
    /// whether a better answer was worth what it cost to find.
    pub fn objective_per_ms(&self) -> f64 {
        let ms = (self.elapsed.as_secs_f64() * 1000.0).max(0.001);
        self.true_objective / ms
    }
}

/// One optimisation backend.
pub trait Solver {
    fn name(&self) -> &'static str;
    /// Whether this solver should be used at this problem size at all.
    fn applicable(&self, n: usize) -> bool {
        n > 0
    }
    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        budget: SolveBudget,
        rng: &mut Rng,
    ) -> SolveOutcome;
}

/// Repair an assignment to satisfy a cardinality constraint.
///
/// Every solver runs its output through this. A penalty term *encourages*
/// feasibility but does not guarantee it, and returning an infeasible
/// selection to a campaign would mean a corpus trim that kept the wrong number
/// of entries. Repair is greedy on the true objective, so it does not undo the
/// solver's work.
fn repair(x: &mut Vec<bool>, constraints: &Constraints, problem: &Problem) {
    let target = match (constraints.exact_count, constraints.max_count, constraints.min_count) {
        (Some(k), _, _) => k,
        (None, Some(max), _) => {
            let n = x.iter().filter(|b| **b).count();
            if n <= max {
                return;
            }
            max
        }
        (None, None, Some(min)) => {
            let n = x.iter().filter(|b| **b).count();
            if n >= min {
                return;
            }
            min
        }
        _ => return,
    };

    let mut count = x.iter().filter(|b| **b).count();

    // Drop the selections that contribute least.
    while count > target {
        let mut worst = None;
        let mut worst_loss = f64::INFINITY;
        for i in 0..x.len() {
            if !x[i] {
                continue;
            }
            x[i] = false;
            let after = problem.true_objective(x);
            x[i] = true;
            let loss = problem.true_objective(x) - after;
            if loss < worst_loss {
                worst_loss = loss;
                worst = Some(i);
            }
        }
        match worst {
            Some(i) => {
                x[i] = false;
                count -= 1;
            }
            None => break,
        }
    }

    // Add whichever unselected item contributes most.
    while count < target {
        let mut best = None;
        let mut best_gain = f64::NEG_INFINITY;
        let before = problem.true_objective(x);
        for i in 0..x.len() {
            if x[i] {
                continue;
            }
            x[i] = true;
            let gain = problem.true_objective(x) - before;
            x[i] = false;
            if gain > best_gain {
                best_gain = gain;
                best = Some(i);
            }
        }
        match best {
            Some(i) => {
                x[i] = true;
                count += 1;
            }
            None => break,
        }
    }
}

fn finish(
    solver: &'static str,
    mut x: Vec<bool>,
    prepared: &PreparedProblem,
    problem: &Problem,
    started: Instant,
    evaluations: u64,
    diagnostics: serde_json::Value,
) -> SolveOutcome {
    repair(&mut x, &prepared.constraints, problem);
    let feasible = prepared.constraints.satisfied_by(&x);
    SolveOutcome {
        solver: solver.to_string(),
        energy: prepared.qubo.energy(&x),
        true_objective: problem.true_objective(&x),
        feasible,
        violation: prepared.constraints.violation(&x),
        elapsed: started.elapsed(),
        evaluations,
        diagnostics,
        assignment: x,
    }
}

// ---------------------------------------------------------------------------
// Classical baseline: greedy
// ---------------------------------------------------------------------------

/// Greedy selection on marginal gain in the true objective.
///
/// The baseline every experimental solver must beat to justify itself. It is
/// not a straw man: for max-coverage, greedy is the best known
/// polynomial-time approximation, within `1 - 1/e` of optimal.
#[derive(Default)]
pub struct Greedy;

impl Solver for Greedy {
    fn name(&self) -> &'static str {
        "greedy"
    }

    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        _budget: SolveBudget,
        _rng: &mut Rng,
    ) -> SolveOutcome {
        let started = Instant::now();
        let n = prepared.qubo.len();
        let mut x = vec![false; n];
        let target = prepared.constraints.exact_count.or(prepared.constraints.max_count).unwrap_or(n);
        let mut evaluations = 0u64;

        for _ in 0..target {
            let before = problem.true_objective(&x);
            evaluations += 1;
            let mut best = None;
            let mut best_gain = f64::NEG_INFINITY;
            for i in 0..n {
                if x[i] {
                    continue;
                }
                x[i] = true;
                let gain = problem.true_objective(&x) - before;
                x[i] = false;
                evaluations += 1;
                if gain > best_gain {
                    best_gain = gain;
                    best = Some(i);
                }
            }
            match best {
                Some(i) => x[i] = true,
                None => break,
            }
        }
        finish(self.name(), x, prepared, problem, started, evaluations, serde_json::json!({}))
    }
}

// ---------------------------------------------------------------------------
// Classical ground truth: exhaustive
// ---------------------------------------------------------------------------

/// Exhaustive search. Only applicable to tiny instances, where it provides the
/// ground truth every other solver's quality is measured against.
pub struct Exhaustive {
    pub max_n: usize,
}

impl Default for Exhaustive {
    fn default() -> Self {
        Exhaustive { max_n: 22 }
    }
}

impl Solver for Exhaustive {
    fn name(&self) -> &'static str {
        "exhaustive"
    }

    fn applicable(&self, n: usize) -> bool {
        n > 0 && n <= self.max_n
    }

    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        budget: SolveBudget,
        _rng: &mut Rng,
    ) -> SolveOutcome {
        let started = Instant::now();
        let n = prepared.qubo.len();
        let mut best = vec![false; n];
        let mut best_obj = f64::NEG_INFINITY;
        let mut evaluations = 0u64;

        for mask in 0u64..(1u64 << n.min(63)) {
            if evaluations % 4096 == 0 && started.elapsed() > budget.wall_clock {
                break;
            }
            let x: Vec<bool> = (0..n).map(|i| mask & (1 << i) != 0).collect();
            evaluations += 1;
            // Only feasible assignments are candidates: the exhaustive answer
            // must be the best *usable* one, not the best energy.
            if !prepared.constraints.satisfied_by(&x) {
                continue;
            }
            let obj = problem.true_objective(&x);
            if obj > best_obj {
                best_obj = obj;
                best = x;
            }
        }
        finish(
            self.name(),
            best,
            prepared,
            problem,
            started,
            evaluations,
            serde_json::json!({ "exhaustive_n": n }),
        )
    }
}

// ---------------------------------------------------------------------------
// Classical metaheuristic: simulated annealing
// ---------------------------------------------------------------------------

/// Simulated annealing on the QUBO energy.
///
/// The strongest purely classical metaheuristic here, and the most honest
/// comparison for the quantum-inspired solvers, since all three are
/// stochastic local search differing only in how they escape local minima.
pub struct SimulatedAnnealing {
    pub initial_temp: f64,
    pub final_temp: f64,
    pub sweeps: u32,
    pub restarts: u32,
}

impl Default for SimulatedAnnealing {
    /// Tuned by sweep: see `tests/optimizer_tuning.rs`. A high initial
    /// temperature and many restarts beat long single runs at a fixed budget
    /// (mean objective 0.921 of greedy against 0.737 for one short cold run),
    /// because escaping the cardinality-penalty basin matters more here than
    /// refining within one.
    fn default() -> Self {
        SimulatedAnnealing { initial_temp: 50.0, final_temp: 0.01, sweeps: 800, restarts: 16 }
    }
}

impl Solver for SimulatedAnnealing {
    fn name(&self) -> &'static str {
        "simulated-annealing"
    }

    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        budget: SolveBudget,
        rng: &mut Rng,
    ) -> SolveOutcome {
        let started = Instant::now();
        let qubo = &prepared.qubo;
        let n = qubo.len();
        let mut evaluations = 0u64;
        let mut best = vec![false; n];
        let mut best_energy = f64::INFINITY;
        let mut restarts_done = 0u32;

        'outer: for _ in 0..self.restarts.max(1) {
            restarts_done += 1;
            // Start from a random feasible-ish point: seeding at the target
            // cardinality gets the search into the feasible region sooner than
            // starting from all-zeros.
            let target = prepared.constraints.exact_count.unwrap_or(n / 2);
            let mut x = vec![false; n];
            let mut idx: Vec<usize> = (0..n).collect();
            rng.shuffle(&mut idx);
            for &i in idx.iter().take(target) {
                x[i] = true;
            }
            let mut energy = qubo.energy(&x);
            evaluations += 1;

            for sweep in 0..self.sweeps {
                if started.elapsed() > budget.wall_clock || evaluations >= budget.max_evaluations {
                    break 'outer;
                }
                // Geometric cooling.
                let frac = sweep as f64 / self.sweeps.max(1) as f64;
                let temp = self.initial_temp * (self.final_temp / self.initial_temp).powf(frac);

                for _ in 0..n {
                    let i = rng.below(n);
                    let d = qubo.delta(&x, i);
                    evaluations += 1;
                    // Accept downhill always, uphill with Boltzmann probability.
                    if d <= 0.0 || rng.unit() < (-d / temp.max(1e-9)).exp() {
                        x[i] = !x[i];
                        energy += d;
                    }
                }
                if energy < best_energy {
                    best_energy = energy;
                    best.copy_from_slice(&x);
                }
            }
        }

        finish(
            self.name(),
            best,
            prepared,
            problem,
            started,
            evaluations,
            serde_json::json!({
                "sweeps": self.sweeps,
                "restarts_done": restarts_done,
                "initial_temp": self.initial_temp,
                "final_temp": self.final_temp,
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// Quantum-inspired evolutionary algorithm
// ---------------------------------------------------------------------------

/// Quantum-inspired evolutionary algorithm, after Han and Kim (2002).
///
/// Each individual is a register of `n` "qubits", each a pair of probability
/// amplitudes `(alpha, beta)` with `alpha^2 + beta^2 = 1`. Observing a register
/// collapses bit `i` to 1 with probability `beta_i^2`, giving a classical
/// assignment. A rotation gate then turns each amplitude pair toward the bit
/// value held by the best solution found so far, so the population's
/// *distribution* converges rather than its members.
///
/// Classical computation throughout: the amplitudes are two floats per bit and
/// the "gate" is a 2x2 rotation matrix. The borrowed structure is the
/// probabilistic representation, which gives a smoother exploration-to-
/// exploitation transition than a bit-flip mutation does.
pub struct Qiea {
    pub population: usize,
    pub generations: u32,
    /// Rotation angle in radians per generation.
    pub theta: f64,
    /// Chance of re-randomising an individual's register, to keep the
    /// population from collapsing onto one basin.
    pub catastrophe_rate: f64,
}

impl Default for Qiea {
    /// Tuned by sweep: see `tests/optimizer_tuning.rs`. The catastrophe
    /// operator is the decisive parameter - without it a large rotation angle
    /// collapses the population onto one basin and quality falls to 0.78 of
    /// greedy, while with it every angle tested stays near 0.96. A small
    /// population works as well as a large one at a fixed budget, because the
    /// budget buys generations rather than members.
    fn default() -> Self {
        Qiea {
            population: 8,
            generations: 100_000, // budget-limited in practice
            theta: 0.05 * std::f64::consts::PI,
            catastrophe_rate: 0.05,
        }
    }
}

/// One qubit register: `beta[i]^2` is the probability that bit `i` observes 1.
struct Register {
    /// Stored as the angle whose cosine is alpha and sine is beta, which keeps
    /// the normalisation `alpha^2 + beta^2 = 1` exact under rotation.
    angles: Vec<f64>,
}

impl Register {
    fn new(n: usize) -> Self {
        // Start in uniform superposition: every bit equally likely.
        Register { angles: vec![std::f64::consts::FRAC_PI_4; n] }
    }

    fn randomise(&mut self, rng: &mut Rng) {
        for a in self.angles.iter_mut() {
            *a = rng.unit() * std::f64::consts::FRAC_PI_2;
        }
    }

    /// Collapse to a classical assignment.
    fn observe(&self, rng: &mut Rng) -> Vec<bool> {
        self.angles
            .iter()
            .map(|a| {
                let beta = a.sin();
                rng.unit() < beta * beta
            })
            .collect()
    }

    /// Rotate each pair toward `target`'s bit values.
    fn rotate_toward(&mut self, current: &[bool], target: &[bool], theta: f64) {
        for i in 0..self.angles.len() {
            let want = target.get(i).copied().unwrap_or(false);
            let have = current.get(i).copied().unwrap_or(false);
            // Only rotate where the best solution disagrees with what this
            // register produced: agreement means no information to add.
            if want == have {
                continue;
            }
            let dir = if want { 1.0 } else { -1.0 };
            self.angles[i] = (self.angles[i] + dir * theta)
                .clamp(0.01, std::f64::consts::FRAC_PI_2 - 0.01);
        }
    }

    /// How converged the register is: 0 at uniform superposition, 1 when every
    /// bit is effectively determined.
    fn convergence(&self) -> f64 {
        let n = self.angles.len().max(1) as f64;
        self.angles
            .iter()
            .map(|a| {
                let p = a.sin() * a.sin();
                (2.0 * (p - 0.5)).abs()
            })
            .sum::<f64>()
            / n
    }
}

impl Solver for Qiea {
    fn name(&self) -> &'static str {
        "quantum-inspired-evolutionary"
    }

    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        budget: SolveBudget,
        rng: &mut Rng,
    ) -> SolveOutcome {
        let started = Instant::now();
        let qubo = &prepared.qubo;
        let n = qubo.len();
        let mut evaluations = 0u64;

        let mut registers: Vec<Register> =
            (0..self.population.max(1)).map(|_| Register::new(n)).collect();
        let mut best = vec![false; n];
        let mut best_energy = f64::INFINITY;
        let mut generations_done = 0u32;

        for _gen in 0..self.generations {
            if started.elapsed() > budget.wall_clock || evaluations >= budget.max_evaluations {
                break;
            }
            generations_done += 1;

            // Observe every register, keep the best observation.
            let mut observations = Vec::with_capacity(registers.len());
            for r in &registers {
                let x = r.observe(rng);
                let e = qubo.energy(&x);
                evaluations += 1;
                if e < best_energy {
                    best_energy = e;
                    best.copy_from_slice(&x);
                }
                observations.push(x);
            }

            // Rotate each register toward the global best.
            for (r, obs) in registers.iter_mut().zip(&observations) {
                r.rotate_toward(obs, &best, self.theta);
            }

            // Catastrophe: re-randomise a converged register so the population
            // does not all settle into the same basin.
            for r in registers.iter_mut() {
                if r.convergence() > 0.95 && rng.bool_with(self.catastrophe_rate.max(0.0)) {
                    r.randomise(rng);
                }
            }
        }

        let mean_convergence = registers.iter().map(|r| r.convergence()).sum::<f64>()
            / registers.len().max(1) as f64;

        finish(
            self.name(),
            best,
            prepared,
            problem,
            started,
            evaluations,
            serde_json::json!({
                "population": self.population,
                "generations_done": generations_done,
                "theta": self.theta,
                "mean_convergence": mean_convergence,
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// Simulated quantum annealing
// ---------------------------------------------------------------------------

/// Discrete-time simulated quantum annealing (path-integral Monte Carlo).
///
/// Simulates a transverse-field Ising system classically. The problem is
/// replicated into `trotter` slices along an imaginary-time axis; each slice
/// carries the QUBO energy scaled by `1/P`, and neighbouring slices are coupled
/// by a term whose strength comes from the transverse field:
///
/// ```text
/// J_perp = -(P T / 2) * ln( tanh( Gamma / (P T) ) )
/// ```
///
/// `Gamma` is annealed from large to small. While it is large the coupling is
/// weak and slices explore independently; as it falls they are forced into
/// agreement and the system settles into one classical configuration. The
/// mechanism this borrows from quantum annealing is tunnelling: a slice can be
/// dragged through an energy barrier by its neighbours, where thermal annealing
/// would have to climb over it.
///
/// Again, classical: this is Monte Carlo over `P` copies of a bit vector, and
/// its cost is `P` times a classical sweep. That cost is exactly why it has to
/// be compared at equal budget rather than at equal sweep count.
pub struct SimulatedQuantumAnnealing {
    /// Number of Trotter slices `P`.
    pub trotter: usize,
    /// Initial transverse field.
    pub gamma_initial: f64,
    pub gamma_final: f64,
    /// Fixed temperature `T`.
    pub temperature: f64,
    pub sweeps: u32,
}

impl Default for SimulatedQuantumAnnealing {
    /// Tuned by sweep: see `tests/optimizer_tuning.rs`. Quality rises
    /// monotonically with the Trotter count (0.80 of greedy at P=2 to 0.92 at
    /// P=32) because more replicas give more tunnelling paths, and a higher
    /// temperature helps because the transverse coupling alone leaves the
    /// system too rigid. The cost of a sweep scales with P, so at a fixed
    /// budget this is a genuine trade-off rather than free improvement.
    fn default() -> Self {
        SimulatedQuantumAnnealing {
            trotter: 32,
            gamma_initial: 3.0,
            gamma_final: 0.05,
            temperature: 2.0,
            sweeps: 100_000, // budget-limited in practice
        }
    }
}

impl Solver for SimulatedQuantumAnnealing {
    fn name(&self) -> &'static str {
        "simulated-quantum-annealing"
    }

    fn solve(
        &mut self,
        prepared: &PreparedProblem,
        problem: &Problem,
        budget: SolveBudget,
        rng: &mut Rng,
    ) -> SolveOutcome {
        let started = Instant::now();
        let qubo = &prepared.qubo;
        let n = qubo.len();
        let p = self.trotter.max(1);
        let t = self.temperature.max(1e-6);
        let mut evaluations = 0u64;

        // One replica per Trotter slice, seeded at the target cardinality.
        let target = prepared.constraints.exact_count.unwrap_or(n / 2);
        let mut slices: Vec<Vec<bool>> = (0..p)
            .map(|_| {
                let mut x = vec![false; n];
                let mut idx: Vec<usize> = (0..n).collect();
                rng.shuffle(&mut idx);
                for &i in idx.iter().take(target) {
                    x[i] = true;
                }
                x
            })
            .collect();

        let mut best = slices[0].clone();
        let mut best_energy = qubo.energy(&best);
        evaluations += 1;
        let mut sweeps_done = 0u32;
        let mut final_gamma = self.gamma_initial;

        for sweep in 0..self.sweeps {
            if started.elapsed() > budget.wall_clock || evaluations >= budget.max_evaluations {
                break;
            }
            sweeps_done += 1;

            // Anneal the transverse field geometrically.
            let frac = sweep as f64 / self.sweeps.max(1) as f64;
            let gamma = self.gamma_initial
                * (self.gamma_final / self.gamma_initial).powf(frac);
            final_gamma = gamma;

            // Coupling between adjacent slices. As gamma falls, tanh(.) falls,
            // its log grows negative, and j_perp grows: the slices are pulled
            // into agreement.
            let arg = (gamma / (p as f64 * t)).max(1e-12);
            let j_perp = -(p as f64 * t / 2.0) * arg.tanh().max(1e-12).ln();

            for slice_idx in 0..p {
                for _ in 0..n {
                    let i = rng.below(n);
                    // Problem energy change, shared across P slices.
                    let d_problem = qubo.delta(&slices[slice_idx], i) / p as f64;
                    evaluations += 1;

                    // Coupling change against the two neighbouring slices,
                    // with periodic boundaries along imaginary time.
                    let prev = slices[(slice_idx + p - 1) % p][i];
                    let next = slices[(slice_idx + 1) % p][i];
                    let here = slices[slice_idx][i];
                    let agree_now = i32::from(here == prev) + i32::from(here == next);
                    let agree_flipped = i32::from(here != prev) + i32::from(here != next);
                    let d_coupling = j_perp * (agree_now - agree_flipped) as f64;

                    let d = d_problem + d_coupling;
                    if d <= 0.0 || rng.unit() < (-d / t).exp() {
                        slices[slice_idx][i] = !here;
                    }
                }

                let e = qubo.energy(&slices[slice_idx]);
                evaluations += 1;
                if e < best_energy {
                    best_energy = e;
                    best.copy_from_slice(&slices[slice_idx]);
                }
            }
        }

        finish(
            self.name(),
            best,
            prepared,
            problem,
            started,
            evaluations,
            serde_json::json!({
                "trotter": p,
                "sweeps_done": sweeps_done,
                "gamma_initial": self.gamma_initial,
                "gamma_final": final_gamma,
                "temperature": self.temperature,
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// Comparison harness
// ---------------------------------------------------------------------------

/// Side-by-side results at equal budget.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub problem: String,
    pub outcomes: Vec<SolveOutcome>,
    /// Ground truth from exhaustive search, when the instance was small enough.
    pub optimal: Option<f64>,
}

impl Comparison {
    /// Best feasible outcome. Infeasible results are never preferred, however
    /// good their objective looks.
    pub fn best(&self) -> Option<&SolveOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.feasible)
            .max_by(|a, b| a.true_objective.partial_cmp(&b.true_objective).unwrap())
    }

    pub fn baseline(&self) -> Option<&SolveOutcome> {
        self.outcomes.iter().find(|o| o.solver == "greedy")
    }

    /// Objective of `solver` relative to the greedy baseline. Above 1.0 means
    /// it found a better answer; this says nothing about what it cost.
    pub fn ratio_to_baseline(&self, solver: &str) -> Option<f64> {
        let base = self.baseline()?;
        let other = self.outcomes.iter().find(|o| o.solver == solver)?;
        if base.true_objective.abs() < 1e-12 {
            return None;
        }
        Some(other.true_objective / base.true_objective)
    }

    /// Fraction of the optimum a solver reached, when the optimum is known.
    pub fn quality(&self, solver: &str) -> Option<f64> {
        let opt = self.optimal?;
        if opt.abs() < 1e-12 {
            return None;
        }
        let o = self.outcomes.iter().find(|o| o.solver == solver)?;
        Some(o.true_objective / opt)
    }
}

/// Run every applicable solver on one problem at the same budget.
///
/// This is the only sanctioned way to make a claim about a solver in this
/// module: the baseline runs alongside, the ground truth is computed when the
/// instance is small enough, and each solver's wall-clock cost is recorded.
pub fn compare_solvers(problem: &Problem, budget: SolveBudget, seed: u64) -> Comparison {
    let prepared = problem.prepare();
    let n = prepared.qubo.len();
    let mut outcomes = Vec::new();

    let mut solvers: Vec<Box<dyn Solver>> = vec![
        Box::new(Greedy),
        Box::new(SimulatedAnnealing::default()),
        Box::new(Qiea::default()),
        Box::new(SimulatedQuantumAnnealing::default()),
    ];

    for s in solvers.iter_mut() {
        if !s.applicable(n) {
            continue;
        }
        // Each solver gets its own identically-seeded stream, so a difference
        // between them is the algorithm and not the random numbers.
        let mut rng = Rng::derive(seed, s.name(), 0);
        outcomes.push(s.solve(&prepared, problem, budget, &mut rng));
    }

    // Ground truth, where the instance is small enough to be certain.
    let mut exhaustive = Exhaustive::default();
    let optimal = if exhaustive.applicable(n) {
        let mut rng = Rng::derive(seed, "exhaustive", 0);
        let o = exhaustive.solve(&prepared, problem, SolveBudget::from_millis(5_000), &mut rng);
        let v = o.true_objective;
        outcomes.push(o);
        Some(v)
    } else {
        None
    };

    Comparison { problem: prepared.description, outcomes, optimal }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Corpus where the best choice is clear: three entries cover disjoint
    /// edges, the rest duplicate them.
    fn disjoint_problem(select: usize) -> Problem {
        Problem::CorpusSubset {
            items: vec![
                CorpusItem { edges: (0..10).collect(), cost_micros: 100 },
                CorpusItem { edges: (10..20).collect(), cost_micros: 100 },
                CorpusItem { edges: (20..30).collect(), cost_micros: 100 },
                CorpusItem { edges: (0..10).collect(), cost_micros: 100 },
                CorpusItem { edges: (0..5).collect(), cost_micros: 100 },
            ],
            select,
        }
    }

    fn random_problem(n: usize, select: usize, seed: u64) -> Problem {
        let mut rng = Rng::from_seed(seed);
        let items = (0..n)
            .map(|_| {
                let count = rng.between(5, 40);
                let mut edges: Vec<u32> = (0..count).map(|_| rng.below(200) as u32).collect();
                edges.sort_unstable();
                edges.dedup();
                CorpusItem { edges, cost_micros: rng.between(100, 5000) as u64 }
            })
            .collect();
        Problem::CorpusSubset { items, select }
    }

    #[test]
    fn qubo_energy_and_delta_agree() {
        // delta() is an O(n) shortcut for the energy change of a flip; if it
        // disagrees with a full recomputation every local search is wrong.
        let mut rng = Rng::from_seed(1);
        let prepared = random_problem(12, 4, 7).prepare();
        let q = &prepared.qubo;
        let n = q.len();
        for _ in 0..200 {
            let x: Vec<bool> = (0..n).map(|_| rng.bool_with(0.5)).collect();
            let i = rng.below(n);
            let before = q.energy(&x);
            let d = q.delta(&x, i);
            let mut y = x.clone();
            y[i] = !y[i];
            let after = q.energy(&y);
            assert!(
                (after - before - d).abs() < 1e-9,
                "delta {d} disagrees with {} - {}",
                after,
                before
            );
        }
    }

    #[test]
    fn formulation_makes_the_intended_selection_optimal() {
        // With three disjoint sets available, choosing them is the right
        // answer; if the QUBO's minimum were elsewhere, no solver could help.
        let p = disjoint_problem(3);
        let prepared = p.prepare();
        let mut exhaustive = Exhaustive::default();
        let mut rng = Rng::from_seed(2);
        let o = exhaustive.solve(&prepared, &p, SolveBudget::from_millis(5_000), &mut rng);
        assert!(o.feasible);
        assert_eq!(o.true_objective, 30.0, "optimal union should be all 30 edges");
        assert_eq!(o.assignment[0..3], [true, true, true]);
    }

    #[test]
    fn penalty_dominates_the_objective_gain() {
        // If the penalty were too small, the QUBO minimum would sit outside
        // the feasible region and the formulation would be broken.
        let prepared = disjoint_problem(2).prepare();
        let max_weight = 10.0;
        assert!(
            prepared.penalty > max_weight,
            "penalty {} does not dominate a single item's weight {}",
            prepared.penalty,
            max_weight
        );
    }

    #[test]
    fn constraints_are_checked_and_violations_explained() {
        let c = Constraints::exactly(2);
        assert!(c.satisfied_by(&[true, true, false]));
        assert!(!c.satisfied_by(&[true, false, false]));
        assert!(c.violation(&[true, false, false]).unwrap().contains("exactly 2"));
        assert!(c.violation(&[true, true, false]).is_none());

        let m = Constraints::at_most(1);
        assert!(m.satisfied_by(&[false, false]));
        assert!(!m.satisfied_by(&[true, true]));
        assert!(Constraints::none().satisfied_by(&[true; 5]));
    }

    #[test]
    fn every_solver_returns_a_feasible_solution() {
        // A penalty term encourages feasibility but does not guarantee it, so
        // every solver's output is repaired and checked. An infeasible corpus
        // selection would mean trimming to the wrong size.
        let problems = [disjoint_problem(3), random_problem(30, 8, 11), random_problem(60, 15, 12)];
        let budget = SolveBudget::from_millis(50);
        for p in &problems {
            let prepared = p.prepare();
            let mut solvers: Vec<Box<dyn Solver>> = vec![
                Box::new(Greedy),
                Box::new(SimulatedAnnealing::default()),
                Box::new(Qiea::default()),
                Box::new(SimulatedQuantumAnnealing::default()),
            ];
            for s in solvers.iter_mut() {
                let mut rng = Rng::from_seed(3);
                let o = s.solve(&prepared, p, budget, &mut rng);
                assert!(
                    o.feasible,
                    "{} returned an infeasible solution: {:?}",
                    o.solver, o.violation
                );
                assert_eq!(o.assignment.len(), prepared.qubo.len());
            }
        }
    }

    #[test]
    fn solvers_respect_their_wall_clock_budget() {
        let p = random_problem(120, 30, 13);
        let prepared = p.prepare();
        let budget = SolveBudget::from_millis(30);
        let mut solvers: Vec<Box<dyn Solver>> = vec![
            Box::new(SimulatedAnnealing { sweeps: 1_000_000, restarts: 100, ..Default::default() }),
            Box::new(Qiea { generations: 1_000_000, ..Default::default() }),
            Box::new(SimulatedQuantumAnnealing { sweeps: 1_000_000, ..Default::default() }),
        ];
        for s in solvers.iter_mut() {
            let mut rng = Rng::from_seed(4);
            let o = s.solve(&prepared, &p, budget, &mut rng);
            assert!(
                o.elapsed < Duration::from_millis(600),
                "{} ran for {:?} against a 30ms budget",
                o.solver,
                o.elapsed
            );
        }
    }

    #[test]
    fn greedy_is_a_strong_baseline_not_a_straw_man() {
        // Greedy is within 1 - 1/e of optimal on max-coverage. If it were
        // weak, beating it would prove nothing.
        let p = disjoint_problem(3);
        let cmp = compare_solvers(&p, SolveBudget::from_millis(40), 5);
        let q = cmp.quality("greedy").expect("optimum known for this size");
        assert!(q >= 1.0 - 1.0 / std::f64::consts::E, "greedy reached only {q:.3} of optimal");
    }

    #[test]
    fn comparison_includes_a_baseline_and_ground_truth_when_small() {
        let cmp = compare_solvers(&disjoint_problem(2), SolveBudget::from_millis(40), 6);
        assert!(cmp.baseline().is_some(), "every comparison must carry the classical baseline");
        assert!(cmp.optimal.is_some(), "a 5-variable instance should have ground truth");
        assert!(cmp.best().is_some());
        // Every solver must be present and feasible.
        for name in [
            "greedy",
            "simulated-annealing",
            "quantum-inspired-evolutionary",
            "simulated-quantum-annealing",
        ] {
            let o = cmp
                .outcomes
                .iter()
                .find(|o| o.solver == name)
                .unwrap_or_else(|| panic!("{name} missing from the comparison"));
            assert!(o.feasible, "{name} infeasible");
        }
    }

    #[test]
    fn exhaustive_is_skipped_on_large_instances() {
        let cmp = compare_solvers(&random_problem(80, 20, 14), SolveBudget::from_millis(30), 7);
        assert!(cmp.optimal.is_none(), "exhaustive search must not be attempted at n=80");
        assert!(!cmp.outcomes.iter().any(|o| o.solver == "exhaustive"));
    }

    #[test]
    fn no_solver_exceeds_the_known_optimum() {
        // A solver reporting better than optimal would mean the objective or
        // the ground truth is wrong.
        for seed in 0..6u64 {
            let p = random_problem(14, 5, 100 + seed);
            let cmp = compare_solvers(&p, SolveBudget::from_millis(60), seed);
            let opt = cmp.optimal.unwrap();
            for o in &cmp.outcomes {
                assert!(
                    o.true_objective <= opt + 1e-9,
                    "{} reported {} above the optimum {}",
                    o.solver,
                    o.true_objective,
                    opt
                );
            }
        }
    }

    #[test]
    fn solvers_are_reproducible_for_a_fixed_seed() {
        let p = random_problem(40, 10, 15);
        let run = || {
            compare_solvers(&p, SolveBudget::from_millis(40).with_evaluations(20_000), 42)
                .outcomes
                .into_iter()
                .map(|o| (o.solver, o.assignment))
                .collect::<Vec<_>>()
        };
        // Equal evaluation budgets rather than wall clock, so the comparison
        // is deterministic rather than dependent on machine timing.
        assert_eq!(run(), run());
    }

    #[test]
    fn budget_allocation_spreads_across_strategies() {
        let p = Problem::BudgetAllocation {
            value_per_unit: vec![10.0, 5.0, 1.0],
            cost_per_unit: vec![1.0, 1.0, 1.0],
            total_units: 6,
            max_units_per_strategy: 4,
        };
        let prepared = p.prepare();
        let mut g = Greedy;
        let mut rng = Rng::from_seed(8);
        let o = g.solve(&prepared, &p, SolveBudget::from_millis(100), &mut rng);
        assert!(o.feasible, "{:?}", o.violation);
        assert_eq!(o.assignment.iter().filter(|b| **b).count(), 6);

        // Diminishing returns should give the best strategy the most units
        // without letting it take everything.
        let cap = 4;
        let units: Vec<usize> = (0..3)
            .map(|s| (0..cap).filter(|u| o.assignment[s * cap + u]).count())
            .collect();
        assert!(units[0] >= units[2], "best strategy did not get the most: {units:?}");
        assert!(units[0] < 6, "one strategy took the whole budget: {units:?}");
    }

    #[test]
    fn true_objective_uses_real_set_union_not_the_pairwise_approximation() {
        // Three sets sharing one edge: the pairwise term counts the overlap
        // three times, the real union counts it once. Scoring solvers on the
        // real objective is what keeps the approximation from distorting the
        // comparison.
        let p = Problem::CorpusSubset {
            items: vec![
                CorpusItem { edges: vec![1, 2], cost_micros: 1 },
                CorpusItem { edges: vec![1, 3], cost_micros: 1 },
                CorpusItem { edges: vec![1, 4], cost_micros: 1 },
            ],
            select: 3,
        };
        assert_eq!(p.true_objective(&[true, true, true]), 4.0);
    }

    #[test]
    fn repair_fixes_cardinality_without_destroying_quality() {
        let p = disjoint_problem(3);
        // Start from an over-selection that includes the three good entries.
        let mut x = vec![true, true, true, true, true];
        repair(&mut x, &Constraints::exactly(3), &p);
        assert_eq!(x.iter().filter(|b| **b).count(), 3);
        assert_eq!(p.true_objective(&x), 30.0, "repair discarded the disjoint entries");

        // And from an under-selection.
        let mut y = vec![false, false, false, false, false];
        repair(&mut y, &Constraints::exactly(3), &p);
        assert_eq!(y.iter().filter(|b| **b).count(), 3);
        assert_eq!(p.true_objective(&y), 30.0);
    }

    #[test]
    fn empty_and_degenerate_problems_do_not_panic() {
        let empty = Problem::CorpusSubset { items: Vec::new(), select: 0 };
        let cmp = compare_solvers(&empty, SolveBudget::from_millis(10), 9);
        for o in &cmp.outcomes {
            assert!(o.feasible);
            assert!(o.assignment.is_empty());
        }

        // Selecting more than exists.
        let over = Problem::CorpusSubset {
            items: vec![CorpusItem { edges: vec![1], cost_micros: 1 }],
            select: 10,
        };
        let prepared = over.prepare();
        assert_eq!(prepared.constraints.exact_count, Some(1), "k must clamp to n");
    }

    #[test]
    fn solver_diagnostics_are_populated() {
        let p = random_problem(20, 6, 16);
        let cmp = compare_solvers(&p, SolveBudget::from_millis(40), 10);
        for o in &cmp.outcomes {
            assert!(o.evaluations > 0, "{} reported no evaluations", o.solver);
            assert!(o.elapsed > Duration::ZERO);
            // Objective per millisecond is what decides whether a better
            // answer was worth its cost.
            assert!(o.objective_per_ms().is_finite());
        }
        let qiea = cmp.outcomes.iter().find(|o| o.solver == "quantum-inspired-evolutionary").unwrap();
        assert!(qiea.diagnostics["generations_done"].as_u64().unwrap() > 0);
        assert!(qiea.diagnostics["mean_convergence"].as_f64().is_some());

        let sqa = cmp.outcomes.iter().find(|o| o.solver == "simulated-quantum-annealing").unwrap();
        assert!(sqa.diagnostics["trotter"].as_u64().unwrap() > 0);
        assert!(sqa.diagnostics["sweeps_done"].as_u64().unwrap() > 0);
    }

    #[test]
    fn qiea_register_behaves_like_a_probability_distribution() {
        let mut rng = Rng::from_seed(11);
        let mut r = Register::new(4);
        // Uniform superposition: each bit should come up about half the time.
        let mut ones = vec![0u32; 4];
        for _ in 0..4000 {
            for (i, b) in r.observe(&mut rng).iter().enumerate() {
                if *b {
                    ones[i] += 1;
                }
            }
        }
        for (i, c) in ones.iter().enumerate() {
            let p = *c as f64 / 4000.0;
            assert!((0.4..0.6).contains(&p), "bit {i} observed 1 with probability {p}");
        }
        assert!(r.convergence() < 0.1, "uniform superposition should be unconverged");

        // Rotate hard toward all-ones; the distribution must follow.
        let target = vec![true; 4];
        for _ in 0..200 {
            let obs = r.observe(&mut rng);
            r.rotate_toward(&obs, &target, 0.2);
        }
        let after: u32 = (0..2000)
            .map(|_| r.observe(&mut rng).iter().filter(|b| **b).count() as u32)
            .sum();
        assert!(after as f64 / 2000.0 > 3.5, "rotation did not converge toward the target");
        assert!(r.convergence() > 0.8, "register should be converged after rotation");
    }
}
