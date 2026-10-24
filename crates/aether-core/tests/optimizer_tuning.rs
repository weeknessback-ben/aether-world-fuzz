//! Empirical tuning and evaluation of the optimisation lab.
//!
//! This is the harness behind every number quoted about the quantum-inspired
//! solvers. It sweeps hyperparameters, then compares the tuned solvers against
//! the classical baseline at equal wall-clock budget across many instances and
//! seeds, and reports both solution quality and what it cost to get.
//!
//! Run with:
//!   cargo test --release -p aether-core --test optimizer_tuning -- --nocapture

mod common;

use std::time::Duration;

use aether_core::intel::qubo::*;
use aether_core::rng::Rng;

/// Instance families, chosen to be the shapes a real corpus produces rather
/// than whatever is easiest to solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// Mostly disjoint coverage: greedy does very well here.
    Disjoint,
    /// Heavy overlap, so the choice of which entries to keep matters.
    Overlapping,
    /// A few broad entries plus many narrow ones, which is what a real corpus
    /// looks like after a while.
    Skewed,
}

impl Family {
    fn name(&self) -> &'static str {
        match self {
            Family::Disjoint => "disjoint",
            Family::Overlapping => "overlapping",
            Family::Skewed => "skewed",
        }
    }
}

fn instance(family: Family, n: usize, select: usize, seed: u64) -> Problem {
    let mut rng = Rng::from_seed(seed);
    let items: Vec<CorpusItem> = (0..n)
        .map(|i| {
            let edges: Vec<u32> = match family {
                Family::Disjoint => {
                    let base = (i * 25) as u32;
                    (0..rng.between(10, 25)).map(|k| base + k as u32).collect()
                }
                Family::Overlapping => {
                    // All drawn from a small universe, so entries collide.
                    (0..rng.between(15, 45))
                        .map(|_| rng.below(90) as u32)
                        .collect()
                }
                Family::Skewed => {
                    if i % 10 == 0 {
                        (0..rng.between(60, 120))
                            .map(|_| rng.below(400) as u32)
                            .collect()
                    } else {
                        (0..rng.between(3, 12))
                            .map(|_| rng.below(400) as u32)
                            .collect()
                    }
                }
            };
            let mut edges = edges;
            edges.sort_unstable();
            edges.dedup();
            CorpusItem {
                edges,
                cost_micros: rng.between(100, 4000) as u64,
            }
        })
        .collect();
    Problem::CorpusSubset { items, select }
}

/// Mean objective a configured solver reaches, relative to greedy, across
/// several instances and seeds. Above 1.0 means it beat the baseline.
fn evaluate<F>(make: F, budget_ms: u64, trials: u32) -> (f64, f64, f64)
where
    F: Fn() -> Box<dyn Solver>,
{
    let mut ratios = Vec::new();
    let mut times_ms = Vec::new();

    for family in [Family::Disjoint, Family::Overlapping, Family::Skewed] {
        for trial in 0..trials {
            let seed = 9000 + trial as u64 * 17 + family as u64;
            let p = instance(family, 60, 15, seed);
            let prepared = p.prepare();

            let mut baseline = Greedy;
            let mut brng = Rng::derive(seed, "greedy", 0);
            let base = baseline.solve(
                &prepared,
                &p,
                SolveBudget::from_millis(budget_ms),
                &mut brng,
            );

            let mut s = make();
            let mut rng = Rng::derive(seed, s.name(), 0);
            let got = s.solve(&prepared, &p, SolveBudget::from_millis(budget_ms), &mut rng);

            assert!(
                got.feasible,
                "{} produced an infeasible solution",
                got.solver
            );
            if base.true_objective > 0.0 {
                ratios.push(got.true_objective / base.true_objective);
            }
            times_ms.push(got.elapsed.as_secs_f64() * 1000.0);
        }
    }
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = ratios.iter().sum::<f64>() / ratios.len().max(1) as f64;
    let median = ratios[ratios.len() / 2];
    let mean_ms = times_ms.iter().sum::<f64>() / times_ms.len().max(1) as f64;
    (mean, median, mean_ms)
}

#[test]
fn tune_simulated_annealing() {
    println!("\n=== Simulated annealing sweep (objective relative to greedy, 25ms budget) ===");
    let mut best = (f64::NEG_INFINITY, String::new());
    for &sweeps in &[50u32, 200, 800] {
        for &restarts in &[1u32, 4, 16] {
            for &t0 in &[1.0f64, 10.0, 50.0] {
                let (mean, median, ms) = evaluate(
                    || {
                        Box::new(SimulatedAnnealing {
                            initial_temp: t0,
                            final_temp: 0.01,
                            sweeps,
                            restarts,
                        })
                    },
                    25,
                    4,
                );
                let label = format!("sweeps={sweeps:<4} restarts={restarts:<3} T0={t0:<5}");
                println!("  {label}  mean={mean:.4} median={median:.4} time={ms:5.1}ms");
                if mean > best.0 {
                    best = (mean, label);
                }
            }
        }
    }
    println!("  -> best: {} at {:.4}\n", best.1, best.0);
}

#[test]
fn tune_quantum_inspired_evolutionary() {
    println!("\n=== QIEA sweep (objective relative to greedy, 25ms budget) ===");
    let mut best = (f64::NEG_INFINITY, String::new());
    for &pop in &[8usize, 16, 32, 64] {
        for &theta_frac in &[0.01f64, 0.05, 0.15, 0.30] {
            for &catastrophe in &[0.0f64, 0.05] {
                let theta = theta_frac * std::f64::consts::PI;
                let (mean, median, ms) = evaluate(
                    || {
                        Box::new(Qiea {
                            population: pop,
                            generations: 100_000, // budget-limited, not generation-limited
                            theta,
                            catastrophe_rate: catastrophe,
                        })
                    },
                    25,
                    4,
                );
                let label =
                    format!("pop={pop:<3} theta={theta_frac:<5}pi catastrophe={catastrophe:<5}");
                println!("  {label}  mean={mean:.4} median={median:.4} time={ms:5.1}ms");
                if mean > best.0 {
                    best = (mean, label);
                }
            }
        }
    }
    println!("  -> best: {} at {:.4}\n", best.1, best.0);
}

#[test]
fn tune_simulated_quantum_annealing() {
    println!("\n=== Simulated quantum annealing sweep (objective relative to greedy, 25ms) ===");
    let mut best = (f64::NEG_INFINITY, String::new());
    for &trotter in &[2usize, 4, 8, 16, 32] {
        for &g0 in &[1.0f64, 3.0, 10.0] {
            for &temp in &[0.1f64, 0.5, 2.0] {
                let (mean, median, ms) = evaluate(
                    || {
                        Box::new(SimulatedQuantumAnnealing {
                            trotter,
                            gamma_initial: g0,
                            gamma_final: 0.05,
                            temperature: temp,
                            sweeps: 100_000, // budget-limited
                        })
                    },
                    25,
                    4,
                );
                let label = format!("trotter={trotter:<3} gamma0={g0:<5} T={temp:<4}");
                println!("  {label}  mean={mean:.4} median={median:.4} time={ms:5.1}ms");
                if mean > best.0 {
                    best = (mean, label);
                }
            }
        }
    }
    println!("  -> best: {} at {:.4}\n", best.1, best.0);
}

#[test]
fn experiment_f_classical_versus_quantum_inspired() {
    // Experiment F from the specification: the classical optimiser against
    // the quantum-inspired ones, at equal budget, with ground truth where the
    // instance is small enough to compute it.
    println!("\n=== Experiment F: classical vs quantum-inspired, equal budget ===");

    for &budget_ms in &[5u64, 25, 100] {
        println!("\n  budget = {budget_ms}ms");
        println!(
            "  {:<32} {:>10} {:>10} {:>10} {:>12}",
            "solver", "mean", "median", "worst", "mean time"
        );

        for name in [
            "simulated-annealing",
            "quantum-inspired-evolutionary",
            "simulated-quantum-annealing",
        ] {
            let make: Box<dyn Fn() -> Box<dyn Solver>> = match name {
                "simulated-annealing" => Box::new(|| {
                    Box::new(SimulatedAnnealing {
                        sweeps: 100_000,
                        restarts: 64,
                        ..Default::default()
                    })
                }),
                "quantum-inspired-evolutionary" => Box::new(|| {
                    Box::new(Qiea {
                        generations: 100_000,
                        ..Default::default()
                    })
                }),
                _ => Box::new(|| {
                    Box::new(SimulatedQuantumAnnealing {
                        sweeps: 100_000,
                        ..Default::default()
                    })
                }),
            };

            let mut ratios = Vec::new();
            let mut times = Vec::new();
            for family in [Family::Disjoint, Family::Overlapping, Family::Skewed] {
                for trial in 0..6u64 {
                    let seed = 4200 + trial * 31 + family as u64;
                    let p = instance(family, 60, 15, seed);
                    let prepared = p.prepare();

                    let mut g = Greedy;
                    let mut grng = Rng::derive(seed, "greedy", 0);
                    let base = g.solve(
                        &prepared,
                        &p,
                        SolveBudget::from_millis(budget_ms),
                        &mut grng,
                    );

                    let mut s = make();
                    let mut rng = Rng::derive(seed, s.name(), 0);
                    let o = s.solve(&prepared, &p, SolveBudget::from_millis(budget_ms), &mut rng);
                    assert!(o.feasible);
                    if base.true_objective > 0.0 {
                        ratios.push(o.true_objective / base.true_objective);
                    }
                    times.push(o.elapsed.as_secs_f64() * 1000.0);
                }
            }
            ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
            println!(
                "  {name:<32} {:>10.4} {:>10.4} {:>10.4} {:>10.1}ms",
                mean,
                ratios[ratios.len() / 2],
                ratios[0],
                times.iter().sum::<f64>() / times.len() as f64
            );
        }
    }

    // Quality against ground truth, on instances small enough to solve exactly.
    println!("\n  Fraction of the true optimum reached (n=16, k=5, exhaustive ground truth):");
    let mut totals: std::collections::BTreeMap<String, Vec<f64>> = Default::default();
    for family in [Family::Disjoint, Family::Overlapping, Family::Skewed] {
        for trial in 0..8u64 {
            let seed = 777 + trial * 13 + family as u64;
            let p = instance(family, 16, 5, seed);
            let cmp = compare_solvers(&p, SolveBudget::from_millis(25), seed);
            for o in &cmp.outcomes {
                if o.solver == "exhaustive" {
                    continue;
                }
                if let Some(q) = cmp.quality(&o.solver) {
                    totals.entry(o.solver.clone()).or_default().push(q);
                }
            }
        }
    }
    for (solver, qs) in &totals {
        let mean = qs.iter().sum::<f64>() / qs.len() as f64;
        let worst = qs.iter().copied().fold(f64::INFINITY, f64::min);
        let optimal_hits = qs.iter().filter(|q| **q >= 0.9999).count();
        println!(
            "  {solver:<32} mean={mean:.4} worst={worst:.4} optimal in {optimal_hits}/{} instances",
            qs.len()
        );
    }
    println!();
}

#[test]
fn experiment_f_budget_allocation_problem_shape() {
    // Max-coverage is submodular, which is exactly the case greedy has a
    // proven (1 - 1/e) guarantee on - a hard baseline to beat. Budget
    // allocation has a different shape: a concave per-strategy return under a
    // global cardinality constraint, with no submodularity guarantee for
    // greedy to lean on. If the quantum-inspired solvers help anywhere, this
    // is where it should show.
    println!("\n=== Experiment F (budget allocation): objective relative to greedy ===");
    println!(
        "  {:<32} {:>10} {:>10} {:>10} {:>12}",
        "solver", "mean", "median", "worst", "mean time"
    );

    let instances: Vec<Problem> = (0..12u64)
        .map(|seed| {
            let mut rng = Rng::from_seed(5000 + seed);
            let m = rng.between(4, 10);
            Problem::BudgetAllocation {
                value_per_unit: (0..m).map(|_| rng.unit() * 10.0 + 0.5).collect(),
                cost_per_unit: (0..m).map(|_| rng.unit() * 4.0 + 0.5).collect(),
                total_units: rng.between(6, 16),
                max_units_per_strategy: rng.between(3, 8),
            }
        })
        .collect();

    for name in [
        "simulated-annealing",
        "quantum-inspired-evolutionary",
        "simulated-quantum-annealing",
    ] {
        let make: Box<dyn Fn() -> Box<dyn Solver>> = match name {
            "simulated-annealing" => Box::new(|| Box::new(SimulatedAnnealing::default())),
            "quantum-inspired-evolutionary" => Box::new(|| Box::new(Qiea::default())),
            _ => Box::new(|| Box::new(SimulatedQuantumAnnealing::default())),
        };

        let mut ratios = Vec::new();
        let mut times = Vec::new();
        for (i, p) in instances.iter().enumerate() {
            let prepared = p.prepare();
            let seed = 5000 + i as u64;

            let mut g = Greedy;
            let mut grng = Rng::derive(seed, "greedy", 0);
            let base = g.solve(&prepared, p, SolveBudget::from_millis(25), &mut grng);

            let mut s = make();
            let mut rng = Rng::derive(seed, s.name(), 0);
            let o = s.solve(&prepared, p, SolveBudget::from_millis(25), &mut rng);
            assert!(o.feasible, "{} infeasible on budget allocation", o.solver);
            if base.true_objective > 0.0 {
                ratios.push(o.true_objective / base.true_objective);
            }
            times.push(o.elapsed.as_secs_f64() * 1000.0);
        }
        ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "  {name:<32} {:>10.4} {:>10.4} {:>10.4} {:>10.1}ms",
            ratios.iter().sum::<f64>() / ratios.len() as f64,
            ratios[ratios.len() / 2],
            ratios[0],
            times.iter().sum::<f64>() / times.len() as f64
        );
    }
    println!();
}

#[test]
fn quantum_inspired_solvers_never_beat_the_known_optimum() {
    // The integrity check behind every number above: if a solver reported
    // better than exhaustive search, the objective or the ground truth would
    // be wrong and the whole comparison meaningless.
    for family in [Family::Disjoint, Family::Overlapping, Family::Skewed] {
        for trial in 0..5u64 {
            let seed = 31337 + trial + family as u64 * 100;
            let p = instance(family, 15, 5, seed);
            let cmp = compare_solvers(&p, SolveBudget::from_millis(30), seed);
            let opt = cmp.optimal.expect("n=15 should have ground truth");
            for o in &cmp.outcomes {
                assert!(
                    o.true_objective <= opt + 1e-9,
                    "{} on {} reported {} above optimum {}",
                    o.solver,
                    family.name(),
                    o.true_objective,
                    opt
                );
                assert!(o.feasible, "{} infeasible on {}", o.solver, family.name());
                assert!(
                    o.elapsed < Duration::from_millis(2000),
                    "{} overran its budget: {:?}",
                    o.solver,
                    o.elapsed
                );
            }
        }
    }
}
