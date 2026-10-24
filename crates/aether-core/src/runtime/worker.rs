//! Worker pool for multi-worker campaigns.
//!
//! Scope, stated plainly: this is the **local** worker abstraction. Each worker
//! is an OS thread with its own executor, its own coverage region, its own
//! scratch directory and its own RNG stream derived from
//! `(campaign_seed, worker_index)`, so adding a worker does not perturb the
//! streams the existing workers draw from and a fixed seed still replays.
//!
//! Workers coordinate through [`SharedState`]: one lock around the corpus and
//! the metadata store. That is the right shape at the scale AETHER runs at -
//! a handful of workers each executing a few thousand times a second, where
//! the lock is held only for a corpus insert and not during execution.
//!
//! Remote workers are **not implemented**. [`WorkerDescriptor`] and
//! [`WorkerTransport`] define the interface a remote implementation would
//! satisfy - registration, capability negotiation, leasing, heartbeats, result
//! delivery - and [`LocalTransport`] is the only implementation. Nothing here
//! pretends otherwise, and `aether doctor` reports distributed execution as
//! unavailable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// What a worker can do, negotiated at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub edge_coverage: bool,
    pub comparison_log: bool,
    pub fork_server: bool,
    pub sanitizer_oracle: bool,
    /// Target identifiers this worker has a usable build for.
    pub targets: Vec<String>,
    pub max_concurrent_tasks: u32,
}

/// Identity and state of one worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDescriptor {
    pub id: String,
    pub index: u32,
    pub kind: WorkerKind,
    pub capabilities: WorkerCapabilities,
    /// Epoch milliseconds of the last heartbeat. A remote implementation would
    /// use this to detect a worker that stopped reporting; the local transport
    /// cannot lose a worker without the thread dying, which is observed
    /// directly.
    pub last_heartbeat_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerKind {
    /// A thread in this process.
    Local,
    /// Another process or machine. No implementation exists.
    Remote,
}

/// One unit of work leased to a worker.
#[derive(Debug, Clone)]
pub struct Task {
    pub id: u64,
    /// Strategy the scheduler chose.
    pub strategy_arm: usize,
    pub budget: u32,
}

/// What a worker reports back.
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub task_id: u64,
    pub worker_index: u32,
    pub executions: u64,
    pub value: f64,
    pub cost_micros: u64,
    pub new_edges: u64,
    pub findings: u32,
    pub retained_inputs: u32,
}

/// How tasks reach workers and results come back.
///
/// The interface a remote implementation would satisfy. Only
/// [`LocalTransport`] exists.
pub trait WorkerTransport: Send + Sync {
    fn register(&self, descriptor: WorkerDescriptor) -> Result<()>;
    fn lease(&self, worker_index: u32) -> Result<Option<Task>>;
    fn complete(&self, result: TaskResult) -> Result<()>;
    fn heartbeat(&self, worker_index: u32) -> Result<()>;
    /// Workers whose heartbeat is older than `timeout`. Always empty for the
    /// local transport, where a dead worker means a dead thread.
    fn stale_workers(&self, timeout: Duration) -> Vec<u32>;
}

/// In-process transport over channels.
pub struct LocalTransport {
    tasks: Mutex<std::collections::VecDeque<Task>>,
    results: Mutex<Vec<TaskResult>>,
    workers: Mutex<Vec<WorkerDescriptor>>,
    next_task_id: AtomicU64,
}

impl Default for LocalTransport {
    fn default() -> Self {
        LocalTransport {
            tasks: Mutex::new(std::collections::VecDeque::new()),
            results: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            next_task_id: AtomicU64::new(1),
        }
    }
}

impl LocalTransport {
    /// Queue a task. Returns its id.
    pub fn submit(&self, strategy_arm: usize, budget: u32) -> u64 {
        let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        let mut q = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(Task {
            id,
            strategy_arm,
            budget,
        });
        id
    }

    pub fn take_results(&self) -> Vec<TaskResult> {
        let mut r = self.results.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *r)
    }

    pub fn queue_depth(&self) -> usize {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn registered(&self) -> Vec<WorkerDescriptor> {
        self.workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl WorkerTransport for LocalTransport {
    fn register(&self, descriptor: WorkerDescriptor) -> Result<()> {
        let mut w = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        // Re-registration replaces, so a restarted worker does not appear twice.
        w.retain(|d| d.index != descriptor.index);
        w.push(descriptor);
        Ok(())
    }

    fn lease(&self, _worker_index: u32) -> Result<Option<Task>> {
        let mut q = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        Ok(q.pop_front())
    }

    fn complete(&self, result: TaskResult) -> Result<()> {
        let mut r = self.results.lock().unwrap_or_else(|e| e.into_inner());
        r.push(result);
        Ok(())
    }

    fn heartbeat(&self, worker_index: u32) -> Result<()> {
        let mut w = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = w.iter_mut().find(|d| d.index == worker_index) {
            d.last_heartbeat_ms = crate::time::now_millis();
        }
        Ok(())
    }

    fn stale_workers(&self, _timeout: Duration) -> Vec<u32> {
        // A local worker cannot stop heartbeating without its thread ending,
        // which the pool observes directly when the join handle finishes.
        Vec::new()
    }
}

/// Backpressure: how much work may be queued before submission waits.
///
/// Without a bound the controller would queue faster than workers drain,
/// and a cancellation would have to discard a large backlog before stopping.
pub struct Backpressure {
    max_queue_depth: usize,
}

impl Backpressure {
    pub fn new(workers: u32) -> Self {
        // Two tasks in flight per worker: enough that a worker never idles
        // waiting for the controller, small enough that cancellation is prompt.
        Backpressure {
            max_queue_depth: (workers as usize * 2).max(2),
        }
    }

    pub fn should_submit(&self, queue_depth: usize) -> bool {
        queue_depth < self.max_queue_depth
    }

    pub fn max_queue_depth(&self) -> usize {
        self.max_queue_depth
    }
}

/// Estimated worth of giving a task to a worker, used when more than one could
/// take it.
///
/// Deliberately not "more workers is proportionally better": a task whose
/// expected benefit is low or that duplicates work already in flight is worth
/// less, and a scheduler that ignored that would spend a second worker
/// re-deriving what the first is already finding.
pub fn task_priority(
    expected_value: f64,
    estimated_cost_ms: f64,
    uncertainty: f64,
    redundancy: f64,
) -> f64 {
    let cost = estimated_cost_ms.max(0.1);
    // Uncertainty is a bonus: an unexplored option is worth trying.
    // Redundancy is a penalty: duplicated work is worth less.
    (expected_value * (1.0 + uncertainty)) / cost / (1.0 + redundancy)
}

/// Shared, lock-guarded state the local workers coordinate through.
pub struct SharedState<T> {
    inner: Arc<Mutex<T>>,
    /// Total time spent waiting for the lock, so contention is measurable
    /// rather than guessed at when scaling is disappointing.
    contention_micros: Arc<AtomicU64>,
}

impl<T> Clone for SharedState<T> {
    fn clone(&self) -> Self {
        SharedState {
            inner: self.inner.clone(),
            contention_micros: self.contention_micros.clone(),
        }
    }
}

impl<T> SharedState<T> {
    pub fn new(value: T) -> Self {
        SharedState {
            inner: Arc::new(Mutex::new(value)),
            contention_micros: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run `f` under the lock, accounting for how long acquiring it took.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let start = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.contention_micros
            .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        f(&mut guard)
    }

    pub fn contention_micros(&self) -> u64 {
        self.contention_micros.load(Ordering::Relaxed)
    }
}

/// Whether distributed execution is available. It is not.
pub fn distributed_available() -> (bool, &'static str) {
    (
        false,
        "Remote workers are not implemented. The WorkerTransport interface defines \
         registration, capability negotiation, leasing, heartbeats and result delivery, \
         but only the in-process LocalTransport exists; multi-worker campaigns run as \
         threads in one process.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(index: u32) -> WorkerDescriptor {
        WorkerDescriptor {
            id: format!("worker-{index}"),
            index,
            kind: WorkerKind::Local,
            capabilities: WorkerCapabilities {
                edge_coverage: true,
                comparison_log: true,
                fork_server: true,
                sanitizer_oracle: false,
                targets: vec!["demo".into()],
                max_concurrent_tasks: 1,
            },
            last_heartbeat_ms: crate::time::now_millis(),
        }
    }

    #[test]
    fn tasks_are_leased_once_each() {
        // Two workers must not both execute the same task.
        let t = LocalTransport::default();
        t.register(descriptor(0)).unwrap();
        t.register(descriptor(1)).unwrap();
        let a = t.submit(0, 32);
        let b = t.submit(1, 32);

        let first = t.lease(0).unwrap().unwrap();
        let second = t.lease(1).unwrap().unwrap();
        assert_ne!(first.id, second.id, "a task was leased twice");
        assert_eq!(
            [first.id, second.id]
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            [a, b].iter().copied().collect()
        );
        assert!(t.lease(0).unwrap().is_none(), "queue should be drained");
    }

    #[test]
    fn results_are_collected_and_drained_once() {
        let t = LocalTransport::default();
        t.complete(TaskResult {
            task_id: 1,
            worker_index: 0,
            executions: 32,
            value: 5.0,
            cost_micros: 1000,
            new_edges: 2,
            findings: 0,
            retained_inputs: 1,
        })
        .unwrap();
        assert_eq!(t.take_results().len(), 1);
        assert!(
            t.take_results().is_empty(),
            "results must not be delivered twice"
        );
    }

    #[test]
    fn re_registration_replaces_rather_than_duplicating() {
        let t = LocalTransport::default();
        t.register(descriptor(0)).unwrap();
        t.register(descriptor(0)).unwrap();
        assert_eq!(t.registered().len(), 1);
    }

    #[test]
    fn heartbeats_update_the_descriptor() {
        let t = LocalTransport::default();
        let mut d = descriptor(0);
        d.last_heartbeat_ms = 1;
        t.register(d).unwrap();
        t.heartbeat(0).unwrap();
        assert!(t.registered()[0].last_heartbeat_ms > 1);
        // A heartbeat for an unknown worker is harmless.
        t.heartbeat(99).unwrap();
    }

    #[test]
    fn local_transport_never_reports_stale_workers() {
        // A local worker cannot stop heartbeating without its thread ending.
        let t = LocalTransport::default();
        let mut d = descriptor(0);
        d.last_heartbeat_ms = 0;
        t.register(d).unwrap();
        assert!(t.stale_workers(Duration::from_millis(1)).is_empty());
    }

    #[test]
    fn backpressure_bounds_the_queue() {
        let bp = Backpressure::new(4);
        assert!(bp.should_submit(0));
        assert!(bp.should_submit(bp.max_queue_depth() - 1));
        assert!(!bp.should_submit(bp.max_queue_depth()));
        // Even a single worker gets some slack.
        assert!(Backpressure::new(1).max_queue_depth() >= 2);
    }

    #[test]
    fn task_priority_accounts_for_cost_uncertainty_and_redundancy() {
        let base = task_priority(10.0, 10.0, 0.0, 0.0);
        assert!(
            task_priority(10.0, 1.0, 0.0, 0.0) > base,
            "cheaper work should rank higher"
        );
        assert!(
            task_priority(10.0, 10.0, 1.0, 0.0) > base,
            "an unexplored option should get a bonus"
        );
        assert!(
            task_priority(10.0, 10.0, 0.0, 1.0) < base,
            "duplicated work should rank lower"
        );
        assert!(
            task_priority(10.0, 0.0, 0.0, 0.0).is_finite(),
            "zero cost must not divide by zero"
        );
    }

    #[test]
    fn shared_state_serialises_access_and_measures_contention() {
        let s = SharedState::new(0u64);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s2 = s.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    s2.with(|v| *v += 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(s.with(|v| *v), 4000, "updates were lost under concurrency");
        // Contention is tracked so disappointing scaling can be diagnosed
        // rather than guessed at.
        let _ = s.contention_micros();
    }

    #[test]
    fn distributed_execution_is_reported_unavailable() {
        let (available, reason) = distributed_available();
        assert!(!available);
        assert!(reason.contains("not implemented"), "{reason}");
        assert!(
            reason.contains("LocalTransport"),
            "should name what does exist: {reason}"
        );
    }
}
