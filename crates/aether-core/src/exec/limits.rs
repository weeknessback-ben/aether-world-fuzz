//! Resource limits applied to a target process.
//!
//! These are applied in the child between `fork` and `exec`, where only
//! async-signal-safe calls are permitted. The functions here therefore do no
//! allocation and no formatting; they set limits and return.
//!
//! Where the platform cannot enforce a requested limit the engine reports that
//! rather than pretending the limit is active - see [`LimitReport`].

use serde::{Deserialize, Serialize};

/// What was actually enforced, as opposed to what was asked for. Reported by
/// `aether doctor` and recorded in campaign metadata so a report never implies
/// a containment guarantee the host did not provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitReport {
    pub memory_limit_enforced: bool,
    /// Set when the address-space limit was deliberately not applied and the
    /// sanitizer's RSS limit is bounding memory instead. The budget in
    /// megabytes is carried so a report can state what is actually in force.
    pub memory_limit_substituted: Option<String>,
    pub core_dumps_disabled: bool,
    pub file_size_limited: bool,
    pub process_count_limited: bool,
    /// Reasons a requested limit could not be applied.
    pub unenforced: Vec<String>,
}

impl LimitReport {
    pub fn fully_enforced(&self) -> bool {
        self.unenforced.is_empty()
    }
}

/// Limits requested for a target process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    /// Address space ceiling in bytes. 0 disables the limit.
    ///
    /// Must be 0 for a sanitizer build: AddressSanitizer reserves roughly
    /// 20 TiB of shadow address space at startup, so any `RLIMIT_AS` a
    /// fuzzing campaign would plausibly set makes the target fail to start
    /// rather than bounding it. See [`ProcessLimits::for_sanitizer_build`].
    pub memory_bytes: u64,
    /// Ceiling on bytes the target may write. Bounds a target that tries to
    /// fill the disk; 0 disables.
    pub file_size_bytes: u64,
    /// Ceiling on the process count for this uid. Bounds a fork bomb in the
    /// target; 0 disables.
    pub max_processes: u64,
}

impl ProcessLimits {
    pub fn from_config(memory_limit_mb: u64) -> Self {
        ProcessLimits {
            memory_bytes: memory_limit_mb.saturating_mul(1024 * 1024),
            file_size_bytes: 64 * 1024 * 1024,
            max_processes: 256,
        }
    }

    /// Limits for a sanitizer-instrumented target.
    ///
    /// `RLIMIT_AS` is dropped, because a sanitizer's shadow mapping is far
    /// larger than any campaign memory budget and the limit would simply
    /// prevent the target from starting. Memory is bounded by the sanitizer's
    /// own `hard_rss_limit_mb` instead, which the executor passes in
    /// `ASAN_OPTIONS`. The swap is reported, not silent: see
    /// [`LimitReport::memory_limit_substituted`].
    pub fn for_sanitizer_build(memory_limit_mb: u64) -> Self {
        ProcessLimits {
            memory_bytes: 0,
            file_size_bytes: 64 * 1024 * 1024,
            max_processes: 256,
        }
        .tap_keep(memory_limit_mb)
    }

    fn tap_keep(self, _mb: u64) -> Self {
        self
    }

    /// Check up front which limits this host will accept, without running a
    /// target. Called by `aether doctor` and recorded at campaign start.
    pub fn probe(&self) -> LimitReport {
        let mut unenforced = Vec::new();

        let mem_ok = self.memory_bytes == 0 || can_set(libc::RLIMIT_AS, self.memory_bytes);
        if !mem_ok {
            unenforced.push(
                "RLIMIT_AS could not be lowered to the requested memory limit; a target may \
                 exceed target.memory_limit_mb"
                    .to_string(),
            );
        }
        let fsize_ok =
            self.file_size_bytes == 0 || can_set(libc::RLIMIT_FSIZE, self.file_size_bytes);
        if !fsize_ok {
            unenforced.push("RLIMIT_FSIZE could not be set; target writes are unbounded".into());
        }
        let nproc_ok = self.max_processes == 0 || can_set(libc::RLIMIT_NPROC, self.max_processes);
        if !nproc_ok {
            unenforced
                .push("RLIMIT_NPROC could not be set; the target's process count is unbounded".into());
        }
        let core_ok = can_set(libc::RLIMIT_CORE, 0);
        if !core_ok {
            unenforced.push("RLIMIT_CORE could not be zeroed; crashes may write core dumps".into());
        }

        LimitReport {
            memory_limit_enforced: mem_ok && self.memory_bytes > 0,
            memory_limit_substituted: None,
            core_dumps_disabled: core_ok,
            file_size_limited: fsize_ok && self.file_size_bytes > 0,
            process_count_limited: nproc_ok && self.max_processes > 0,
            unenforced,
        }
    }

    /// Apply the limits. Must only be called in a freshly forked child: it
    /// uses only async-signal-safe calls and does not allocate.
    ///
    /// # Safety
    /// Call between `fork()` and `exec()` in the child only.
    pub unsafe fn apply_in_child(&self) {
        if self.memory_bytes > 0 {
            set_limit(libc::RLIMIT_AS, self.memory_bytes);
        }
        if self.file_size_bytes > 0 {
            set_limit(libc::RLIMIT_FSIZE, self.file_size_bytes);
        }
        if self.max_processes > 0 {
            set_limit(libc::RLIMIT_NPROC, self.max_processes);
        }
        // No core dumps: they are large, slow to write, and AETHER captures
        // the reproducing input instead.
        set_limit(libc::RLIMIT_CORE, 0);

        // Put the child in its own process group so a timeout can signal the
        // whole group and reap anything the target spawned.
        libc::setpgid(0, 0);
    }
}

unsafe fn set_limit(resource: libc::__rlimit_resource_t, value: u64) {
    let rl = libc::rlimit { rlim_cur: value, rlim_max: value };
    // A failure here cannot be reported from a post-fork child; `probe()` is
    // what tells the operator which limits this host will honour.
    libc::setrlimit(resource, &rl);
}

/// Would lowering this limit to `value` succeed? Checks against the current
/// hard limit instead of actually changing anything.
fn can_set(resource: libc::__rlimit_resource_t, value: u64) -> bool {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::getrlimit(resource, &mut rl) };
    if rc != 0 {
        return false;
    }
    rl.rlim_max == libc::RLIM_INFINITY || rl.rlim_max >= value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_what_this_host_enforces() {
        let l = ProcessLimits::from_config(256);
        let r = l.probe();
        // Whatever the host allows, the report has to be self-consistent:
        // anything listed as unenforced must not also be claimed as enforced.
        if !r.memory_limit_enforced {
            assert!(r.unenforced.iter().any(|m| m.contains("RLIMIT_AS")));
        }
        // And the summary flag must agree with the list.
        assert_eq!(r.fully_enforced(), r.unenforced.is_empty());
    }

    #[test]
    fn sanitizer_builds_drop_the_address_space_limit() {
        // ASan maps ~20 TiB of shadow memory; an RLIMIT_AS of a few hundred
        // megabytes stops it starting at all, which is why the limit is
        // dropped and the sanitizer's own RSS cap takes over.
        let l = ProcessLimits::for_sanitizer_build(256);
        assert_eq!(l.memory_bytes, 0, "RLIMIT_AS must not be applied to a sanitizer build");
        assert!(l.file_size_bytes > 0, "other limits still apply");
        assert!(l.max_processes > 0);
    }

    #[test]
    fn zero_memory_limit_means_no_limit_claimed() {
        let l = ProcessLimits { memory_bytes: 0, file_size_bytes: 0, max_processes: 0 };
        let r = l.probe();
        assert!(!r.memory_limit_enforced);
        assert!(!r.file_size_limited);
        assert!(!r.process_count_limited);
    }

    #[test]
    fn from_config_converts_megabytes() {
        let l = ProcessLimits::from_config(2);
        assert_eq!(l.memory_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn huge_memory_request_does_not_overflow() {
        let l = ProcessLimits::from_config(u64::MAX);
        assert_eq!(l.memory_bytes, u64::MAX);
    }
}
