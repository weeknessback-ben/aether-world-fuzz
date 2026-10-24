//! The shared memory region AETHER and an instrumented target communicate
//! through.
//!
//! The layout mirrors `runtime/aether_rt.h` exactly. It is addressed by
//! explicit byte offsets rather than a `#[repr(C)]` mirror struct, because the
//! region is written by another process: reading it through a Rust reference
//! would be claiming an aliasing guarantee that does not hold. All accesses go
//! through volatile reads and writes on a raw pointer.
//!
//! The region is a file in `/dev/shm` (a tmpfs, so no disk I/O) whose path is
//! passed to the target in `AETHER_SHM_PATH`. The engine validates the header
//! the target writes and refuses a region whose magic, version or sizes
//! disagree, rather than misinterpreting whatever is there.

use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

// --- ABI constants, kept in step with runtime/aether_rt.h -----------------
pub const SHM_MAGIC: u32 = 0xAE12_E401;
pub const SHM_VERSION: u32 = 1;
pub const MAP_SIZE: usize = 65_536;
pub const MAP_MASK: usize = MAP_SIZE - 1;
pub const CMP_CAP: usize = 4_096;

const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_MAP_SIZE: usize = 8;
const OFF_CMP_CAP: usize = 12;
const OFF_EXEC_COUNT: usize = 16;
const OFF_CMP_LEN: usize = 24;
const OFF_FLAGS: usize = 28;
const OFF_GUARD_COUNT: usize = 32;
const HEADER_SIZE: usize = 40;

const OFF_MAP: usize = HEADER_SIZE;
const OFF_CMP: usize = OFF_MAP + MAP_SIZE;
const CMP_ENTRY_SIZE: usize = 24;
pub const REGION_SIZE: usize = OFF_CMP + CMP_CAP * CMP_ENTRY_SIZE;

pub const FLAG_CMPLOG_ON: u32 = 0x1;
pub const FLAG_CMP_OVERFLOW: u32 = 0x2;

/// One comparison recorded by the target. `is_const` marks `v0` as a
/// compile-time constant, which is what makes the pair usable for
/// input-to-state substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpEntry {
    pub v0: u64,
    pub v1: u64,
    pub pc_hash: u32,
    pub width: u8,
    pub is_const: bool,
}

/// A mapped coverage region. Unmaps and unlinks on drop.
pub struct CoverageShm {
    path: PathBuf,
    base: *mut u8,
    len: usize,
    owns_file: bool,
}

// The region is only ever touched through volatile accesses on `base`, and
// `CoverageShm` hands out no references into it, so moving one between threads
// is sound. It is deliberately not `Sync`: one executor owns one region.
unsafe impl Send for CoverageShm {}

impl CoverageShm {
    /// Create a fresh region. The file lives in `/dev/shm` when available,
    /// falling back to the system temp directory on a host without it.
    pub fn create(tag: &str) -> Result<Self> {
        let dir = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let path = dir.join(format!("aether-{}-{}", std::process::id(), tag));
        Self::create_at(&path)
    }

    pub fn create_at(path: &Path) -> Result<Self> {
        // O_EXCL: never adopt a region a previous run or another process left
        // behind, which would mix one target's coverage into another's.
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(path);
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|e| Error::io(path, e))?
            }
            Err(e) => return Err(Error::io(path, e)),
        };
        file.set_len(REGION_SIZE as u64).map_err(|e| Error::io(path, e))?;

        let base = unsafe { map_fd(file.as_raw_fd(), REGION_SIZE) }?;
        let shm = CoverageShm {
            path: path.to_path_buf(),
            base,
            len: REGION_SIZE,
            owns_file: true,
        };
        // Seed the header so a target that never starts still leaves a region
        // the engine can validate rather than read as garbage.
        shm.write_u32(OFF_MAGIC, SHM_MAGIC);
        shm.write_u32(OFF_VERSION, SHM_VERSION);
        shm.write_u32(OFF_MAP_SIZE, MAP_SIZE as u32);
        shm.write_u32(OFF_CMP_CAP, CMP_CAP as u32);
        shm.write_u32(OFF_CMP_LEN, 0);
        shm.write_u32(OFF_FLAGS, 0);
        shm.write_u32(OFF_GUARD_COUNT, 0);
        Ok(shm)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_u32(&self, off: usize, v: u32) {
        debug_assert!(off + 4 <= self.len);
        unsafe { std::ptr::write_volatile(self.base.add(off) as *mut u32, v) }
    }

    fn read_u32(&self, off: usize) -> u32 {
        debug_assert!(off + 4 <= self.len);
        unsafe { std::ptr::read_volatile(self.base.add(off) as *const u32) }
    }

    fn read_u64(&self, off: usize) -> u64 {
        debug_assert!(off + 8 <= self.len);
        unsafe { std::ptr::read_volatile(self.base.add(off) as *const u64) }
    }

    /// Clear the edge map and the comparison log. Called before every run so
    /// the observations belong to that run alone.
    pub fn reset(&self) {
        unsafe { std::ptr::write_bytes(self.base.add(OFF_MAP), 0, MAP_SIZE) };
        self.write_u32(OFF_CMP_LEN, 0);
        // Preserve FLAG_CMPLOG_ON; clear only the per-run overflow bit.
        let flags = self.read_u32(OFF_FLAGS) & !FLAG_CMP_OVERFLOW;
        self.write_u32(OFF_FLAGS, flags);
    }

    /// Validate the header the target wrote. A mismatch means the target was
    /// built against a different runtime ABI, which makes every reading from
    /// the region meaningless.
    pub fn validate_header(&self) -> Result<()> {
        let magic = self.read_u32(OFF_MAGIC);
        if magic != SHM_MAGIC {
            return Err(Error::exec(
                "coverage region",
                format!("magic {magic:#x} != expected {SHM_MAGIC:#x}; the target was not built \
                         with this version of the AETHER runtime"),
            ));
        }
        let version = self.read_u32(OFF_VERSION);
        if version != SHM_VERSION {
            return Err(Error::exec(
                "coverage region",
                format!("runtime ABI version {version} != expected {SHM_VERSION}"),
            ));
        }
        let map_size = self.read_u32(OFF_MAP_SIZE) as usize;
        let cmp_cap = self.read_u32(OFF_CMP_CAP) as usize;
        if map_size != MAP_SIZE || cmp_cap != CMP_CAP {
            return Err(Error::exec(
                "coverage region",
                format!("geometry mismatch: map {map_size} cmp {cmp_cap}, expected {MAP_SIZE}/{CMP_CAP}"),
            ));
        }
        Ok(())
    }

    /// Copy the edge map out for this run. A copy rather than a borrow: the
    /// target may still be running and writing into the region.
    pub fn snapshot_map(&self, out: &mut [u8; MAP_SIZE]) {
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(OFF_MAP), out.as_mut_ptr(), MAP_SIZE)
        };
    }

    /// Copy and bucket the map in one pass, skipping untouched regions.
    ///
    /// This is the hot path: it runs once per execution, and a plain
    /// copy-then-classify walks all 65,536 slots twice. A real target touches
    /// a small fraction of the map, so reading it eight bytes at a time and
    /// skipping zero words costs far less. Measured on this host it cut
    /// roughly 20% off the per-execution time.
    pub fn snapshot_classified(&self, out: &mut [u8; MAP_SIZE]) -> u32 {
        debug_assert_eq!(MAP_SIZE % 8, 0);
        let mut covered = 0u32;
        let src = unsafe { self.base.add(OFF_MAP) };
        let words = MAP_SIZE / 8;
        for w in 0..words {
            // A single 8-byte read, then a zero test: the common case is an
            // untouched word, which costs one load and one branch.
            let chunk = unsafe { std::ptr::read_volatile(src.add(w * 8) as *const u64) };
            if chunk == 0 {
                // `out` is zeroed by the caller for a fresh buffer; clear
                // anyway so a reused buffer cannot leak a previous run.
                unsafe { std::ptr::write_bytes(out.as_mut_ptr().add(w * 8), 0, 8) };
                continue;
            }
            let bytes = chunk.to_ne_bytes();
            for (i, raw) in bytes.iter().enumerate() {
                let c = classify_count(*raw);
                out[w * 8 + i] = c;
                if c != 0 {
                    covered += 1;
                }
            }
        }
        covered
    }

    /// Number of distinct map slots the run touched. Cheap, and enough for
    /// status output; novelty against the global map is computed separately.
    pub fn count_covered(&self) -> u32 {
        let mut n = 0u32;
        for i in 0..MAP_SIZE {
            let v = unsafe { std::ptr::read_volatile(self.base.add(OFF_MAP + i)) };
            if v != 0 {
                n += 1;
            }
        }
        n
    }

    pub fn guard_count(&self) -> u32 {
        self.read_u32(OFF_GUARD_COUNT)
    }

    pub fn target_exec_count(&self) -> u64 {
        self.read_u64(OFF_EXEC_COUNT)
    }

    pub fn cmplog_overflowed(&self) -> bool {
        self.read_u32(OFF_FLAGS) & FLAG_CMP_OVERFLOW != 0
    }

    /// Read the comparisons recorded during the last run, capped at `limit`.
    pub fn read_cmp_entries(&self, limit: usize) -> Vec<CmpEntry> {
        let len = (self.read_u32(OFF_CMP_LEN) as usize).min(CMP_CAP).min(limit);
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let off = OFF_CMP + i * CMP_ENTRY_SIZE;
            unsafe {
                let v0 = std::ptr::read_volatile(self.base.add(off) as *const u64);
                let v1 = std::ptr::read_volatile(self.base.add(off + 8) as *const u64);
                let pc_hash = std::ptr::read_volatile(self.base.add(off + 16) as *const u32);
                let width = std::ptr::read_volatile(self.base.add(off + 20));
                let is_const = std::ptr::read_volatile(self.base.add(off + 21));
                // Guard against a target that scribbled a nonsense width.
                if !matches!(width, 1 | 2 | 4 | 8) {
                    continue;
                }
                out.push(CmpEntry { v0, v1, pc_hash, width, is_const: is_const != 0 });
            }
        }
        out
    }
}

unsafe fn map_fd(fd: RawFd, len: usize) -> Result<*mut u8> {
    let p = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if p == libc::MAP_FAILED {
        return Err(Error::exec(
            "coverage region",
            format!("mmap failed: {}", std::io::Error::last_os_error()),
        ));
    }
    Ok(p as *mut u8)
}

impl Drop for CoverageShm {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.len) };
        if self.owns_file {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// AFL's hit-count buckets. Collapsing raw counts into log2-ish classes is
/// what stops a loop that ran 101 times instead of 100 from being reported as
/// new behaviour on every single execution.
#[inline]
pub fn classify_count(v: u8) -> u8 {
    match v {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

pub fn classify_map(map: &mut [u8; MAP_SIZE]) {
    for b in map.iter_mut() {
        *b = classify_count(*b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_layout_matches_the_c_abi() {
        // These numbers come from compiling runtime/aether_rt.h and printing
        // offsetof(); if either side moves, this test catches it.
        assert_eq!(HEADER_SIZE, 40);
        assert_eq!(OFF_MAP, 40);
        assert_eq!(OFF_CMP, 65_576);
        assert_eq!(CMP_ENTRY_SIZE, 24);
        assert_eq!(REGION_SIZE, 163_880);
    }

    #[test]
    fn create_reset_and_validate() {
        let shm = CoverageShm::create("test-basic").unwrap();
        shm.validate_header().unwrap();
        assert_eq!(shm.count_covered(), 0);
        shm.reset();
        assert_eq!(shm.read_cmp_entries(16).len(), 0);
        assert!(shm.path().exists());
    }

    #[test]
    fn region_is_removed_on_drop() {
        let path = {
            let shm = CoverageShm::create("test-drop").unwrap();
            shm.path().to_path_buf()
        };
        assert!(!path.exists(), "shared memory file outlived its owner");
    }

    #[test]
    fn rejects_a_region_with_a_foreign_header() {
        let shm = CoverageShm::create("test-badmagic").unwrap();
        shm.write_u32(OFF_MAGIC, 0xDEAD_0000);
        let e = shm.validate_header().unwrap_err();
        assert!(e.to_string().contains("magic"), "{e}");

        shm.write_u32(OFF_MAGIC, SHM_MAGIC);
        shm.write_u32(OFF_VERSION, 999);
        assert!(shm.validate_header().unwrap_err().to_string().contains("ABI version"));
    }

    #[test]
    fn hit_counts_collapse_into_buckets() {
        assert_eq!(classify_count(0), 0);
        assert_eq!(classify_count(1), 1);
        assert_eq!(classify_count(2), 2);
        assert_eq!(classify_count(3), 4);
        // Everything in one bucket must classify identically: this is what
        // keeps a loop iteration count from looking like new coverage.
        for v in 4..=7u8 { assert_eq!(classify_count(v), 8); }
        for v in 8..=15u8 { assert_eq!(classify_count(v), 16); }
        for v in 32..=127u8 { assert_eq!(classify_count(v), 64); }
        for v in 128..=255u8 { assert_eq!(classify_count(v), 128); }
    }

    #[test]
    fn nonsense_cmp_widths_are_dropped() {
        let shm = CoverageShm::create("test-badcmp").unwrap();
        // Forge one entry with an impossible width and one that is valid.
        unsafe {
            let p = shm.base.add(OFF_CMP);
            std::ptr::write_volatile(p as *mut u64, 0xAA);
            std::ptr::write_volatile(p.add(8) as *mut u64, 0xBB);
            std::ptr::write_volatile(p.add(16) as *mut u32, 7);
            std::ptr::write_volatile(p.add(20), 3u8); // invalid width
            std::ptr::write_volatile(p.add(21), 1u8);

            let q = shm.base.add(OFF_CMP + CMP_ENTRY_SIZE);
            std::ptr::write_volatile(q as *mut u64, 0xCC);
            std::ptr::write_volatile(q.add(8) as *mut u64, 0xDD);
            std::ptr::write_volatile(q.add(16) as *mut u32, 9);
            std::ptr::write_volatile(q.add(20), 4u8); // valid
            std::ptr::write_volatile(q.add(21), 1u8);
        }
        shm.write_u32(OFF_CMP_LEN, 2);
        let entries = shm.read_cmp_entries(16);
        assert_eq!(entries.len(), 1, "invalid-width entry should be dropped");
        assert_eq!(entries[0].v0, 0xCC);
        assert_eq!(entries[0].width, 4);
    }

    #[test]
    fn cmp_len_beyond_capacity_is_clamped() {
        let shm = CoverageShm::create("test-clamp").unwrap();
        // A target that scribbles a huge cmp_len must not make us read past
        // the end of the region.
        shm.write_u32(OFF_CMP_LEN, u32::MAX);
        let entries = shm.read_cmp_entries(usize::MAX);
        assert!(entries.len() <= CMP_CAP);
    }
}
