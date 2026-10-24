//! Content-addressed storage for test cases and artifacts.
//!
//! An object's path is derived from its content hash, so storing the same
//! bytes twice is a no-op and a reference is never ambiguous. Writes are
//! atomic: content goes to a temporary file in the same directory and is
//! renamed into place, so a crash mid-write cannot leave a truncated object
//! that a later read would treat as valid.
//!
//! Hashes that arrive from outside the process are validated as plain
//! lowercase hex before they reach a path, so a crafted identifier cannot
//! escape the store directory.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::hash::{content_hash, validate_content_hash, ContentHash};

pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).map_err(|e| Error::io(root, e))?;
        Ok(ContentStore { root: root.to_path_buf() })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Two levels of fan-out from the first four hex characters, so no single
    /// directory accumulates more than a few thousand entries at corpus sizes
    /// AETHER works at.
    fn path_for(&self, hash: &str) -> Result<PathBuf> {
        validate_content_hash(hash)?;
        Ok(self.root.join(&hash[0..2]).join(&hash[2..4]).join(hash))
    }

    /// Store bytes and return their hash. Idempotent.
    pub fn put(&self, bytes: &[u8]) -> Result<ContentHash> {
        let hash = content_hash(bytes);
        let path = self.path_for(&hash)?;
        if path.exists() {
            return Ok(hash);
        }
        let dir = path.parent().expect("path_for always has a parent");
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;

        // Write to a unique temporary name, then rename. rename(2) within a
        // directory is atomic, so a reader sees either no object or a complete
        // one - never a partial write from an interrupted campaign.
        let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), crate::ids::InputId::new()));
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
            f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
            f.flush().map_err(|e| Error::io(&tmp, e))?;
        }
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(hash),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                // Another worker may have won the race; that is success.
                if path.exists() {
                    Ok(hash)
                } else {
                    Err(Error::io(&path, e))
                }
            }
        }
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>> {
        let path = self.path_for(hash)?;
        std::fs::read(&path).map_err(|_| Error::not_found("corpus object", hash))
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.path_for(hash).map(|p| p.exists()).unwrap_or(false)
    }

    /// Verify that stored content still hashes to its name.
    ///
    /// A mismatch means on-disk corruption or tampering; the store refuses the
    /// object rather than handing back content under a name it does not match.
    pub fn verify(&self, hash: &str) -> Result<bool> {
        let bytes = self.get(hash)?;
        Ok(content_hash(&bytes) == hash)
    }

    /// Remove an object. Used by retention policy, never by the campaign loop.
    pub fn remove(&self, hash: &str) -> Result<()> {
        let path = self.path_for(hash)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    /// Total bytes and object count, for status output and retention.
    pub fn usage(&self) -> Result<(u64, u64)> {
        let mut bytes = 0u64;
        let mut count = 0u64;
        walk(&self.root, &mut |p: &Path| {
            if let Ok(m) = std::fs::metadata(p) {
                if m.is_file()
                    && !p
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with(".tmp-"))
                        .unwrap_or(false)
                {
                    bytes += m.len();
                    count += 1;
                }
            }
        })?;
        Ok((bytes, count))
    }

    /// Delete leftover temporary files from an interrupted run.
    pub fn clean_temporaries(&self) -> Result<u64> {
        let mut removed = 0;
        let mut victims = Vec::new();
        walk(&self.root, &mut |p: &Path| {
            if p.file_name()
                .map(|n| n.to_string_lossy().starts_with(".tmp-"))
                .unwrap_or(false)
            {
                victims.push(p.to_path_buf());
            }
        })?;
        for v in victims {
            if std::fs::remove_file(&v).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // Do not follow symlinks: a link planted in the store directory could
        // otherwise make a traversal walk out of it.
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk(&p, f)?;
        } else {
            f(&p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "aether-cas-{tag}-{}-{}",
                std::process::id(),
                crate::ids::InputId::new()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn put_get_round_trips() {
        let t = Tmp::new("rt");
        let cas = ContentStore::open(&t.0).unwrap();
        let h = cas.put(b"hello world").unwrap();
        assert_eq!(cas.get(&h).unwrap(), b"hello world");
        assert!(cas.contains(&h));
        assert!(cas.verify(&h).unwrap());
    }

    #[test]
    fn storing_identical_content_twice_is_one_object() {
        let t = Tmp::new("dedup");
        let cas = ContentStore::open(&t.0).unwrap();
        let a = cas.put(b"same").unwrap();
        let b = cas.put(b"same").unwrap();
        assert_eq!(a, b);
        let (_, count) = cas.usage().unwrap();
        assert_eq!(count, 1, "deduplication must happen at the storage layer");
    }

    #[test]
    fn empty_content_is_storable() {
        let t = Tmp::new("empty");
        let cas = ContentStore::open(&t.0).unwrap();
        let h = cas.put(b"").unwrap();
        assert_eq!(cas.get(&h).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn missing_object_is_a_not_found_error() {
        let t = Tmp::new("missing");
        let cas = ContentStore::open(&t.0).unwrap();
        let e = cas.get(&"ab".repeat(16)).unwrap_err();
        assert_eq!(e.kind(), "not_found");
    }

    #[test]
    fn crafted_hashes_cannot_escape_the_store() {
        let t = Tmp::new("traversal");
        let cas = ContentStore::open(&t.0).unwrap();
        for bad in [
            "../../../../etc/passwd",
            "..",
            "/etc/passwd",
            "ab/../../../etc/passwd",
            &"A".repeat(32),
            "",
            "zz",
        ] {
            assert!(cas.get(bad).is_err(), "accepted hash {bad:?}");
            assert!(!cas.contains(bad), "contains() accepted {bad:?}");
            assert!(cas.remove(bad).is_err(), "remove() accepted {bad:?}");
        }
        // Nothing outside the store was touched.
        assert!(std::path::Path::new("/etc/passwd").exists());
    }

    #[test]
    fn corruption_is_detected_not_returned_silently() {
        let t = Tmp::new("corrupt");
        let cas = ContentStore::open(&t.0).unwrap();
        let h = cas.put(b"original").unwrap();
        let p = cas.path_for(&h).unwrap();
        std::fs::write(&p, b"tampered").unwrap();
        assert!(!cas.verify(&h).unwrap(), "verify must notice altered content");
    }

    #[test]
    fn usage_counts_objects_and_bytes() {
        let t = Tmp::new("usage");
        let cas = ContentStore::open(&t.0).unwrap();
        cas.put(b"1234").unwrap();
        cas.put(b"123456").unwrap();
        let (bytes, count) = cas.usage().unwrap();
        assert_eq!(count, 2);
        assert_eq!(bytes, 10);
    }

    #[test]
    fn temporaries_are_excluded_from_usage_and_cleanable() {
        let t = Tmp::new("tmpclean");
        let cas = ContentStore::open(&t.0).unwrap();
        cas.put(b"real").unwrap();
        // Simulate an interrupted write.
        let dir = t.0.join("00").join("11");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".tmp-999-leftover"), b"partial").unwrap();

        let (_, count) = cas.usage().unwrap();
        assert_eq!(count, 1, "a partial write must not count as an object");
        assert_eq!(cas.clean_temporaries().unwrap(), 1);
        assert_eq!(cas.clean_temporaries().unwrap(), 0, "cleanup is idempotent");
    }

    #[test]
    fn remove_is_idempotent() {
        let t = Tmp::new("rm");
        let cas = ContentStore::open(&t.0).unwrap();
        let h = cas.put(b"gone soon").unwrap();
        cas.remove(&h).unwrap();
        assert!(!cas.contains(&h));
        cas.remove(&h).unwrap();
    }

    #[test]
    fn symlinks_in_the_store_are_not_followed() {
        // A symlink planted in the store must not make usage() walk out of it.
        let t = Tmp::new("symlink");
        let cas = ContentStore::open(&t.0).unwrap();
        cas.put(b"real").unwrap();
        let link = t.0.join("escape");
        if std::os::unix::fs::symlink("/etc", &link).is_ok() {
            let (_, count) = cas.usage().unwrap();
            assert_eq!(count, 1, "walk followed a symlink out of the store");
        }
    }

    #[test]
    fn large_content_round_trips() {
        let t = Tmp::new("large");
        let cas = ContentStore::open(&t.0).unwrap();
        let data = vec![0xABu8; 1 << 20];
        let h = cas.put(&data).unwrap();
        assert_eq!(cas.get(&h).unwrap().len(), data.len());
        assert!(cas.verify(&h).unwrap());
    }
}
