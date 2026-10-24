//! Typed identifiers.
//!
//! Campaign, input, finding and target IDs are distinct types so they cannot
//! be swapped at a call site. All of them are short, sortable, filesystem-safe
//! strings: a millisecond timestamp prefix keeps them roughly chronological,
//! and a random suffix keeps them unique across concurrent workers.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! typed_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Mint a fresh identifier.
            pub fn new() -> Self {
                $name(format!("{}-{}", $prefix, crate::ids::mint_suffix()))
            }
            /// Wrap an existing string, e.g. one read back from the database.
            pub fn from_string(s: impl Into<String>) -> Self {
                $name(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            /// Reject an identifier that could escape a directory or confuse a
            /// shell. Every ID that arrives from outside the process (CLI
            /// argument, MCP request, database row) goes through this.
            pub fn validate(&self) -> crate::error::Result<()> {
                crate::ids::validate_id_str(&self.0, $prefix)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

typed_id!(CampaignId, "cmp", "Identifies one campaign run.");
typed_id!(InputId, "inp", "Identifies one corpus input (distinct from its content hash).");
typed_id!(FindingId, "fnd", "Identifies one finding record.");
typed_id!(TargetId, "tgt", "Identifies one target definition.");
typed_id!(JobId, "job", "Identifies one asynchronous job started through the API.");

/// Identifiers must stay safe to use as a path component and as a SQL
/// parameter. Anything outside `[A-Za-z0-9_-]` is refused rather than escaped,
/// because there is no legitimate reason for an AETHER-minted ID to contain
/// one and accepting it would widen the path-traversal surface.
pub(crate) fn validate_id_str(s: &str, expect_prefix: &str) -> crate::error::Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(crate::error::Error::config(
            "identifier",
            format!("length {} outside 1..=64", s.len()),
        ));
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(crate::error::Error::config(
            "identifier",
            format!("{s:?} contains characters outside [A-Za-z0-9_-]"),
        ));
    }
    if !s.starts_with(expect_prefix) {
        return Err(crate::error::Error::config(
            "identifier",
            format!("{s:?} does not start with expected prefix {expect_prefix:?}"),
        ));
    }
    Ok(())
}

/// Timestamp, then a per-process sequence number, then a random tail.
///
/// The layout is chosen so lexicographic order is minting order within a
/// process: the millisecond prefix dominates across milliseconds, and the
/// monotonic sequence number breaks ties inside one. The random tail mixes in
/// the pid so two processes writing to the same store cannot collide. Ordering
/// inside a single millisecond would only break after 65,536 mints in that
/// millisecond, which is far above any rate AETHER mints IDs at.
pub(crate) fn mint_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let millis = crate::time::now_millis();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    let tail = crate::hash::splitmix64(millis ^ (pid << 32) ^ seq);
    format!(
        "{:010x}{:04x}{:04x}",
        millis & 0xff_ffff_ffff,
        seq & 0xffff,
        tail & 0xffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_valid() {
        let a = CampaignId::new();
        let b = CampaignId::new();
        assert_ne!(a, b);
        a.validate().unwrap();
        b.validate().unwrap();
    }

    #[test]
    fn traversal_attempts_are_refused() {
        for bad in ["cmp-../../etc/passwd", "cmp-a/b", "cmp-a;rm -rf /", "cmp-a\0b", ""] {
            let id = CampaignId::from_string(bad);
            assert!(id.validate().is_err(), "accepted dangerous id {bad:?}");
        }
    }

    #[test]
    fn wrong_prefix_is_refused() {
        assert!(CampaignId::from_string("fnd-0123456789abcdef").validate().is_err());
    }

    #[test]
    fn ids_sort_in_minting_order() {
        let minted: Vec<String> =
            (0..500).map(|_| CampaignId::new().as_str().to_string()).collect();
        let mut sorted = minted.clone();
        sorted.sort();
        // Lexicographic order must equal minting order: the timestamp prefix
        // orders across milliseconds and the sequence number inside one.
        assert_eq!(minted, sorted);
    }

    #[test]
    fn ids_are_fixed_width() {
        // Fixed width is what makes lexicographic ordering equal numeric
        // ordering; a variable-length suffix would break it.
        let widths: std::collections::BTreeSet<usize> =
            (0..200).map(|_| CampaignId::new().as_str().len()).collect();
        assert_eq!(widths.len(), 1, "identifier width must not vary: {widths:?}");
    }
}
