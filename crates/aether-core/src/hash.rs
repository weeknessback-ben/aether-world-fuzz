//! Content hashing and signature helpers.
//!
//! Corpus inputs are content-addressed with BLAKE3 truncated to 128 bits: at
//! corpus sizes AETHER targets (millions of inputs at the very most) that is
//! far below any practical collision risk, and it halves the index size and
//! the length of every path under `objects/`.

/// 32 lowercase hex characters, i.e. 128 bits of BLAKE3.
pub type ContentHash = String;

pub fn content_hash(bytes: &[u8]) -> ContentHash {
    let full = blake3::hash(bytes);
    hex16(&full.as_bytes()[..16])
}

/// Hash an ordered list of byte strings so a sequence test case gets a single
/// stable identity. The length of each element is folded in, so `["ab","c"]`
/// and `["a","bc"]` do not collide.
pub fn sequence_hash(parts: &[Vec<u8>]) -> ContentHash {
    let mut h = blake3::Hasher::new();
    h.update(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    hex16(&h.finalize().as_bytes()[..16])
}

/// Hash arbitrary labelled text, used for failure signatures where the inputs
/// are already-normalised strings rather than raw bytes.
pub fn signature_hash(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    hex16(&h.finalize().as_bytes()[..8])
}

fn hex16(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Validate a hash that arrived from outside the process before it is used to
/// build a filesystem path. Refuses anything that is not plain lowercase hex.
pub fn validate_content_hash(h: &str) -> crate::error::Result<()> {
    if h.len() != 32
        || !h
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(crate::error::Error::storage(
            "content hash",
            format!("{h:?} is not 32 lowercase hex characters"),
        ));
    }
    Ok(())
}

/// SplitMix64. Used for cheap non-cryptographic mixing where a full hash is
/// wasteful: ID suffixes, map index derivation, bandit context bucketing.
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_stable_and_distinct() {
        assert_eq!(content_hash(b"hello"), content_hash(b"hello"));
        assert_ne!(content_hash(b"hello"), content_hash(b"hellp"));
        assert_eq!(content_hash(b"hello").len(), 32);
        validate_content_hash(&content_hash(b"hello")).unwrap();
    }

    #[test]
    fn empty_input_hashes() {
        validate_content_hash(&content_hash(b"")).unwrap();
    }

    #[test]
    fn sequence_hash_respects_boundaries() {
        let a = sequence_hash(&[b"ab".to_vec(), b"c".to_vec()]);
        let b = sequence_hash(&[b"a".to_vec(), b"bc".to_vec()]);
        assert_ne!(a, b, "sequence hash must not ignore element boundaries");
    }

    #[test]
    fn rejects_non_hex_hashes() {
        for bad in [
            "",
            "xyz",
            "../../etc/passwd",
            &"A".repeat(32),
            &"a".repeat(31),
        ] {
            assert!(validate_content_hash(bad).is_err(), "accepted {bad:?}");
        }
    }
}
