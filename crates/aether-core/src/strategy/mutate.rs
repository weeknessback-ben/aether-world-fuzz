//! Byte-level mutation operators.
//!
//! These are the primitives every mutation strategy composes. Each takes an
//! input and an RNG and returns a mutated copy, and each is individually
//! tested, because a mutation operator that silently does nothing is an
//! expensive bug: the campaign keeps paying for executions that cannot
//! discover anything.
//!
//! Two invariants hold across all of them:
//!
//! * The result never exceeds `max_len`. A strategy that could grow an input
//!   without bound would eventually exhaust memory and disk.
//! * An operator either changes the input or reports that it could not. The
//!   caller can then try something else instead of burning an execution on a
//!   duplicate.

use crate::rng::Rng;

/// Values that disproportionately often sit at a boundary in real code:
/// signed and unsigned limits, off-by-ones around them, and small counts.
const INTERESTING_8: &[i8] = &[-128, -1, 0, 1, 16, 32, 64, 100, 127];
const INTERESTING_16: &[i16] = &[-32768, -129, -1, 0, 1, 128, 255, 256, 512, 1000, 1024, 4096, 32767];
const INTERESTING_32: &[i32] = &[
    -2147483648, -100663046, -32769, -1, 0, 1, 32768, 65535, 65536, 100663045, 2147483647,
];

/// Which operator produced a candidate, for per-operator accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    BitFlip,
    ByteFlip,
    ByteSet,
    Arithmetic,
    InterestingValue,
    Insert,
    Delete,
    Duplicate,
    Shuffle,
    Truncate,
    Extend,
}

impl Operator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operator::BitFlip => "bit-flip",
            Operator::ByteFlip => "byte-flip",
            Operator::ByteSet => "byte-set",
            Operator::Arithmetic => "arithmetic",
            Operator::InterestingValue => "interesting-value",
            Operator::Insert => "insert",
            Operator::Delete => "delete",
            Operator::Duplicate => "duplicate",
            Operator::Shuffle => "shuffle",
            Operator::Truncate => "truncate",
            Operator::Extend => "extend",
        }
    }

    pub const ALL: &'static [Operator] = &[
        Operator::BitFlip,
        Operator::ByteFlip,
        Operator::ByteSet,
        Operator::Arithmetic,
        Operator::InterestingValue,
        Operator::Insert,
        Operator::Delete,
        Operator::Duplicate,
        Operator::Shuffle,
        Operator::Truncate,
        Operator::Extend,
    ];
}

/// Apply one operator. Returns `false` when it could not change the input,
/// for example a deletion on an already-empty buffer.
pub fn apply(op: Operator, buf: &mut Vec<u8>, rng: &mut Rng, max_len: usize) -> bool {
    let changed = match op {
        Operator::BitFlip => bit_flip(buf, rng),
        Operator::ByteFlip => byte_flip(buf, rng),
        Operator::ByteSet => byte_set(buf, rng),
        Operator::Arithmetic => arithmetic(buf, rng),
        Operator::InterestingValue => interesting_value(buf, rng),
        Operator::Insert => insert(buf, rng, max_len),
        Operator::Delete => delete(buf, rng),
        Operator::Duplicate => duplicate(buf, rng, max_len),
        Operator::Shuffle => shuffle(buf, rng),
        Operator::Truncate => truncate(buf, rng),
        Operator::Extend => extend(buf, rng, max_len),
    };
    // Enforced here rather than trusted of each operator, so a future
    // operator cannot quietly breach the ceiling.
    if buf.len() > max_len {
        buf.truncate(max_len);
    }
    changed
}

pub fn bit_flip(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let i = rng.below(buf.len());
    let bit = rng.below(8);
    buf[i] ^= 1 << bit;
    true
}

pub fn byte_flip(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let i = rng.below(buf.len());
    buf[i] = !buf[i];
    true
}

pub fn byte_set(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let i = rng.below(buf.len());
    let old = buf[i];
    let mut new = rng.byte();
    // Make sure it is actually a change: otherwise the caller pays for an
    // execution of an identical input.
    if new == old {
        new = old.wrapping_add(1);
    }
    buf[i] = new;
    true
}

/// Add or subtract a small delta from an integer field, at 1, 2 or 4 bytes
/// wide and in either endianness. Catches off-by-one handling of length and
/// count fields, which a random byte rarely does.
pub fn arithmetic(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let width = match rng.below(3) {
        0 => 1,
        1 => 2,
        _ => 4,
    };
    if buf.len() < width {
        return bit_flip(buf, rng);
    }
    let i = rng.below(buf.len() - width + 1);
    let delta = rng.between(1, 35) as i64 * if rng.bool_with(0.5) { 1 } else { -1 };
    let big_endian = rng.bool_with(0.5);

    match width {
        1 => buf[i] = (buf[i] as i64).wrapping_add(delta) as u8,
        2 => {
            let mut b = [buf[i], buf[i + 1]];
            let v = if big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) };
            let nv = (v as i64).wrapping_add(delta) as u16;
            b = if big_endian { nv.to_be_bytes() } else { nv.to_le_bytes() };
            buf[i..i + 2].copy_from_slice(&b);
        }
        _ => {
            let mut b = [buf[i], buf[i + 1], buf[i + 2], buf[i + 3]];
            let v = if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) };
            let nv = (v as i64).wrapping_add(delta) as u32;
            b = if big_endian { nv.to_be_bytes() } else { nv.to_le_bytes() };
            buf[i..i + 4].copy_from_slice(&b);
        }
    }
    true
}

/// Overwrite a field with a boundary value.
pub fn interesting_value(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let big_endian = rng.bool_with(0.5);
    let choice = rng.below(3);
    match choice {
        0 => {
            let i = rng.below(buf.len());
            buf[i] = INTERESTING_8[rng.below(INTERESTING_8.len())] as u8;
            true
        }
        1 if buf.len() >= 2 => {
            let i = rng.below(buf.len() - 1);
            let v = INTERESTING_16[rng.below(INTERESTING_16.len())] as u16;
            let b = if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
            buf[i..i + 2].copy_from_slice(&b);
            true
        }
        _ if buf.len() >= 4 => {
            let i = rng.below(buf.len() - 3);
            let v = INTERESTING_32[rng.below(INTERESTING_32.len())] as u32;
            let b = if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
            buf[i..i + 4].copy_from_slice(&b);
            true
        }
        _ => {
            let i = rng.below(buf.len());
            buf[i] = INTERESTING_8[rng.below(INTERESTING_8.len())] as u8;
            true
        }
    }
}

pub fn insert(buf: &mut Vec<u8>, rng: &mut Rng, max_len: usize) -> bool {
    if buf.len() >= max_len {
        return false;
    }
    let room = max_len - buf.len();
    let n = rng.between(1, room.min(16));
    let at = rng.below(buf.len() + 1);
    let fill: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
    buf.splice(at..at, fill);
    true
}

pub fn delete(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.is_empty() {
        return false;
    }
    let n = rng.between(1, buf.len().min(16));
    let at = rng.below(buf.len() - n + 1);
    buf.drain(at..at + n);
    true
}

/// Copy a run of bytes from one place in the input to another. Cheap way to
/// produce repeated structure, which is what overruns a fixed-size buffer.
pub fn duplicate(buf: &mut Vec<u8>, rng: &mut Rng, max_len: usize) -> bool {
    if buf.is_empty() || buf.len() >= max_len {
        return false;
    }
    let room = max_len - buf.len();
    let n = rng.between(1, buf.len().min(room).min(64));
    let from = rng.below(buf.len() - n + 1);
    let chunk: Vec<u8> = buf[from..from + n].to_vec();
    let at = rng.below(buf.len() + 1);
    buf.splice(at..at, chunk);
    true
}

pub fn shuffle(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let n = rng.between(2, buf.len().min(32));
    let at = rng.below(buf.len() - n + 1);
    let before: Vec<u8> = buf[at..at + n].to_vec();
    rng.shuffle(&mut buf[at..at + n]);
    buf[at..at + n] != before[..]
}

pub fn truncate(buf: &mut Vec<u8>, rng: &mut Rng) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let keep = rng.between(1, buf.len() - 1);
    buf.truncate(keep);
    true
}

pub fn extend(buf: &mut Vec<u8>, rng: &mut Rng, max_len: usize) -> bool {
    if buf.len() >= max_len {
        return false;
    }
    let room = max_len - buf.len();
    let n = rng.between(1, room.min(64));
    // Repeat the last byte rather than add noise: a long run of one value is
    // what tends to overflow a length-prefixed field.
    let fill = if buf.is_empty() { rng.byte() } else { buf[buf.len() - 1] };
    buf.extend(std::iter::repeat(fill).take(n));
    true
}

/// Apply several operators in sequence, AFL's "havoc" stacking.
///
/// Stacking matters: many defects need two coordinated changes, such as a
/// length field adjusted *and* the payload lengthened, which a single
/// operator per execution would reach only by chance.
pub fn havoc(buf: &mut Vec<u8>, rng: &mut Rng, max_len: usize, max_stack: u32) -> u32 {
    let stack = 1 << rng.below(max_stack.max(1) as usize + 1);
    let mut applied = 0;
    for _ in 0..stack {
        let op = Operator::ALL[rng.below(Operator::ALL.len())];
        if apply(op, buf, rng, max_len) {
            applied += 1;
        }
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> Rng {
        Rng::from_seed(0xA37E)
    }

    #[test]
    fn every_operator_changes_a_reasonable_input() {
        // An operator that silently no-ops wastes every execution spent on it.
        for op in Operator::ALL {
            let mut any_change = false;
            let mut r = rng();
            for _ in 0..200 {
                let mut buf = b"The quick brown fox jumps over the lazy dog".to_vec();
                let before = buf.clone();
                if apply(*op, &mut buf, &mut r, 256) && buf != before {
                    any_change = true;
                    break;
                }
            }
            assert!(any_change, "{} never changed a 43-byte input", op.as_str());
        }
    }

    #[test]
    fn operators_never_exceed_the_length_ceiling() {
        let mut r = rng();
        for op in Operator::ALL {
            for _ in 0..200 {
                let mut buf = vec![0x41u8; 60];
                apply(*op, &mut buf, &mut r, 64);
                assert!(buf.len() <= 64, "{} produced {} bytes", op.as_str(), buf.len());
            }
        }
    }

    #[test]
    fn operators_handle_an_empty_input_without_panicking() {
        let mut r = rng();
        for op in Operator::ALL {
            for _ in 0..50 {
                let mut buf: Vec<u8> = Vec::new();
                apply(*op, &mut buf, &mut r, 32);
                assert!(buf.len() <= 32);
            }
        }
    }

    #[test]
    fn operators_handle_a_single_byte_input() {
        let mut r = rng();
        for op in Operator::ALL {
            for _ in 0..50 {
                let mut buf = vec![0x7Fu8];
                apply(*op, &mut buf, &mut r, 8);
                assert!(buf.len() <= 8);
            }
        }
    }

    #[test]
    fn growth_operators_report_failure_at_the_ceiling() {
        let mut r = rng();
        for op in [Operator::Insert, Operator::Duplicate, Operator::Extend] {
            let mut buf = vec![0x41u8; 32];
            assert!(
                !apply(op, &mut buf, &mut r, 32),
                "{} claimed success with no room to grow",
                op.as_str()
            );
            assert_eq!(buf.len(), 32);
        }
    }

    #[test]
    fn delete_reports_failure_on_an_empty_input() {
        let mut r = rng();
        let mut buf = Vec::new();
        assert!(!delete(&mut buf, &mut r));
    }

    #[test]
    fn byte_set_always_actually_changes_the_byte() {
        let mut r = rng();
        for _ in 0..500 {
            let mut buf = vec![0x5Au8];
            byte_set(&mut buf, &mut r);
            assert_ne!(buf[0], 0x5A, "byte_set must not leave the value unchanged");
        }
    }

    #[test]
    fn bit_flip_changes_exactly_one_bit() {
        let mut r = rng();
        for _ in 0..200 {
            let mut buf = vec![0b1010_1010u8; 4];
            let before = buf.clone();
            bit_flip(&mut buf, &mut r);
            let diff: u32 = before
                .iter()
                .zip(&buf)
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            assert_eq!(diff, 1, "bit_flip changed {diff} bits");
        }
    }

    #[test]
    fn arithmetic_reaches_both_directions_and_both_endiannesses() {
        // A length field needs both +1 and -1 to be explored; an operator
        // stuck on one sign would miss half the off-by-one cases.
        let mut r = rng();
        let mut saw_increase = false;
        let mut saw_decrease = false;
        for _ in 0..2000 {
            let mut buf = vec![0x00, 0x80, 0x00, 0x00];
            let before = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            arithmetic(&mut buf, &mut r);
            let after = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if after > before {
                saw_increase = true;
            }
            if after < before {
                saw_decrease = true;
            }
            if saw_increase && saw_decrease {
                break;
            }
        }
        assert!(saw_increase && saw_decrease, "arithmetic only moved one way");
    }

    #[test]
    fn interesting_values_land_boundary_numbers_in_the_buffer() {
        let mut r = rng();
        let mut saw_u8_max = false;
        let mut saw_zero = false;
        for _ in 0..3000 {
            let mut buf = vec![0x41u8; 8];
            interesting_value(&mut buf, &mut r);
            if buf.contains(&0xFF) {
                saw_u8_max = true;
            }
            if buf.contains(&0x00) {
                saw_zero = true;
            }
            if saw_u8_max && saw_zero {
                break;
            }
        }
        assert!(saw_u8_max, "never produced 0xFF");
        assert!(saw_zero, "never produced 0x00");
    }

    #[test]
    fn mutations_are_reproducible_for_a_fixed_seed() {
        let run = || {
            let mut r = Rng::from_seed(99);
            let mut out = Vec::new();
            for _ in 0..50 {
                let mut buf = b"deterministic".to_vec();
                havoc(&mut buf, &mut r, 128, 4);
                out.push(buf);
            }
            out
        };
        assert_eq!(run(), run(), "a fixed seed must replay identical mutations");
    }

    #[test]
    fn havoc_stacks_multiple_operators() {
        let mut r = rng();
        let mut total = 0;
        for _ in 0..200 {
            let mut buf = b"some input to mutate".to_vec();
            total += havoc(&mut buf, &mut r, 256, 5);
        }
        // With stacking up to 2^5, 200 rounds must average well above one.
        assert!(total > 200, "havoc applied only {total} operators over 200 rounds");
    }

    #[test]
    fn havoc_respects_the_ceiling_over_many_rounds() {
        let mut r = rng();
        let mut buf = b"seed".to_vec();
        for _ in 0..5000 {
            havoc(&mut buf, &mut r, 100, 6);
            assert!(buf.len() <= 100, "havoc grew the input to {}", buf.len());
        }
    }

    #[test]
    fn havoc_does_not_collapse_every_input_to_empty() {
        // Deletion-heavy stacking could shrink everything to nothing, which
        // would make the strategy useless after a few rounds.
        let mut r = rng();
        let mut nonempty = 0;
        for _ in 0..200 {
            let mut buf = b"a reasonably long starting input".to_vec();
            havoc(&mut buf, &mut r, 256, 4);
            if !buf.is_empty() {
                nonempty += 1;
            }
        }
        assert!(nonempty > 150, "only {nonempty}/200 mutations kept any bytes");
    }

    #[test]
    fn shuffle_reports_whether_it_reordered() {
        let mut r = rng();
        // A two-byte buffer of identical values cannot be visibly shuffled.
        let mut same = vec![0x41u8, 0x41];
        assert!(!shuffle(&mut same, &mut r));
        // A varied buffer should reorder within a few attempts.
        let mut ok = false;
        for _ in 0..50 {
            let mut varied: Vec<u8> = (0..16).collect();
            if shuffle(&mut varied, &mut r) {
                ok = true;
                break;
            }
        }
        assert!(ok);
    }
}
