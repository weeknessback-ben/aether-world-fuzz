//! Structure-aware mutation.
//!
//! Mutates a structured input while keeping selected structural constraints
//! intact. The difference from byte-level mutation is what survives: a random
//! byte flip in a length field usually makes the record unparseable, so the
//! target rejects it at the header and nothing past the parser is reached.
//! This strategy changes a field's *value* and then repairs the length that
//! describes it, so the mutated input still parses and the mutation reaches
//! the code that uses the value.
//!
//! The structure is inferred, not declared. A type-length-value shape is
//! detectable from the bytes alone, and the inference reports when it does not
//! find one so the strategy can decline rather than corrupt the input.

use crate::error::Result;
use crate::rng::Rng;

use super::{Base, Candidate, CandidateResult, Strategy, StrategyCapabilities, StrategyContext};

/// A field discovered in an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub offset: usize,
    pub len: usize,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A fixed header or magic at the start.
    Header,
    /// A byte that selects an interpretation.
    Type,
    /// A length describing the payload that follows it.
    Length { describes: usize },
    Payload,
}

/// Inferred layout of an input.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub fields: Vec<Field>,
    /// Record header length the walk used, needed to reconstruct a record.
    pub record_header_len: usize,
    /// How confident the inference is, in `[0, 1]`. Below the strategy's
    /// threshold the input is treated as unstructured.
    pub confidence: f64,
}

impl Layout {
    pub fn length_fields(&self) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(|f| matches!(f.kind, FieldKind::Length { .. }))
    }
}

/// Try to read an input as a sequence of type-length-value records.
///
/// `header_len` bytes are taken as a fixed stream header. Each record is then
/// `record_header_len` bytes - the last of which is a single-byte length -
/// followed by that many payload bytes. Two shapes are common and both are
/// supported: `[type][len]` (header length 2) and a marker-prefixed
/// `[marker][type][len]` (header length 3, which is what
/// `fixtures/toy_parser.c` uses).
///
/// Confidence is the fraction of the input the walk consumed without running
/// off the end, so an input that starts plausibly and then disagrees with the
/// layout scores low rather than being treated as structured.
pub fn infer_tlv_layout(input: &[u8], header_len: usize, record_header_len: usize) -> Layout {
    let mut layout = Layout::default();
    if record_header_len == 0 || input.len() <= header_len {
        return layout;
    }
    if header_len > 0 {
        layout.fields.push(Field { offset: 0, len: header_len, kind: FieldKind::Header });
    }

    let mut off = header_len;
    let mut consumed = header_len;
    let mut records = 0;
    while off + record_header_len <= input.len() {
        let len_off = off + record_header_len - 1;
        let declared = input[len_off] as usize;
        let payload_off = len_off + 1;
        if payload_off + declared > input.len() {
            // The declared length runs past the end: the walk disagrees with
            // the data, so stop and let confidence reflect that.
            break;
        }
        // Everything before the length byte is type/marker material.
        if record_header_len > 1 {
            layout.fields.push(Field {
                offset: off,
                len: record_header_len - 1,
                kind: FieldKind::Type,
            });
        }
        layout
            .fields
            .push(Field { offset: len_off, len: 1, kind: FieldKind::Length { describes: declared } });
        if declared > 0 {
            layout
                .fields
                .push(Field { offset: payload_off, len: declared, kind: FieldKind::Payload });
        }
        off = payload_off + declared;
        consumed = off;
        records += 1;
    }

    layout.confidence = if records == 0 {
        0.0
    } else {
        consumed as f64 / input.len() as f64
    };
    layout.record_header_len = record_header_len;
    layout
}

/// Record header lengths the inference will try, in order of preference.
const RECORD_HEADER_CANDIDATES: &[usize] = &[3, 2, 4];

/// Infer a layout by trying each supported record shape and keeping whichever
/// explains the most of the input.
///
/// Guessing a single shape would make the strategy useless on any format that
/// happened to use a different one, and would silently "find" structure of the
/// wrong shape in an input that really had another.
pub fn infer_best_layout(input: &[u8], header_len: usize) -> Layout {
    let mut best = Layout::default();
    for &rh in RECORD_HEADER_CANDIDATES {
        let l = infer_tlv_layout(input, header_len, rh);
        if l.confidence > best.confidence {
            best = l;
        }
    }
    best
}

pub struct StructureAware {
    max_len: usize,
    header_len: usize,
    /// Minimum inference confidence before the input is treated as structured.
    min_confidence: f64,
    structured_attempts: u64,
    unstructured_skips: u64,
}

impl Default for StructureAware {
    fn default() -> Self {
        StructureAware {
            max_len: 65_536,
            header_len: 4,
            min_confidence: 0.6,
            structured_attempts: 0,
            unstructured_skips: 0,
        }
    }
}

impl StructureAware {
    /// Change a payload's size and repair the length byte that describes it,
    /// so the record still parses.
    fn resize_payload(
        input: &[u8],
        layout: &Layout,
        rng: &mut Rng,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let lengths: Vec<&Field> = layout.length_fields().collect();
        if lengths.is_empty() {
            return None;
        }
        let f = lengths[rng.below(lengths.len())];
        let FieldKind::Length { describes } = f.kind else { return None };
        let payload_off = f.offset + 1;
        if payload_off + describes > input.len() {
            return None;
        }

        // A new size that still fits in the single length byte.
        let new_size = rng.between(0, 255).min(max_len.saturating_sub(input.len() - describes));
        let mut out = Vec::with_capacity(input.len() + new_size);
        out.extend_from_slice(&input[..payload_off]);
        let fill = if describes > 0 { input[payload_off] } else { 0x41 };
        out.extend(std::iter::repeat(fill).take(new_size));
        out.extend_from_slice(&input[payload_off + describes..]);
        // Repair the length so the record remains well-formed: this is the
        // whole point of the strategy.
        out[f.offset] = new_size as u8;
        if out.len() > max_len {
            return None;
        }
        Some(out)
    }

    /// Change a length byte *without* repairing the payload, producing a
    /// deliberate inconsistency. The complement of `resize_payload`: this is
    /// what finds a parser that trusts a declared length.
    fn corrupt_length(input: &[u8], layout: &Layout, rng: &mut Rng) -> Option<Vec<u8>> {
        let lengths: Vec<&Field> = layout.length_fields().collect();
        if lengths.is_empty() {
            return None;
        }
        let f = lengths[rng.below(lengths.len())];
        let mut out = input.to_vec();
        let old = out[f.offset];
        let new = match rng.below(4) {
            0 => 0xFF,
            1 => 0x00,
            2 => old.wrapping_add(1),
            _ => old.wrapping_sub(1),
        };
        if new == old {
            return None;
        }
        out[f.offset] = new;
        Some(out)
    }

    /// Mutate a payload's contents, leaving all structure alone.
    fn mutate_payload(
        input: &[u8],
        layout: &Layout,
        rng: &mut Rng,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let payloads: Vec<&Field> = layout
            .fields
            .iter()
            .filter(|f| f.kind == FieldKind::Payload && f.len > 0)
            .collect();
        if payloads.is_empty() {
            return None;
        }
        let f = payloads[rng.below(payloads.len())];
        let mut out = input.to_vec();
        let mut slice = out[f.offset..f.offset + f.len].to_vec();
        // Length-preserving operators only, so the structure stays valid.
        let op = match rng.below(4) {
            0 => super::mutate::Operator::BitFlip,
            1 => super::mutate::Operator::ByteSet,
            2 => super::mutate::Operator::Arithmetic,
            _ => super::mutate::Operator::InterestingValue,
        };
        if !super::mutate::apply(op, &mut slice, rng, f.len) {
            return None;
        }
        slice.resize(f.len, 0);
        out[f.offset..f.offset + f.len].copy_from_slice(&slice);
        if out.len() > max_len || out == input {
            return None;
        }
        Some(out)
    }

    /// Duplicate a whole record, keeping each record internally consistent.
    fn duplicate_record(
        input: &[u8],
        layout: &Layout,
        rng: &mut Rng,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let types: Vec<&Field> =
            layout.fields.iter().filter(|f| f.kind == FieldKind::Type).collect();
        if types.is_empty() {
            return None;
        }
        let t = types[rng.below(types.len())];
        let rh = layout.record_header_len.max(1);
        let len_byte = *input.get(t.offset + rh - 1)? as usize;
        let record_end = t.offset + rh + len_byte;
        if record_end > input.len() {
            return None;
        }
        let record = &input[t.offset..record_end];
        if input.len() + record.len() > max_len {
            return None;
        }
        let mut out = Vec::with_capacity(input.len() + record.len());
        out.extend_from_slice(&input[..record_end]);
        out.extend_from_slice(record);
        out.extend_from_slice(&input[record_end..]);
        Some(out)
    }
}

impl Strategy for StructureAware {
    fn id(&self) -> &'static str {
        "structure-aware"
    }

    fn capabilities(&self) -> StrategyCapabilities {
        StrategyCapabilities {
            id: self.id().into(),
            requires_coverage: false,
            requires_cmplog: false,
            requires_grammar: false,
            requires_corpus: true,
            produces_sequences: false,
            description: "mutates structured inputs while repairing the fields that \
                          describe them, so the result still parses"
                .into(),
        }
    }

    fn initialize(&mut self, ctx: &StrategyContext<'_>) -> Result<()> {
        self.max_len = ctx.max_input_bytes;
        self.header_len = ctx.param_u64("structure_header_len", 4).min(64) as usize;
        self.min_confidence = ctx.param_f64("structure_min_confidence", 0.6).clamp(0.0, 1.0);
        Ok(())
    }

    fn propose(&mut self, budget: u32, bases: &[Base], rng: &mut Rng) -> Vec<Candidate> {
        if bases.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(budget as usize);
        for _ in 0..budget {
            let base = &bases[rng.below(bases.len())];
            let layout = infer_best_layout(&base.bytes, self.header_len);

            if layout.confidence < self.min_confidence {
                // No structure found. Declining is the honest answer: mutating
                // as though a layout existed would just corrupt the input, and
                // the byte-level strategies already cover that case.
                self.unstructured_skips += 1;
                continue;
            }
            self.structured_attempts += 1;

            let (mutated, note) = match rng.below(4) {
                0 => (
                    Self::resize_payload(&base.bytes, &layout, rng, self.max_len),
                    "resize-payload",
                ),
                1 => (Self::corrupt_length(&base.bytes, &layout, rng), "corrupt-length"),
                2 => (
                    Self::mutate_payload(&base.bytes, &layout, rng, self.max_len),
                    "mutate-payload",
                ),
                _ => (
                    Self::duplicate_record(&base.bytes, &layout, rng, self.max_len),
                    "duplicate-record",
                ),
            };
            if let Some(bytes) = mutated {
                out.push(Candidate::from_base(bytes, base, note));
            }
        }
        out
    }

    fn observe(&mut self, _results: &[CandidateResult]) {}

    fn export_state(&self) -> serde_json::Value {
        serde_json::json!({
            "structured_attempts": self.structured_attempts,
            "unstructured_skips": self.unstructured_skips,
            "header_len": self.header_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use std::collections::BTreeMap;

    /// A valid stream for fixtures/toy_parser.c: header, then two records.
    fn tlv() -> Vec<u8> {
        let mut v = b"TLV1".to_vec();
        v.extend_from_slice(&[b'T', 0x01, 0x02, b'a', b'b']);
        v.extend_from_slice(&[b'T', 0x02, 0x03, b'c', b'd', b'e']);
        v
    }

    fn built(params: &BTreeMap<String, toml::Value>) -> StructureAware {
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut s = StructureAware::default();
        s.initialize(&ctx(&dict, None, params)).unwrap();
        s
    }

    #[test]
    fn infers_a_tlv_layout_with_high_confidence() {
        let l = infer_best_layout(&tlv(), 4);
        assert!(l.confidence > 0.95, "confidence was {}", l.confidence);
        assert_eq!(l.length_fields().count(), 2);
        assert!(l.fields.iter().any(|f| f.kind == FieldKind::Header));
        // The length fields must describe the real payload sizes.
        let sizes: Vec<usize> = l
            .length_fields()
            .map(|f| match f.kind {
                FieldKind::Length { describes } => describes,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(sizes, vec![2, 3]);
    }

    #[test]
    fn infers_both_supported_record_shapes() {
        // Marker-prefixed [marker][type][len], as the toy parser uses.
        let three = tlv();
        let l3 = infer_best_layout(&three, 4);
        assert_eq!(l3.record_header_len, 3, "confidence {}", l3.confidence);
        assert!(l3.confidence > 0.95);

        // Plain [type][len] records after a 4-byte header.
        let mut two = b"HDR1".to_vec();
        two.extend_from_slice(&[0x01, 0x02, b'a', b'b']);
        two.extend_from_slice(&[0x02, 0x01, b'c']);
        let l2 = infer_best_layout(&two, 4);
        assert!(l2.confidence > 0.95, "confidence {}", l2.confidence);
        assert_eq!(l2.length_fields().count(), 2);
    }

    #[test]
    fn reports_low_confidence_on_unstructured_input() {
        for junk in [
            b"random bytes with no structure at all".to_vec(),
            vec![0xFFu8; 32],
            b"TLV1".to_vec(),
            Vec::new(),
        ] {
            let l = infer_best_layout(&junk, 4);
            assert!(
                l.confidence < 0.6,
                "claimed structure in {:?} (confidence {})",
                String::from_utf8_lossy(&junk),
                l.confidence
            );
        }
    }

    #[test]
    fn declines_unstructured_input_rather_than_corrupting_it() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(1);
        let cands = s.propose(32, &bases(&[b"no structure here whatsoever"]), &mut rng);
        assert!(cands.is_empty(), "should decline, not invent a layout");
        assert!(s.export_state()["unstructured_skips"].as_u64().unwrap() > 0);
    }

    #[test]
    fn resize_keeps_the_record_consistent() {
        // The defining property: after resizing a payload, the length byte
        // must still describe it, so the input still parses.
        let mut rng = Rng::from_seed(2);
        let input = tlv();
        let layout = infer_best_layout(&input, 4);

        let mut checked = 0;
        for _ in 0..200 {
            if let Some(out) = StructureAware::resize_payload(&input, &layout, &mut rng, 4096) {
                let re = infer_best_layout(&out, 4);
                assert!(
                    re.confidence > 0.95,
                    "resize produced an inconsistent record: {:?} (confidence {})",
                    out,
                    re.confidence
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "resize never produced anything");
    }

    #[test]
    fn corrupt_length_deliberately_breaks_consistency() {
        // The complement: this one is supposed to produce an inconsistency,
        // because that is what finds a parser trusting a declared length.
        let mut rng = Rng::from_seed(3);
        let input = tlv();
        let layout = infer_best_layout(&input, 4);
        let mut saw_inconsistent = false;
        for _ in 0..200 {
            if let Some(out) = StructureAware::corrupt_length(&input, &layout, &mut rng) {
                assert_eq!(out.len(), input.len(), "corruption must not change length");
                if infer_best_layout(&out, 4).confidence < 0.95 {
                    saw_inconsistent = true;
                }
            }
        }
        assert!(saw_inconsistent, "corrupt_length never produced an inconsistency");
    }

    #[test]
    fn payload_mutation_preserves_structure() {
        let mut rng = Rng::from_seed(4);
        let input = tlv();
        let layout = infer_best_layout(&input, 4);
        let mut checked = 0;
        for _ in 0..200 {
            if let Some(out) = StructureAware::mutate_payload(&input, &layout, &mut rng, 4096) {
                assert_eq!(out.len(), input.len(), "payload mutation changed the length");
                assert!(out.starts_with(b"TLV1"));
                let re = infer_best_layout(&out, 4);
                assert!(re.confidence > 0.95, "structure broken: {:?}", out);
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn record_duplication_keeps_the_stream_parseable() {
        let mut rng = Rng::from_seed(5);
        let input = tlv();
        let layout = infer_best_layout(&input, 4);
        let mut checked = 0;
        for _ in 0..100 {
            if let Some(out) = StructureAware::duplicate_record(&input, &layout, &mut rng, 4096) {
                assert!(out.len() > input.len());
                let re = infer_best_layout(&out, 4);
                assert!(re.confidence > 0.95, "duplication broke the stream: {:?}", out);
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn proposals_respect_the_length_ceiling() {
        let mut params = BTreeMap::new();
        params.insert("structure_header_len".into(), toml::Value::Integer(4));
        let dict: Vec<Vec<u8>> = Vec::new();
        let mut c = ctx(&dict, None, &params);
        c.max_input_bytes = 24;
        let mut s = StructureAware::default();
        s.initialize(&c).unwrap();
        let mut rng = Rng::from_seed(6);
        let b = vec![Base { id: crate::ids::InputId::new(), bytes: tlv(), cmp_entries: vec![] }];
        for cand in s.propose(100, &b, &mut rng) {
            assert!(cand.bytes.len() <= 24, "got {} bytes", cand.bytes.len());
        }
    }

    #[test]
    fn all_four_operations_are_reachable() {
        let params = BTreeMap::new();
        let mut s = built(&params);
        let mut rng = Rng::from_seed(7);
        let b = vec![Base { id: crate::ids::InputId::new(), bytes: tlv(), cmp_entries: vec![] }];
        let mut notes = std::collections::HashSet::new();
        for _ in 0..40 {
            for c in s.propose(32, &b, &mut rng) {
                notes.insert(c.note);
            }
        }
        for want in ["resize-payload", "corrupt-length", "mutate-payload", "duplicate-record"] {
            assert!(notes.contains(want), "{want} never produced a candidate: {notes:?}");
        }
    }

    #[test]
    fn is_reproducible_for_a_fixed_seed() {
        let params = BTreeMap::new();
        let b = vec![Base {
            id: crate::ids::InputId::from_string("inp-fixed"),
            bytes: tlv(),
            cmp_entries: vec![],
        }];
        let run = || {
            let mut s = built(&params);
            let mut rng = Rng::from_seed(321);
            s.propose(24, &b, &mut rng).into_iter().map(|c| c.bytes).collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
