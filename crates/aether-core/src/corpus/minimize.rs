//! Input minimisation by delta debugging.
//!
//! Given an input and a predicate that says whether the interesting behaviour
//! still happens, produce a smaller input that still triggers it. Used for two
//! different purposes:
//!
//! * **Finding minimisation.** Shrink a crashing input so a human reading the
//!   report can see what actually matters. The predicate re-runs the target
//!   and checks the failure signature still matches - not merely that it still
//!   crashes, because shrinking one crash into a *different* crash would make
//!   the evidence wrong.
//! * **Corpus minimisation.** Shrink a seed so later executions are cheaper,
//!   with the predicate checking that coverage is preserved.
//!
//! The algorithm is ddmin's structure: try removing large chunks, halve the
//! chunk size when a pass makes no progress, and finish with single-byte
//! removal. Every candidate is bounded by an execution budget, because a
//! pathological input must not be able to stall the evidence pipeline.

/// Why minimisation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimizeStop {
    /// No further reduction was possible.
    Converged,
    /// The execution budget ran out; the result is valid but not minimal.
    BudgetExhausted,
    /// The predicate never held, even for the original input.
    PredicateNeverHeld,
}

#[derive(Debug, Clone)]
pub struct MinimizeOutcome {
    pub input: Vec<u8>,
    pub original_len: usize,
    pub execs_used: u32,
    pub stop: MinimizeStop,
}

impl MinimizeOutcome {
    pub fn reduction_ratio(&self) -> f64 {
        if self.original_len == 0 {
            return 0.0;
        }
        1.0 - (self.input.len() as f64 / self.original_len as f64)
    }
}

/// Minimise `input` while `still_interesting` holds.
///
/// The predicate is called with candidate inputs and must be deterministic
/// enough to be useful; an intermittent predicate yields a valid but larger
/// result rather than an incorrect one, because a candidate is only accepted
/// when the predicate actually returns true.
pub fn minimize<F>(input: &[u8], max_execs: u32, mut still_interesting: F) -> MinimizeOutcome
where
    F: FnMut(&[u8]) -> bool,
{
    let original_len = input.len();
    let mut execs = 0u32;

    // Confirm the starting point. Without this, a flaky or misconfigured
    // predicate would silently "minimise" to an empty input.
    execs += 1;
    if !still_interesting(input) {
        return MinimizeOutcome {
            input: input.to_vec(),
            original_len,
            execs_used: execs,
            stop: MinimizeStop::PredicateNeverHeld,
        };
    }

    let mut current = input.to_vec();

    // Phase 1: chunk removal, from large chunks down to single bytes.
    let mut chunk = (current.len() / 2).max(1);
    while chunk >= 1 {
        let mut offset = 0;
        let mut removed_any = false;
        while offset < current.len() {
            if execs >= max_execs {
                return MinimizeOutcome {
                    input: current,
                    original_len,
                    execs_used: execs,
                    stop: MinimizeStop::BudgetExhausted,
                };
            }
            let end = (offset + chunk).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - offset));
            candidate.extend_from_slice(&current[..offset]);
            candidate.extend_from_slice(&current[end..]);

            execs += 1;
            if still_interesting(&candidate) {
                current = candidate;
                removed_any = true;
                // Do not advance: the next chunk has shifted into this offset.
            } else {
                offset += chunk;
            }
        }
        if chunk == 1 {
            // A full single-byte pass that removed something may enable more,
            // so repeat; otherwise stop.
            if !removed_any {
                break;
            }
        } else {
            chunk /= 2;
        }
    }

    // Phase 2: value simplification. Replacing a byte with zero often removes
    // an incidental detail and makes the reported input easier to read,
    // without changing its length.
    let mut i = 0;
    while i < current.len() {
        if execs >= max_execs {
            return MinimizeOutcome {
                input: current,
                original_len,
                execs_used: execs,
                stop: MinimizeStop::BudgetExhausted,
            };
        }
        if current[i] != 0 {
            let saved = current[i];
            current[i] = 0;
            execs += 1;
            if !still_interesting(&current) {
                current[i] = saved;
            }
        }
        i += 1;
    }

    MinimizeOutcome {
        input: current,
        original_len,
        execs_used: execs,
        stop: MinimizeStop::Converged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduces_to_the_essential_bytes() {
        // Only the presence of "BOOM" matters; everything else is padding.
        let input = b"xxxxxxxxxxBOOMyyyyyyyyyy".to_vec();
        let r = minimize(&input, 10_000, |c| c.windows(4).any(|w| w == b"BOOM"));
        assert_eq!(
            r.input,
            b"BOOM",
            "got {:?}",
            String::from_utf8_lossy(&r.input)
        );
        assert_eq!(r.stop, MinimizeStop::Converged);
        assert!(r.reduction_ratio() > 0.8);
    }

    #[test]
    fn preserves_a_predicate_that_needs_a_length() {
        // A predicate requiring at least 8 bytes must not be minimised below it.
        let input = vec![0x41u8; 64];
        let r = minimize(&input, 10_000, |c| c.len() >= 8);
        assert_eq!(r.input.len(), 8);
        assert_eq!(r.stop, MinimizeStop::Converged);
    }

    #[test]
    fn simplifies_byte_values_where_they_do_not_matter() {
        // Length matters, content does not: the result should be zeroed, which
        // is far easier to read in a report than arbitrary bytes.
        let input = vec![0x5Au8; 6];
        let r = minimize(&input, 10_000, |c| c.len() == 6);
        assert_eq!(r.input, vec![0u8; 6]);
    }

    #[test]
    fn keeps_bytes_whose_values_do_matter() {
        let input = b"AxBxCx".to_vec();
        let r = minimize(&input, 10_000, |c| {
            c.len() == 6 && c[0] == b'A' && c[2] == b'B' && c[4] == b'C'
        });
        assert_eq!(r.input, b"A\0B\0C\0");
    }

    #[test]
    fn a_predicate_that_never_holds_leaves_the_input_untouched() {
        // The guard that stops a misconfigured predicate "minimising" a
        // crashing input down to nothing.
        let input = b"important".to_vec();
        let r = minimize(&input, 10_000, |_| false);
        assert_eq!(r.input, input, "must not shrink what it cannot verify");
        assert_eq!(r.stop, MinimizeStop::PredicateNeverHeld);
        assert_eq!(r.execs_used, 1, "should give up after the first check");
    }

    #[test]
    fn budget_is_respected_and_reported() {
        // The predicate needs nearly the whole input, so almost every removal
        // attempt fails and the pass grinds through many candidates. An
        // always-true predicate would instead converge in a handful of execs
        // and never reach the budget.
        let input = vec![0x41u8; 4096];
        let mut calls = 0;
        let r = minimize(&input, 20, |c| {
            calls += 1;
            c.len() >= 4000
        });
        assert!(r.execs_used <= 20, "used {}", r.execs_used);
        assert_eq!(r.stop, MinimizeStop::BudgetExhausted);
        assert!(calls <= 20);
        // A budget-limited result is still valid, just not minimal.
        assert!(r.input.len() >= 4000);
    }

    #[test]
    fn result_is_always_valid_under_the_predicate() {
        // Whatever it returns, re-checking the result must still hold. This is
        // the property the evidence engine depends on.
        let predicate = |c: &[u8]| c.windows(2).any(|w| w == b"\xDE\xAD") && c.len() >= 4;
        let input = b"\x00\x01\xDE\xAD\x02\x03\x04\x05".to_vec();
        let r = minimize(&input, 10_000, predicate);
        assert!(
            predicate(&r.input),
            "minimised input no longer satisfies the predicate"
        );
    }

    #[test]
    fn handles_empty_and_single_byte_inputs() {
        let r = minimize(b"", 100, |_| true);
        assert!(r.input.is_empty());
        assert_eq!(r.reduction_ratio(), 0.0);

        let r = minimize(b"A", 100, |c| !c.is_empty());
        assert_eq!(r.input.len(), 1);
    }

    #[test]
    fn an_intermittent_predicate_yields_a_valid_if_larger_result() {
        // Returning true only every other call: the result must still satisfy
        // the predicate's stable part rather than being wrong.
        let mut n = 0;
        let input = b"KEEPzzzzzzzzzzzz".to_vec();
        let r = minimize(&input, 10_000, |c| {
            n += 1;
            n % 2 == 0 && c.starts_with(b"KEEP")
        });
        assert!(
            r.input.starts_with(b"KEEP"),
            "got {:?}",
            String::from_utf8_lossy(&r.input)
        );
    }

    #[test]
    fn minimisation_is_deterministic() {
        let input = b"prefix-TARGET-suffix".to_vec();
        let run = || minimize(&input, 10_000, |c| c.windows(6).any(|w| w == b"TARGET")).input;
        assert_eq!(
            run(),
            run(),
            "same input and predicate must give the same result"
        );
    }
}
