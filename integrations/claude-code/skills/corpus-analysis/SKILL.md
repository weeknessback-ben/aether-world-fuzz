---
name: corpus-analysis
description: Analyse an AETHER corpus to explain what a campaign explored and why it stalled. Use when asked why fuzzing found nothing, whether a corpus is any good, how to improve seeds, or what a campaign actually covered.
---

# Analysing a corpus

The corpus is what a campaign learned. When a campaign underperforms, the
corpus usually says why — long before more CPU time would help.

## Gather the picture

- `aether_corpus_analyze` — size, distinct behaviours, mean score, and the
  highest-ranked entries with their coverage contribution and originating
  strategy.
- `aether_coverage_summary` — edges reached, instrumented guard count,
  saturation.
- `aether_campaign_status` — stagnation phase and strategy allocation.

## Reading it

**Corpus size barely above the seed count.** Almost nothing was interesting
enough to keep. Either the target rejects nearly every input at a first check,
or coverage feedback is not working. Confirm with `aether_target_inspect`:
`instrumented: false` explains it completely.

**Coverage saturation near 1.0.** Most instrumented code has been reached. More
time will not help much. What helps is a harness that reaches code the current
one cannot — often the real finding of the analysis.

**Saturation low and flat.** Something is blocking progress early. Look at the
top entries: if they are all short and all score similarly, inputs are being
rejected before anything interesting runs. Seeds, a dictionary, or a grammar
are the fix.

**`distinct_behaviours` much smaller than the corpus.** Many inputs drive the
target the same way. The corpus is bigger than it is diverse, and its
redundancy term is already down-weighting them.

**One strategy holding most of the allocation.** The scheduler found it most
productive per unit of compute. That is working as intended. If it is
`cmplog-guided`, the target is probably gated by magic values — a dictionary of
those constants may help further.

**`saturation: null`.** Not measurable, not zero. The target did not report a
guard count, so there is no denominator. Do not present it as 0%.

## Recommending improvements

In the order that usually pays off:

1. **Seeds.** One valid input is worth more than any amount of blind mutation
   on a format parser. Ask whether real example inputs exist.
2. **A dictionary.** Cheap and effective where the format has keywords or
   magic values. Extract them from the source or the format specification.
3. **A grammar.** Where inputs are structured and a valid one is hard to reach
   by mutation, generation beats mutation.
4. **A better harness.** If saturation is already high, the limit is what the
   harness can reach, not how long it runs.
5. **More time.** Last, not first. Only when coverage is still climbing.

## Honest framing

A corpus with high coverage and no findings is a real result: this target, this
harness, this budget produced no reproducible defect. That is worth stating
plainly, and it is not the same as the target being correct.
