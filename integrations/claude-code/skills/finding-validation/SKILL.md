---
name: finding-validation
description: Validate a suspected fuzzing finding into reproducible evidence, or establish that it does not reproduce. Use when asked whether a crash is real, to reproduce or minimise a crashing input, to triage fuzzing results, or to write up a defect report.
---

# Validating a finding

A crash observed once is a candidate, not a defect. This skill turns one into
evidence, or establishes that it cannot be.

## The question to answer

Not "did it crash" — the campaign already recorded that. The questions are:

1. Does it reproduce, and how reliably?
2. Is the failure now the **same defect** as the one recorded?
3. What is the smallest input that still triggers it?
4. What can honestly be said about severity?

## 1. Read the recorded evidence

`aether_finding_detail` with the finding id. Note:

- `status` — see the statuses below.
- `repro_successes` / `repro_attempts` — the rate established when it was found.
- `reproduce_argv` and `input_delivery` — how to run it by hand.
- `trigger_hash` and `minimized_hash` — the original is always kept, even after
  minimisation, so the finding stays auditable.
- `notes` — caveats the engine recorded, including whether varying symptoms
  were seen across runs.
- `unenforced_limits` — limits this host did not actually apply. A finding
  produced without a memory limit in force deserves that caveat.

## 2. Re-validate

`aether_finding_validate` re-runs the input. Read the result carefully:

- `matches_recorded_signature: true` → same defect, and the new rate is a
  second independent measurement. Report both.
- `matches_recorded_signature: false` → a **different** failure happened. This
  matters: it usually means memory corruption whose symptom varies between
  runs, which is more serious than a stable crash, not less. Report both
  signatures and say so.
- `successes: 0` → it did not reproduce at all. Say so plainly. Do not report
  it as a defect. Common causes worth checking: the target was rebuilt, the
  defect depends on address layout, or it needs a sanitizer build to be visible.
- `other_signatures > 0` → several distinct failures from one input. Same
  reading as above.

Raise `attempts` when the rate matters — 20 or 50 runs give a much better
estimate than 5 for an intermittent defect.

## 3. Minimise

`aether_finding_minimize`. The minimiser only accepts a candidate that
reproduces the **same signature**, so a minimised input is still the same
defect.

Read `revalidated` in the result:

- `true` → the minimised input was independently confirmed. Use it in the
  report.
- `false` → it could not be confirmed. Report the original input and say the
  minimisation is unconfirmed. Do not quietly present an unvalidated minimised
  input as the reproducer.

`reduction` tells you how much was removed. A 95% reduction usually makes the
defect obvious on reading; no reduction at all often means every byte matters,
which is itself informative.

## 4. Write it up

Structure that keeps facts separate from inference:

**What was observed** — the fault, the signature, the reproduction rate as a
fraction, the reproduction command, the input size before and after
minimisation.

**What the sanitizer reported**, if any — the fault class and the top frames.
Those name the code involved.

**What is not known** — and say it explicitly:

- Whether the defect is exploitable. A fuzzer cannot determine this. The
  engine records `exploitabilityAssessed: false` and so should the write-up.
- The root cause, unless the stack frames make it genuinely unambiguous.
- Whether it affects other versions or configurations.

**Severity** as the evidence supports it:

| Evidence | Reasonable statement |
| --- | --- |
| Sanitizer reports a memory-safety violation | "Memory-safety violation. Exploitability not assessed." |
| Fault signal, no sanitizer detail | "Crash. Cause not diagnosed; may or may not be memory corruption." |
| Timeout | "Exceeded the deadline. May be an infinite loop, or simply slow." |
| Invariant violation, clean exit | "Incorrect result against the declared expectation. Did not crash." |

Never write "critical", "remote code execution" or "attacker can" from fuzzing
evidence alone. None of those follow from a crash.

## What to refuse

If asked to describe a finding as a vulnerability, assign a CVSS score, or
assert impact that the evidence does not support, say what the evidence does
support and what would be needed to go further — usually manual analysis of the
faulting code. That is a more useful answer than a number with nothing behind
it.
