# Fixture policy

Netbraid admits fixtures by the boundary they protect, not by byte volume or
dataset fame.

## Contract fixtures

Small hand-authored or licensed upstream artifacts isolate one schema, parser,
adapter, replay, or reducer invariant. They run offline in the normal suite.

Synthetic fixtures use documentation-range addresses, locally administered MAC
addresses, fictional names, readable generation notes, and no copied private
payload. An upstream binary fixture requires:

- a redistribution license and included notice when required;
- repository, immutable revision, source path, and source URL;
- Git blob identity where available;
- exact decoded byte count and SHA-256 digest;
- a bounded committed representation; and
- a named behavior with typed expectations.

Tool-dependent smoke tests may decode the same bytes, but integrity and license
checks must not require the network or installed Wireshark tools.

## Scenario bundles

A scenario combines time-ordered evidence, source coverage and freshness,
operator questions, supported conclusions, required abstentions, and optional
bounded viewport text. Admission requires a distinct operator decision or
false-positive risk.

Useful scenario families include attachment changes, overlay changes,
impairment localization, passive visibility gaps, saved-capture boundaries,
and presentation pressure. The suite does not claim that its class balance
matches real-world prevalence.

## Capture-derived scenarios

Capture-derived evidence needs a disclosure contract separate from provenance.
The manifest records source origin, derivation, acquisition mode, sensitivity,
immutable coordinates, raw and normalized digests, license, and retained
identifier classes.

Reviewers must be able to enumerate every retained identifier class in
ingestible records. Opaque bytes, unknown provenance, incompatible license,
unbounded size, or a vague “realism” justification fail admission.

Raw private household, workplace, person-presence, controller, credential, and
sensor captures do not belong in the public repository. Sanitization is not
assumed safe merely because visible names were replaced.

## Larger evaluation data

Large public corpora and private calibration data belong outside Git behind
content-addressed manifests. Their oracle must state what is authoritative,
what is only another tool's interpretation, and which versions produced it.
Ordinary tests must remain offline, bounded, and reproducible.

## Promotion gate

A new evidence or inference family needs representative positive, negative,
partial, stale, and ambiguous cases; provenance and disclosure review; explicit
abstention behavior; deterministic replay; and a concrete consumer. Until then,
keep it experimental or outside the public contract.
