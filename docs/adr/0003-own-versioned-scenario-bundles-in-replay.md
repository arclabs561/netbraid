---
status: accepted
date: 2026-07-27
governs:
  - rust/crates/netbraid-replay/**
  - rust/src/scenario.rs
  - rust/src/main.rs
  - docs/design/evaluation-corpus.md
  - docs/design/derived-intelligence-boundary.md
  - docs/design/rust-library-boundary.md
  - docs/design/capture-conversation-reduction.md
  - .github/workflows/ci.yml
  - justfile
why: A closed scenario contract must validate evidence, coverage, abstentions, and presentation pressure through the same deterministic replay library consumed by operators without becoming a new evidence or identity schema.
rejected:
  - Put scenario manifests in netbraid-evidence as durable source observations
  - Let each CLI invent fixtures and expected-output conventions independently
  - Treat screenshots or captured terminal bytes as the scenario oracle
confidence: high
review_trigger: Revisit if a second replay engine needs the manifest without Netbraid semantics, or if large/private corpus distribution requires a separate content-addressed package.
---

# Own versioned scenario bundles in replay

## Context

Small packet and schema fixtures protect parser contracts but do not prove that
an operator conclusion remains useful across attachment changes, route changes,
source gaps, or constrained terminal views. Linktop, Netbraid, and Infra need a
shared finite scenario description, while source evidence must remain free of
test-oracle and presentation concerns.

A directory of ad hoc captures and screenshots would not state which conclusions
are supported, which claims require abstention, whether source coverage is current,
or which exact bytes were evaluated. Putting those fields into
`netbraid-evidence` would incorrectly make an evaluation manifest a source record.

## Decision

`netbraid-replay` owns `netbraid.scenario_bundle.v0`: a strict finite manifest,
closed artifact inventory, and deterministic checkpoint replay receipt.

The manifest separates source coverage state from freshness. Expected
conclusions distinguish supported results from required abstentions and cite
artifact records, coverage rows, and limitations. Viewport fixtures are ASCII,
ANSI-free, and checked against declared dimensions; they are presentation
assertions, not the semantic oracle.

Conclusions are authored evaluation oracles, not facts inferred by the bundle
validator. Validation proves their shape, evidence availability, coverage
references, and checkpoint ordering; it cannot prove arbitrary natural-language
semantics. Consumer tests must derive their own typed projection and compare it
with the declared oracle. Likewise, viewport validation proves exact bounded
terminal-cell fixture bytes, not that Linktop rendered them; Linktop's native
terminal QA owns that comparison.

Every artifact has an exact byte count and SHA-256. Artifacts are flat relative
filenames opened from a stable directory handle with no-follow semantics on
Unix; symlinks, nested directories, and undeclared files fail validation.
Host-path JSONL uses the existing strict replay parser. Saved-capture JSONL,
when declared, uses the existing saved-capture validator. Timeline references use
`artifact#record`, are unique and monotonic, and may not cite future evidence.
The closure identifier is the SHA-256 of the exact `scenario.json` bytes and is
reported by validation and replay; it is not self-stored in the manifest.

The normal library remains fixture-free. Three tiny `PUBLIC_SYNTHETIC` bundles
are available only through the non-default `scenario-fixtures` feature:

- Wi-Fi to hotspot and back, with exact observer-scoped recurrence and explicit
  place/owner abstention;
- overlay entry and exit, with provider, RF-causality, and intent abstention; and
- a neighbor-cache source gap, where stale evidence cannot become current
  presence or claimed departure.

The maintainer CLI exposes offline `scenario validate` and `scenario replay`
commands. Both read only the named directory and perform no collection,
subprocess, or network operation.

## Consequences

- Netbraid and downstream consumers can test the same evidence and abstention
  semantics at named checkpoints without sharing renderer internals.
- The built-ins establish Tier 2 admission mechanics, not realistic prevalence,
  multi-modal schema readiness, fingerprint quality, entity identity, or live
  fusion parity.
- Larger public synthetic bundles can use the same directory API. Private
  calibration bundles require a later privacy/retention contract; distribution,
  private labels, and source rows remain external to this crate.
- New inference families still require positive, conflicting, and abstained
  scenarios plus their own calibration and promotion gates.
