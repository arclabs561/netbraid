# Architecture

Netbraid separates evidence types, deterministic replay, external-tool
adapters, and presentation so that changing a CLI or tool invocation does not
silently change what a record means.

## Dependency direction

```text
                  netbraid::evidence
                    ^           ^
                    |           |
          netbraid::replay   adapters::tshark
                 ^  ^           ^
                 |   \         /
     netbraid::infer  netbraid CLI
```

`evidence` has no CLI, collection, controller, or process dependency. `replay`
parses and reduces those types without contacting the network. The optional
TShark adapter owns subprocess control and saved-capture normalization. The CLI
selects a finite human or machine projection. `infer` exposes finite,
versioned reducers over supplied evidence; it does not acquire observations or
apply deployment policy.

## Evidence model

Evidence records preserve:

- a schema and producer identity;
- observer and acquisition provenance when known;
- event and artifact time bounds;
- source extent and normalization completeness;
- typed observed fields;
- quarantined input that could not be represented; and
- limitations needed to interpret absence or inference.

Canonical serialization and domain-separated digests make deterministic record
streams comparable. Occurrence receipts bind one run, its wall-clock interval,
tool invocations, and the digest of the deterministic records. Occurrence
fields are deliberately excluded from `--records-jsonl`.

Evidence extent, observation provenance, interaction projections, event
alignment, artifact lineage, topology, and attribution are orthogonal axes.
Local containment exists where a source format guarantees it, but flow,
conversation, session, transmission, device, source, variant, and identity are
not successive levels of one hierarchy. Projection membership records its
observation scope and reducer policy; inferred alignment and attribution use
typed claim records with cited evidence and explicit alternatives.

This is a finite semantic graph in the ordinary data-model sense, not a graph
database or an open relation vocabulary. The core keeps small typed records and
pure reducers; storage engines and indexes remain consumer choices.

## Saved-capture path

1. Resolve one regular input file and copy it into a private staging directory.
2. Hash the staged bytes.
3. Run bounded Capinfos for file/container facts.
4. Run bounded TShark with name resolution disabled and an explicit registry.
5. Parse typed rows; preserve invalid rows as quarantines.
6. Re-hash the staged file and reject a mutation.
7. Emit a manifest, packet records, quarantines, and a successful-run receipt.
8. Reduce eligible packet records into conservative capture conversations.

Conversation direction uses canonical endpoint order. It does not infer
initiator, client/server roles, application identity, or intent. Packets with
ambiguous or unsupported layer shapes remain counted as excluded evidence.

## Scenario path

A scenario loader opens a closed directory, verifies the exact digest-bound
inventory, parses the manifest-selected schema, and validates every evidence
reference, checkpoint, coverage row, conclusion, abstention, and viewport.
Replay returns only the finite prefix declared at a named checkpoint.

Scenarios carry authored oracles. Validation proves their structural and
evidence closure; it does not certify arbitrary prose as ground truth.

## Inference path

Inference is a collection of explicit reducers, not one open-ended engine. The
content-relation, packet same-event, saved-PCAP packet-shape, counter/capture,
and admitted calibrated event-relation families each retain two substantive
alternatives plus unknown. Each proven family can project an evidence-linked
finite claim after recomputing the assessment from the caller-supplied source
values: a canonical list of source roles, source schemas, source identifiers,
and content digests around the same finite projection. A mismatched reference
fails before claim construction. The nested projection remains the
identifier-free view; the claim retains references rather than raw evidence or
the family-specific decision basis.

The v0 calibrated event-relation family is one bidirectional lower-distance
reducer with a fixed quantile policy, not a common model interface. It requires
two distinct opaque observation references, a validated prediction, its
calibration profile, and a separate held-out evaluation receipt whose frozen
gate status records `passed`. Profile, prediction, and receipt digests are
domain-separated. The prediction frame identifier is derived from the
canonical pair of observation references, so a prediction for another pair is
rejected. Scores, thresholds, model details, and evaluation metrics do not
enter the finite projection.

The receipt is evidence supplied by the caller. Content binding detects later
changes, but Netbraid does not resolve the cited report, partition, protocol,
or policy and does not authenticate the receipt producer. A consumer that
requires those guarantees must verify them before accepting the claim. This
admits one model result for replay and composition; it does not make an event
relation into identity, source, device, intent, authorization, or tamper.

Several finite claims can be placed in one bounded canonical composition.
Exact duplicates collapse and divergent claims for the same family, reducer,
and canonical inputs are rejected. Claims in different slots remain
independent: their co-presence does not establish a shared subject, identity,
confidence, or cross-family decision. A family omitted from the composition is
not assessed, which is distinct from that family's explicit unknown result.

The packet/flow-record correspondence family is one step before a finite claim.
It accepts a narrow directional flow-record projection rather than an adapter's
native type. Candidate admission requires matching TCP/UDP endpoints and
overlapping closed intervals. Split and merge components remain intact, and a
private bounded factor graph combines timing and aggregate-counter heuristics.
Exact enumeration is component-bounded. A component that exceeds its edge
bound abstains without partial edge beliefs. If all otherwise eligible
components do not fit the report assignment budget, all of them abstain rather
than giving priority to identifier order. Packet flows with fallback-only
orientation and flow records without a duration are not admitted. Normalized
heuristic belief is model-relative rather than calibrated, and the in-memory
source indices are not replay identifiers.

The optional Zeek entry point projects retained `conn.log` fields into the
flow-record contract and preserves its earlier result names. Other adapters can
project the same timestamp, endpoint, protocol, packet-count, and IP-octet
semantics without depending on Zeek. This is not a common interface for signal,
packet, conversation, source, or identity evidence. A new relation family keeps
its own source semantics and contributes only finite variables and factors to
the private kernel.

The RSSI shift-explanation family is the second use of that kernel. Its
variables represent observer-wide and source-wide explanations over the
deterministic RSSI reference-frame classification. Stable links remain in each
connected component as counter-evidence. For each shifted link, residual
belief is the exact joint mass where neither endpoint-wide explanation is
active; it does not require a redundant enumerated variable and does not erase
or relabel the original link evidence. Exact enumeration is bounded over the
free endpoint variables, and a refusal emits no partial beliefs. The output
remains an in-memory heuristic assessment, not causal identification or a
calibrated probability. Aggregate baseline samples are bounded before
classification. Separate state-space and assignment-work budgets cover exact
enumeration and the family-specific table and residual passes.

The content-relation family compares canonical SHA-256 declarations and keeps
unavailable digests unknown. Matching declarations do not prove byte equality
or establish the same object, event, source, device, variant, or identity;
different declarations do not establish corruption, transformation, tampering,
authorization, or intent. The
saved-PCAP family content-binds complete fingerprint candidates and lifts
corroborated, conflicting, and not-comparable lower comparisons to same packet
shape, different packet shape, and unknown respectively. Those shape
alternatives do not imply event, capture, device, source, variant, identity,
intent, or integrity. Matching packet structure also remains
non-discriminating for the separate packet same-event family, so that reducer
never supports same-event from structural agreement alone.

The deterministic RSSI reference-frame reducer is one layer earlier: it reports bounded
fixed-point link evidence, source-wide shift candidates, and observer-scoped
shift candidates. Source-wide changes are removed before observer attribution.
Those candidates are not location, movement, device-identity, intent, or attack
conclusions; a consumer must supply any policy that interprets them.

## Compatibility snapshots

The `net`, `device`, and `here` commands read a historical controller audit
shape. They are a compatibility edge around saved data, not part of the
evidence core and not a live controller client.

## Legacy acquisition

The Go program is a separate live process that writes PCAP and event artifacts.
It shares a repository and binary name for historical reasons but no Rust
runtime or data model. The Docker image contains only that compatibility
binary. New reusable contracts belong in the Rust package.

See [Design decisions](../DECISIONS.md) for the constraints behind this
structure.
