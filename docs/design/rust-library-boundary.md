---
status: experimental
consumers:
  - netbraid CLI
  - Linktop
---

# Rust library boundary

## Problem

Netbraid and host-facing tools need to exchange policy-neutral network evidence
without making one CLI invoke another or copying comparison semantics between
repositories. The shared contract must remain useful without a daemon,
controller, operational store, or particular workstation layout.

The first shared slice is deliberately narrower than a multi-modal observation
or identity-fusion schema. It exercises serialization, provenance, coverage,
ordering, replay, and second-consumer mechanics without claiming that endpoint
identity, traffic fingerprinting, or live fusion is settled.

## Decision

Netbraid exposes three Rust libraries beside its operator CLI:

```text
                         netbraid-evidence
                    /          |          \
          netbraid-replay      |      netbraid-adapter-tshark
                 \             |             /
                  Linktop CLI/TUI       netbraid CLI
```

`netbraid-evidence` owns serialized, versioned record types and their local
invariants. It has no collectors, renderer, wall-clock reads, filesystem
access, networking, controller client, or deployment policy.

`netbraid-replay` owns deterministic operations over those records: JSONL
decoding, append validation, ordering, context comparison, recurrence, and
replay summaries, plus pure capture-conversation reduction over packet
envelopes. It may perform explicit file I/O, but it is not a daemon or generic
storage framework. The same records, ordering inputs, and cutoff must produce
the same state.

`netbraid-adapter-tshark` owns the offline saved-capture process and provenance
boundary. It returns `netbraid-evidence` records; it does not capture live traffic
or infer acquisition coverage.

The `netbraid` package remains an operator CLI. It may import the libraries as
commands earn concrete use cases. The legacy Go CLI remains compatibility capture
code and is not a library foundation.

Linktop imports the libraries directly for optional prior-context comparison.
It remains usable with no history path and no Netbraid executable, service, or
store. Imported libraries may not initiate network activity.

## Dependency and release policy

Within the Netbraid workspace, packages use local `path` plus exact workspace
`version` dependencies. Across repositories, consumers use crates.io semver
releases and a lockfile. Cross-repository filesystem paths and floating Git
branches are forbidden; an exact Git revision is reserved for a deliberate
unreleased compatibility trial.

The current mixed Go/Rust repository keeps its Rust application under `rust/`
while the root Go CLI remains a compatibility surface. At the all-Rust cutover,
the intended shape is a root virtual Cargo workspace with a tracked lockfile:

```text
Cargo.toml
Cargo.lock
crates/
  netbraid/             # operator application
  netbraid-adapter-tshark/
  netbraid-evidence/    # versioned records and invariants
  netbraid-replay/      # deterministic replay and explicit file I/O
```

Do not add `core`, `model`, `store`, `fusion`, `runtime`, or daemon crates in
anticipation of future work. A package boundary must isolate a real dependency
set, reusable API, independently released artifact, or second consumer.

`netbraid-adapter-tshark` earns its process boundary by owning bounded shell-free
offline invocation, subprocess deadlines, private input staging, tool and
effective-configuration provenance, a declared first-occurrence field registry,
exact timestamp parsing, canonicalization, quarantine, and normalization
completeness. Returning raw TShark JSON would not have earned a crate. Its
saved-PCAP contract is specified in
[`../saved-pcap-normalization.md`](../saved-pcap-normalization.md).

## Host-path v0 contract

`HostPathObservationV0` records:

- event and acquisition ordering supplied by the collector;
- an observer ID and source adapter identity;
- passive or active collection policy;
- explicit coverage and missing-source labels;
- interface and link type;
- network-name visibility and value when available;
- association ID and associated BSSID when exposed;
- next hop and its passively cached link-layer binding when present;
- resolver set and path address prefixes.

It cannot assert endpoint identity, presence, device role, application
protocol, human intent, physical location, or absence outside declared
coverage.

Comparison is open-world:

- equal keys are exact key matches;
- conflicting values observed on both sides support a context change;
- a field observed on only one side is compatible enrichment.

Missing evidence is not an equivalence relation. Renderers must preserve the
compatible state rather than turning it into sameness or change.

The recurrence result distinguishes:

- no prior exact key match;
- an unanchored exact key match; and
- anchored exact recurrence when the key includes a gateway next-hop
  link-layer address.

A repeated BSSID is separate attachment corroboration. It never promotes an
unanchored match into context identity. Equal missing gateway bindings or
BSSIDs therefore remain key matches, not a recurring-network claim.

A network context is not a physical place. SSIDs and private addressing repeat,
one site may contain several BSSIDs, clients roam, and hotspots move. Human
place labels and coordinates belong above this raw evidence contract.

## JSONL integrity

`read_jsonl` is strict.

`read_jsonl_recovering_tail` may return a valid prefix only when the malformed
fragment is final and unterminated. It returns a typed warning with that prefix.
Malformed internal records, newline-terminated malformed records, and
syntactically complete invalid evidence remain errors.

`append_jsonl` validates existing content strictly, canonicalizes the record,
writes the record and newline from one buffer, and refuses to append behind a
corrupt tail. A valid final record without a newline receives one separator.
This is a single-writer-per-log contract, not a cross-process locking or
durability guarantee.

## Non-goals

- No live collection, controller access, active discovery, or packet capture in
  the evidence or replay libraries.
- No host-facing diagnosis, rendering, or interaction in Netbraid libraries.
- No default durable history in a consumer.
- No multi-modal identity, person presence, consent, or credential policy.
- No reimplementation of Kismet, TShark, Zeek, Nmap, or controller acquisition.
- No claim that a hostname-shaped observer ID is durable hardware identity.

## Gates

- Golden JSON fixtures cover canonical serialization and validation.
- Replay is deterministic under explicit ordering and equal timestamps.
- Unknown schema IDs and malformed records fail explicitly.
- Set-like fields canonicalize before serialization and comparison.
- Compatible missing evidence never becomes a transition or recurrence claim.
- Interrupted-tail recovery is warning-bearing and read-only at the consumer.
- Append never writes behind known corruption.
- A consumer builds from crates.io without a sibling Netbraid checkout.
- Shared crates contain no collection, controller, actuation, or identity
  policy.
- Capture conversations keep observation points separate, use canonical
  endpoint direction rather than guessed initiator direction, and report
  excluded packet-envelope coverage.
- Saved-capture adapter fixtures include a content-addressed, licensed upstream
  corpus beyond the hand-authored one-packet cases; the integrity test is
  network- and tool-independent, while the smoke lane exercises installed
  Wireshark tools.
- Semver publication requires backward-compatibility tests and representative
  fixtures for each promoted evidence family beyond the host-path and current
  saved-capture slices.
