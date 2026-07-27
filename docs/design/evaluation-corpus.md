---
status: proposed
consumers:
  - Netbraid evidence, replay, and adapter promotion
  - Linktop deterministic output and operator-scenario QA
  - Infra fusion shadow-parity and cutover gates
related:
  - ../saved-pcap-normalization.md
  - capture-conversation-reduction.md
  - rust-library-boundary.md
  - saved-capture-wlan-evidence.md
---

# Evaluation corpus

## Problem

A packet fixture can prove that one adapter parses one file without proving that
an operator conclusion is useful, that a Linktop view survives a context change,
or that Infra's multi-source fusion can replay and correct itself. Putting every
artifact into one growing `fixtures/` directory would blur five different jobs:
wire-contract regression, realistic operator scenarios, tool disagreement,
longitudinal behavior, and private calibration.

The corpus needs explicit tiers with different admission rules. More bytes are
not better coverage; each admitted case must protect a named inference,
abstention, provenance, or presentation boundary.

## Context

At this decision point, the saved-capture contract corpus contains eleven
licensed, immutable public fixtures totaling 11,843 decoded bytes: nine PCAP and
two PCAPNG; eight Ethernet, one raw IEEE 802.11, and two radiotap captures.
Three fixtures carry wireless expectations. Replay groups 17 packet envelopes
into nine capture conversations and explicitly excludes 51: 40 for ambiguous
network layer, one for ambiguous transport layer, and ten for unmodeled
encapsulation.

That is strong adapter-boundary coverage for its size. It is not a representative
sample of networks or security incidents. Linktop separately has schema/output
goldens and extensive in-module deterministic TUI tests, but no shared,
multi-artifact context-transition corpus. Infra has one Netbraid release-boundary
fixture; its deployed Kismet, BLE, rtl_433, Meshtastic, UniFi, and Home Assistant
sources do not yet have one replayable, cross-source parity bundle.

## Non-goals

- Do not publish raw household, person-presence, controller, or sensor captures.
- Do not use packet count, capture duration, or dataset fame as a proxy for
  semantic coverage.
- Do not treat another dissector's output as ground truth when tools can
  legitimately model layers, sessions, or application candidates differently.
- Do not label device identity, person, intent, or location from weak network
  features merely to make an evaluation scorable.
- Do not put multi-gigabyte corpora in Git or make ordinary unit tests depend on
  network downloads, Wireshark, Zeek, Suricata, or nDPI.

## Options considered

### One in-repository corpus

This is simple to discover, but it couples fast contract tests to slow scenario
and security evaluations, encourages Git growth, and pressures private
calibration data toward unsafe sanitization. Rejected.

### One external benchmark

Public IDS datasets provide traffic volume and labels, but generally do not
encode Linktop host-path transitions, source coverage, operator actions, or
Infra correction semantics. Their labels also answer a different question from
evidence provenance and abstention. Rejected as the sole evaluation source.

### Tier by evidence job

Keep tiny contract fixtures in Git; represent larger or multi-source cases with
content-addressed manifests; keep identifiable calibration material sealed.
Every tier has its own oracle and promotion gate. Chosen.

## Chosen approach

### Tier 1: contract fixtures

Small, reviewable inputs exercise one serialized schema, adapter, replay, or
reducer invariant. Public upstream bytes require an immutable revision and path,
Git blob ID, decoded SHA-256, redistribution license, bounded size, and exact
normalization/reduction expectations. Synthetic inputs retain readable
generation comments and documentation-range identifiers.

These fixtures run offline in the normal suite. Installed-tool smoke normalizes
each capture twice and proves deterministic records, receipt-bound digests,
replay equality, and typed reduction coverage. This tier is allowed to be
adversarial rather than realistic: the deep IPv6 extension-header case exists
to protect ordered-stack depth, while VXLAN exists to prove that nested
encapsulation is not flattened into a false conversation.

### Tier 2: realistic scenario bundles

A scenario is a manifest plus time-ordered source artifacts, expected evidence
gaps, operator questions, and output assertions. It may combine host-path
records, finite Linktop QA frames, controller snapshots, and saved captures.
The oracle is not a screenshot alone: it states the supported diagnosis,
required abstentions, source freshness/coverage, and the machine-readable
records that justify the presentation.

Those statements remain authored test oracles. The bundle validator rejects
unknown or future evidence, contradictory coverage, current observed coverage
without cited evidence, unsafe artifacts, and invalid viewport bytes; it does
not infer the truth of arbitrary prose or execute Linktop. Each consumer's
evaluation must produce an independent typed projection and compare it with the
declared oracle and, for presentation cases, render the declared viewport.

The first suite should allocate cases by risk, not claimed real-world
prevalence:

| Scenario class | Required variations |
| --- | --- |
| Attachment/context transition | Wi-Fi to hotspot and back; same SSID with BSSID roam; unrelated site/network; address and resolver changes |
| Route/overlay transition | physical attachment stable while VPN or exit-node route changes; overlay removed; split-route case |
| Impairment localization | gateway loss/jitter; DNS failure or delay; public-edge delay; local link healthy while remote path degrades |
| Passive visibility gap | empty or stale neighbor cache; controller unavailable; peer absent outside coverage; randomized address |
| Presentation pressure | overview, link, peers, and event views at narrow/short/wide terminals with dwell before and after a change |
| Saved-artifact boundary | truncation, tunnels, multi-interface PCAPNG, wireless management/data mix, malformed or quarantined rows |

These are suite weights, not estimates of how often users encounter each class.
One scenario earns admission only when it exposes a distinct operator decision
or a known false-positive risk.

The implemented `netbraid.scenario_bundle.v0` contract lives in
`netbraid-replay`, not `netbraid-evidence`. A bundle is a closed directory:
`scenario.json` plus an exact flat inventory of regular, non-symlink artifacts
with byte counts and SHA-256 digests. Unix loaders bind file opens to a stable
directory handle and use no-follow semantics. The manifest keeps coverage state
separate from freshness, cites evidence as `artifact#record`, distinguishes
supported conclusions from required abstentions, and constrains ASCII/ANSI-free
viewport fixtures to declared cells. The exact manifest bytes produce an
externally reported closure digest; the manifest does not contain its own
digest.

Four non-default `scenario-fixtures` built-ins establish the first admission
slice: Wi-Fi/hotspot recurrence; a same-SSID BSSID attachment transition
followed by an incompatible reused-label boundary; overlay entry/exit; and a
stale neighbor-cache gap. They use documentation addresses, locally
administered MAC addresses, and fictional network names. These tiny synthetic
cases prove the harness and named false-positive guards; they do not satisfy
the full variation table or claim a representative usage distribution.

### Tier 3: differential-tool corpora

Run the same immutable capture through bounded, version-pinned adapters for
TShark, Zeek, Suricata, and, when fingerprint work begins, nDPI. A native
Netbraid extractor enters this tier before it can replace any TShark-backed
semantic family. Compare facts at explicit semantic boundaries: packet extent,
endpoint tuple, protocol stack, reconstruction gap, handshake contribution,
application candidate, parser warning, and abstention reason. Differences are
recorded, not majority-voted. Two tools reading one capture are two
interpretations of one source, not independent observations.

Good next sources are generated fixtures whose provenance is inspectable:
OISF's MIT-licensed `suricata-verify` includes small PCAPs beside their
generation notes, and Arkime's Apache-2.0 test corpus includes paired captures
and expected records. Zeek's trace tree is valuable but has heterogeneous
per-file origins; its own trace index must be audited per artifact before any
vendoring. Public IDS datasets remain external evaluation candidates until
their exact terms, immutable versions, label semantics, and privacy properties
are recorded.

### Tier 4: longitudinal replay evaluations

These bundles span repeated contexts, late arrival, duplicate delivery,
collector silence, clock uncertainty, correction, and schema/extractor
upgrades. The core oracles are:

- shuffled delivery converges to the same cutoff state as batch replay;
- duplicate delivery does not duplicate semantic observations;
- a source frontier and collector health remain distinct;
- late evidence emits a named correction or quarantine rather than rewriting
  history silently;
- recurrence never crosses a site/network or attachment boundary without
  explicit compatible evidence; and
- deterministic output stays byte-identical for the same records, versions,
  cutoff, and configuration.

This tier is the gate for temporal baselines, episodes, and multi-source fusion,
not the packet adapter suite.

### Tier 5: private calibration datasets

Identifiable Kismet, controller, BLE, rtl_433, Meshtastic, Home Assistant, and
operator-confirmed binding data stays outside the public repository under the
owning collection and consent policies. A private manifest records content
digests, time/site scope, observer placement, feature extractor version,
labeling method, retention, and allowed evaluations.

Calibration evaluates candidate quality and abstention, not just top-1
accuracy. Required slices include unknown devices, randomized identifiers,
NAT/VPN/relay contexts, shared protocol stacks, moved sensors, source conflict,
and temporal drift. Public reports expose aggregate metrics and sanitized error
classes, never source rows or stable household identifiers.

## Tradeoffs

The tiers add manifest and harness work and prevent one attractive aggregate
score. That is deliberate: adapter determinism, operator usefulness, parser
agreement, replay correctness, and fingerprint calibration are different
claims. Content-addressed external bundles also require a fetch/cache tool
before they can run, but keep normal development fast and preserve license and
privacy boundaries.

## Implementation plan

1. Keep Tier 1 admission and smoke checks in
   `netbraid-adapter-tshark`; add a fixture only with a named boundary.
2. Extend the implemented scenario manifest only with an existing strict source
   family and a named operator decision; do not add generic untyped event rows.
3. Add the remaining context-transition, impairment, saved-artifact, and
   presentation-pressure variations; have Linktop consume the same checkpoint
   receipts at multiple terminal sizes.
4. Add one version-pinned differential runner and one generated public capture
   before broadening protocol coverage.
5. Use Infra shadow reads to export sealed Tier 4/5 manifests and aggregate
   parity reports; do not change its one-writer authority as part of curation.

## Decision gates

- A contract fixture is removed when no assertion fails without it or another
  smaller fixture protects the same boundary.
- A public artifact is rejected if its exact license, immutable origin, or
  privacy status is unresolved.
- A new inference family does not ship until a realistic scenario bundle
  contains positive, conflicting, and abstained cases.
- A fingerprint score is not called confidence until private, time-separated
  calibration reports discrimination, calibration, coverage/abstention, and
  error slices.
- Infra cutover remains blocked until longitudinal replay matches batch results
  and shadow parity across every deployed source family has a named rollback.

## Open questions

- What minimum sanitized aggregate can be published from private calibration
  while preserving useful error analysis?
- Which exact Zeek, Suricata, and Arkime generated fixtures close the next
  contract gap without duplicating the current corpus?
