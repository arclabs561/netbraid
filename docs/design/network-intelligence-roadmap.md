---
status: active
scope: public evidence, replay, evaluation, and acquisition mechanics
decisions:
  - ../adr/0001-adopt-netbraid-product-identity.md
  - ../adr/0002-publish-netbraid-crates.md
  - ../adr/0003-own-versioned-scenario-bundles-in-replay.md
  - ../adr/0004-admit-public-reviewed-capture-derived-scenarios.md
grounded_in:
  - derived-intelligence-boundary.md
  - evaluation-corpus.md
  - rust-acquisition-cutover.md
  - rust-library-boundary.md
  - saved-capture-wlan-evidence.md
review_trigger: capture-derived fixtures enter Linktop, a second replay engine appears, a second independent capture-derived corpus needs product distribution, a live deployment asks Netbraid to own policy or identity authority, or a promoted intelligence family cannot preserve source lineage and abstention
---

# Roadmap: public network evidence and replay

## Where we are

Netbraid is the reusable, policy-neutral evidence side of the network
intelligence stack. Its Rust workspace currently provides:

- `netbraid-evidence` for versioned records and local invariants;
- `netbraid-replay` for strict finite input, deterministic replay, trailing
  triage, and closed scenario bundles;
- `netbraid-adapter-tshark` for a bounded saved-capture process and provenance
  boundary; and
- `netbraid` for finite operator and integration commands.

The implemented slices cover host-path recurrence, deterministic saved-PCAP
normalization, WLAN evidence, capture conversations, provenance-qualified
trailing triage, four small `PUBLIC_SYNTHETIC` v0 operator scenarios, and one
separately gated `PUBLIC_REVIEWED` v1 capture-derived scenario. The latter
exercises a real capture-prefix boundary: the seventh normalized IEEE 802.11
frame adds a deauthentication observation while source-wide absence, attack,
causality, actor, access-point, channel, and count claims remain unsupported.
Linktop is a real external consumer of the evidence and replay libraries and
can review normalized saved evidence without invoking the Netbraid CLI.

The four Rust packages carry 0.3.0 workspace metadata but are not yet published
on crates.io. The release identity is reconciled: commit `df67497` is the
immutable 0.3.0 candidate, the capture-derived work is included in its
changelog boundary, public CI is green, and the non-publishing release workflow
has built and bundled all three native targets. One valid scoped-token
bootstrap is still required to establish the four crate names before trusted
publishers can take over. Do not publish later `main` bytes as 0.3.0 or create
the tag before registry verification. The existing `netbraid-v0.2.0` tag
identifies an earlier commit and must not be reused.

Package licensing follows the bytes Cargo actually distributes, not which
features are enabled. `netbraid`, `netbraid-evidence`, and
`netbraid-adapter-tshark` remain `MIT OR Unlicense`; repository-only capture
corpora are excluded from their source archives. `netbraid-replay` distributes
the reviewed BSD-derived scenario fixture and notice, so its archive declares
`(MIT OR Unlicense) AND BSD-3-Clause`. A materially larger supported corpus
needs its own data-package or content-addressed release boundary instead of
broadening unrelated runtime crates.

The root Go capture command and `swucb` remain compatibility code. They are not
the architecture to port feature by feature. Netbraid is not a daemon, live
fusion writer, household identity database, packet-retention service, or
Linktop backend.

Netbraid is the product and package identity. Established `netmon.*` wire
schemas and digests remain readable compatibility identities; renaming durable
bytes would create churn without operator value.

## Roadmap split

Three roadmaps have different authority:

- this document owns public Netbraid records, reducers, adapters, corpora, and
  release gates;
- Linktop's
  [operator-intelligence roadmap](https://github.com/arclabs561/linktop/blob/main/docs/design/operator-intelligence-roadmap.md)
  owns the immediate terminal product and its human and machine projections;
- Infra's private `netbraid-identity-fusion-roadmap.md` owns deployed
  collectors, private identity and consent joins, shadow parity, writer
  cutover, retention, and Home Assistant projection.

An implementation belongs in the lowest reusable layer that has both a real
consumer and a costly invariant. Cross-repository CLI invocation is not a
library boundary, and shared subject matter is not enough reason for another
crate or repository.

## Program invariants

- Passive observation is the default. Active acquisition is explicit, bounded,
  policy-checked, and receipted.
- Every derived result retains source, observer, event and acquisition time,
  coverage, extractor or rule version, conflicts, and an explicit unknown or
  abstained result.
- Missing evidence becomes a negative claim only when the relevant interval
  and source completeness support it.
- Two tools interpreting one artifact are alternative interpretations, not two
  independent observations.
- Feature observations, candidate assessments, private bindings, and people
  are separate layers. A fingerprint never creates a device or person fact.
- A network context, attachment, overlay, place candidate, and verified place
  remain distinct. SSID, BSSID, gateway, OUI, or public egress alone does not
  prove physical location.
- TShark, Kismet, Zeek, Suricata, nDPI, controllers, and flow exporters retain
  specialist semantic ownership. Netbraid normalizes declared boundaries; it
  does not quietly reimplement their entire scope.
- Human text, JSON/JSONL, replay, and downstream TUI views project the same
  typed meaning at different densities.
- No new `core`, `model`, `fusion`, `runtime`, store, daemon, or umbrella crate
  is added without a second consumer or a measured invariant that the current
  four-package graph cannot own.
- Useful results should appear on the first supported observation. Longer
  dwell may improve distributions, recurrence, and baselines but cannot be a
  prerequisite for basic provenance, change, coverage, or abstention.

## Product outcomes and time to value

Netbraid is successful when reusable evidence helps an operator or another
tool answer progressively richer questions without making the first result
wait for a long-running service:

| Observation horizon | Reusable result |
| --- | --- |
| First supported record or snapshot | source identity, current context, direct positive facts, coverage, limitations, and an honest unknown |
| Seconds to minutes or one bounded capture | changes, rates, distributions, conversations, scoped positive and negative findings, and the evidence that would reduce uncertainty |
| A return or repeated incident | a context-compatible episode or baseline that cites both current and prior evidence without asserting physical place |
| Multiple observers or retained intervals | disagreement, earliest supported change, source-frontier gaps, and advisory application, service, stack, or role candidates with abstention |
| Explicit operator action | a bounded acquisition, experiment, or retained artifact whose request, execution, interval, side effects, and completion are receipted |

Linktop decides how much of this meaning fits in a TUI, finite report, or
stream. Infra decides which deployed and private sources may be retained and
joined. Netbraid owns the versioned meaning and deterministic reduction shared
by those consumers.

## Dependency direction

```text
specialist artifacts/tools
          |
netbraid-adapter-* ---> netbraid-evidence <--- netbraid-replay
          \                    |                    /
           \---------------- netbraid CLI ----------/
                                |
                     released crates / artifacts
                         /                   \
                    Linktop                Infra

future opt-in acquisition policy ---> Muxer
```

Adapters produce evidence. Replay owns deterministic reduction and scenario
loading. The CLI is an operator and integration surface, not a service
dependency. Linktop imports version-pinned evidence/replay libraries and keeps
its exact Git revision until its registry migration gate passes. Infra may
consume released libraries or the finite CLI at an explicit process boundary;
it never depends on a sibling checkout.

Muxer remains outside the graph until a fixed or seeded acquisition controller
has proved requested-versus-executed action, dwell, coverage, propensity, and
failure receipts. It can eventually select among caller-authorized arms; it
cannot authorize acquisition or define evidence semantics.

## Immediate execution order

These are gated lanes, not one serial feature train. In particular, registry
bootstrap does not block repository-only scenario or evaluation work.

1. Bootstrap the four 0.3.0 registry names from the clean `df67497` candidate
   using one valid scoped credential, configure trusted publishing, revoke the
   bootstrap credential, verify the registry packages, and only then tag that
   exact commit. The version decision and release rehearsal are complete.
2. Finish the operator-decision scenario matrix and Linktop presentation gate.
   Prioritize impairment localization, partial peer visibility, split-route
   behavior, and the smallest differential capture cases over corpus volume.
3. Support Linktop's explicit incident-capsule implementation only with
   reusable embedded records and replay. Linktop owns the transaction,
   retention choice, completion marker, and sanitized export.
4. Add one differential evidence family at a time from a named operator
   question and immutable fixture. The typed artifact-loading boundary is now
   in place; use it rather than returning source-specific parsing to the
   scenario orchestrator when controller, Kismet, flow, or another artifact
   family is admitted.
5. Promote episodes, baselines, fingerprint candidates, and optional live
   acquisition only after their later phase gates pass. Do not let the
   language migration or the ambitious product ceiling bypass evidence,
   calibration, authority, and rollback.

## Phase 0: establish the narrow Rust foundation (complete)

The current packages prove immutable records, deterministic replay, one bounded
specialist adapter, finite CLI projections, a real external library consumer,
and a closed scenario-bundle contract. Saved-capture review and replay remain
offline, bounded, and read-only.

Gate: passed. Canonical Rust checks, installed-TShark smoke, scenario replay,
package inventory, and public CI are green at the implementation checkpoint.

Value: an operator can inspect and replay evidence now without waiting for a
daemon, long baseline, or multi-modal schema.

## Phase 1: publish the Rust packages under one immutable identity

Commit `df67497` is the rehearsed 0.3.0 candidate. Its changelog includes the
capture-derived work, its public CI is green, and the workflow's `check-only`
path passed the release contract, dependency audit, three native builds,
archive packaging, and checksum bundle. From a clean checkout of that exact
commit, bootstrap each crate name with a fresh scoped token, configure the
GitHub trusted publisher, revoke the token, and verify each registry package's
repository, version, VCS SHA, dirty state, and yanked state before creating the
tag and GitHub release. Later commits with unchanged manifest versions are not
0.3.0 publication candidates.

Do not move Linktop as part of this publication. Linktop ADR-0008 currently
retains the exact Git revision until the crates it consumes exist on crates.io
at one compatible release identity and the later multi-modal compatibility
gate passes, while Netbraid ADR-0002 correctly forbids reusing 0.2.0 for newer
bytes. Whatever identity the release reconciliation selects, Linktop keeps its
Git pin until its accepted ADR is amended or superseded; this roadmap cannot
silently relax that gate. Infra release consumers must pin a released artifact
or semver contract, never a sibling path.

Consumer: fresh-clone users, future library consumers, and Infra admission
gates.

Gate: all four crates resolve from crates.io at one release identity; the
trusted publisher is configured; the bootstrap token is revoked; an external
scratch consumer and Infra pass from clean checkouts without a local Netbraid
directory. Linktop migration has its own accepted gate.

Reversibility: consumers retain their last exact known-good revision until the
registry build passes.

## Phase 2: make scenarios exercise operator decisions

Keep the four compiled `netbraid.scenario_bundle.v0` built-ins exact. Additional
public-synthetic v0 directories may remain repository evaluation data, but a
larger compiled built-in inventory needs an explicit versioning decision.
Admit capture-derived cases only through the separately gated,
disclosure-reviewed `netbraid.scenario_bundle.v1` contract. Keep both
contracts strict and admit only named false-positive risks. Fill the
highest-value gaps from the evaluation corpus:

- independently evidenced 802.11 roam/ESS continuity and unrelated-site
  variation beyond the implemented same-SSID BSSID attachment transition and
  incompatible reused-label network boundary;
- split routes and overlay changes without attachment changes;
- gateway, resolver, and remote-edge impairment localization;
- partial and stale peer visibility;
- saved-capture truncation, tunnels, multi-interface PCAPNG, and wireless
  management/data mixtures; and
- Linktop overview, link, peers, and event projections at wide, short, and
  narrow viewports before and after a transition.

The manifest's prose remains an authored evaluation oracle. Each consumer must
independently derive its typed result and render its own output; validation
does not turn prose into a proved network fact.

Checkpoint (2026-07-27): a fourth public synthetic scenario now distinguishes
an observed same-SSID BSSID attachment change with a compatible host-path
boundary from a later incompatible boundary that reuses the same label. It
requires abstention on physical place, network owner, access-point identity,
and whether the attachment change was an actual 802.11 roam.

A first `PUBLIC_REVIEWED` capture-derived scenario now guards a saved-capture
packet-limit boundary: six normalized IEEE 802.11 frames support only a
prefix-scoped disconnect-frame `not_observed`, while a seventh frame adds one
deauthentication observation without establishing attack intent, disconnect
causality, actor identity, managed access-point identity, radio channel, or the
source-wide frame count. Its observed/upstream/normalized lineage and BSD
notice are closed over exact package bytes under a separate non-default
feature; it does not widen the synthetic v0 contract. Before a second
independent capture-derived corpus becomes product data, decide whether its
bytes and aggregate licensing stay in replay or move to a separately versioned
data distribution. Enabling the capture-derived fixture in Linktop fires
ADR-0004's review trigger and requires a disclosure-aware consumer review; the
current Linktop pin and feature set have not crossed that boundary.

Scenario ingestion now has a private typed artifact-loading boundary.
Host-path records and parsed saved-capture streams retain their family through
bundle validation, replay projection, v1 disclosure checks, and checkpoint
input resolution. Viewport bytes remain available only to dimension checks;
license text is validated and classified but its payload is then discarded.
This removes repeated saved-capture parsing and makes the loading and retained
representation seam explicit before another source family is admitted, without
claiming a plug-in replay architecture or changing either scenario schema or
the public replay API. Raw saved-capture bytes are dropped after validation;
the existing owned checkpoint-input API clones its bounded parsed stream.

Consumer: Linktop product QA and Netbraid replay. Infra's multi-source Tier 4/5
corpus remains separately sealed under its deployment and privacy authority.

Gate: each admitted scenario protects a distinct operator decision or
abstention; replay is byte-deterministic; consumer tests cover supported,
conflicting, partial, and unknown outcomes; presentation cases pass both
portable and native-terminal capture.

Reversibility: scenario features remain non-default and consumers can retain a
prior exact release. Any fixture replacement is a new versioned, digest-closed
distribution rather than an in-place mutation.

## Phase 3: support a Linktop-owned incident evidence capsule

Linktop
[ADR-0012](https://github.com/arclabs561/linktop/blob/main/docs/adr/0012-own-private-incident-capsules-as-explicit-transactions.md)
ratifies an explicit operator-owned recording transaction. An intermittent
incident needs a finite, private handoff containing the invocation and tool
versions, path generations, typed changes, coverage gaps, explicit
active-operation receipts, artifact digests, and final human and machine
summaries. Ordinary Linktop operation must not retain packets or create this
artifact implicitly.

Implementation remains gated on Linktop serializing every source observation
needed to reproduce its conclusions. Netbraid supplies versioned embedded
records and deterministic replay where those are reusable; it does not own the
container, completion marker, retention choice, or sanitization transaction.
Attaching an already-created packet artifact is explicit under ADR-0012;
starting or coordinating packet acquisition remains a separate later
decision.

Consumer: operator handoff, deterministic replay, and agent-assisted incident
review.

Gate: an interrupted write produces no valid completion receipt; replay from
the capsule reproduces the same typed conclusions; a sanitized export names
every removed or transformed field; packet retention remains explicit.

Reversibility: the capsule is opt-in and private. No background service or
implicit retention is introduced.

## Phase 4: promote temporal episodes and baselines

Build path- or site-scoped episodes only after Tier 4 longitudinal fixtures
prove duplicate, reordering, late evidence, correction, source-frontier, and
restart semantics. A reducer compares evidence at an explicit cutoff and never
reads ambient wall time.

Episodes must answer concrete questions: what changed before a symptom, which
segment was implicated first, whether the same failure recurred under a
compatible context, and what evidence was unavailable. They do not infer place
from a nickname or merge unrelated contexts because they share private
addressing.

Consumer: recurring-incident triage in Linktop and sealed shadow analysis in
Infra.

Gate: incremental replay equals batch recomputation or emits a versioned
correction; recurrence never crosses an incompatible context; an episode is
useful after one change and becomes richer rather than merely possible after a
long dwell.

Reversibility: episodes and indexes are rebuildable projections over immutable
evidence.

## Phase 5: broaden evidence through differential boundaries

Add one evidence family at a time from a named immutable artifact and operator
question. Near-term candidates are richer acquisition receipts,
multi-interface capture provenance, and a handshake-local TLS or QUIC feature
experiment with contributing frame references. Each lane has its own gate;
native packet extraction is not a prerequisite for temporal episodes. Add one
version-pinned differential runner against a mature specialist before
promoting a native extractor.

A native Rust parser may own a narrow measured profile, such as transport
headers or one handshake projection, only after it matches or explicitly
disagrees with the specialist corpus. TShark remains the default saved-capture
dissector until replacement is earned on semantics, failure behavior,
provenance, and maintenance cost.

Consumer: saved-capture triage and future focused Linktop evidence views.

Gate: positive, conflicting, truncated, unsupported, and abstained fixtures;
stable contributing-source references; bounded execution; versioned
differences rather than majority-voted truth.

Reversibility: disable the experimental adapter or feature registry without
invalidating lower-level packet envelopes.

## Phase 6: add advisory fingerprint and role candidates

First serialize typed, family-specific feature observations with source and
window provenance. Then evaluate advisory application, service, stack, or
device-role candidates against public differential fixtures and sealed private
calibration data. Preserve alternatives, conflicts, drift, out-of-distribution
conditions, and open-world unknown.

Physical-device and person binding remain private policy decisions. No global
index of unknown devices, automatic person labeling, or transitive weak-edge
merge is permitted.

Consumer: operator-reviewed focused evidence, never an automatic binding path.

Gate: time-separated calibration and error slices exist; abstention is
measured; software upgrades, randomized identifiers, NAT, VPN, relay, shared
libraries, and site changes are represented; each displayed candidate cites
the exact feature observations and method version.

Reversibility: remove the candidate method while preserving source features and
accepted private bindings.

## Phase 7: support Infra shadow cutover at a released boundary

Infra may shadow a released Netbraid reducer or candidate over one sealed
interval and compare its existing diagnostic projection. Netbraid owns only
the reusable records and deterministic reduction demonstrated by that
consumer; Infra owns private joins, deployment, writer authority, retention,
rollback, and eventual Python retirement.

Consumer: one named Infra source or projection, not an implicit repository-wide
Rust rewrite.

Gate: the candidate is a released artifact rather than a sibling checkout;
sealed replay covers restart, correction, absence, and unknown behavior; shadow
parity names disagreements; cutover has one writer and a demonstrated rollback.
This gate does not depend on Netbraid owning live acquisition.

Reversibility: Infra retains the last known-good writer until each source or
projection passes independently.

## Phase 8: add optional fixed acquisition and retire Go by proven slice

Build the first Rust live-acquisition slice around a fixed round-robin or
seeded randomized schedule. Preserve hardware and regulatory eligibility,
requested and executed action, retune latency, dwell interval, drops,
completeness, terminal reason, and replayable receipts.

Cut over one consumer at a durable source boundary with one writer and a
rollback artifact. Do not port `swucb`; delete it and the Go capture path only
after the corresponding operator outcomes have Rust owners and no live
consumer imports remain. Go deletion happens per proven slice and is not
blocked on adaptive acquisition.

Consumer: an explicitly configured acquisition deployment, not Linktop's
passive default.

Gate: fixed or seeded replay is deterministic; requested action, executed
action, interval, observation, and terminal status share one receipt; a failure
injection proves rollback with no lost or duplicate interval; consumer and
dependency scans prove each legacy slice is deletable.

Reversibility: retain the last known-good writer until the new boundary passes;
the acquisition controller can be disabled without changing passive evidence.

## Phase 9: consider optional Muxer adaptation

Only after the fixed or seeded controller passes and a concrete adaptive
operator case exists may a released, propensity-correct Muxer policy select
among caller-authorized eligible arms. Muxer never authorizes acquisition,
widens the arm set, defines evidence meaning, or gates Go retirement.

Consumer: a measured acquisition deployment whose fixed baseline leaves a
specific, quantified allocation problem.

Gate: exact selected-action propensity and policy state survive receipts;
coverage is measured in airtime or useful observation rather than selection
count; fixed control and adaptive policy run on the same eligible-arm and
failure corpus.

Reversibility: disable the adaptive selector while preserving the fixed
controller and evidence contract.

## Structural forks requiring a decision before code

1. Linktop registry migration: retain the exact Git revision until Linktop
   ADR-0008's current conditions pass or a separately evidenced ADR amends
   them.
2. Scenario data distribution: before a second independent capture-derived
   corpus becomes product data, keep fixture bytes in replay or move them to a
   separately versioned content-addressed package with its own aggregate
   license.
3. Native packet extraction: the first promoted semantic profile and its
   specialist differential authority.
4. Policy-neutral binding reduction: promotion from Infra only after a second
   consumer or costly shared invariant.
5. Live writer cutover: the first source and its durable checkpoint or sealed
   interval; Infra owns private writer replacement.
6. Muxer integration: only after a fixed/seeded receipt-grade acquisition
   baseline and a released propensity-correct Muxer version.
7. Rust workspace placement: moving the existing workspace from `rust/` to the
   repository root requires an independent operator or maintenance benefit and
   must not be bundled with runtime retirement.

## Deferred, not promised

eBPF/BPF capture adapters, broad native Wireshark replacement, Kismet or Zeek
live daemons, generalized graph stores, learned physical-place inference,
cross-site unknown-device tracking, and autonomous active scanning are not
hidden phases. Each requires a named operator decision, representative data,
an authority boundary, and a separate scope decision before it enters this
roadmap. Root-workspace relocation is likewise deferred until it has a
concrete consumer or maintenance payoff.
