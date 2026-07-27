---
status: proposed
consumers:
  - Netmon evidence, replay, adapters, and CLI
  - Linktop focused evidence projections
  - Infra shadow replay and private fusion
related:
  - rust-library-boundary.md
  - capture-conversation-reduction.md
  - evaluation-corpus.md
  - ../../README.md
---

# Derived intelligence boundary

## Problem

“Fusion,” “tracking,” and “fingerprinting” currently describe several
different jobs:

- preserving observations from several sources without erasing disagreement;
- aligning those observations in time and deriving bounded episodes;
- classifying traffic, software, services, or device roles from features;
- joining rotating or source-local endpoints to a physical device; and
- projecting private device assignments into place or person presence.

Treating those as one subsystem would turn weak features into identity,
deployment policy into a reusable library, and offline replay into a claim
about live observability. Treating them as permanently unrelated would leave
each consumer to reimplement ordering, coverage, correction, and explanation.

The boundary must say which mechanics are reusable, which conclusions remain
advisory, and which authority stays in a private deployment.

## Terms

Use these terms consistently in schemas, text, and the TUI:

- **observation**: a source-qualified fact with event time, source reference,
  observer, acquisition context, and applicable coverage;
- **alignment**: deterministic ordering and comparison of observations without
  merging their source identity;
- **episode**: a method-versioned, half-open interval over one typed subject,
  with trigger, supporting and conflicting observations, coverage gaps, and a
  terminal state;
- **feature observation**: a typed protocol- or behavior-family fact, not a
  classification;
- **candidate assessment**: a reversible advisory result over cited feature
  observations, returning alternatives or an explicit abstention;
- **binding**: a separately authorized assertion that an endpoint or enrolled
  anchor refers to a private physical device;
- **identity fusion**: reduction of binding events under private authority,
  scope, consent, and purpose policy; and
- **projection**: one human or machine view over those objects.

“Tracking” alone is avoided. Linktop tracks one process-local path generation;
Netmon may construct typed episodes; Infra may maintain authorized private
bindings. None of those permits a global longitudinal index over unknown
devices.

## Current boundary

The implemented Rust core is intentionally narrower than this target:

- `netmon-evidence` serializes experimental host-path and saved-capture
  observations plus source, policy, coverage, extractor, and run receipts.
- `netmon-replay` performs deterministic JSONL replay, host-path comparison,
  and a non-serialized capture-conversation reduction.
- The TShark adapter normalizes one declared field registry from an immutable
  saved capture. It reports normalization completeness, not capture-wide,
  channel-wide, or network-wide observability.
- Linktop consumes only host-path evidence at an exact Git revision. Its
  process-local path and peer dwell are not durable cross-source episodes.
- Infra remains the sole deployed observation/fusion plane and production
  writer. Its source tables, topology, placement, retention, device
  assignments, consent, and person projections do not move into Netmon.

There is no stable multi-modal schema, serialized episode, fingerprint
candidate, live Netmon daemon, or production Rust fusion writer today.

## Decision

### Preserve specialist semantic ownership

Kismet owns radio acquisition, datasource health, monitor/channel behavior,
and KismetDB semantics. Wireshark/TShark owns deep packet dissection. Zeek,
Suricata, nDPI, controllers, DHCP servers, resolvers, and flow exporters own
their source-native records and interpretations.

Netmon adds an adapter only when it can preserve:

- immutable source identity or a durable live cursor;
- observer and observation-point identity;
- event and acquisition time plus clock uncertainty;
- acquisition policy and coverage;
- extractor/tool/configuration identity;
- source-native references and warnings; and
- an explicit unsupported, excluded, or unknown result.

The first Wireshark integration remains a bounded `tshark` and `capinfos`
subprocess adapter. It does not use a shell, isolates ambient configuration and
plugins, bounds input/output/time, and records tool and configuration
identities. This stable process boundary is preferable to binding the Rust
workspace to Wireshark's internal C object graph and plugin lifecycle.

### Grow a parallel native-Rust extractor

Native-Rust normalization is useful only where it improves capability,
correctness, portability, privilege separation, streaming, or maintainability.
Language composition is not a product goal and does not justify replacing a
stronger specialist. A native implementation is a second extractor profile,
not a silent implementation swap behind the TShark registry. Its manifest must
name a different adapter, version, configuration digest, field registry,
supported semantic families, and completeness result. Records from two
extractors over one artifact are two interpretations of one observation, not
independent observations and not votes.

The surveyed Rust ecosystem provides useful layers, but no evaluated candidate
met this design's libwireshark-equivalent breadth:

- [`pcap-parser`](https://github.com/rusticata/pcap-parser) is a safe,
  zero-copy, streaming PCAP/PCAPNG container parser. It preserves the
  multi-section, multi-interface, endianness, timestamp, option, and
  decryption-secrets structure that a native adapter must not flatten.
- [`etherparse`](https://github.com/JulianSchmid/etherparse) provides a
  well-tested, allocation-free Ethernet, VLAN, ARP, IP, extension-header, TCP,
  UDP, ICMP, and Linux-SLL decoder. Its optional IP defragmentation needs
  Netmon-owned global context, byte, and timeout bounds before use.
- [`rustnet-core`](https://github.com/domcyrus/rustnet/tree/main/crates/rustnet-core)
  demonstrates a reusable capture-independent packet/connection core and
  source-local DPI. Its current TCP application detection operates on packet
  payloads rather than a general reconstructed byte stream; QUIC CRYPTO is a
  narrower reassembled exception.
- [`protolens`](https://github.com/chunhuitrue/protolens) demonstrates bounded
  per-direction TCP reordering and protocol state machines over reconstructed
  streams. It deliberately leaves flow ownership and protocol recognition to
  its caller, and its protocol breadth is much smaller than Wireshark's.
- Rusticata's
  [`pcap-analyzer`](https://github.com/rusticata/pcap-analyzer) is a native
  offline framework to evaluate before assembling equivalent flow,
  fragmentation, reconstruction, and plugin machinery locally. Its current
  registered application parsers and operator contract are much narrower than
  Wireshark's dissector surface.
- Finished tools such as [`RustNet`](https://github.com/domcyrus/rustnet) are
  valuable implementation references and possible source adapters. Netmon
  imports a published library only when the library boundary, failure
  semantics, maintenance, license, and differential fixtures are better than
  copying a small stable primitive or executing the stronger specialist.

A native profile is layered:

```text
immutable capture
  -> container and interface/timestamp context
  -> link/network/transport decode
  -> IP fragment and transport-stream reconstruction
  -> handshake or transaction-local protocol decode
  -> typed Netmon evidence plus receipt
```

The first candidate slice stops after link/network/transport decode and targets
only the existing narrow Ethernet/Linux-SLL packet-envelope fields. It uses
`pcap-parser` plus `etherparse`, emits explicit unsupported-linktype results,
and does not add IP defragmentation, TCP reconstruction, TLS, QUIC, or
application sessions. No evaluated native composition currently preserves
Netmon's radiotap/IEEE 802.11 contract, so TShark remains authoritative for
that evidence and the long encapsulation tail.

Later layers are added only for a concrete operator question. Each preserves
unsupported, truncated, ambiguous, capped, and malformed results. Stream
reconstruction must specify overlap, retransmission, wrap, gap, memory,
timeout, and midstream policy. Application parsing cannot consume a
concatenation that silently erases direction, gaps, or contributing frame
references. Before building a native stateful L7 path, evaluate whether a
bounded TShark, Zeek, Suricata, or other specialist adapter answers the
question more correctly.

TShark remains the default extractor while a native profile grows one semantic
family at a time. It may remain the production extractor indefinitely where it
is more complete or trustworthy. Native promotion requires:

- byte-identical native output for repeated runs;
- differential fixtures against version-pinned TShark and, where useful,
  another specialist;
- explicit disagreement records rather than majority voting;
- adversarial truncation, fragmentation, overlap, retransmission, midstream,
  multi-interface, and resource-limit cases;
- fuzzing or equivalent parser-hardening evidence at every untrusted-byte
  boundary; and
- one operator projection that uses the promoted evidence without claiming
  broader dissector parity.

One capture/interface uses one extractor profile. Netmon does not silently
combine TShark fields and native fields into a row whose semantic authority
cannot be reconstructed.

This avoids both extremes: binding Netmon to Wireshark internals unnecessarily
and rewriting mature dissection breadth before a concrete operator question
needs it.

### Keep three kinds of fusion separate

1. **Source-preserving ingestion** stores adjacent observations and receipts.
   It is not an identity conclusion.
2. **Evidence alignment and assessment** is policy-neutral, deterministic, and
   replayable. These mechanics may be promoted into Netmon when fixtures and a
   second consumer justify them.
3. **Identity fusion and publication** applies private bindings, placement,
   consent, purpose, retention, and writer authority. Infra/private owns it.

Netmon never depends on Infra or private policy. Infra may consume released
Netmon crates or artifacts for shadow replay; it does not depend on a sibling
checkout path. Linktop depends on pinned evidence/replay libraries, never the
Netmon CLI or an Infra service.

### Model episodes before longitudinal identity

Every episode has one explicit subject and segmentation method. Examples:

- Linktop path generation;
- gateway impairment interval;
- resolver failure and recovery;
- capture-wide conversation;
- later, a timeout-sessionized transport flow;
- source-health gap; or
- private device-room dwell after an authorized binding.

An episode does not create a durable entity. Two episodes may be compared only
through explicit compatible subject evidence and scope. A tuple, MAC address,
SSID, JA3/JA4 value, RF signature, or timing pattern cannot silently become the
cross-episode key it is later used to validate.

### Separate features, assessments, and bindings

The promotion chain is:

```text
source record
  -> typed feature observation
  -> candidate assessment or abstention
  -> optional private operator/enrollment binding
  -> authorized projection
```

A feature observation is family-specific. TLS, TCP, DHCP, DNS-SD, RF, and
behavioral features do not share an untyped feature map.

A candidate assessment names:

- its typed subject and observation window;
- method family, version, and artifact/configuration digest;
- supporting, conflicting, ignored, capped, and unavailable evidence;
- applicable coverage and gaps;
- ranked alternatives;
- drift or validity horizon;
- correction or supersession lineage; and
- either a candidate label or a typed abstention reason.

Candidate kinds are limited to application, service, protocol stack, and
device role until a separately governed use case earns another kind. Candidate
assessment does not contain a person identity, create a physical-device
binding, or support transitive closure over weak edges.

Do not call a score “confidence” before time-separated calibration reports
discrimination, calibration, abstention coverage, and error slices. Source,
age, support, contradiction, and coverage are useful before a probability is.

### Do not attach handshake inference to a packet accidentally

JA3, JA3S, JA4, ALPN, SNI, supported versions, and similar fields describe a
handshake or a tool's interpretation of one. TShark may reassemble a handshake
from several TCP segments, observe several handshake messages in one frame, or
begin midstream. A first-occurrence field projection cannot prove that
independently selected TLS fields refer to the same semantic handshake.

Before serializing TLS features:

1. define a handshake-local subject and direction;
2. cite every contributing packet record or a receipt-bound deterministic
   derivation;
3. distinguish observed wire fields from TShark-derived digests;
4. preserve the extractor and reassembly configuration;
5. represent truncation, midstream capture, retransmission, TLS 1.3 legacy
   version fields, ECH/no-SNI, and unsupported fields; and
6. pass positive, conflicting, and abstained replay fixtures.

Until those gates pass, protocol presence in a packet envelope is not a traffic
fingerprint contract.

## Operator value

Derived intelligence earns a surface only when it changes an operator decision:

| Circumstance | Useful derived result | Decision |
| --- | --- | --- |
| A failure recurs after network switches | comparable path episodes with changed attachment, route, resolver, and coverage | wait, change network, enable a bounded probe, or collect a capsule |
| A VPN overlays a healthy Wi-Fi link | separate attachment and effective-route episodes | inspect the overlay instead of blaming RF |
| Two observers disagree about one endpoint | source-preserved contradiction and freshness | inspect the authoritative source or abstain from binding |
| An encrypted exchange dominates a symptom window | application/service/stack candidates with alternatives and exact pivots | inspect the cited handshake/flow or hand off the capture |
| An endpoint changes identifiers | scoped candidate continuity with no automatic identity | enroll/assert privately or leave it unknown |
| A source is silent or drops data | coverage gap rather than negative presence | repair acquisition before acting on absence |
| An incident needs handoff | deterministic evidence capsule and sanitized projection | reproduce the conclusion without sharing raw private data |

The top-level Linktop view continues to prioritize current answer, causal
reason, relevant change, active path, consequential workload, coverage gap,
and next move. Inventory and candidate detail remain focused views.

An effective route through a tunnel is two layers, not one interface. Linktop
must preserve both the overlay carrying the routed traffic and the physical
underlay carrying that overlay. For example, `utun4` may be the effective
route while `en0` supplies Wi-Fi association, RF, and physical counters.
Showing only either layer prevents an operator from localizing the fault.

## Session and packet retention

Ordinary Linktop and Netmon operation creates no durable session artifact
unless the operator names one. Normal exit says what the process itself wrote
and whether packet capture was enabled. It cannot claim that shell
redirection, terminal scrollback, or another process retained nothing.

An explicit Linktop recording transaction, for example
`linktop record --dwell 30 --output incident.linktop.jsonl`, should produce a
compact non-packet evidence capsule:

- invocation and tool versions;
- observation interval and path generations;
- typed local observations and changes;
- coverage/source gaps;
- active experiment receipts when explicitly enabled;
- final human and machine summaries; and
- content digests plus a sanitization/export receipt.

The capsule is no-clobber, private by default, visibly labels `packets: 0`,
and ends with a terminal receipt. An interrupted write remains explicitly
partial. A prior-context log is a different input: reading prior evidence must
not implicitly append to it or reuse it as the new incident artifact.

Raw PCAP/PCAPNG is a different, more sensitive transaction. It must name the
capture owner, interface/observation point, duration or other hard bound,
snaplen, acquisition filter, promiscuous/rfmon state, channel plan when
applicable, output path, loss/drop counters, and retention intent. Linktop may
recommend or orchestrate a specialist capture only through an explicit
operator action. Netmon may normalize the completed artifact; it does not
silently start capture.

When an overlay is active, a packet-capture recommendation distinguishes inner
overlay capture from outer underlay capture. Their visibility and privacy
consequences differ.

Infra's deployed Kismet plane keeps its existing collection and retention
authority. A live radio roster or device view is not permission to retain raw
packets.

## Surface contract

TUI, finite text, JSON/JSONL, dwell output, replay, and agent-facing summaries
project the same semantic objects. They may differ in density, not meaning.

One internal projection provides the operator transaction:

```text
observation
  id, generation, typed subject, interval, sources, freshness

assessment
  state, reason code, decisive observation IDs, coverage, limitations

action
  label, exact key or command, acquisition delta, question answered

receipt
  terminal state, elapsed interval, generations, records, artifacts,
  bytes, digests, and packet-data policy
```

The surfaces specialize the delivery:

- the TUI renders current state and focused evidence continuously;
- finite text renders one bounded observation and a terminal receipt;
- JSON renders one complete document;
- JSONL emits typed updates and exactly one terminal receipt;
- dwell capture records the same updates while native terminal QA takes
  screenshots at declared viewports; and
- replay renders the same projection from recorded evidence without consulting
  live state.

Human prose is rendered from typed reason and limitation data. Machine output
does not require an agent to reverse-engineer TUI-only reducers.

Every derived row exposes or links to:

- outcome and verb: observed, derived, candidate, verified, or unknown;
- typed subject and interval;
- source/observer and evidence references;
- age and coverage;
- alternative/conflict/abstention state; and
- one exact passive pivot or explicit bounded action.

Machine output does not serialize presentation prose as the only explanation.
Human output does not omit the coverage qualifier that controls the machine
claim.

## Rejected shapes

- One generic `Fingerprint` record containing raw features and a label.
- One generic feature map shared by unrelated protocols and modalities.
- A `netmon-fingerprint`, `netmon-fusion`, or third shared repository before an
  independent release or dependency boundary exists.
- A Linktop privileged packet engine or mandatory Netmon daemon.
- Porting the legacy Go capture architecture feature for feature.
- Claiming complete Kismet, Wireshark, Zeek, Suricata, nDPI, or Nmap parity.
- Hiding a native-Rust extractor behind the TShark field-registry identity.
- Concatenating TCP payloads without explicit direction, gap, overlap,
  retransmission, and contributing-frame semantics.
- Treating two analyzers over one artifact as independent observations.
- Global indexing or cross-site linkage of unknown devices.
- Device/person/place/intent claims from OUI, SSID, public address, RSSI,
  cache membership, or traffic shape alone.
- Silent PCAP retention at the end of an ordinary TUI session.

## Promotion order

1. Keep packet normalization, conversation reduction, host-path recurrence,
   and their coverage limits deterministic.
2. Add a content-addressed Linktop scenario-bundle contract for attachment,
   route/overlay, impairment, cache, and viewport changes.
3. Add acquisition-receipt fixtures for filters, snaplen, drops, clock facts,
   observation points, and source progress.
4. Add a native container/transport experimental profile only where it answers
   a concrete operator question or improves a measured boundary; give it a
   differential receipt without claiming application-dissection parity.
5. Prove one handshake-local, contributing-frame-aware TLS feature extraction
   experiment without a serialized candidate schema.
6. Build one Linktop focused evidence projection that renders a positive
   candidate, a contradiction, and an abstention with identical machine
   semantics.
7. Serialize a feature observation only if the experiment and second consumer
   make the invariant costly to duplicate.
8. Add candidate assessment only with time-separated calibration and
   open-world evals.
9. Build Infra's sealed six-source longitudinal corpus and prove batch versus
   shuffled, duplicate, late, dropped, and restarted replay parity.
10. Promote policy-neutral alignment or binding mechanics only under their
   existing ADR gates. Keep the Python writer authoritative until a fenced,
   measured, reversible cutover.

## Gates

- Same records, versions, cutoff, and configuration produce byte-identical
  output independent of delivery order.
- Source frontier, collector health, and observation coverage remain distinct.
- Late evidence emits a named correction or quarantine, never a silent rewrite.
- Negative claims fail closed without applicable complete coverage.
- Unknown-subject linkage cannot cross site, collection purpose, validity,
  retention, or export scope.
- No weak candidate edge participates in transitive identity closure.
- Every inference family has positive, conflicting, abstained, truncated, and
  out-of-distribution cases.
- One human and one machine consumer agree on outcome, scope, evidence, and
  abstention.
- A live writer cutover has one authority, a durable source boundary, shadow
  parity, rollback, and no lost interval.
