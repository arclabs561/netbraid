---
status: experimental
consumers:
  - netbraid CLI
future-consumers:
  - Linktop focused evidence views
---

# Capture conversation reduction

## Problem

Packet envelopes preserve replayable facts but do not directly answer the first
questions an operator asks of a saved capture:

| Circumstance | Useful answer |
| --- | --- |
| A capture is unexpectedly large or busy | Which endpoint pairs account for the most frames and frame octets? |
| One direction appears impaired or silent | How asymmetric are the directional frame and octet counts? |
| A brief event must be aligned with another source | When was the first and last observed frame for the endpoint pair? |
| A TCP exchange looks incomplete | Which direction contained observed SYN, SYN-ACK, FIN, or RST flags? |
| Some packets cannot be summarized safely | How many were excluded, and for which explicit key-ambiguity reason? |

The current text summary lists L3 directions and destination ports separately.
That is compact, but it fragments one exchange across two lists and cannot show
bidirectional asymmetry. Traffic fingerprinting, application candidates, and
episode construction would all be premature without a deterministic,
coverage-bearing aggregate beneath them.

## Vocabulary and prior art

TShark's documented `-z conv,type` produces capture-wide conversation tables
with frames and bytes in each direction, totals, relative start time, and
duration. Zeek's `conn.log` uses originator/responder direction and distinguishes
payload bytes from IP bytes and packet counts. IPFIX defines a bidirectional
flow as paired uniflows and permits initiator, perimeter, or arbitrary direction
assignment, while warning that first-observed direction can be wrong for a
midstream capture.

Sources:

- [TShark manual: conversation statistics](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Zeek `conn.log` reference](https://docs.zeek.org/en/master/reference/logs/conn.html)
- [RFC 5103: Bidirectional Flow Export Using IPFIX](https://datatracker.ietf.org/doc/html/rfc5103)

Netbraid will call this first aggregate a **capture conversation**, not a flow,
connection, session, or episode:

- it spans one artifact rather than an idle/active timeout window;
- repeated use of one tuple is not sessionized;
- the capture may begin midstream or end early;
- endpoint direction is canonical and arbitrary, not an initiator claim; and
- frame octets are not payload or transferred-content bytes.

## Non-goals

- TCP stream reassembly, retransmission analysis, or connection-state parity
  with Zeek.
- UDP transaction/session inference or idle-timeout flow splitting.
- ICMP conversations in the first reducer.
- Service, application, operating-system, device-role, person, or intent
  inference.
- Treating the first observed endpoint as the initiator.
- Flattening tunnels, VLANs, multiple observation points, or incomplete
  first-occurrence field groups into one five-tuple.
- Emitting a new normalized evidence family for a deterministic result that the
  Netbraid CLI and Linktop can recompute from packet-envelope evidence.

## Options considered

### Parse TShark `-z conv` display output

This would reuse Wireshark's aggregation but add another process, make a
human-oriented table a machine contract, and hide why Netbraid excluded a packet.
It would also produce a second derivation path beside the packet-envelope
records. Rejected.

### Add a `netbraid-flow` or reducer crate

A new crate would suggest a separately released dependency or dependency set
that does not yet exist. `netbraid::replay` already owns deterministic operations
over evidence records and is already consumed by Linktop. Rejected until a real
dependency or release boundary appears.

### Reduce packet envelopes in `netbraid::replay`

One pure reducer over versioned packet envelopes gives the same result to the
Netbraid CLI and Linktop's finite saved-evidence review, adds no process or
collection capability, and can return explicit exclusion coverage. Chosen.

## Decision

`netbraid::replay` owns an experimental pure capture-conversation reducer.
`netbraid::evidence` remains unchanged because the result is not a normalized
evidence record. The Netbraid CLI uses the reducer in finite text output and in
the bounded, versioned `netmon.saved_pcap_triage.v0` operator projection. That
projection binds to the deterministic normalized-record digest and carries only
the top cumulative conversation plus coverage and candidate drill-down pivots.
The candidate five-tuple filter is intentionally not reducer membership: it may
also select packets excluded for VLAN, tunnel, repeated-layer, or other typed
eligibility reasons. Raw `--jsonl`
normalization output remains the manifest, successful-run receipt, packet
envelopes, and quarantines.

An eligible packet has:

1. exactly one observed IP family and exactly one TCP or UDP field group;
2. exactly one corresponding network protocol and transport protocol in
   `frame.protocols`;
3. no protocol named in the unmodeled partition/tunnel registry (initially
   VLAN, MPLS, PPPoE, GRE, VXLAN, Geneve, GTP, L2TP, and Teredo), and no
   repeated IP or transport layer;
4. complete, distinct source/destination address and port fields; and
5. an observation-point key consisting of section number, interface ID, and
   encapsulation type, including explicit unknown values.

The reducer canonicalizes the two `(address, port)` endpoints by address-family
bytes and then port. It labels them `endpoint_a` and `endpoint_b`; those names
are stable ordering labels only. The conversation key is observation point, IP
family, transport protocol, and the two canonical endpoints.

Each direction retains:

- frame count;
- original frame octets;
- captured frame octets; and
- for TCP, counts of frames with SYN without ACK, SYN-ACK, FIN, and RST flags.

Each conversation retains the earliest and latest packet-envelope event time.
The report also counts all emitted packet envelopes, grouped packets, and
excluded packets by typed reason. Ranking is deterministic: descending original
frame octets, then descending frames, then canonical key.

The finite triage projection names whether each claim covers the complete
capture or only the normalized packet subset. A positive WLAN disconnect-frame
or top-conversation observation is useful from its first supporting packet.
Deauthentication and disassociation counts remain separate typed observations
when both occur; one subtype never hides the other.
Absence is never promoted beyond that scope: a partial subset with no IEEE
802.11 or eligible conversation evidence is insufficient, while a supported
WLAN subset with no deauthentication or disassociation frame is only
`not_observed` within that subset. Normalized, WLAN, disconnect, and top
conversation windows retain event timestamps and observed span.

The CLI labels the section **capture conversations** and states that it is
capture-wide. It never calls original frame octets payload bytes, transferred
bytes, goodput, or throughput. The capture section prints exact absolute bounds
once; each conversation prints start/end offsets from that capture start plus
its span, matching the operator convention of capture-relative conversation
timing without discarding the underlying event timestamps.

## Tradeoffs

- Conservative exclusions reduce apparent coverage, especially for VLAN,
  tunnel, ICMP, fragmented, or partially decoded traffic. They are preferable
  to a confident but false five-tuple.
- Canonical endpoint ordering is reproducible but less immediately intuitive
  than client/server labels. TCP flag evidence can later support an explicit
  initiator candidate without changing the base direction.
- Capture-wide aggregation can merge tuple reuse. The output name and scope
  prevent it from masquerading as sessionized flow data. One long artifact can
  also span a network-context change on the same interface; without aligned
  context evidence, the reducer cannot split that boundary. The selected top
  conversation is cumulative across the claim scope and does not imply recent
  or time-local relevance. An operator may request a separate explicit
  source-artifact trailing interval with `--tail-seconds`; it never replaces
  the cumulative result or introduces an implicit warm-up threshold. The
  interval is anchored to occurrence-receipt file packet times when available,
  falls back explicitly to normalized packet event time otherwise, and includes
  both boundaries. Source-artifact packet extent, normalized packet artifact
  extent, and selected packet extent remain distinct. Negative conclusions are
  qualified only by complete normalization plus consistent occurrence file
  bounds spanning the requested interval; otherwise the projection abstains.
  Packet timestamp extrema do not establish continuous acquisition coverage.
- The reducer counts L2 frame octets because that is what the packet envelope
  records. Payload and IP-octet counters require additional explicit fields.

## Gates

- Reversing packet direction updates the opposite directional counter in the
  same conversation.
- Equal endpoint tuples on different section/interface/encapsulation keys never
  merge.
- Input ordering does not change sorted output, counters, or time bounds.
- Ambiguous IP/transport groups and protocols in the explicit unmodeled
  partition/tunnel registry are excluded with a typed reason. The registry is
  conservative and owned by the v0 reducer implementation; it is not a
  universal tunnel detector.
- Identical source/destination endpoints are excluded rather than assigned an
  invented direction.
- Original and captured octets remain separately named and tested.
- TCP flag counters distinguish SYN without ACK from SYN-ACK.
- The CLI states grouped/excluded coverage and capture-wide scope.
- Explicit trailing-interval selection is input-order invariant, includes both
  requested time boundaries, preserves cumulative output when absent, emits a
  candidate pivot bounded to the requested packet-time interval, and rejects a
  normalized timestamp outside receipt file bounds.
- Raw evidence JSONL output remains unchanged. A finite derived operator
  projection must use its own schema, bind to the normalized-record digest, and
  preserve capture-conversation scope and exclusions. V1 retains the complete
  validated manifest and optional occurrence receipt, while the v0 projection
  remains wire-compatible. The public projection paths reject count,
  capture-ID, receipt-digest, and receipt/normalized-time inconsistencies. The
  projection is not appended to the normalized evidence stream.

## Promotion questions

- Which real captures justify VLAN and tunnel key fields in a new packet-envelope
  registry?
- What idle/active timeout and TCP lifecycle policy would justify a true flow or
  connection record?
- Does Linktop have a focused evidence view that needs this exact reducer, or is
  the Netbraid CLI the only real consumer?
- Which stable reduction receipt should bind future serialized conversation
  records to packet-envelope inputs and reducer version?
