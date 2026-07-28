# Capture conversations

Netbraid reduces eligible packet envelopes into a bounded, deterministic
summary that helps an operator pivot through a saved capture without claiming
session semantics the evidence cannot support.

## Identity and direction

A conversation key contains the observation point, network family, canonical
endpoint pair, and transport tuple when present. Endpoint order is a stable
bytewise order, not a guess about initiator, client, server, request, or
response.

Observation points remain separate. Netbraid does not merge equal tuples from
different capture interfaces or encapsulation contexts.

## Contribution

For each eligible envelope the reducer records:

- packet and captured/original byte counts;
- first and last observed event times;
- directional counts in canonical endpoint order;
- the ordered protocol stacks that contributed; and
- incomplete-capture signals such as truncation.

Ranking is deterministic and bounded. The complete machine records remain the
source of truth when a text projection omits lower-ranked conversations.

## Exclusions

An envelope is excluded, with a counted reason, when it cannot support one
unambiguous key. Typical reasons include:

- no supported network layer;
- conflicting IPv4 and IPv6 candidates;
- repeated or nested fields that cannot be flattened safely;
- conflicting TCP and UDP candidates; or
- an unsupported encapsulation boundary.

Exclusion is evidence about reducer coverage, not a malformed-packet verdict.
The operator summary reports both grouped and excluded counts.

## Interpretation

A conversation is a capture-local grouping of observed headers. It is not:

- a reassembled transport connection;
- an authenticated endpoint or device;
- a verified application or service;
- an actor, person, role, or owner;
- proof of direction, intent, compromise, or causality; or
- proof that unobserved traffic was absent.

Protocol stacks, addresses, ports, timing, and byte shapes are useful pivots
and can support explicitly labeled candidates. Stronger conclusions require
additional evidence and a consumer-owned inference contract.
