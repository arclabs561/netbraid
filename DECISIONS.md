# Design decisions

This file records the product decisions a contributor needs in order to change
Netbraid without weakening its evidence boundary. Implementation history
remains in Git; private deployment planning stays outside the public repository.

## One Rust package

The public Rust library and CLI are one Cargo package named `netbraid`. Evidence,
replay, optional adapters, fixtures, and the binary use Cargo features rather
than separate registry packages. This keeps one version, one compatibility
story, and one release lifecycle while the public boundaries remain small.

## Evidence and replay are the core

`netbraid::evidence` owns versioned, policy-neutral observations.
`netbraid::replay` owns strict parsing, finite scenarios, triage, and pure
reducers. Optional adapters translate bounded external artifacts or tools into
those records. The CLI projects the same types for operators and machines.

Collection, storage, identity policy, deployment, and presentation-specific
diagnosis are consumers of the core, not hidden authorities inside it.

## Preserve provenance before inference

Every promoted record family needs source identity, acquisition policy when
known, time bounds, normalization or coverage state, and deterministic replay.
Unknown, absent, partial, quarantined, and unobserved are distinct states.

Addresses, ports, protocol fields, network names, registrant hints, recurrence,
and traffic shapes may support pivots or candidates. They do not by themselves
verify a device, owner, application, person, place, intent, or security event.

## Model evidence units and claims on separate axes

Signal ranges, capture occurrences, decoded packets, flow/session projections,
conversations, topology paths, content artifacts, transmissions, devices,
physical sources, and identities do not form one universal containment tree.
Netbraid keeps immutable evidence families separate and connects them with a
closed set of versioned, typed relations and claim records.

Hierarchy is retained only where the source contract guarantees it, such as a
frame occurrence captured on one interface or a byte range in one artifact.
Flow membership records the observation scope, reducer, key, time bounds, and
sessionization policy. Cross-observer same-event, physical-source, device,
variant, authorization, intent, and tamper statements remain evidence-backed
hypotheses rather than parent links.

This permits competing projections over the same evidence and many-to-many
links for reassembly, encapsulation, duplicate observations, and attribution.
It rejects both a universal superclass hierarchy and an open-ended graph/RDF
engine: reducers and relation vocabularies remain finite Rust contracts.

## Keep probabilistic machinery private and claims family-specific

Finite relation families may use a private typed factor graph when independent
per-record decisions would lose split, merge, or shared-evidence structure.
Candidate admission remains a deterministic family rule. Factors state whether
they are heuristics, deterministic constraints, priors, or likelihoods, and
carry their direct evidence and dependence declarations.

The first solver enumerates bounded connected components. Exact, infeasible,
and resource-abstained outcomes are separate; a resource refusal does not emit
partial beliefs as exact output. Heuristic factors yield only model-relative
normalized belief. They cannot be mixed with probabilistic factors in one
graph. A future prior or likelihood must cite an immutable model-profile digest,
while any empirical calibration claim additionally requires a separate
held-out evaluation receipt.

This does not make the private graph a public relation vocabulary or storage
model. Public records remain finite and family-specific. In-memory candidate
indices are not durable evidence identities and cannot be promoted to a
replayable claim without content-bound source references.

The graph also does not define a universal observation or flow superclass.
Packet sessions, decoded logs, signal windows, transmissions, conversations,
and identity candidates retain different admission, coverage, and provenance
contracts. Each relation family maps only its own finite variables and factors
into the private solver. Shared mechanics are reused without forcing unlike
evidence into the packet/flow-record schema.

The second family is deliberately non-packet: RSSI reference-frame links map
to observer- and source-shift variables plus a derived residual-link belief. It
reuses exact component inference without importing packet, flow, address, port,
or Zeek semantics. This demonstrates the intended mechanical reuse; the RSSI
family's single joint factor does not itself exercise cross-factor dependence
validation, justify publishing the generic graph, or treat all observations as
one schema.

## Offline and passive Rust defaults

The Rust CLI reads saved evidence or a regular saved capture. It does not open
live interfaces, scan a LAN, manipulate radio channels, or contact controllers.
Normalizing an existing artifact is passive, but the artifact records its
original acquisition policy only when independently known.

Future active acquisition must be explicit, bounded, provenance-bearing, and
separable from passive use. It may not silently enter a default command.

## External dissectors are adapters

TShark and Capinfos own mature capture-container and protocol dissection.
Netbraid invokes them through one bounded offline adapter instead of exposing
their complete evolving output or reimplementing Wireshark. The adapter selects
a fixed registry, disables name resolution, isolates personal configuration,
records effective-tool provenance, quarantines invalid rows, and enforces
resource limits.

The resulting schema is Netbraid's contract; a particular executable or plugin
set is not.

## Scenario fixtures have disclosure contracts

Small synthetic fixtures are public by construction and use documentation
identifiers. Capture-derived fixtures require immutable origin, license,
content digest, retained-identifier inventory, bounded size, named utility, and
explicit review. Raw private captures and sanitized-looking derivatives are not
admitted casually.

Fixtures prove named inference, abstention, provenance, or presentation
boundaries. Quantity and packet volume are not substitutes for semantic
coverage.

## Separate data acquisition from evaluation

`data/` owns tracked public-source descriptions, bounded fetchers, and their
hermetic integrity tests. Downloaded archives and captures, generated products,
and machine-local receipts remain ignored under `data/raw/`, `data/derived/`,
and `data/receipts/`.

`eval/` owns dataset-backed evaluators, bounded fixtures, harness tests, and
aggregate experiment ledgers. Evaluation may consume ignored artifacts but may
not silently promote source bytes, labels, or dataset-specific policy into the
library contract. Deployment-specific campaign configuration remains outside
the reusable evaluator.

Every retained derived campaign artifact has a checked-in producer and a
canonical recipe. Meaningful campaigns repeat deterministic production and
evaluation or state why repetition is inapplicable; an interactive command
transcript alone is not provenance.

## Keep historical wire names stable

Some published schema, producer, registry, and digest identifiers use the
historical `netmon.*` namespace. They remain unchanged where renaming would
break serialized compatibility. New product and Rust API names use `netbraid`.

## Legacy Go is retired

The former root Go capture CLI and disconnected acquisition-policy experiment
predated the Rust core and had no active package, release, or deployment
consumer. Their final source remains recoverable at the `netwatch-go-final`
tag. They are not part of Netbraid's active architecture or support surface;
new acquisition boundaries must enter through explicit evidence adapters and
their evaluation gates.

## Distribution

One Cargo package and executable are published as `netbraid`. Tagged releases
add native Linux and macOS archives, checksums, and build provenance. The
package source archive contains only material needed by the library, CLI, and
supported public fixtures.
