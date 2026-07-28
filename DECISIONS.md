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

## Keep historical wire names stable

Some published schema, producer, registry, and digest identifiers use the
historical `netmon.*` namespace. They remain unchanged where renaming would
break serialized compatibility. New product and Rust API names use `netbraid`.

## Legacy Go is compatibility-only

The root Go capture CLI and disconnected acquisition-policy experiment predate
the Rust core. They are not architectural dependencies of the Rust package.
They receive compatibility, security, and build fixes until their remaining
contract can be retired without losing useful acquisition evidence.

## Distribution

One Cargo package and executable are published as `netbraid`. Tagged releases
add native Linux and macOS archives, checksums, and build provenance. The
package source archive contains only material needed by the library, CLI, and
supported public fixtures.
