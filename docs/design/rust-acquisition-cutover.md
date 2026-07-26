---
status: proposed
consumers:
  - Netmon
  - Infra
  - Linktop
related:
  - rust-library-boundary.md
  - capture-conversation-reduction.md
  - ../saved-pcap-normalization.md
---

# Rust acquisition cutover

## Problem

Netmon has a policy-neutral Rust evidence and replay core, an offline TShark
adapter, a legacy Go live-capture CLI, and a retained but unused Go
sliding-window UCB experiment. The Go CLI defaults to uniform hopping; its
optional adaptive hopper uses a separate Gamma/raw-count Thompson sampler.
Infra separately operates the live MQTT recorder, sealed fusion archives,
retention, health, and Home Assistant projections in Python.
Operational site and sensor placement also live in Infra. Private device
identity and binding data live in the sibling-private repository, while
`household.toml` remains the authority for people, roles, consent, and allowed
purposes.

“Make it all Rust” is a direction, not a safe cutover plan. Replacing the live
writers before Rust can consume their sealed artifacts, preserve provenance,
replay deterministically, and shadow the existing projections would combine a
language migration with a schema migration and an operational cutover.

The package graph must also answer where reusable personal crates belong. In
particular, Muxer already owns bandit selection and drift primitives; Netmon
should not grow a second adaptive-selection implementation merely because the
legacy Go tree contains `swucb`.

## Operator outcomes

The cutover is successful when:

1. a released Netmon artifact can normalize and replay representative sealed
   network evidence with deterministic, receipt-bound output;
2. Infra can invoke or embed that release without a sibling checkout;
3. a Rust shadow path agrees with the existing live plane or abstains for an
   explicit coverage reason;
4. one writer can be cut over at a durable boundary and rolled back without a
   lost or duplicated interval; and
5. the Go capture CLI and `swucb` package can be deleted rather than maintained
   beside a nominal Rust replacement.

## Non-goals

- Moving Pulumi, launchd or systemd units, credentials, site placement,
  retention policy, private identity bindings, or Home Assistant policy into
  Netmon.
- Making Linktop a packet-capture process or a frontend for raw PCAP.
- Adding speculative `core`, `fusion`, `runtime`, `store`, or scheduler crates
  before a real consumer gives them a distinct dependency or release boundary.
- Making adaptive or active collection the default.
- Importing a personal crate only because its vocabulary is adjacent.

## Options considered

### Port the legacy Go tree module by module

This preserves the old runtime shape, including its mixed capture, hopping,
rendering, and storage concerns. It would also port the `swucb` experiment even
though Muxer already owns a stronger reusable policy surface. Rejected.

### Replace the live Infra plane first

This targets the largest visible Python surface, but Netmon cannot yet represent
Kismet Wi-Fi observations, Hypha BLE aggregates, rtl_433, Meshtastic, UniFi,
presence projections, site placement, or durable source offsets. Rejected until
sealed-artifact parity and shadow reconciliation exist.

### Build from immutable evidence outward

Release the current offline boundary, add representative sealed artifacts, move
reusable validation and replay into Rust, shadow existing projections, then cut
over one writer at a durable interval. Retire the Go capture path only after its
remaining required behavior has a Rust owner. Chosen.

## Relevant prior art

- Linux wireless regulatory processing makes the current regulatory domain,
  hardware capabilities, DFS state, and no-initiating-radiation restrictions
  authoritative inputs, not rewards for a learner to trade away:
  [Linux wireless regulatory rules](https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/processing_rules.html).
- Kismet treats channel hopping as a coverage-versus-completeness choice whose
  feasible rate depends on hardware:
  [Kismet channel hopping](https://www.kismetwireless.net/docs/readme/datasources/channelhop/).
- Li et al. establish offline evaluation from uniformly randomized logging
  under explicit event and action assumptions:
  [unbiased offline evaluation](https://arxiv.org/abs/1003.5956). Netmon
  chooses a seeded randomized schedule as its reproducible control; the seed
  and RF hopping adaptation are Netmon design choices, not claims from that
  paper.
- Sliding-window and discounted UCB are useful piecewise-stationary comparison
  policies, not reasons to preserve the current Go implementation:
  [Garivier and Moulines](https://arxiv.org/abs/0805.3415).
- CUSUM-UCB needs deliberate exploration to feed its detectors. Netmon should
  use known radio, regulatory, network, and location changes as explicit epoch
  boundaries and reserve drift detection for unannounced changes within an
  epoch:
  [Liu, Lee, and Shroff](https://arxiv.org/abs/1711.03539).
- EXP3-IX is suitable for an adversarial or rapidly changing reward sequence,
  but its comparator is the best fixed arm and it does not own radio retune
  cost:
  [Neu](https://arxiv.org/abs/1506.03271). Batching a decision into a bounded
  dwell is therefore part of Netmon's execution contract, consistent with the
  switching-cost treatment in
  [SpecWatch](https://arxiv.org/abs/1710.05981).

## Decision

### Dependency direction

```text
                       muxer
                         |
             future opt-in acquisition policy
                         |
netmon-adapter-* --> netmon-evidence <-- netmon-replay
          \               |                 /
           \-------------- netmon CLI -----/
                            |
                   released artifact/API
                            |
                           Infra

Linktop --> released netmon-evidence + netmon-replay
```

`netmon-evidence` remains the lowest policy-neutral contract. `netmon-replay`
owns deterministic reducers. Acquisition adapters produce evidence but do not
own deployment. The Netmon CLI is an operator and integration surface, not a
service dependency.

Infra owns deployed transports, sealed intervals, operational stores,
retention, health, operational site and sensor placement, and compatibility
projections. The sibling-private repository owns physical-device aliases,
assignments, scoped identifiers, and desired bindings. `household.toml` owns
people, roles, access capability, consent, and allowed-purpose policy. Infra may
consume a released Netmon CLI or libraries; it must not depend on a sibling path
or on Netmon's human-readable prose.

Linktop consumes released evidence/replay libraries for host-facing diagnosis.
Imported evidence must be explicitly associated with a Linktop path generation
by observer and acquisition interval. Linktop does not parse raw PCAP or inherit
TShark as a runtime dependency.

### Muxer replaces adaptive selection, not Netmon semantics

The Go `swucb` package has no live consumer and has no place in the final Rust
graph. The actual live Go hopper uses a different Thompson sampler and is not a
behavioral compatibility target when that optional strategy is selected. The
Rust cutover must preserve required operator outcomes and evidence invariants,
not its implementation order or reward math.

The first Rust acquisition slice uses a fixed round-robin or seeded randomized
schedule. This validates channel setting, requested-versus-executed action,
bounded dwell, interval attribution, receipts, failure handling, and replay
before adaptation can obscure an acquisition error.

When a concrete adaptive acquisition consumer exists, its Rust implementation
may depend on Muxer's domain-neutral arm-selection policy. The first experiment
uses EXP3-IX over a stable ordered arm universe within one policy epoch. Netmon
passes the current eligible subset and a logged decision seed, then records the
exact selection probability used to update the policy. A regulatory-domain,
radio, hardware, or materially different location transition starts a new
epoch. Transient cooldown or capability changes only change the eligible
subset.

That dependency belongs only in the acquisition package or module that owns the
consumer. It does not belong in `netmon-evidence`, `netmon-replay`, Linktop, or
the passive default path.

The dependency is not added until that consumer exists. Its intended
declaration is:

```toml
muxer = { version = "=0.5.3", default-features = false, features = ["stochastic", "serde"] }
```

This exposes EXP3-IX and serializable policy state without enabling contextual
or Boltzmann policies. Netmon does not depend directly on Muxer's `pare`,
`logp`, or optional `drawset` implementation dependencies.

Netmon remains responsible for:

- constructing the eligible channel or sensor arms from hardware, regulatory,
  operator, and collection-policy constraints;
- deciding dwell bounds, cooldowns, total active budget, and terminal
  conditions;
- translating observed yield and quality into a documented reward;
- binding one decision ID to the requested action, executed action, exact
  observation interval, and attributed outcome;
- recording policy and acquisition epoch IDs, observer/radio identity, the
  stable arm universe, ordered eligible subset, exclusion reasons, policy
  version/configuration/state digest, reward schema, seed, exact propensity
  distribution, planned and actual dwell, retune latency, remaining budget,
  raw metrics, completeness, drops, normalized reward, and terminal reason; and
- proving that replay of a receipt does not silently re-run acquisition.

Muxer may select among the eligible arms and expose drift or exploration
signals. It cannot authorize an active operation or turn an empirical score
into evidence of device identity, presence, or intent.

Muxer's generic `Decision` remains an inner algorithm decision rather than the
durable receipt. In the proposed pinned release it contains the policy, chosen
arm, optional probabilities, and notes, but not Netmon's context, complete
candidate authority, executed action, interval, or observation identity. For
the first RF policy, Netmon does not use:

- Muxer's quality-routing `Router`, `Outcome`, or `Summary` profile;
- `StickyMab`, whose dwell is a count of decisions rather than elapsed radio
  time;
- Thompson sampling, whose Beta/fractional-reward decision lacks exact
  posterior-max propensities;
- Boltzmann selection, whose current Gumbel-max path uses ambient randomness;
  or
- contextual LinUCB before a typed, fixture-backed context schema exists.

Coverage floors and CUSUM may later constrain or reset a policy, but they do
not authorize active acquisition. A coverage floor must be defined in airtime
or useful observation coverage rather than selection count alone.

### Other personal crates

- Piku is prior art for isolated PTY lifecycle tests. Linktop already owns a
  smaller bounded native-terminal screenshot transaction, so neither tool
  imports the other and no shared TUI crate is justified.
- Durability may become an Infra-owned append-only spool primitive after the
  durable-source-offset contract is designed. Infra still owns event schema,
  offsets, sealing, retention, and rollback.
- Segstore is not the source evidence log. It is eligible only as a rebuildable
  derived query index after a measured query or retention need.
- Statskit is eligible in the offline Rust-versus-Python shadow evaluation once
  the multi-modal parity corpus exists. It does not enter live reduction.
- Clump and Fingerprints require a fixture-backed operator question,
  calibrated completeness, and explicit abstention. Cluster, unseen-mass, or
  novelty outputs remain hypotheses and collection signals, never device,
  place, or intent facts.
- Direct Logp, Pare, Drawset, Graphops, Lattix, Hypha host, Cnk, and Sbits
  dependencies are not earned by the initial Rust flip.

## Dependency-ordered cutover

1. Distribute the current Rust boundary. Keep CI green, version the
   workspace, and publish checksummed macOS/Linux binaries plus schema fixtures.
2. Add an Infra contract test. Run a pinned Netmon release against a
   sanitized saved capture in a temporary directory; verify schema order,
   digests, and byte-for-byte deterministic reruns.
3. Establish the multi-modal parity corpus. Add sanitized Kismet, Hypha,
   rtl_433, Meshtastic, UniFi, presence, and sealed fusion-archive fixtures.
4. Decode sealed artifacts in Rust. Add only the evidence types and adapter
   boundaries demonstrated by the corpus. Deployment remains in Infra.
5. Shadow replay and projections. Compare known presence, explicit
   abstention, freshness, location, duplicate, restart, and reorder behavior
   without writing MQTT, SQLite, or Home Assistant state.
6. Create a durable live boundary. Add an append-only spool, checkpoint, or
   sealed-interval protocol before any live Rust consumer. MQTT QoS 0 arrival
   order is not a replay cursor.
7. Cut over one additive projection. Use one writer, a durable boundary,
   injected failure, and a demonstrated rollback.
8. Implement opt-in Rust acquisition if still needed. Start with a fixed or
   seeded randomized schedule and prove receipt-bound attribution. Add Muxer
   EXP3-IX only after that control passes and an adaptive operator case exists.
9. Delete superseded runtimes. Remove the Go CLI and `swucb` after capture
   parity; remove each Python writer only after its Rust replacement passes
   shadow, cutover, and rollback gates.

## Gates

- Default Netmon and Linktop execution remains passive.
- Every active action is explicitly enabled, bounded, attributable, and
  receipt-bearing.
- A released artifact, not a sibling checkout, is the Infra dependency.
- Representative sealed artifacts cover every promoted evidence family.
- Repeated offline input yields byte-identical canonical output.
- Shadow comparison names disagreement and unknown coverage; it does not force a
  match.
- Live cutover has one writer and one rollback authority at any instant.
- Muxer receives only caller-eligible arms and cannot widen collection scope.
- A policy epoch keeps its full arm universe and ordering stable.
- Requested action, executed action, interval, and observation share one durable
  decision identity.
- Raw packet counts are normalized for actual dwell and completeness before
  entering an adaptive reward.
- Linktop imported traffic evidence is fenced to a path generation or shown as
  unassociated.
- Go and Python deletion happens per proven parity slice, not by repository-wide
  flag day.

## Revisit triggers

- A second live acquisition consumer needs the same scheduling dependency set.
- A sealed fusion artifact demonstrates a reusable adapter boundary.
- Infra has a durable source cursor and requests live Rust shadowing.
- Linktop has a focused imported-evidence view with a concrete attachment
  contract.
- A release exists and cross-repository consumers can leave exact Git pins.
