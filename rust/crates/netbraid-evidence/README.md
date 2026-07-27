# netbraid-evidence

`netbraid-evidence` defines policy-neutral, versioned network-evidence records
and their local invariants. It performs no collection, filesystem access,
networking, wall-clock reads, rendering, identity fusion, or deployment policy.

The crate intentionally preserves its existing `netmon.*.v0` serialized schema,
digest-profile, environment-policy, and field-registry identifiers. Those names
are wire compatibility identifiers, not the current product name. Producer
identity is separate: Netbraid 0.2 adapters emit `netbraid-*` identities while
historical `netmon-*` producer values remain readable.

The canonical, pretty-JSON v0 fixtures live in `tests/fixtures/v0` and ship in
the crate package.

```toml
[dependencies]
netbraid-evidence = "0.2"
```

License: MIT OR Unlicense.
