# Architecture decisions

This ledger records structural decisions that future contributors would
otherwise re-derive or re-litigate. Implementation detail and one-change
choices belong in code review, not here.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-adopt-netbraid-product-identity.md) | Adopt Netbraid as the product and package identity without renaming established wire identifiers | Accepted |
| [0002](0002-publish-netbraid-crates.md) | Publish the real Netbraid CLI and libraries to crates.io while retaining GitHub binary releases | Accepted |
| [0003](0003-own-versioned-scenario-bundles-in-replay.md) | Own strict, finite operator-scenario bundles and checkpoint replay in `netbraid-replay` | Accepted |
| [0004](0004-admit-public-reviewed-capture-derived-scenarios.md) | Admit disclosure-reviewed capture-derived scenarios without weakening the public-synthetic v0 contract | Accepted |
| [0005](0005-keep-public-eval-fetching-in-repository.md) | Keep allowlisted public evaluation fetching in Netbraid with ignored local data | Accepted |
| [0006](0006-admit-three-public-wireless-corpora.md) | Admit three exact, primary-source wireless corpora to the local fetch catalog | Accepted |
