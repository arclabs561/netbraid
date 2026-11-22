# Experiment 0039 — Can counter agreement identify a session?

## Design

This finite challenge follows an exploratory single-candidate counter probe.
The holdout consists of new, disjoint session groups. There is no fitting or
choice of a threshold from the holdout. Each group has two sequential TCP
sessions on the same directional five-tuple, 60 seconds apart. The experiment
observes one packet-flow summary and both accounting records. Each session
receives an ID before either observation is made. IDs are used only to score
predictions. The two production edges are inferred together.

Cross two time projections (a common bucket, or equal padding preserving
midpoints) with four counter conditions (complete distinct, incomplete
distinct, incomplete colliding with the other session, complete equal).
Run each cell with the query first and second in chronological order.
Every record window overlaps the query. Holdout port numbers, time origins
and counter magnitudes vary by group. These are deliberate cases, not random
draws from traffic.

Compare the default production marginal disposition with the same-tuple and
overlapping-window rule on every edge. For a separate one-of-two retrieval
question, compare the higher production marginal to the closer interval
midpoint among eligible records. Report wins, losses and ties at full query
coverage. A tie contributes half a correct answer in expectation under a
uniform forced choice; never resolve one using input order. Also report how
many queries each ranker can decide without tie breaking.

Coarse, equal-counter twins have identical scorer-visible record inputs. A
swap of their hidden session IDs preserves all observables and changes truth.
No deterministic rule can distinguish the two assignments from these inputs.

## Results

All 32 edges (16 same-session, 16 different-session) received binary decisions.

| Binary rule | True positives | False positives | True negatives | False negatives |
| --- | ---: | ---: | ---: | ---: |
| Default Rust marginal | 4 | 4 | 12 | 12 |
| Five-tuple and overlapping time | 16 | 16 | 0 | 0 |

The decisions have equal accuracy on this design, with different errors.
The Rust scorer rejected all eight incomplete true observations. Four had
exactly the counters of the other session. In each of these four cases that
other record received 998,035,543 ppb of model-relative belief and the true
record received 45,685 ppb. Those values describe the model's ranking only.

| Time projection | Counter condition | Rust ranking of true record (2 queries) | Midpoint ranking (2 queries) |
| --- | --- | --- | --- |
| Common bucket | Complete distinct | 2 wins | 2 ties |
| Common bucket | Incomplete distinct | 2 ties | 2 ties |
| Common bucket | Incomplete collision | 2 losses | 2 ties |
| Common bucket | Complete equal | 2 ties | 2 ties |
| Padded | Complete distinct | 2 wins | 2 wins |
| Padded | Incomplete distinct | 2 ties | 2 wins |
| Padded | Incomplete collision | 2 losses | 2 wins |
| Padded | Complete equal | 2 ties | 2 wins |

At forced full coverage the expected correct counts are 8/16 for the Rust
ranking and 12/16 for nearest midpoint under uniform tie breaking. Each rule
also makes eight strict choices without tie breaking. The Rust ranking gets
4/8 right on its selected queries and nearest midpoint gets 8/8 on its own.
They select different subsets. On the four queries where both choose
strictly, the counts are 2/4 and 4/4 respectively.

The two common-bucket, complete-equal queries are unidentifiable by input
symmetry. In contrast, on the padded, complete-equal cases the timestamp
midpoint supplies a distinguishing feature even though the scorer ties.

## Interpretation and limits

Exact counters can distinguish complete observations sharing a coarse time
window. The same heuristic can strongly prefer a different session when a
partial observation happens to reproduce that session's counters. For a
one-to-one identity claim, independent lineage or an explicit observation-loss
model would need separate evaluation. The production scorer also models splits
and merges. This experiment measures its transfer to a narrower identity
question.

The four counter treatments are deliberately weighted equally. Packet and byte
counts move together in fixed-size request/reply pairs. Symmetric time padding
favors midpoint distance by construction. The two orderings per cell exercise
both truth positions. They do not estimate a sampling distribution.
These exact fixture counts support the counterexample. They provide no
population accuracy, calibration estimate, or confidence interval.

## Reproduce

From the repository root with the locked Rust dependencies cached:

```sh
cargo run --quiet --offline --locked --manifest-path rust/Cargo.toml \
  --example synthetic_session_identity > /tmp/synthetic-session-identity.tsv
sha256sum /tmp/synthetic-session-identity.tsv
```

Expected stdout SHA-256 is
`30ba58d42ec5eac53411121c858535953b3018a8c19d27c3a3e319e9757a9b96`.
Each row includes both beliefs, both default dispositions and both retrieval
outcomes. The example checks candidate admission, exact component inference
and equality of the two records in the unidentifiable cases. All inputs are
constructed in memory from documentation addresses. The production scorer
was evaluated at revision `2e83a953feaaf3d103e2d75f1513cb00b006bd95`.
