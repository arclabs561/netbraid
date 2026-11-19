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
