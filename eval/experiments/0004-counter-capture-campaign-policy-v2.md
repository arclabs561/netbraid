# Experiment 0004: Counter-capture campaign policy v2

## Hypothesis

A versioned, explicit campaign policy can evaluate non-legacy regime names,
split sizes, candidate counts, truth positions, and opaque split groups without
changing the legacy schema-v1 result for the same 24-run campaign.

## Method

Base revision: `95e82f1`.

Implement schema-v2 policy parsing in `eval/counter_capture_campaign.py` while
retaining schema-v1 as a frozen compatibility profile. Run:

```sh
python3 eval/test-counter-capture-campaign.py
python3 eval/test-counter-capture-eval.py
```

The hermetic checks compare the complete schema-v1 result before and after the
change, exercise a smaller schema-v2 campaign with non-legacy regime tokens and
rotated truth positions, and verify malformed policies and cross-split group
overlap fail closed. V2 does not report a binomial confidence interval because
shared calibration and candidate reuse make its outcomes dependent.

## Data provenance

The checks use only generated integer `TrafficWindow` values from
`eval/test-counter-capture-campaign.py`. They contain no packet bytes, source
paths, addresses, interfaces, or deployment-selected run identifiers. No
downloaded corpus is used, so this experiment tests contract semantics rather
than real-world ranking quality.

## Results

`just counter-capture-eval-check` passed 15 checks: seven evaluator-unit
checks and eight campaign-contract checks. The schema-v1 campaign retained its
exact 7,072-byte canonical result, with SHA-256
`885478d71795e925aed5fbf7f7de2bed1a985a65f2c35478d12a9e11a3c6a15c`, and
omitted policy output. The schema-v2 fixture evaluated two opaque regimes, one
calibration plus four held-out runs per regime, three candidates, and rotated
truth indices. All eight held-out runs selected their declared truth index.
Invalid policy shapes, bounds, run counts, candidate counts, truth indices, and
cross-split group reuse failed closed. A separate boundary case retained four
abstentions in the 4/8 denominator and changed the engineering acceptance gate
from pass at four successes to fail at five. V2 omitted the unjustified exact
binomial interval and disclosed the dependence reason.

These are contract results from generated windows, not estimates of ranking
quality on a deployment or public corpus.

## Conclusion

The hypothesis held for the contract boundary. Schema v2 can express a smaller
non-legacy campaign without weakening schema-v1 compatibility. The next
evidence-bearing step is to generate a preregistered v2 manifest from real
derived windows and report per-regime outcomes; these hermetic checks do not
justify changing the ranking model or its feature set.
