# mmWave jamming receiver cross-fit v0

## Hypothesis

A fixed five-feature nearest-centroid score fitted on three receiver elements
will rank the jammer-present member above the jammer-absent member in held-out
pairs from the fourth receiver element often enough to reject a one-sided fair
sign null at 0.05. At least 36 of 40 held-out pairs must be non-tied, and wins
must exceed losses.

## Method

This hypothesis and the policy in
`eval/fixtures/mmwave-jamming-receiver-crossfit-v0.json` were fixed before
computing any predictive feature or score from the paired-grid cache. The Git
basis is `29e4011`.

The evaluator will join the path-free 80-row grid adapter to the separate
observation oracle by opaque observation identifier. It will construct four
folds. Each receiver group is the test group exactly once; all three other
receiver groups are training data. Both members of every matched
receiver/regime/target pair stay in the same fold. Radar-configuration groups
therefore cannot cross a train/test boundary.

The fixed feature vector contains log mean complex power, global power
coefficient of variation, and power dispersion across each of the ADC-sample,
chirp, and frame axes. These are computed from the fixed 16 by 16 by 8
real/imaginary grid only. Paths, names, source shape, storage extent, digests,
receiver, regime, target count, and group identifiers are not model inputs.

Each fold independently fits feature means, nonzero scales, and two class
centroids from training rows. There is no feature selection, hyperparameter
search, validation gate, or calibration role. A positive score means closer to
the jammer-present centroid. Every observation is scored out of receiver group
exactly once.

The primary statistic compares the two out-of-fold scores in each matched
pair. Ties do not enter the exact one-sided binomial sign test, but at least 36
non-tied pairs are required. Balanced accuracy, macro-F1, and the rate at which
both pair members are classified correctly are secondary diagnostics and do
not alter the gate.

## Data provenance

Zenodo record 6516954, DOI `10.5281/zenodo.6516954`: the 80 admitted MAT v5
artifacts and 40 matched controlled-condition pairs represented by the
pair-aligned cache from experiment 0027. The cache was compiled with exact
artifact admission and shared pair indices, then reopened read-only by mmap.

The publisher's receiver numbers are treated only as four grouping elements.
They do not establish four independent devices, sites, people, sessions, or
events. The controlled condition is not evidence of actor identity, intent,
authorization, tamper, or maliciousness.

## Results

The canonical recipe completed twice with byte-identical 4,627-byte reports,
both mode 0600. Every observation was scored once while its receiver group was
absent from the corresponding 60-row training fold.

The primary pairwise result was 28 wins, 12 losses, and no ties across 40
held-out pairs. The ranking rate was 0.70 and the preregistered one-sided exact
binomial calculation was `0.008294501687`; all three mechanical terms passed.
An adversarial post-run audit then showed that this calculation is
anti-conservative for reciprocal cross-fit predictions: the four fitted models
share training data, so the 40 signs are dependent. The canonical report now
labels the value nominal, forces the inferential gate closed, and has status
`inference_blocked`.

The secondary zero-threshold row result was weaker. Balanced accuracy was
`0.625`, macro-F1 was `0.624765478424`, and only 10 of 40 pairs had both
members classified correctly. Fold balanced accuracies, reported without
receiver identifiers, were `0.50`, `0.65`, `0.65`, and `0.70`. The 0.50 fold
classified every row as jammer-absent.

```json
{
  "schema": "netbraid.mmwave_jamming_receiver_crossfit_result_summary.v0",
  "heldout_balanced_accuracy": 0.625,
  "heldout_macro_f1": 0.624765478424,
  "fold_balanced_accuracies": [
    0.5,
    0.65,
    0.65,
    0.7
  ],
  "paired_ranking": {
    "both_members_correct_pairs": 10,
    "losses": 12,
    "nominal_one_sided_exact_p_value": 0.008294501687,
    "ties": 0,
    "wins": 28
  },
  "status": "inference_blocked"
}
```

The report SHA-256 is
`c908a52b2d09fa2a2af1884c5585c0e5f8eeba699a12947c7639321c37e2aea8`.
The canonical recipe verifies the tracked JSON summary against the ignored
report before returning success.

## Conclusion

The preregistered inferential hypothesis is not established. The five coarse
content summaries produced 28/40 receiver-held-out pair wins in this corpus,
but the original significance gate was invalid for the dependent cross-fit
predictions. The fixed single-row threshold is also not reliable enough to
call this a detector.

The nominal binomial probability assumes independent, exchangeable pair signs.
Reciprocal cross-fit violates independence even before considering the
unobserved event and session relations in this release. The raw 28/40
numerator is therefore the durable descriptive result; the probability does
not support a confirmatory or population-level claim.

This is not external validation or a standalone or live detector: the grid
coordinates are derived jointly within each matched pair. It does not support
claims about independent hardware, sessions, sites, physical identity,
tamper, intent, authorization, or maliciousness. Independent repeated
acquisitions are the next requirement for stronger attribution or deployment
claims.
