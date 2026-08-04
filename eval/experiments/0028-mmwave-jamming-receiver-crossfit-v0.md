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

Not executed.

## Conclusion

Pending. A passing result would support only coarse-grid discrimination across
receiver elements in this campaign. It would not be external validation or a
standalone or live detector: the grid coordinates are derived jointly within
each matched pair. It would not support claims about independent hardware,
sessions, sites, physical identity, tamper, or malicious intent.
