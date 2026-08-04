# Experiment 0021: RUFF-UWB open-set source relation v0

## Hypothesis

A device-disjoint baseline using the frozen cross-campaign magnitude projection
may distinguish same-source from different-source RUFF-UWB pairs with at least
50% validation coverage, at most 10% false matches, and at most 10% false
nonmatches. The test role must remain unread unless all metadata and validation
gates pass.

## Method

Status: preregistered and metadata-gated. Pre-implementation revision:
`e508e11`.

The 13 opaque publisher source/device pairs are ordered by a fixed hash before
row sampling and assigned as four train, three calibration, three validation,
and three test devices. Every observation from both campaigns follows its
device. The split compiler requires a bijective source/device map shared by
both campaigns and canonical proof that physical source, physical device,
event, and session do not cross any role boundary. Unknown or unobserved event
or session groups stop the experiment before waveform I/O and before a split
manifest is published.

If the metadata gate becomes satisfiable, each device/location/campaign cell
will contribute at most eight deterministically selected rows to one normalized
centroid. Each one-meter cell will be paired with one same-source and one
metadata-selected different-source two-meter cell. The frozen projection is
magnitude, maximum-positive-gradient alignment to sample 40, a common
200-sample crop, and four centered, L2-normalized 128-sample windows.

Training will fit only coordinate means and scales for a symmetric standardized
squared-distance score. Calibration will lock the 0.90 same-score quantile and
0.10 different-score quantile as decision thresholds; the former must be less
than the latter. Scores at or below the same threshold emit `same`, scores at
or above the different threshold emit `different`, and scores between them
abstain.

Validation must have at least 50% coverage, at most 10% false matches, at most
10% false nonmatches, both non-abstaining decisions, and same/different support
from every validation device. Failure leaves test feature reads at zero. A
passing gate permits one test run with no configuration candidates. Outcomes
are dependent within devices, so the report will retain exact counts and
per-device or device-pair breakdowns without a binomial confidence interval or
population-level claim.

The metadata-only contract is:

```sh
just ruff-uwb-open-set-source-split-check
just ruff-uwb-open-set-source-split
```

The predictive evaluator is intentionally not implemented until the split
compiler can publish a manifest whose canonical audit status is `pass`.

## Data provenance

- Source: the two pinned RUFF-UWB NPY archives and central fetch receipts used
  by experiments 0006 and 0018.
- Publisher claim: the same 13 transmitting boards occur in both campaigns.
- Local inputs: ignored opaque observation oracles and, only after every split
  gate passes, ignored receipt-bound row adapters and read-only mmap arrays.
- Identity limitation: shared publisher labels are treated as board aliases;
  no serial-number evidence is available.
- Retention: split manifests, arrays, adapters, and future reports remain
  ignored. Tracked code and logs retain no paths, raw labels, row indices,
  source identifiers, or waveform values.

## Results

Not run. The hypothesis and gates were recorded before invoking the split
compiler on the real oracle inventory.

## Conclusion

Pending. A metadata-gate failure is a negative result and will not be repaired
by inventing event or session labels from campaign, day, location, filename, or
row order.
