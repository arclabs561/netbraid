# mmWave jamming layout attribution v0

## Hypothesis

The 20 combined-layout mismatches from experiment 0025 are caused by MAT
variable-name differences, while array shape/class remains invariant in all 40
matched cells.

## Method

This hypothesis was written before adding the decomposed counters or rerunning
the corpus. The Git basis is `52e175b`; the result update will record the exact
producer commit.

The follow-up keeps the original combined signature and all storage-extent
gates. It adds two pairwise diagnostics computed from the same already-admitted
metadata:

- variable-name signature only; and
- array shape/class multiset only.

Run:

```sh
just mmwave-jamming-layout-profile
```

The interpretation is fixed before the run. A 40/40 array-layout match permits
later payload work only after an extractor proves it excludes names, paths,
storage encoding, and byte extent. It does not clear the existing metadata
blocker. Any array-layout mismatch instead requires an explicit shape
normalization or paired-window policy before payload evaluation.

## Data provenance

The same 80 pinned artifacts and 40 matched cells from Zenodo record 6516954,
DOI `10.5281/zenodo.6516954`. No split, detector, or identity oracle is added.

## Results

Not recorded. The decomposed producer has not been run on the corpus.

## Conclusion

Pending the preregistered attribution run.
