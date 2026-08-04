# mmWave jamming MAT layout audit v0

## Hypothesis

MAT variable layouts will be invariant within each matched jammer-present and
jammer-absent cell, while compressed file extent may differ. Any extent or
layout mismatch must block storage metadata from model features before a
payload evaluation is designed.

## Method

This hypothesis was written before the real corpus run. The implementation and
preregistration started from Git commit `34aebea`. The exact producer commit is
`2e62c42`.

Run:

```sh
just mmwave-jamming-layout-profile
```

The recipe runs `eval/profile-mmwave-jamming-mat-layout.py` twice and requires
byte-identical reports. The producer first performs the existing exact
size/MD5/SHA-256/local-receipt admission. It then uses SciPy 1.17.1 only to
inspect MAT v5 variable metadata through regular non-symlink descriptors with
before/after identity checks. It materializes no array values.

The preregistered gates are pairwise and exact:

- all 40 pairs have identical variable-name, shape, and class signatures;
- all 40 pairs have identical file extents; and
- all 40 pairs fall in the same one-MiB extent class.

A failed gate is a feature-admission blocker. It is not a jammer-detection
metric and does not imply that the differing metadata is causal or useful.

## Data provenance

Zenodo record 6516954, DOI `10.5281/zenodo.6516954`: 80 pinned MAT artifacts,
738,542,988 bytes, arranged as 40 receiver/regime/target matched pairs. The
publisher filenames establish the controlled jammer-present/absent condition.
They do not establish event, session, physical-source, device, variant, actor,
tamper, authorization, or malicious-intent truth.

## Results

The canonical recipe completed twice with byte-identical 1,413-byte reports,
both mode 0600. All 80 receipt-bound artifacts were admitted (738,542,988
bytes), and no array values were materialized.

| Pairwise gate | Matching | Mismatching |
|---|---:|---:|
| variable-name, shape, and class signature | 20 | 20 |
| exact file extent | 0 | 40 |
| one-MiB extent class | 16 | 24 |

The report status is `blocked` with all three preregistered reasons. It retains
no path, filename, variable name, condition label, receiver/target label,
digest, or per-artifact row.

## Conclusion

The hypothesis did not hold. Storage extent is condition-associated throughout
the matched grid and cannot be admitted as a model feature. The combined MAT
signature also differs in half the pairs.

That combined signature is sufficient for the preregistered block but not for
attribution: it does not say whether the 20 mismatches come from variable names,
array shape/class, or both. A follow-up diagnostic must decompose those terms
without weakening this result or admitting any of them as features.
