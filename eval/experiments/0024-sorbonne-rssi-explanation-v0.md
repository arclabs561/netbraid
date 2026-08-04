# Experiment 0024: Sorbonne RSSI condition contrast

## Hypothesis

With the 1 m Sorbonne RSSI trace as a fixed baseline, the held-out 1 m control
will classify no link as shifted. The 50 m acquisition condition will classify
more links as shifted, and its one source-role belief will exceed both its
control value and every contrast observer-role belief.

## Method

The protocol was written and content-hashed before the first evaluable run,
against implementation base `1efc6c3`. It was not externally timestamped, so
the artifact is a reproducible local protocol lock rather than independent
proof of preregistration.

The first preflight stopped before inference because the unsynchronized 1 m
S03 member has a leading space in its first header cell. Revision 1 admits only
that exact 103,064-byte member at SHA-256
`14aaedfbaa196d385b5ce05282e458773fbc1ee7eec83bfce8804929a8570deb`
and normalizes only ` Frame_number` to `Frame_number`. Any other malformed
header still fails closed.

```sh
just sorbonne-rssi-explanation-eval
```

The locked campaign reads exactly ten unsynchronized 1 m TSV members and ten
unsynchronized 50 m members. For each observer, zero-based even 1 m rows form
the baseline. The lower median RSSI among odd 1 m rows is the control recent
reading; the lower median among all matching 50 m rows is the contrast recent
reading. Lower medians are observed readings, not interpolated values.

Only RSSI enters the model. Observer filenames become closed synthetic roles;
the one publisher address becomes a constant synthetic source role after an
exactly-one-value integrity gate. Time, sequence number, event labels, frame
number, channel, type, subtype, retransmission, and condition labels are not
inference inputs. The Rust bridge emits aggregate model values and no role
identifiers.

The reference-frame threshold and existing default explanation weights were
fixed before execution. No threshold is fit from either condition.

## Data provenance

- Publisher DOI: `10.57745/HAOPHF`.
- Local archive: `data/raw/220211012-SU-Outdoors-Campus.zip`.
- Expected SHA-256:
  `7a650d450d339683cf7591bc24a6006238456b8dfa54e352aa1aceda8682c3f8`.
- Fetch and verification: `data/fetch/fetch-public-eval-corpus.py` with key
  `sorbonne-campus-rssi`.
- Campaign: `eval/fixtures/sorbonne-rssi-explanation-campaign-v0.json`.
- Generated reports: ignored under `data/derived/eval/`.

## Metrics and gates

- Selected member, row, and baseline-sample counts by condition.
- Eligible and shifted links as raw numerators over ten.
- Exact, infeasible, and abstained component counts and assignments evaluated.
- Source and observer relative-belief count, minimum, maximum, and sum in PPB.
- Residual relative-belief count, minimum, maximum, and sum in PPB.
- Source-minus-maximum-observer margin and control-to-contrast deltas.
- Byte-identical repeated report serialization.

Every component must be exact. Control shifted links must equal zero. Contrast
must shift more links; its sole source-role belief must exceed its control
value and the largest contrast observer belief. All raw metrics are retained
when an expectation fails.

## Results

The canonical recipe completed twice with byte-identical ignored reports. All
registered gates passed.

- Corpus: 18,926 control rows, 14,561 contrast rows, and 9,466 baseline
  readings across ten links. The exactly-one-address integrity gate and the one
  registered header erratum both held.
- Control: 0 of 10 links shifted. The one source-role relative belief was 0
  PPB; all ten observer-role beliefs were 15,384,615 PPB.
- Contrast: 10 of 10 links shifted. The one source-role relative belief was
  999,994,858 PPB; all ten observer-role beliefs were 30,307,714 PPB.
- Source-minus-maximum-observer contrast margin: 969,687,144 PPB.
- Contrast residual beliefs: ten values of 302 PPB.
- Both arms formed one exact component and evaluated all 2,048 assignments;
  neither arm was infeasible or resource-abstained.

These are model-relative heuristic values, not calibrated probabilities. No
generated report, source address, raw RSSI row, role identifier, member path,
or local path is committed.

## Limits

The two conditions are dependent slices of one publisher experiment, not
generalization folds. Directory labels construct the comparison; they are not
predicted. Row parity is deterministic but not an independence claim. One
source node connected to ten observers structurally favors a source-wide
explanation when many links shift, so source-belief dominance tests model
response rather than physical cause. The campaign does not estimate distance,
location, identity, cause, tamper, authorization, intent, or calibrated
probability.
