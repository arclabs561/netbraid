# Experiment 0019: SMoRFFI relation-split capability v0

## Hypothesis

The pinned SMoRFFI v3 CSV corpus can be converted into deterministic,
memory-mappable row artifacts without retaining publisher identifiers or input
paths, but it cannot support a leakage-safe physical-source relation split
because its publisher metadata does not expose an independent acquisition
session axis.

## Method

Status: executed against the complete pinned local corpus.

`just smorffi-row-adapter-check` exercises strict receipt binding,
variable-length complex parsing, flat NPY and half-open offset generation,
read-only mmap reuse, path and publisher-value omission, resource ceilings,
source-label consistency, atomic output replacement, and the one exact
digest-bound malformed-header repair.

`just smorffi-split-capability-check` validates the complete adapter metadata
contract without opening either NPY. A valid capability report must record a
successful audit, zero payload bytes read, zero partitions assigned, and the
stable `unbounded_session_axis` blocker. It must not publish a relation-split
manifest.

`just smorffi-rust-vector-adapter` recompiles the private artifacts and projects
the rank-one complex IQ and unsigned offset arrays through Netbraid's public
bounded NPY vector API. The integration requires exact extents, finite sampled
IQ components, and a complete offset vector with no equal or decreasing
adjacent values.

The full ignored corpus was compiled with `just smorffi-row-adapter`; the
metadata-only result was then produced with `just smorffi-split-capability`.

## Data provenance

- Source: Kaggle dataset version 3 for the SMoRFFI same-model IEEE 802.11g
  corpus, acquired by the checked-in bounded fetcher.
- Integrity: exact local inventory SHA-256 values recorded after the
  version-pinned download. The publisher supplies no artifact checksum.
- Evaluation unit: one publisher CSV row and its variable-length complex
  preamble.
- Candidate relation: different publisher-claimed physical source within one
  hardware model.
- Missing split axis: acquisition session. File boundaries and row order are
  explicitly invalid substitutes.
- Retention: corpus bytes, NPY arrays, row offsets, adapter, and capability
  report remain ignored; only aggregate method and limits are tracked here.

## Results

The adapter's ten hermetic tests and capability report's seven hermetic tests
pass. The real compiler accepted all 123 receipt-bound CSV files as 122,511
logical records containing 38,561,309 finite complex samples. Sequence lengths
range from 288 through 579; only 37,288 records have the nominal 288 samples.
The private NPY artifacts reopen as read-only memmaps, contain strictly
increasing half-open row offsets, and occupy about 618 MB for IQ plus 1 MB for
offsets.

The Rust vector adapter integration also passed. It read a bounded two-value IQ
window and the complete 122,512-value offset vector, confirmed the exact source
extents, and found no equal or decreasing adjacent offsets. No source path was
retained in projection metadata.

The metadata-only capability audit passed without opening either payload. Its
nested relation-split result is `blocked`, with zero partitions assigned and no
manifest published. No model metric or physical-source relation metric is
reported.

## Conclusion

The storage hypothesis held. The split hypothesis did not: publisher device
labels can construct a same-model different-source oracle, but no valid
train/calibration/validation/test isolation can be demonstrated without an
acquisition-session axis. The observed row and sequence-length distribution
also differs from the publisher's nominal 123,000 records of 288 samples; the
adapter preserves the receipt-bound bytes but does not interpret the variable
tails as a verified preamble boundary.

This result does not establish physical identity, same-source continuity,
receiver or location generalization, integrity, tamper, authorization, intent,
or maliciousness.
