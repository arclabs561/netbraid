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

The adapter's hermetic tests and capability report's seven hermetic tests
pass. The real compiler accepted all 123 receipt-bound CSV files as 122,511
logical records containing 35,365,248 finite complex samples. 121,998 records
have the nominal 288 samples and the other 513 have 448. The private NPY
artifacts reopen as read-only memmaps, contain strictly increasing half-open
row offsets, and occupy about 566 MB for IQ plus 1 MB for offsets.

Correction: the first run reported 38,561,309 samples, lengths from 288
through 579, and only 37,288 records at 288 samples. Those figures came from a
parser bug. The publisher's preamble cells are NumPy's printed form of a
complex array, which pads the real part for column alignment
(`0.2147587 +1.52928218e-01j`), and the adapter split such an element into a
real sample and an imaginary sample. The adapter now rejoins the two parts and
rejects any unpaired real or imaginary token; the counts above are from a
recompile with that fix.

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
also differs from the publisher's nominal 123,000 records of 288 samples (513
records hold 448); the adapter preserves the receipt-bound bytes but does not
interpret either length as a verified preamble boundary.

This result does not establish physical identity, same-source continuity,
receiver or location generalization, integrity, tamper, authorization, intent,
or maliciousness.
