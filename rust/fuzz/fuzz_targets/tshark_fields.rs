#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // Every non-empty row becomes a packet or a quarantine; parsing never panics.
    let (packets, quarantines, rows_seen) =
        netbraid::adapters::tshark::fuzz_parse_field_rows(input);
    assert_eq!(packets + quarantines, rows_seen);
});
