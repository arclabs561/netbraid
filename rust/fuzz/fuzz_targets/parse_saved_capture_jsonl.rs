#![no_main]

use libfuzzer_sys::fuzz_target;
use netbraid_replay::parse_saved_capture_jsonl;

fuzz_target!(|input: &[u8]| {
    let _ = parse_saved_capture_jsonl(input);
});
