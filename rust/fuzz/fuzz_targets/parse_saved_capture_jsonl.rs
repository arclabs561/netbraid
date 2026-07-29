#![no_main]

use libfuzzer_sys::fuzz_target;
use netbraid_replay::{
    parse_saved_capture_jsonl, project_saved_pcap_fingerprint_v0,
    project_saved_pcap_triage_v1, project_saved_pcap_wlan_fingerprint_v0,
    SavedPcapTriageOptionsV1,
};

fuzz_target!(|input: &[u8]| {
    if let Ok(records) = parse_saved_capture_jsonl(input) {
        if let Ok(triage) =
            project_saved_pcap_triage_v1(&records, SavedPcapTriageOptionsV1::default())
        {
            let _ = project_saved_pcap_fingerprint_v0(&triage);
        }
        let _ = project_saved_pcap_wlan_fingerprint_v0(&records);
    }
});
