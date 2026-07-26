use std::fs;
use std::path::Path;

use netmon_evidence::{
    CaptureManifestV0, CaptureRunReceiptV0, HostPathObservationV0, PacketEnvelopeV0,
    PacketQuarantineV0,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

const FIXTURE_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema-fixtures/v0");

#[test]
fn v0_fixture_inventory_is_exact_pretty_and_valid() {
    let expected = [
        "capture_manifest_v0.json",
        "capture_run_receipt_v0.json",
        "host_path_observation_v0.json",
        "packet_envelope_v0.json",
        "packet_envelope_wlan_v0.json",
        "packet_quarantine_v0.json",
    ];
    let mut actual: Vec<String> = fs::read_dir(FIXTURE_DIRECTORY)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    actual.sort();
    assert_eq!(actual, expected);

    let host_path = read_fixture::<HostPathObservationV0>(expected[2]);
    host_path.validate().unwrap();
    let manifest = read_fixture::<CaptureManifestV0>(expected[0]);
    manifest.validate().unwrap();
    let receipt = read_fixture::<CaptureRunReceiptV0>(expected[1]);
    receipt.validate().unwrap();
    let packet = read_fixture::<PacketEnvelopeV0>(expected[3]);
    packet.validate().unwrap();
    let wireless_packet = read_fixture::<PacketEnvelopeV0>(expected[4]);
    wireless_packet.validate().unwrap();
    let quarantine = read_fixture::<PacketQuarantineV0>(expected[5]);
    quarantine.validate().unwrap();
}

fn read_fixture<T>(name: &str) -> T
where
    T: DeserializeOwned + Serialize,
{
    let text = fs::read_to_string(Path::new(FIXTURE_DIRECTORY).join(name)).unwrap();
    let value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        text,
        "{name} is not canonical pretty JSON"
    );
    value
}
