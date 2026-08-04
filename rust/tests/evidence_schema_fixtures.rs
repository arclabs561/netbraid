use std::fs;
use std::path::Path;

use netbraid::evidence::{
    CaptureManifestV0, CaptureRunReceiptV0, HostPathObservationV0, PacketEnvelopeV0,
    PacketQuarantineV0,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

const FIXTURE_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/evidence/v0");

#[test]
fn v0_fixture_inventory_is_exact_pretty_and_valid() {
    let expected = [
        "capture_manifest_v0.json",
        "capture_run_receipt_v0.json",
        "host_path_observation_v0.json",
        "packet_envelope_bluetooth_le_v0.json",
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

    let host_path = read_fixture::<HostPathObservationV0>("host_path_observation_v0.json");
    host_path.validate().unwrap();
    let manifest = read_fixture::<CaptureManifestV0>("capture_manifest_v0.json");
    manifest.validate().unwrap();
    let receipt = read_fixture::<CaptureRunReceiptV0>("capture_run_receipt_v0.json");
    receipt.validate().unwrap();
    let packet = read_fixture::<PacketEnvelopeV0>("packet_envelope_v0.json");
    packet.validate().unwrap();
    let bluetooth_le_packet =
        read_fixture::<PacketEnvelopeV0>("packet_envelope_bluetooth_le_v0.json");
    bluetooth_le_packet.validate().unwrap();
    let wireless_packet = read_fixture::<PacketEnvelopeV0>("packet_envelope_wlan_v0.json");
    wireless_packet.validate().unwrap();
    let quarantine = read_fixture::<PacketQuarantineV0>("packet_quarantine_v0.json");
    quarantine.validate().unwrap();
}

#[test]
fn legacy_netmon_adapter_identity_remains_readable() {
    let text = include_str!("fixtures/evidence/compat/netmon-adapter-manifest-v0.json");
    let manifest: CaptureManifestV0 = serde_json::from_str(text).unwrap();

    manifest.validate().unwrap();
    assert_eq!(manifest.extractor.adapter, "netmon-adapter-tshark");
    assert_eq!(manifest.extractor.adapter_version, "0.1.0");
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
