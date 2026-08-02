use netbraid::evidence::PacketEnvelopeV0;
use netbraid::infer::{
    assess_counter_capture_v0, assess_packet_same_event_v0, CounterCaptureProfileV0,
    CounterCaptureReferenceV0, CounterCaptureScaleVectorPpbV0, PacketSameEventDispositionV0,
    PacketSameEventReferenceV0, PacketSameEventUnknownReasonV0, TrafficWindowEvidenceV0,
    TrafficWindowV0,
};

fn packet() -> PacketEnvelopeV0 {
    serde_json::from_str(include_str!(
        "fixtures/replay/evidence-v0/packet_envelope_v0.json"
    ))
    .expect("fixture is a valid packet envelope")
}

#[test]
fn public_inference_facade_retains_unknown_alternative() {
    let left = packet();
    let mut right = packet();
    right.capture_id =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
    right.record_id = format!("{}:frame:1", right.capture_id);

    let result = assess_packet_same_event_v0(&left, &right).expect("valid assessment");

    assert_eq!(
        result.reference,
        PacketSameEventReferenceV0::Unknown {
            reason: PacketSameEventUnknownReasonV0::MissingIeee80211Evidence,
        }
    );
    assert_eq!(
        result.same_event,
        PacketSameEventDispositionV0::Underdetermined
    );
    assert_eq!(result.unknown, PacketSameEventDispositionV0::Supported);
}

#[test]
fn public_inference_facade_exposes_counter_capture_without_changing_packet_exports() {
    let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
    let counter = TrafficWindowEvidenceV0::declared_complete("counter:facade:0", window);
    let capture = TrafficWindowEvidenceV0::declared_complete("capture:facade:0", window);
    let profile = CounterCaptureProfileV0::new(
        "profile:facade:0",
        CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
        0,
        1,
    )
    .unwrap();

    let result = assess_counter_capture_v0(&counter, &capture, &profile).unwrap();

    assert_eq!(
        result.reference,
        CounterCaptureReferenceV0::CaptureAccountsForWindow
    );
}
