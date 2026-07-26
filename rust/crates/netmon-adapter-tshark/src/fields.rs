use std::net::{Ipv4Addr, Ipv6Addr};

use netmon_evidence::{
    EthernetFieldsV0, Ipv4FieldsV0, Ipv6FieldsV0, PACKET_ENVELOPE_SCHEMA_V0,
    PACKET_QUARANTINE_SCHEMA_V0, PacketEnvelopeV0, PacketFrameV0, PacketQuarantineV0,
    TcpFieldsV0, UdpFieldsV0,
};

pub const FIELD_REGISTRY_ID: &str = "netmon.tshark.packet_envelope.v0";

pub const FIELDS: &[&str] = &[
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.section_number",
    "frame.interface_id",
    "frame.encap_type",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
];

pub(crate) struct ParsedRows {
    pub packets: Vec<PacketEnvelopeV0>,
    pub quarantines: Vec<PacketQuarantineV0>,
    pub rows_seen: usize,
}

pub(crate) fn parse_rows(stdout: &[u8], capture_id: &str) -> ParsedRows {
    let mut packets = Vec::new();
    let mut quarantines = Vec::new();
    let mut rows_seen = 0;
    let mut previous_frame = None;

    for raw_bytes in stdout.split(|byte| *byte == b'\n') {
        let raw_bytes = raw_bytes.strip_suffix(b"\r").unwrap_or(raw_bytes);
        if raw_bytes.is_empty() {
            continue;
        }
        rows_seen += 1;
        let raw_row = String::from_utf8_lossy(raw_bytes).into_owned();
        match parse_row(&raw_row, capture_id) {
            Ok(packet)
                if previous_frame
                    .is_none_or(|previous| packet.frame.number > previous) =>
            {
                previous_frame = Some(packet.frame.number);
                packets.push(packet);
            }
            Ok(packet) => quarantines.push(quarantine(
                capture_id,
                rows_seen,
                Some(packet.frame.number),
                "frame number is not strictly increasing",
                raw_row,
            )),
            Err(reason) => quarantines.push(quarantine(
                capture_id,
                rows_seen,
                frame_number_hint(&raw_row),
                reason,
                raw_row,
            )),
        }
    }

    ParsedRows {
        packets,
        quarantines,
        rows_seen,
    }
}

fn parse_row(raw_row: &str, capture_id: &str) -> Result<PacketEnvelopeV0, String> {
    let fields: Vec<&str> = raw_row.split('\t').collect();
    if fields.len() != FIELDS.len() {
        return Err(format!(
            "field count {} does not match registry field count {}",
            fields.len(),
            FIELDS.len()
        ));
    }

    let frame_number = parse_required(fields[0], FIELDS[0])?;
    let ethernet = if fields[8].is_empty() && fields[9].is_empty() {
        None
    } else {
        Some(EthernetFieldsV0 {
            source: canonical_ethernet(fields[8])?,
            destination: canonical_ethernet(fields[9])?,
        })
    };
    let ipv4 = parse_ipv4(&fields)?;
    let ipv6 = parse_ipv6(&fields)?;
    let tcp = parse_tcp(&fields)?;
    let udp = parse_udp(&fields)?;
    let packet = PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{capture_id}:frame:{frame_number}"),
        capture_id: capture_id.into(),
        frame: PacketFrameV0 {
            number: frame_number,
            event_time_unix_ns: parse_epoch_ns(fields[1])?,
            original_len: parse_required(fields[2], FIELDS[2])?,
            captured_len: parse_required(fields[3], FIELDS[3])?,
            section_number: parse_optional(fields[4], FIELDS[4])?,
            interface_id: parse_optional(fields[5], FIELDS[5])?,
            encapsulation_type: parse_optional(fields[6], FIELDS[6])?,
            protocols: fields[7]
                .split(':')
                .filter(|protocol| !protocol.is_empty())
                .map(str::to_owned)
                .collect(),
        },
        ethernet,
        ipv4,
        ipv6,
        tcp,
        udp,
    };
    packet.validate().map_err(|error| error.to_string())?;
    Ok(packet)
}

fn parse_ipv4(fields: &[&str]) -> Result<Option<Ipv4FieldsV0>, String> {
    match (fields[10].is_empty(), fields[11].is_empty(), fields[12].is_empty()) {
        (true, true, true) => Ok(None),
        (false, false, false) => Ok(Some(Ipv4FieldsV0 {
            source: fields[10]
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("{} is not an IPv4 address", fields[10]))?
                .to_string(),
            destination: fields[11]
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("{} is not an IPv4 address", fields[11]))?
                .to_string(),
            protocol: parse_required(fields[12], FIELDS[12])?,
        })),
        _ => Err("incomplete first-occurrence IPv4 field group".into()),
    }
}

fn parse_ipv6(fields: &[&str]) -> Result<Option<Ipv6FieldsV0>, String> {
    match (fields[13].is_empty(), fields[14].is_empty(), fields[15].is_empty()) {
        (true, true, true) => Ok(None),
        (false, false, false) => Ok(Some(Ipv6FieldsV0 {
            source: fields[13]
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("{} is not an IPv6 address", fields[13]))?
                .to_string(),
            destination: fields[14]
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("{} is not an IPv6 address", fields[14]))?
                .to_string(),
            next_header: parse_required(fields[15], FIELDS[15])?,
        })),
        _ => Err("incomplete first-occurrence IPv6 field group".into()),
    }
}

fn parse_tcp(fields: &[&str]) -> Result<Option<TcpFieldsV0>, String> {
    match (fields[16].is_empty(), fields[17].is_empty(), fields[18].is_empty()) {
        (true, true, true) => Ok(None),
        (false, false, false) => Ok(Some(TcpFieldsV0 {
            source_port: parse_required(fields[16], FIELDS[16])?,
            destination_port: parse_required(fields[17], FIELDS[17])?,
            flags: parse_u16_auto_radix(fields[18], FIELDS[18])?,
        })),
        _ => Err("incomplete first-occurrence TCP field group".into()),
    }
}

fn parse_udp(fields: &[&str]) -> Result<Option<UdpFieldsV0>, String> {
    match (fields[19].is_empty(), fields[20].is_empty()) {
        (true, true) => Ok(None),
        (false, false) => Ok(Some(UdpFieldsV0 {
            source_port: parse_required(fields[19], FIELDS[19])?,
            destination_port: parse_required(fields[20], FIELDS[20])?,
        })),
        _ => Err("incomplete first-occurrence UDP field group".into()),
    }
}

fn parse_required<T>(value: &str, field: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    if value.is_empty() {
        return Err(format!("{field} is missing"));
    }
    value
        .parse()
        .map_err(|_| format!("{field} has invalid value {value:?}"))
}

fn parse_optional<T>(value: &str, field: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    if value.is_empty() {
        Ok(None)
    } else {
        parse_required(value, field).map(Some)
    }
}

fn parse_u16_auto_radix(value: &str, field: &str) -> Result<u16, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16).map_err(|_| format!("{field} has invalid value {value:?}"))
    } else {
        parse_required(value, field)
    }
}

fn canonical_ethernet(value: &str) -> Result<Option<String>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.to_ascii_lowercase();
    let mut parts = value.split(':');
    let valid = (0..6).all(|_| {
        parts
            .next()
            .is_some_and(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }) && parts.next().is_none();
    if valid {
        Ok(Some(value))
    } else {
        Err(format!("{value:?} is not an Ethernet address"))
    }
}

fn parse_epoch_ns(value: &str) -> Result<i64, String> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (seconds, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
    {
        return Err(format!("frame.time_epoch has invalid value {value:?}"));
    }
    let seconds: i128 = seconds
        .parse()
        .map_err(|_| format!("frame.time_epoch has invalid value {value:?}"))?;
    let fraction: i128 = if fraction.is_empty() {
        0
    } else {
        let parsed: i128 = fraction
            .parse()
            .map_err(|_| format!("frame.time_epoch has invalid value {value:?}"))?;
        parsed * 10_i128.pow(u32::try_from(9 - fraction.len()).unwrap())
    };
    let magnitude = seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(fraction))
        .ok_or_else(|| format!("frame.time_epoch is out of range: {value:?}"))?;
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).map_err(|_| format!("frame.time_epoch is out of range: {value:?}"))
}

fn frame_number_hint(raw_row: &str) -> Option<u64> {
    raw_row.split('\t').next()?.parse().ok()
}

fn quarantine(
    capture_id: &str,
    source_line: usize,
    frame_number_hint: Option<u64>,
    reason: impl Into<String>,
    raw_row: String,
) -> PacketQuarantineV0 {
    PacketQuarantineV0 {
        schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
        capture_id: capture_id.into(),
        source_line: u64::try_from(source_line).unwrap_or(u64::MAX),
        frame_number_hint,
        reason: reason.into(),
        raw_row,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tcp_row() -> String {
        [
            "1",
            "1700000000.123456789",
            "54",
            "54",
            "0",
            "0",
            "1",
            "eth:ethertype:ip:tcp",
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "192.0.2.1",
            "198.51.100.2",
            "6",
            "",
            "",
            "",
            "40000",
            "443",
            "0x0002",
            "",
            "",
        ]
        .join("\t")
    }

    #[test]
    fn parser_preserves_exact_time_and_first_occurrence_fields() {
        let parsed = parse_rows(format!("{}\n", tcp_row()).as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 1);
        let packet = &parsed.packets[0];
        assert_eq!(packet.frame.event_time_unix_ns, 1_700_000_000_123_456_789);
        assert_eq!(packet.frame.protocols, ["eth", "ethertype", "ip", "tcp"]);
        assert_eq!(packet.tcp.as_ref().unwrap().destination_port, 443);
    }

    #[test]
    fn timestamp_parser_handles_pre_epoch_values_without_floats() {
        assert_eq!(parse_epoch_ns("-0.5").unwrap(), -500_000_000);
        assert_eq!(parse_epoch_ns("1").unwrap(), 1_000_000_000);
        assert!(parse_epoch_ns("1.1234567890").is_err());
    }

    #[test]
    fn malformed_and_non_monotonic_rows_are_quarantined() {
        let mut second = tcp_row().replacen("1\t", "2\t", 1);
        second = second.replacen("192.0.2.1", "not-an-ip", 1);
        let repeated = tcp_row();
        let input = format!("{}\n{second}\n{repeated}\n", tcp_row());
        let parsed = parse_rows(input.as_bytes(), CAPTURE_ID);

        assert_eq!(parsed.rows_seen, 3);
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.quarantines.len(), 2);
        assert!(parsed.quarantines[0].reason.contains("IPv4"));
        assert!(parsed.quarantines[1]
            .reason
            .contains("not strictly increasing"));
    }
}
