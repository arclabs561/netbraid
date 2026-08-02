use std::net::{Ipv4Addr, Ipv6Addr};

use crate::evidence::{
    EthernetFieldsV0, Ieee80211FieldsV0, Ipv4FieldsV0, Ipv6FieldsV0, PacketEnvelopeV0,
    PacketFrameV0, PacketQuarantineV0, TcpFieldsV0, UdpFieldsV0, WlanRadioFieldsV0,
    PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};

pub const FIELD_REGISTRY_ID: &str = "netmon.tshark.packet_envelope.v3";

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
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.ta",
    "wlan.ra",
    "wlan.sa",
    "wlan.da",
    "wlan.bssid",
    "wlan.ssid",
    "wlan_radio.channel",
    "wlan_radio.frequency",
    "wlan_radio.signal_dbm",
    "wpan.frame_type",
    "wpan.version",
    "wpan.seq_no",
    "wpan.dst_pan",
    "wpan.dst16",
    "wpan.dst64",
    "wpan.src_pan",
    "wpan.src16",
    "wpan.src64",
    "wpan.cmd",
    "wpan.fcs_ok",
    "ip.len",
    "ipv6.plen",
    "tcp.stream",
];

const IP_LENGTH_INDEX: usize = 43;
const IPV6_PAYLOAD_LENGTH_INDEX: usize = 44;
const TCP_STREAM_INDEX: usize = 45;
const IPV6_HEADER_LENGTH_OCTETS: u32 = 40;

struct ParsedIeee802154Fields {
    frame_type: u8,
    frame_version: u8,
    sequence_number: Option<u8>,
    destination_pan_id: Option<u16>,
    destination_short: Option<u16>,
    destination_extended: Option<String>,
    source_pan_id: Option<u16>,
    source_short: Option<u16>,
    source_extended: Option<String>,
    command: Option<u8>,
    fcs_valid: Option<bool>,
}

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
            Ok(packet) if previous_frame.is_none_or(|previous| packet.frame.number > previous) => {
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
    let original_len = parse_required(fields[2], FIELDS[2])?;
    let captured_len = parse_required(fields[3], FIELDS[3])?;
    let capture_truncated = captured_len < original_len;
    let ethernet = if fields[8].is_empty() && fields[9].is_empty() {
        None
    } else {
        Some(EthernetFieldsV0 {
            source: canonical_ethernet(fields[8])?,
            destination: canonical_ethernet(fields[9])?,
        })
    };
    let ipv4 = parse_ipv4(&fields, capture_truncated)?;
    let ipv6 = parse_ipv6(&fields, capture_truncated)?;
    let tcp = parse_tcp(&fields)?;
    let udp = parse_udp(&fields)?;
    let ieee80211 = parse_ieee80211(&fields)?;
    let wlan_radio = parse_wlan_radio(&fields)?;
    let ieee802154 = parse_ieee802154(&fields)?;
    let mut packet = PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{capture_id}:frame:{frame_number}"),
        capture_id: capture_id.into(),
        frame: PacketFrameV0 {
            number: frame_number,
            event_time_unix_ns: parse_epoch_ns(fields[1])?,
            original_len,
            captured_len,
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
        ieee802154: None,
        ieee80211,
        wlan_radio,
    };
    if let Some(fields) = ieee802154 {
        packet
            .set_ieee802154_fields(
                (fields.frame_type, fields.frame_version),
                fields.sequence_number,
                (
                    fields.destination_pan_id,
                    fields.destination_short,
                    fields.destination_extended,
                ),
                (
                    fields.source_pan_id,
                    fields.source_short,
                    fields.source_extended,
                ),
                fields.command,
                fields.fcs_valid,
            )
            .map_err(|error| error.to_string())?;
    }
    packet.validate().map_err(|error| error.to_string())?;
    Ok(packet)
}

fn parse_ipv4(fields: &[&str], capture_truncated: bool) -> Result<Option<Ipv4FieldsV0>, String> {
    match (
        fields[10].is_empty(),
        fields[11].is_empty(),
        fields[12].is_empty(),
        fields[IP_LENGTH_INDEX].is_empty(),
    ) {
        (true, true, true, true) => Ok(None),
        (true, true, true, false) if capture_truncated => Ok(None),
        (false, false, false, _) => Ok(Some(Ipv4FieldsV0 {
            source: fields[10]
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("{} is not an IPv4 address", fields[10]))?
                .to_string(),
            destination: fields[11]
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("{} is not an IPv4 address", fields[11]))?
                .to_string(),
            protocol: parse_required(fields[12], FIELDS[12])?,
            total_length_octets: parse_optional(fields[IP_LENGTH_INDEX], FIELDS[IP_LENGTH_INDEX])?,
        })),
        _ => Err("incomplete first-occurrence IPv4 field group".into()),
    }
}

fn parse_ipv6(fields: &[&str], capture_truncated: bool) -> Result<Option<Ipv6FieldsV0>, String> {
    match (
        fields[13].is_empty(),
        fields[14].is_empty(),
        fields[15].is_empty(),
        fields[IPV6_PAYLOAD_LENGTH_INDEX].is_empty(),
    ) {
        (true, true, true, true) => Ok(None),
        (true, true, true, false) if capture_truncated => Ok(None),
        (false, false, false, _) => Ok(Some(Ipv6FieldsV0 {
            source: fields[13]
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("{} is not an IPv6 address", fields[13]))?
                .to_string(),
            destination: fields[14]
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("{} is not an IPv6 address", fields[14]))?
                .to_string(),
            next_header: parse_required(fields[15], FIELDS[15])?,
            total_length_octets: parse_ipv6_total_length(fields[IPV6_PAYLOAD_LENGTH_INDEX])?,
        })),
        _ => Err("incomplete first-occurrence IPv6 field group".into()),
    }
}

fn parse_tcp(fields: &[&str]) -> Result<Option<TcpFieldsV0>, String> {
    match (
        fields[16].is_empty(),
        fields[17].is_empty(),
        fields[18].is_empty(),
        fields[TCP_STREAM_INDEX].is_empty(),
    ) {
        (true, true, true, true) => Ok(None),
        (false, false, false, _) => Ok(Some(TcpFieldsV0 {
            source_port: parse_required(fields[16], FIELDS[16])?,
            destination_port: parse_required(fields[17], FIELDS[17])?,
            flags: parse_u16_auto_radix(fields[18], FIELDS[18])?,
            stream_index: parse_optional(fields[TCP_STREAM_INDEX], FIELDS[TCP_STREAM_INDEX])?,
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

fn parse_ieee80211(fields: &[&str]) -> Result<Option<Ieee80211FieldsV0>, String> {
    match (fields[21].is_empty(), fields[22].is_empty()) {
        (true, true) => {
            if fields[23..=28].iter().any(|field| !field.is_empty()) {
                Err("IEEE 802.11 attributes exist without frame type and subtype".into())
            } else {
                Ok(None)
            }
        }
        (false, false) => Ok(Some(Ieee80211FieldsV0 {
            frame_type: parse_required(fields[21], FIELDS[21])?,
            frame_subtype: parse_required(fields[22], FIELDS[22])?,
            transmitter: canonical_ethernet(fields[23])?,
            receiver: canonical_ethernet(fields[24])?,
            source: canonical_ethernet(fields[25])?,
            destination: canonical_ethernet(fields[26])?,
            bssid: canonical_ethernet(fields[27])?,
            ssid_hex: canonical_ssid_hex(fields[28])?,
        })),
        _ => Err("incomplete first-occurrence IEEE 802.11 frame type group".into()),
    }
}

fn parse_wlan_radio(fields: &[&str]) -> Result<Option<WlanRadioFieldsV0>, String> {
    if fields[29..=31].iter().all(|field| field.is_empty()) {
        Ok(None)
    } else {
        Ok(Some(WlanRadioFieldsV0 {
            channel: parse_optional(fields[29], FIELDS[29])?,
            center_frequency_mhz: parse_optional(fields[30], FIELDS[30])?,
            signal_dbm: parse_optional(fields[31], FIELDS[31])?,
        }))
    }
}

fn parse_ieee802154(fields: &[&str]) -> Result<Option<ParsedIeee802154Fields>, String> {
    if fields[32..=42].iter().all(|field| field.is_empty()) {
        return Ok(None);
    }
    if fields[32].is_empty() || fields[33].is_empty() {
        return Err(
            "IEEE 802.15.4 attributes exist without complete frame type and version".into(),
        );
    }
    if !fields[36].is_empty() && !fields[37].is_empty() {
        return Err("IEEE 802.15.4 destination has both short and extended addresses".into());
    }
    if !fields[39].is_empty() && !fields[40].is_empty() {
        return Err("IEEE 802.15.4 source has both short and extended addresses".into());
    }

    Ok(Some(ParsedIeee802154Fields {
        frame_type: parse_u8_auto_radix(fields[32], FIELDS[32])?,
        frame_version: parse_u8_auto_radix(fields[33], FIELDS[33])?,
        sequence_number: parse_optional_u8_auto_radix(fields[34], FIELDS[34])?,
        destination_pan_id: parse_optional_u16_auto_radix(fields[35], FIELDS[35])?,
        destination_short: parse_optional_u16_auto_radix(fields[36], FIELDS[36])?,
        destination_extended: canonical_eui64(fields[37], FIELDS[37])?,
        source_pan_id: parse_optional_u16_auto_radix(fields[38], FIELDS[38])?,
        source_short: parse_optional_u16_auto_radix(fields[39], FIELDS[39])?,
        source_extended: canonical_eui64(fields[40], FIELDS[40])?,
        command: parse_optional_u8_auto_radix(fields[41], FIELDS[41])?,
        fcs_valid: parse_optional_tshark_bool(fields[42], FIELDS[42])?,
    }))
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

fn parse_ipv6_total_length(value: &str) -> Result<Option<u32>, String> {
    parse_optional::<u32>(value, FIELDS[IPV6_PAYLOAD_LENGTH_INDEX])?
        .map(|payload_length| {
            payload_length
                .checked_add(IPV6_HEADER_LENGTH_OCTETS)
                .ok_or_else(|| {
                    format!(
                        "{} total length overflows u32",
                        FIELDS[IPV6_PAYLOAD_LENGTH_INDEX]
                    )
                })
        })
        .transpose()
}

fn parse_u16_auto_radix(value: &str, field: &str) -> Result<u16, String> {
    parse_unsigned_auto_radix(value, field)
}

fn parse_u8_auto_radix(value: &str, field: &str) -> Result<u8, String> {
    parse_unsigned_auto_radix(value, field)
}

fn parse_unsigned_auto_radix<T>(value: &str, field: &str) -> Result<T, String>
where
    T: TryFrom<u64>,
{
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| format!("{field} has invalid value {value:?}"))?;
    T::try_from(parsed).map_err(|_| format!("{field} has invalid value {value:?}"))
}

fn parse_optional_u8_auto_radix(value: &str, field: &str) -> Result<Option<u8>, String> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_u8_auto_radix(value, field).map(Some)
    }
}

fn parse_optional_u16_auto_radix(value: &str, field: &str) -> Result<Option<u16>, String> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_u16_auto_radix(value, field).map(Some)
    }
}

fn parse_optional_tshark_bool(value: &str, field: &str) -> Result<Option<bool>, String> {
    match value {
        "" => Ok(None),
        "True" | "true" | "1" => Ok(Some(true)),
        "False" | "false" | "0" => Ok(Some(false)),
        _ => Err(format!("{field} has invalid value {value:?}")),
    }
}

fn canonical_ethernet(value: &str) -> Result<Option<String>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.to_ascii_lowercase();
    let mut parts = value.split(':');
    let valid = (0..6).all(|_| {
        parts.next().is_some_and(|part| {
            part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none();
    if valid {
        Ok(Some(value))
    } else {
        Err(format!("{value:?} is not an Ethernet address"))
    }
}

fn canonical_ssid_hex(value: &str) -> Result<Option<String>, String> {
    if value.is_empty() || value == "<MISSING>" {
        return Ok(None);
    }
    let value = value.to_ascii_lowercase();
    if value.len().is_multiple_of(2)
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(Some(value))
    } else {
        Err(format!(
            "{} has invalid nonempty SSID bytes {value:?}",
            FIELDS[28]
        ))
    }
}

fn canonical_eui64(value: &str, field: &str) -> Result<Option<String>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.to_ascii_lowercase();
    let mut parts = value.split(':');
    let valid = (0..8).all(|_| {
        parts.next().is_some_and(|part| {
            part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none();
    if valid {
        Ok(Some(value))
    } else {
        Err(format!("{field} is not an EUI-64 address: {value:?}"))
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
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "40",
            "",
            "7",
        ]
        .join("\t")
    }

    fn ipv6_udp_row() -> String {
        let mut fields = tcp_row().split('\t').map(str::to_owned).collect::<Vec<_>>();
        fields[2] = "62".into();
        fields[3] = "62".into();
        fields[7] = "eth:ethertype:ipv6:udp".into();
        for field in &mut fields[10..=12] {
            field.clear();
        }
        fields[13] = "2001:db8::1".into();
        fields[14] = "2001:db8::2".into();
        fields[15] = "17".into();
        for field in &mut fields[16..=18] {
            field.clear();
        }
        fields[19] = "5353".into();
        fields[20] = "5353".into();
        fields[IP_LENGTH_INDEX].clear();
        fields[IPV6_PAYLOAD_LENGTH_INDEX] = "8".into();
        fields[TCP_STREAM_INDEX].clear();
        fields.join("\t")
    }

    fn wireless_row() -> String {
        [
            "2",
            "1700000000.223456789",
            "144",
            "144",
            "0",
            "0",
            "23",
            "radiotap:wlan_radio:wlan",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "0",
            "5",
            "02:00:00:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "02:00:00:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "02:00:00:00:00:01",
            "6F6D7573",
            "1",
            "2412",
            "-74",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        .join("\t")
    }

    fn ieee802154_row() -> String {
        [
            "3",
            "1700000000.323456789",
            "18",
            "18",
            "0",
            "0",
            "104",
            "wpan",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "0x0003",
            "1",
            "42",
            "0x1234",
            "0x5678",
            "",
            "",
            "",
            "02:00:00:00:00:00:00:01",
            "0x04",
            "True",
            "",
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
        assert_eq!(packet.ipv4.as_ref().unwrap().total_length_octets, Some(40));
        assert_eq!(packet.tcp.as_ref().unwrap().destination_port, 443);
        assert_eq!(packet.tcp.as_ref().unwrap().stream_index, Some(7));
    }

    #[test]
    fn parser_normalizes_ipv6_payload_length_to_total_length() {
        let parsed = parse_rows(format!("{}\n", ipv6_udp_row()).as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 1);
        let packet = &parsed.packets[0];
        assert_eq!(packet.ipv6.as_ref().unwrap().total_length_octets, Some(48));
        assert_eq!(packet.udp.as_ref().unwrap().destination_port, 5353);
    }

    #[test]
    fn parser_preserves_ip_length_across_truncated_capture_boundary() {
        let mut fields = tcp_row().split('\t').map(str::to_owned).collect::<Vec<_>>();
        fields[2] = "74".into();
        fields[3] = "54".into();
        fields[IP_LENGTH_INDEX] = "60".into();
        let row = fields.join("\t");

        let parsed = parse_rows(format!("{row}\n").as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        let packet = &parsed.packets[0];
        assert_eq!(packet.frame.original_len, 74);
        assert_eq!(packet.frame.captured_len, 54);
        assert_eq!(packet.ipv4.as_ref().unwrap().total_length_octets, Some(60));
    }

    #[test]
    fn parser_treats_length_only_network_fields_as_capture_truncation() {
        let mut ipv4 = tcp_row().split('\t').map(str::to_owned).collect::<Vec<_>>();
        ipv4[2] = "98".into();
        ipv4[3] = "20".into();
        ipv4[7] = "eth:ethertype:ip".into();
        for field in &mut ipv4[10..=12] {
            field.clear();
        }
        for field in &mut ipv4[16..=18] {
            field.clear();
        }
        ipv4[TCP_STREAM_INDEX].clear();

        let mut ipv6 = ipv6_udp_row()
            .split('\t')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        ipv6[0] = "2".into();
        ipv6[2] = "110".into();
        ipv6[3] = "20".into();
        ipv6[7] = "eth:ethertype:ipv6".into();
        for field in &mut ipv6[13..=15] {
            field.clear();
        }
        for field in &mut ipv6[19..=20] {
            field.clear();
        }

        let parsed = parse_rows(
            format!("{}\n{}\n", ipv4.join("\t"), ipv6.join("\t")).as_bytes(),
            CAPTURE_ID,
        );

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(parsed.packets[0].frame.captured_len, 20);
        assert!(parsed.packets[0].ipv4.is_none());
        assert_eq!(parsed.packets[1].frame.captured_len, 20);
        assert!(parsed.packets[1].ipv6.is_none());
    }

    #[test]
    fn malformed_or_inconsistent_flow_fields_are_quarantined() {
        let mutate = |base: String, frame_number: usize, index: usize, value: &str| {
            let mut fields = base.split('\t').map(str::to_owned).collect::<Vec<_>>();
            fields[0] = frame_number.to_string();
            fields[index] = value.into();
            fields.join("\t")
        };
        let mut orphan_ip_length = tcp_row().split('\t').map(str::to_owned).collect::<Vec<_>>();
        orphan_ip_length[0] = "4".into();
        for field in &mut orphan_ip_length[10..=12] {
            field.clear();
        }
        let mut orphan_stream = tcp_row().split('\t').map(str::to_owned).collect::<Vec<_>>();
        orphan_stream[0] = "5".into();
        for field in &mut orphan_stream[16..=18] {
            field.clear();
        }
        let rows = [
            mutate(tcp_row(), 1, IP_LENGTH_INDEX, "0"),
            mutate(tcp_row(), 2, IP_LENGTH_INDEX, "55"),
            mutate(
                ipv6_udp_row(),
                3,
                IPV6_PAYLOAD_LENGTH_INDEX,
                &u32::MAX.to_string(),
            ),
            orphan_ip_length.join("\t"),
            orphan_stream.join("\t"),
        ];

        let parsed = parse_rows(format!("{}\n", rows.join("\n")).as_bytes(), CAPTURE_ID);

        assert!(parsed.packets.is_empty());
        for reason in [
            "IPv4 total length must be greater than zero",
            "IPv4 total length exceeds original frame length",
            "ipv6.plen total length overflows u32",
            "incomplete first-occurrence IPv4 field group",
            "incomplete first-occurrence TCP field group",
        ] {
            assert!(
                parsed
                    .quarantines
                    .iter()
                    .any(|quarantine| quarantine.reason.contains(reason)),
                "missing quarantine reason for {reason}"
            );
        }
    }

    #[test]
    fn parser_preserves_wireless_header_and_normalized_radio_evidence() {
        let parsed = parse_rows(format!("{}\n", wireless_row()).as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        let packet = &parsed.packets[0];
        let ieee80211 = packet.ieee80211.as_ref().unwrap();
        assert_eq!((ieee80211.frame_type, ieee80211.frame_subtype), (0, 5));
        assert_eq!(ieee80211.transmitter.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(ieee80211.ssid_hex.as_deref(), Some("6f6d7573"));
        let radio = packet.wlan_radio.as_ref().unwrap();
        assert_eq!(radio.channel, Some(1));
        assert_eq!(radio.center_frequency_mhz, Some(2412));
        assert_eq!(radio.signal_dbm, Some(-74));
    }

    #[test]
    fn parser_preserves_wildcard_ssid_as_absent_evidence() {
        let mut fields = wireless_row()
            .split('\t')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        fields[28] = "<MISSING>".into();
        let row = fields.join("\t");

        let parsed = parse_rows(format!("{row}\n").as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(
            parsed.packets[0]
                .ieee80211
                .as_ref()
                .expect("wireless frame")
                .ssid_hex,
            None
        );
    }

    #[test]
    fn parser_matches_synthetic_tshark_ieee802154_output() {
        let parsed = parse_rows(format!("{}\n", ieee802154_row()).as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 1);
        let encoded = serde_json::to_value(&parsed.packets[0]).unwrap();
        let ieee802154 = &encoded["ieee802154"];
        assert_eq!(ieee802154["frame_type"], 3);
        assert_eq!(ieee802154["frame_version"], 1);
        assert_eq!(ieee802154["sequence_number"], 42);
        assert_eq!(ieee802154["destination_pan_id"], 0x1234);
        assert_eq!(ieee802154["destination"]["kind"], "short");
        assert_eq!(ieee802154["destination"]["value"], 0x5678);
        assert_eq!(ieee802154["source"]["value"], "02:00:00:00:00:00:00:01");
        assert_eq!(ieee802154["command"], 4);
        assert_eq!(ieee802154["fcs_status"], "valid");
        assert!(ieee802154.get("payload").is_none());
        assert_eq!(FIELD_REGISTRY_ID, "netmon.tshark.packet_envelope.v3");
        assert!(FIELDS.iter().all(|field| !field.contains("payload")));
        assert!(!FIELDS.contains(&"tcp.seq"));
        assert!(!FIELDS.contains(&"tcp.ack"));
    }

    #[test]
    fn parser_tolerates_absent_optional_ieee802154_fields() {
        let mut fields = ieee802154_row()
            .split('\t')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for field in &mut fields[34..=42] {
            field.clear();
        }
        let row = fields.join("\t");

        let parsed = parse_rows(format!("{row}\n").as_bytes(), CAPTURE_ID);

        assert!(parsed.quarantines.is_empty());
        assert_eq!(parsed.packets.len(), 1);
        let encoded = serde_json::to_value(&parsed.packets[0]).unwrap();
        let ieee802154 = encoded["ieee802154"].as_object().unwrap();
        assert_eq!(ieee802154.len(), 2);
        assert_eq!(ieee802154["frame_type"], 3);
        assert_eq!(ieee802154["frame_version"], 1);
    }

    #[test]
    fn malformed_present_ieee802154_fields_are_quarantined() {
        let mutate = |frame_number: usize, index: usize, value: &str| {
            let mut fields = ieee802154_row()
                .split('\t')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            fields[0] = frame_number.to_string();
            fields[index] = value.into();
            fields.join("\t")
        };
        let rows = [
            mutate(3, 32, ""),
            mutate(4, 35, "0xzzzz"),
            mutate(5, 37, "02:00:00:00:00:00:00:02"),
            mutate(6, 40, "not-an-eui64"),
            mutate(7, 42, "Unknown"),
            mutate(8, 32, "0x0008"),
            mutate(9, 33, "4"),
        ];
        let input = format!("{}\n", rows.join("\n"));

        let parsed = parse_rows(input.as_bytes(), CAPTURE_ID);

        assert!(parsed.packets.is_empty());
        assert_eq!(parsed.quarantines.len(), rows.len());
        for field in [
            "frame type and version",
            "wpan.dst_pan",
            "both short and extended",
            "EUI-64",
            "wpan.fcs_ok",
            "invalid IEEE 802.15.4 frame type",
            "invalid IEEE 802.15.4 frame version",
        ] {
            assert!(
                parsed
                    .quarantines
                    .iter()
                    .any(|quarantine| quarantine.reason.contains(field)),
                "missing quarantine reason for {field}"
            );
        }
    }

    #[test]
    fn unsigned_parser_has_decimal_and_tshark_hex_parity() {
        for value in u8::MIN..=u8::MAX {
            assert_eq!(
                parse_u8_auto_radix(&value.to_string(), "u8"),
                parse_u8_auto_radix(&format!("0x{value:04x}"), "u8")
            );
        }
        for value in u16::MIN..=u16::MAX {
            assert_eq!(
                parse_u16_auto_radix(&value.to_string(), "u16"),
                parse_u16_auto_radix(&format!("0x{value:04x}"), "u16")
            );
        }
    }

    #[test]
    fn malformed_wireless_groups_are_quarantined_with_specific_reasons() {
        let mutate = |index: usize, value: &str| {
            let mut fields = wireless_row()
                .split('\t')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            fields[index] = value.into();
            fields.join("\t")
        };

        let missing_type_and_subtype = {
            let mut fields = wireless_row()
                .split('\t')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            fields[21].clear();
            fields[22].clear();
            fields.join("\t")
        };
        let missing_subtype = mutate(22, "");
        let zero_channel = mutate(29, "0");
        let input = format!("{missing_type_and_subtype}\n{missing_subtype}\n{zero_channel}\n");
        let parsed = parse_rows(input.as_bytes(), CAPTURE_ID);

        assert!(parsed.packets.is_empty());
        assert_eq!(parsed.quarantines.len(), 3);
        assert!(parsed.quarantines[0]
            .reason
            .contains("attributes exist without frame type and subtype"));
        assert!(parsed.quarantines[1]
            .reason
            .contains("incomplete first-occurrence IEEE 802.11 frame type group"));
        assert!(parsed.quarantines[2]
            .reason
            .contains("WLAN channel must be greater than zero"));
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
