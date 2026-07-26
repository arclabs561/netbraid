use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use netmon_adapter_tshark::{
    normalize_saved_capture, NormalizationReport, NormalizeOptions, DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_STDOUT_BYTES, DEFAULT_PACKET_LIMIT, DEFAULT_TIMEOUT,
};
use netmon_evidence::{NormalizationStateV0, PacketEnvelopeV0};
use netmon_replay::{
    reduce_capture_conversations, CaptureConversationV0, ConversationDirectionV0,
    TransportProtocolV0,
};

const MIB: u64 = 1024 * 1024;

#[derive(Debug, Args)]
pub struct PcapArgs {
    /// Saved PCAP or PCAPNG file to read. Live interfaces are not accepted.
    pub input: PathBuf,

    /// Observer that produced the artifact, when independently known.
    #[arg(long)]
    pub observer_id: Option<String>,

    /// Artifact acquisition time in Unix milliseconds, when independently known.
    #[arg(long)]
    pub acquired_time_unix_ms: Option<i64>,

    /// Emit versioned manifest, run receipt, packet, and quarantine records as JSONL.
    #[arg(long, conflicts_with = "records_jsonl")]
    pub jsonl: bool,

    /// Emit only deterministic manifest, packet, and quarantine records as JSONL.
    #[arg(long, conflicts_with = "jsonl")]
    pub records_jsonl: bool,

    /// Maximum packets TShark may read. A longer file makes normalization partial.
    #[arg(long, default_value_t = DEFAULT_PACKET_LIMIT)]
    pub packet_limit: usize,

    /// Maximum saved-capture size accepted, in MiB.
    #[arg(long, default_value_t = DEFAULT_MAX_INPUT_BYTES / MIB)]
    pub max_input_mib: u64,

    /// Maximum TShark stdout accepted, in MiB.
    #[arg(long, default_value_t = DEFAULT_MAX_STDOUT_BYTES as u64 / MIB)]
    pub max_output_mib: u64,

    /// Maximum subprocess deadline; metadata and version probes use lower safety caps.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT.as_secs())]
    pub timeout_seconds: u64,

    /// TShark executable to invoke.
    #[arg(long, default_value = "tshark")]
    pub tshark: PathBuf,

    /// Capinfos executable to invoke.
    #[arg(long, default_value = "capinfos")]
    pub capinfos: PathBuf,

    /// Permit executable personal Wireshark plugins; their registrations are fingerprinted.
    #[arg(long)]
    pub allow_personal_plugins: bool,
}

pub fn run(args: &PcapArgs) -> Result<()> {
    let max_input_bytes = args
        .max_input_mib
        .checked_mul(MIB)
        .context("--max-input-mib is too large")?;
    let max_stdout_bytes = args
        .max_output_mib
        .checked_mul(MIB)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .context("--max-output-mib is too large for this platform")?;
    let report = normalize_saved_capture(
        &args.input,
        &NormalizeOptions {
            tshark_path: args.tshark.clone(),
            capinfos_path: args.capinfos.clone(),
            observer_id: args.observer_id.clone(),
            acquired_time_unix_ms: args.acquired_time_unix_ms,
            allow_personal_plugins: args.allow_personal_plugins,
            packet_limit: args.packet_limit,
            max_input_bytes,
            max_stdout_bytes,
            timeout: Duration::from_secs(args.timeout_seconds),
            ..NormalizeOptions::default()
        },
    )
    .with_context(|| format!("normalizing {}", args.input.display()))?;

    if args.jsonl || args.records_jsonl {
        print_jsonl(&report, args.jsonl)
    } else {
        print_summary(&args.input, &report);
        Ok(())
    }
}

fn print_jsonl(report: &NormalizationReport, include_receipt: bool) -> Result<()> {
    let mut output = BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut output, &report.manifest).context("writing capture manifest")?;
    output.write_all(b"\n")?;
    if include_receipt {
        serde_json::to_writer(&mut output, &report.receipt)
            .context("writing capture run receipt")?;
        output.write_all(b"\n")?;
    }
    for packet in &report.packets {
        serde_json::to_writer(&mut output, packet).context("writing packet envelope")?;
        output.write_all(b"\n")?;
    }
    for quarantine in &report.quarantines {
        serde_json::to_writer(&mut output, quarantine).context("writing packet quarantine")?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    Ok(())
}

fn print_summary(input: &Path, report: &NormalizationReport) {
    let manifest = &report.manifest;
    println!("capture");
    println!(
        "  file          {}",
        operator_text(&input.display().to_string())
    );
    println!("  content       {}", manifest.artifact.content_sha256);
    println!("  bytes         {}", manifest.artifact.size_bytes);
    println!(
        "  observer      {}",
        manifest
            .observer_id
            .as_deref()
            .map(operator_text)
            .unwrap_or_else(|| "unknown (not asserted)".into())
    );
    println!(
        "  acquisition   {}",
        if manifest.acquisition_policy.is_some() {
            "policy supplied"
        } else {
            "policy unknown (detached artifact)"
        }
    );
    println!("  registry      {}", manifest.extractor.field_registry);
    println!(
        "  configuration {}",
        manifest.extractor.configuration_sha256
    );

    let file = &report.receipt.file;
    println!("\ncapture file");
    println!(
        "  format        {} / {} / {}",
        operator_text(&file.file_type),
        operator_text(&file.encapsulation),
        operator_text(&file.timestamp_precision)
    );
    println!(
        "  extent        {} packets / {} original packet-data octets / {} file bytes",
        file.packet_count, file.original_data_size_bytes, file.file_size_bytes
    );
    println!(
        "  snaplen       {}",
        file.snaplen
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unavailable".into())
    );
    match (
        file.earliest_packet_time_unix_ns,
        file.latest_packet_time_unix_ns,
        file.duration_ns,
    ) {
        (Some(first), Some(last), Some(duration)) => println!(
            "  file span     {} .. {}  ({})",
            format_epoch_ns(first),
            format_epoch_ns(last),
            format_u64_duration_ns(duration)
        ),
        _ => println!("  file span     unavailable (empty capture)"),
    }
    if file.capture_hardware.is_some()
        || file.capture_operating_system.is_some()
        || file.capture_application.is_some()
    {
        println!(
            "  provenance    hardware={} / os={} / application={}",
            file.capture_hardware
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into()),
            file.capture_operating_system
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into()),
            file.capture_application
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into())
        );
    }

    println!("\nnormalization");
    println!(
        "  state         {}",
        normalization_label(manifest.normalization.state)
    );
    println!(
        "  packets       {} emitted / {} quarantined / limit {}{}",
        manifest.normalization.packet_rows_emitted,
        manifest.normalization.packet_rows_quarantined,
        manifest.normalization.packet_limit,
        if manifest.normalization.packet_limit_reached {
            " (reached; capture may continue)"
        } else {
            ""
        }
    );
    println!(
        "  inspection    {} of {} file packets",
        manifest.normalization.packet_rows_emitted + manifest.normalization.packet_rows_quarantined,
        file.packet_count
    );

    if report.packets.is_empty() {
        println!("\nnormalized packet subset\n  no packet rows emitted");
        print_quarantines(report);
        print_successful_run(report);
        return;
    }

    let first_ns = report
        .packets
        .iter()
        .map(|packet| packet.frame.event_time_unix_ns)
        .min()
        .unwrap();
    let last_ns = report
        .packets
        .iter()
        .map(|packet| packet.frame.event_time_unix_ns)
        .max()
        .unwrap();
    let wire_bytes: u64 = report
        .packets
        .iter()
        .map(|packet| u64::from(packet.frame.original_len))
        .sum();
    let captured_bytes: u64 = report
        .packets
        .iter()
        .map(|packet| u64::from(packet.frame.captured_len))
        .sum();

    println!("\nnormalized packet subset");
    println!(
        "  span          {} .. {}  ({})",
        format_epoch_ns(first_ns),
        format_epoch_ns(last_ns),
        format_duration_ns(last_ns.saturating_sub(first_ns))
    );
    println!("{}", format_frame_extent(wire_bytes, captured_bytes));

    if let Some(summary) = render_ieee80211_summary(&report.packets) {
        print!("{summary}");
    }
    print_capture_conversations(report);

    let protocol_stacks = count_by(report, |packet| {
        (!packet.frame.protocols.is_empty()).then(|| packet.frame.protocols.join(":"))
    });
    print_counts("protocol stacks", &protocol_stacks, 8);
    print_quarantines(report);
    print_successful_run(report);
}

fn render_ieee80211_summary(packets: &[PacketEnvelopeV0]) -> Option<String> {
    const FRAME_MIX_LIMIT: usize = 12;
    const RADIO_CONTEXT_LIMIT: usize = 8;
    const IDENTIFIER_LIMIT: usize = 8;

    #[derive(Default)]
    struct RadioContextSummary {
        frames: usize,
        signals: Vec<i8>,
    }

    let wireless_frames = packets
        .iter()
        .filter(|packet| packet.ieee80211.is_some())
        .count();
    if wireless_frames == 0 {
        return None;
    }

    let radio_frames = packets
        .iter()
        .filter(|packet| packet.wlan_radio.is_some())
        .count();
    let bssid_frames = packets
        .iter()
        .filter(|packet| {
            packet
                .ieee80211
                .as_ref()
                .and_then(|fields| fields.bssid.as_ref())
                .is_some()
        })
        .count();
    let transmitter_frames = packets
        .iter()
        .filter(|packet| {
            packet
                .ieee80211
                .as_ref()
                .and_then(|fields| fields.transmitter.as_ref())
                .is_some()
        })
        .count();
    let ssid_frames = packets
        .iter()
        .filter(|packet| {
            packet
                .ieee80211
                .as_ref()
                .and_then(|fields| fields.ssid_hex.as_ref())
                .is_some()
        })
        .count();

    let mut frame_mix: BTreeMap<(u8, u8), usize> = BTreeMap::new();
    let mut bssids: BTreeMap<String, usize> = BTreeMap::new();
    let mut transmitters: BTreeMap<String, usize> = BTreeMap::new();
    let mut ssids: BTreeMap<String, usize> = BTreeMap::new();
    for fields in packets
        .iter()
        .filter_map(|packet| packet.ieee80211.as_ref())
    {
        *frame_mix
            .entry((fields.frame_type, fields.frame_subtype))
            .or_default() += 1;
        if let Some(value) = &fields.bssid {
            *bssids.entry(value.clone()).or_default() += 1;
        }
        if let Some(value) = &fields.transmitter {
            *transmitters.entry(value.clone()).or_default() += 1;
        }
        if let Some(value) = &fields.ssid_hex {
            *ssids.entry(value.clone()).or_default() += 1;
        }
    }

    let mut output = String::new();
    writeln!(output, "\nIEEE 802.11").unwrap();
    writeln!(
        output,
        "  scope         normalized packet subset; observed frame fields only"
    )
    .unwrap();
    writeln!(
        output,
        "  coverage      {wireless_frames} WLAN frames / {radio_frames} with radio metadata"
    )
    .unwrap();
    writeln!(
        output,
        "  identifiers   BSSID {bssid_frames} frames / {} unique; TA {transmitter_frames} / {}; \
         nonempty SSID {ssid_frames} / {}",
        bssids.len(),
        transmitters.len(),
        ssids.len()
    )
    .unwrap();

    let mut ranked_frames: Vec<_> = frame_mix.into_iter().collect();
    ranked_frames.sort_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });
    write_ranked_header(
        &mut output,
        "frame mix",
        ranked_frames.len(),
        FRAME_MIX_LIMIT,
    );
    for ((frame_type, frame_subtype), count) in ranked_frames.iter().take(FRAME_MIX_LIMIT).copied()
    {
        writeln!(
            output,
            "  {count:>8}  {} [type {frame_type} subtype {frame_subtype}]",
            ieee80211_frame_label(frame_type, frame_subtype)
        )
        .unwrap();
    }
    write_omitted_count(
        &mut output,
        ranked_frames.len(),
        FRAME_MIX_LIMIT,
        "frame subtypes",
    );

    let mut radio_contexts: BTreeMap<(Option<u32>, Option<u16>), RadioContextSummary> =
        BTreeMap::new();
    for radio in packets
        .iter()
        .filter_map(|packet| packet.wlan_radio.as_ref())
    {
        let entry = radio_contexts
            .entry((radio.channel, radio.center_frequency_mhz))
            .or_default();
        entry.frames += 1;
        if let Some(signal) = radio.signal_dbm {
            entry.signals.push(signal);
        }
    }
    if !radio_contexts.is_empty() {
        let mut ranked_contexts: Vec<_> = radio_contexts.into_iter().collect();
        ranked_contexts.sort_by(|(left_key, left_summary), (right_key, right_summary)| {
            right_summary
                .frames
                .cmp(&left_summary.frames)
                .then_with(|| left_key.cmp(right_key))
        });
        write_ranked_header(
            &mut output,
            "radio contexts",
            ranked_contexts.len(),
            RADIO_CONTEXT_LIMIT,
        );
        for ((channel, frequency), summary) in ranked_contexts.iter_mut().take(RADIO_CONTEXT_LIMIT)
        {
            write!(
                output,
                "  {:>8}  channel {} / {} MHz",
                summary.frames,
                optional_number(*channel),
                optional_number(*frequency)
            )
            .unwrap();
            if summary.signals.is_empty() {
                writeln!(output, " / signal unavailable").unwrap();
            } else {
                summary.signals.sort_unstable();
                let minimum = summary.signals[0];
                let median = median_signal_dbm(&summary.signals);
                let maximum = summary.signals[summary.signals.len() - 1];
                writeln!(
                    output,
                    " / signal {minimum}..{maximum} dBm / median {median} dBm (n={})",
                    summary.signals.len()
                )
                .unwrap();
            }
        }
        write_omitted_count(
            &mut output,
            ranked_contexts.len(),
            RADIO_CONTEXT_LIMIT,
            "radio contexts",
        );
    }

    write_ranked_observations(&mut output, "BSSIDs", &bssids, IDENTIFIER_LIMIT);
    write_ranked_observations(
        &mut output,
        "transmitter addresses (TA)",
        &transmitters,
        IDENTIFIER_LIMIT,
    );
    if !ssids.is_empty() {
        write_ranked_header(&mut output, "SSID elements", ssids.len(), IDENTIFIER_LIMIT);
        writeln!(
            output,
            "  scope         nonempty elements only; hex is authoritative"
        )
        .unwrap();
        let mut ranked: Vec<_> = ssids.into_iter().collect();
        ranked.sort_by(|(left_name, left_count), (right_name, right_count)| {
            right_count
                .cmp(left_count)
                .then_with(|| left_name.cmp(right_name))
        });
        for (ssid_hex, count) in ranked.iter().take(IDENTIFIER_LIMIT) {
            match decode_ssid_hex(ssid_hex).and_then(|bytes| String::from_utf8(bytes).ok()) {
                Some(ssid) => {
                    writeln!(
                        output,
                        "  {count:>8}  text={:?} / hex={ssid_hex}",
                        operator_text(&ssid)
                    )
                    .unwrap();
                }
                None => writeln!(output, "  {count:>8}  hex={ssid_hex}").unwrap(),
            }
        }
        write_omitted_count(&mut output, ranked.len(), IDENTIFIER_LIMIT, "SSID elements");
    }

    Some(output)
}

fn write_ranked_observations(
    output: &mut String,
    title: &str,
    counts: &BTreeMap<String, usize>,
    limit: usize,
) {
    if counts.is_empty() {
        return;
    }
    let mut ranked: Vec<_> = counts.iter().collect();
    ranked.sort_by(|(left_name, left_count), (right_name, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_name.cmp(right_name))
    });
    write_ranked_header(output, title, ranked.len(), limit);
    for (name, count) in ranked.iter().take(limit) {
        writeln!(output, "  {count:>8}  {}", operator_text(name)).unwrap();
    }
    write_omitted_count(output, ranked.len(), limit, "observations");
}

fn write_ranked_header(output: &mut String, title: &str, total: usize, limit: usize) {
    writeln!(
        output,
        "\n{title} (ranked by frame count; showing {}/{total})",
        total.min(limit)
    )
    .unwrap();
}

fn write_omitted_count(output: &mut String, total: usize, limit: usize, noun: &str) {
    if total > limit {
        writeln!(output, "  … {} more {noun}", total - limit).unwrap();
    }
}

fn decode_ssid_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn median_signal_dbm(sorted: &[i8]) -> String {
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle].to_string()
    } else {
        let doubled = i16::from(sorted[middle - 1]) + i16::from(sorted[middle]);
        if doubled % 2 == 0 {
            (doubled / 2).to_string()
        } else {
            format!("{:.1}", f32::from(doubled) / 2.0)
        }
    }
}

fn ieee80211_frame_label(frame_type: u8, frame_subtype: u8) -> &'static str {
    match (frame_type, frame_subtype) {
        (0, 0) => "association request",
        (0, 1) => "association response",
        (0, 2) => "reassociation request",
        (0, 3) => "reassociation response",
        (0, 4) => "probe request",
        (0, 5) => "probe response",
        (0, 6) => "measurement pilot",
        (0, 8) => "beacon",
        (0, 9) => "announcement traffic indication message (ATIM)",
        (0, 10) => "disassociation",
        (0, 11) => "authentication",
        (0, 12) => "deauthentication",
        (0, 13) => "action",
        (0, 14) => "action no acknowledgment",
        (0, _) => "management reserved/extension subtype",
        (1, 2) => "trigger",
        (1, 3) => "target wake time acknowledgment (TWT Ack)",
        (1, 4) => "beamforming report poll",
        (1, 5) => "VHT/HE/EHT/ranging NDP announcement",
        (1, 7) => "control wrapper",
        (1, 8) => "block acknowledgment request",
        (1, 9) => "block acknowledgment",
        (1, 10) => "power-save poll (PS-Poll)",
        (1, 11) => "request to send (RTS)",
        (1, 12) => "clear to send (CTS)",
        (1, 13) => "acknowledgment (ACK)",
        (1, 14) => "contention-free end (CF-End)",
        (1, 15) => "contention-free end + acknowledgment",
        (1, _) => "control reserved/extension subtype",
        (2, 0) => "data",
        (2, 1) => "data + CF-Ack",
        (2, 2) => "data + CF-Poll",
        (2, 3) => "data + CF-Ack + CF-Poll",
        (2, 4) => "null function (no data)",
        (2, 5) => "CF-Ack (no data)",
        (2, 6) => "CF-Poll (no data)",
        (2, 7) => "CF-Ack + CF-Poll (no data)",
        (2, 8) => "QoS data",
        (2, 9) => "QoS data + CF-Ack",
        (2, 10) => "QoS data + CF-Poll",
        (2, 11) => "QoS data + CF-Ack + CF-Poll",
        (2, 12) => "QoS null (no data)",
        (2, 14) => "QoS CF-Poll (no data)",
        (2, 15) => "QoS CF-Ack + CF-Poll (no data)",
        (2, _) => "data reserved subtype",
        (3, _) => "extension frame",
        _ => "unknown frame class",
    }
}

fn print_quarantines(report: &NormalizationReport) {
    if report.quarantines.is_empty() {
        return;
    }
    println!("\nquarantine");
    for row in report.quarantines.iter().take(8) {
        println!(
            "  line {:>6}  frame {:>6}  {}",
            row.source_line,
            row.frame_number_hint
                .map(|number| number.to_string())
                .unwrap_or_else(|| "?".into()),
            row.reason
        );
    }
    if report.quarantines.len() > 8 {
        println!("  … {} more", report.quarantines.len() - 8);
    }
}

fn count_by(
    report: &NormalizationReport,
    key: impl Fn(&netmon_evidence::PacketEnvelopeV0) -> Option<String>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for packet in &report.packets {
        if let Some(key) = key(packet) {
            *counts.entry(key).or_default() += 1;
        }
    }
    counts
}

fn print_counts(title: &str, counts: &BTreeMap<String, usize>, limit: usize) {
    if counts.is_empty() {
        return;
    }
    println!("\n{title}");
    let mut ranked: Vec<_> = counts.iter().collect();
    ranked.sort_by(|(left_name, left_count), (right_name, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_name.cmp(right_name))
    });
    for (name, count) in ranked.into_iter().take(limit) {
        println!("  {count:>8}  {}", operator_text(name));
    }
}

fn print_capture_conversations(report: &NormalizationReport) {
    let reduced = reduce_capture_conversations(&report.packets);
    let capture_start_unix_ns = report
        .packets
        .iter()
        .map(|packet| packet.frame.event_time_unix_ns)
        .min()
        .expect("capture conversations require at least one emitted packet");
    println!("\ncapture conversations");
    if !reduced.conversations.is_empty() {
        println!("  scope         capture-wide; endpoint A/B is canonical, not initiator");
    }
    println!(
        "  coverage      {} grouped / {} emitted packet envelopes / {} excluded",
        reduced.packet_envelopes_grouped,
        reduced.packet_envelopes_seen,
        reduced.packet_envelopes_excluded
    );
    for (reason, count) in &reduced.exclusions {
        println!("  excluded      {count} {}", reason.label());
    }
    for conversation in reduced.conversations.iter().take(8) {
        print_capture_conversation(conversation, capture_start_unix_ns);
    }
    if reduced.conversations.len() > 8 {
        println!(
            "  … {} more capture conversations",
            reduced.conversations.len() - 8
        );
    }
}

fn print_capture_conversation(conversation: &CaptureConversationV0, capture_start_unix_ns: i64) {
    let protocol = match conversation.key.transport {
        TransportProtocolV0::Tcp => "TCP",
        TransportProtocolV0::Udp => "UDP",
    };
    println!(
        "\n  {protocol} {} ↔ {}",
        format_endpoint(&conversation.key.endpoint_a),
        format_endpoint(&conversation.key.endpoint_b)
    );
    println!(
        "    point       section={} / interface={} / encapsulation={}",
        optional_number(conversation.key.observation_point.section_number),
        optional_number(conversation.key.observation_point.interface_id),
        optional_number(conversation.key.observation_point.encapsulation_type)
    );
    println!(
        "    total       {} {} / {} original frame octets / {} captured frame octets",
        conversation.total_frames(),
        plural(conversation.total_frames(), "frame", "frames"),
        conversation.total_original_frame_octets(),
        conversation.total_captured_frame_octets()
    );
    print_conversation_direction("A→B", &conversation.a_to_b);
    print_conversation_direction("B→A", &conversation.b_to_a);
    println!(
        "    timing      +{} .. +{} from capture start / {} span",
        format_duration_ns(
            conversation
                .earliest_event_time_unix_ns
                .saturating_sub(capture_start_unix_ns)
        ),
        format_duration_ns(
            conversation
                .latest_event_time_unix_ns
                .saturating_sub(capture_start_unix_ns)
        ),
        format_duration_ns(
            conversation
                .latest_event_time_unix_ns
                .saturating_sub(conversation.earliest_event_time_unix_ns)
        )
    );
}

fn print_successful_run(report: &NormalizationReport) {
    println!("\nsuccessful run");
    println!("  id            {}", report.receipt.run_id);
    println!(
        "  elapsed       {}",
        format_u64_duration_ns(report.receipt.elapsed_ns)
    );
    println!(
        "  capinfos      {}",
        operator_text(&report.receipt.capinfos.tool_version)
    );
    println!(
        "  tshark        {}",
        operator_text(&report.receipt.tshark.tool_version)
    );
    println!(
        "  records       {}",
        report.receipt.normalized_records_sha256
    );
}

fn print_conversation_direction(label: &str, direction: &ConversationDirectionV0) {
    print!(
        "    {label:<11} {} {} / {} original / {} captured",
        direction.frames,
        plural(direction.frames, "frame", "frames"),
        direction.original_frame_octets,
        direction.captured_frame_octets
    );
    if let Some(flags) = &direction.tcp_flags {
        if flags.syn_without_ack_frames != 0
            || flags.syn_ack_frames != 0
            || flags.fin_frames != 0
            || flags.rst_frames != 0
        {
            print!(
                " / flags SYN={} SYN+ACK={} FIN={} RST={}",
                flags.syn_without_ack_frames,
                flags.syn_ack_frames,
                flags.fin_frames,
                flags.rst_frames
            );
        }
    }
    println!();
}

fn format_endpoint(endpoint: &netmon_replay::ConversationEndpointV0) -> String {
    match endpoint.address {
        std::net::IpAddr::V4(address) => format!("{address}:{}", endpoint.port),
        std::net::IpAddr::V6(address) => format!("[{address}]:{}", endpoint.port),
    }
}

fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn plural<'a>(value: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if value == 1 {
        singular
    } else {
        plural
    }
}

fn operator_text(value: &str) -> String {
    const MAX_CHARACTERS: usize = 240;

    let mut characters = value.chars();
    let mut escaped = String::new();
    for character in characters.by_ref().take(MAX_CHARACTERS) {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{{{:x}}}", u32::from(character));
            }
            character => escaped.push(character),
        }
    }
    if characters.next().is_some() {
        escaped.push('…');
    }
    escaped
}

fn normalization_label(state: NormalizationStateV0) -> &'static str {
    match state {
        NormalizationStateV0::Complete => "complete",
        NormalizationStateV0::Partial => "partial",
    }
}

fn format_epoch_ns(value: i64) -> String {
    let negative = value.is_negative();
    let magnitude = i128::from(value).abs();
    let seconds = magnitude / 1_000_000_000;
    let nanos = magnitude % 1_000_000_000;
    format!(
        "{}{seconds}.{nanos:09} unix",
        if negative { "-" } else { "" }
    )
}

fn format_duration_ns(value: i64) -> String {
    if value < 1_000_000 {
        format!("{value} ns")
    } else if value < 1_000_000_000 {
        format!("{:.3} ms", value as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", value as f64 / 1_000_000_000.0)
    }
}

fn format_u64_duration_ns(value: u64) -> String {
    if value < 1_000_000 {
        format!("{value} ns")
    } else if value < 1_000_000_000 {
        format!("{:.3} ms", value as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", value as f64 / 1_000_000_000.0)
    }
}

fn format_frame_extent(original_frame_octets: u64, captured_frame_octets: u64) -> String {
    format!(
        "  octets        {original_frame_octets} original frame octets / \
         {captured_frame_octets} captured frame octets / {} uncaptured octets",
        original_frame_octets.saturating_sub(captured_frame_octets)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmon_evidence::{
        Ieee80211FieldsV0, PacketFrameV0, WlanRadioFieldsV0, PACKET_ENVELOPE_SCHEMA_V0,
    };

    const CAPTURE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn wireless_packet(
        frame: u64,
        frame_type: u8,
        frame_subtype: u8,
        signal_dbm: Option<i8>,
    ) -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{CAPTURE_ID}:frame:{frame}"),
            capture_id: CAPTURE_ID.into(),
            frame: PacketFrameV0 {
                number: frame,
                event_time_unix_ns: i64::try_from(frame).unwrap(),
                original_len: 100,
                captured_len: 100,
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(23),
                protocols: vec!["radiotap".into(), "wlan_radio".into(), "wlan".into()],
            },
            ethernet: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            ieee80211: Some(Ieee80211FieldsV0 {
                frame_type,
                frame_subtype,
                transmitter: Some("02:00:00:00:00:01".into()),
                receiver: Some("ff:ff:ff:ff:ff:ff".into()),
                source: Some("02:00:00:00:00:01".into()),
                destination: Some("ff:ff:ff:ff:ff:ff".into()),
                bssid: Some("02:00:00:00:00:01".into()),
                ssid_hex: Some("6f6d7573".into()),
            }),
            wlan_radio: Some(WlanRadioFieldsV0 {
                channel: Some(1),
                center_frequency_mhz: Some(2412),
                signal_dbm,
            }),
        }
    }

    #[test]
    fn epoch_format_is_exact_for_pre_epoch_values() {
        assert_eq!(format_epoch_ns(-500_000_000), "-0.500000000 unix");
        assert_eq!(format_epoch_ns(1_000_000_001), "1.000000001 unix");
    }

    #[test]
    fn duration_format_uses_operator_units() {
        assert_eq!(format_duration_ns(999), "999 ns");
        assert_eq!(format_duration_ns(1_500_000), "1.500 ms");
        assert_eq!(format_duration_ns(2_000_000_000), "2.000 s");
        assert_eq!(format_u64_duration_ns(2_000_000_000), "2.000 s");
    }

    #[test]
    fn packet_extent_does_not_overclaim_link_wire_bytes() {
        assert_eq!(
            format_frame_extent(120, 80),
            "  octets        120 original frame octets / 80 captured frame octets / 40 uncaptured octets"
        );
    }

    #[test]
    fn operator_text_escapes_controls_and_bounds_untrusted_metadata() {
        assert_eq!(operator_text("sensor\n\u{1b}[31m"), "sensor\\n\\u{1b}[31m");
        let long = "x".repeat(241);
        assert_eq!(operator_text(&long), format!("{}…", "x".repeat(240)));
    }

    #[test]
    fn wireless_summary_prioritizes_coverage_frame_mix_and_radio_context() {
        let packets = [
            wireless_packet(1, 0, 5, Some(-74)),
            wireless_packet(2, 0, 5, Some(-20)),
            wireless_packet(3, 1, 13, None),
        ];

        let output = render_ieee80211_summary(&packets).unwrap();

        assert!(output.contains("coverage      3 WLAN frames / 3 with radio metadata"));
        assert!(output
            .contains("identifiers   BSSID 3 frames / 1 unique; TA 3 / 1; nonempty SSID 3 / 1"));
        assert!(output.contains("2  probe response [type 0 subtype 5]"));
        assert!(output.contains("1  acknowledgment (ACK) [type 1 subtype 13]"));
        assert!(
            output.contains("3  channel 1 / 2412 MHz / signal -74..-20 dBm / median -47 dBm (n=2)")
        );
        assert!(output.contains("text=\"omus\" / hex=6f6d7573"));
    }

    #[test]
    fn wireless_summary_uses_current_expert_subtype_vocabulary() {
        assert_eq!(ieee80211_frame_label(0, 6), "measurement pilot");
        assert_eq!(ieee80211_frame_label(1, 2), "trigger");
        assert_eq!(
            ieee80211_frame_label(1, 3),
            "target wake time acknowledgment (TWT Ack)"
        );
        assert_eq!(ieee80211_frame_label(1, 4), "beamforming report poll");
        assert_eq!(
            ieee80211_frame_label(1, 5),
            "VHT/HE/EHT/ranging NDP announcement"
        );
    }

    #[test]
    fn wireless_summary_discloses_every_bounded_ranked_section() {
        let packets = (0_u8..13)
            .map(|index| {
                let mut packet = wireless_packet(u64::from(index) + 1, 0, index, Some(-40));
                let address = format!("02:00:00:00:00:{:02x}", index + 1);
                let fields = packet.ieee80211.as_mut().unwrap();
                fields.bssid = Some(address.clone());
                fields.transmitter = Some(address);
                fields.ssid_hex = Some(format!("{:02x}", index + 1));
                let radio = packet.wlan_radio.as_mut().unwrap();
                radio.channel = Some(u32::from(index) + 1);
                radio.center_frequency_mhz = Some(2_400 + u16::from(index));
                packet
            })
            .collect::<Vec<_>>();

        let output = render_ieee80211_summary(&packets).unwrap();

        assert!(output.contains("frame mix (ranked by frame count; showing 12/13)"));
        assert!(output.contains("… 1 more frame subtypes"));
        assert!(output.contains("radio contexts (ranked by frame count; showing 8/13)"));
        assert!(output.contains("… 5 more radio contexts"));
        assert!(output.contains("BSSIDs (ranked by frame count; showing 8/13)"));
        assert!(output.contains("transmitter addresses (TA) (ranked by frame count; showing 8/13)"));
        assert!(output.contains("SSID elements (ranked by frame count; showing 8/13)"));
        assert!(output.contains("… 5 more SSID elements"));
    }

    #[test]
    fn no_wireless_evidence_does_not_add_an_empty_section() {
        assert!(render_ieee80211_summary(&[]).is_none());
    }
}
