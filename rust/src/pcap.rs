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
use netmon_evidence::NormalizationStateV0;

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
    #[arg(long)]
    pub jsonl: bool,

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

    if args.jsonl {
        print_jsonl(&report)
    } else {
        print_summary(&args.input, &report);
        Ok(())
    }
}

fn print_jsonl(report: &NormalizationReport) -> Result<()> {
    let mut output = BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut output, &report.manifest).context("writing capture manifest")?;
    output.write_all(b"\n")?;
    serde_json::to_writer(&mut output, &report.receipt).context("writing capture run receipt")?;
    output.write_all(b"\n")?;
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
    println!(
        "  extractor     {}",
        operator_text(&manifest.extractor.tool_version)
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
        "  extent        {} packets / {} original packet bytes / {} file bytes",
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
        "  file rows     {} declared / {} inspected",
        file.packet_count,
        manifest.normalization.packet_rows_emitted + manifest.normalization.packet_rows_quarantined
    );

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

    if report.packets.is_empty() {
        println!("\npacket envelope\n  no packet rows emitted");
        print_quarantines(report);
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

    println!("\npacket envelope");
    println!(
        "  span          {} .. {}  ({})",
        format_epoch_ns(first_ns),
        format_epoch_ns(last_ns),
        format_duration_ns(last_ns.saturating_sub(first_ns))
    );
    println!(
        "  octets        {} on wire / {} captured / {} not captured",
        wire_bytes,
        captured_bytes,
        wire_bytes.saturating_sub(captured_bytes)
    );

    let protocol_stacks = count_by(report, |packet| {
        (!packet.frame.protocols.is_empty()).then(|| packet.frame.protocols.join(":"))
    });
    print_counts("protocol stacks", &protocol_stacks, 8);

    let conversations = count_many(report, |packet| {
        let mut values = Vec::new();
        if let Some(ipv4) = &packet.ipv4 {
            values.push(format!("IPv4 {} → {}", ipv4.source, ipv4.destination));
        }
        if let Some(ipv6) = &packet.ipv6 {
            values.push(format!("IPv6 {} → {}", ipv6.source, ipv6.destination));
        }
        values
    });
    print_counts("L3 directions (first occurrence)", &conversations, 8);

    let transport = count_many(report, |packet| {
        let mut values = Vec::new();
        if let Some(tcp) = &packet.tcp {
            values.push(format!("TCP dst/{}", tcp.destination_port));
        }
        if let Some(udp) = &packet.udp {
            values.push(format!("UDP dst/{}", udp.destination_port));
        }
        values
    });
    print_counts("transport destinations (first occurrence)", &transport, 8);
    print_quarantines(report);
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

fn count_many(
    report: &NormalizationReport,
    keys: impl Fn(&netmon_evidence::PacketEnvelopeV0) -> Vec<String>,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for packet in &report.packets {
        for key in keys(packet) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn operator_text_escapes_controls_and_bounds_untrusted_metadata() {
        assert_eq!(operator_text("sensor\n\u{1b}[31m"), "sensor\\n\\u{1b}[31m");
        let long = "x".repeat(241);
        assert_eq!(operator_text(&long), format!("{}…", "x".repeat(240)));
    }
}
