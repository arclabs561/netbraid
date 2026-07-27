// Compatibility reader for the latest saved netops audit snapshot. It interprets
// signal, congestion, and client placement from one local JSONL record; it does not
// capture traffic, query a controller, or implement Netbraid's gated evidence/replay
// core.

mod pcap;
mod scenario;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OPERATOR_TEXT_CHARS: usize = 160;
const OPERATOR_LIST_ITEMS: usize = 8;
const AP_LIST_ITEMS: usize = 32;
const WEAK_CLIENT_LIST_ITEMS: usize = 20;

#[derive(Parser)]
#[command(
    name = "netbraid",
    version,
    about = "Inspect saved network evidence and compatibility snapshots"
)]
struct Cli {
    /// audit-history.jsonl to read (default: ~/.cache/netops/audit-history.jsonl)
    #[arg(long)]
    file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read the latest saved controller compatibility snapshot for the network.
    Net,
    /// Read one device from the latest saved controller compatibility snapshot.
    Device { query: String },
    /// Match this host against the latest saved controller compatibility snapshot.
    Here,
    /// Replay an experimental v0 host-path evidence JSONL log.
    Evidence {
        /// Path to a netmon.host_path_observation.v0 JSONL log.
        log: PathBuf,
    },
    /// Normalize and summarize one saved PCAP or PCAPNG artifact through Wireshark tools.
    Pcap(pcap::PcapArgs),
    /// Validate or replay a finite, offline scenario bundle.
    Scenario(scenario::ScenarioArgs),
}

enum ClientMatch<'a> {
    Exact(&'a Client),
    UniquePartial(&'a Client),
    Ambiguous(Vec<&'a Client>),
    None,
}

fn match_clients<'a>(s: &'a Snapshot, query: &str) -> ClientMatch<'a> {
    let q = query.to_lowercase();
    let fields = |client: &'a Client| {
        [
            client.name.as_deref(),
            client.mac.as_deref(),
            client.ip.as_deref(),
        ]
    };
    let exact = s
        .clients
        .iter()
        .filter(|client| {
            fields(client)
                .iter()
                .flatten()
                .any(|value| value.to_lowercase() == q)
        })
        .collect::<Vec<_>>();
    match exact.as_slice() {
        [client] => return ClientMatch::Exact(client),
        [] => {}
        _ => return ClientMatch::Ambiguous(exact),
    }
    let partial = s
        .clients
        .iter()
        .filter(|client| {
            fields(client)
                .iter()
                .flatten()
                .any(|value| value.to_lowercase().contains(&q))
        })
        .collect::<Vec<_>>();
    match partial.as_slice() {
        [] => ClientMatch::None,
        [client] => ClientMatch::UniquePartial(client),
        _ => ClientMatch::Ambiguous(partial),
    }
}

struct LoadedSnapshot {
    source: PathBuf,
    snapshot: Snapshot,
}

#[derive(Deserialize)]
struct Snapshot {
    ts: i64,
    #[serde(default)]
    aps: BTreeMap<String, Ap>,
    #[serde(default)]
    clients: Vec<Client>,
    #[serde(default)]
    clients_wireless: u32,
    #[serde(default)]
    clients_wired: u32,
    sat_min: Option<i64>,
    sat_avg: Option<i64>,
    wan_status: Option<String>,
}

#[derive(Deserialize)]
struct Ap {
    #[serde(default)]
    uptime_h: f64,
    uplink: Option<String>,
    #[serde(default)]
    clients: u32,
    #[serde(default)]
    radios: BTreeMap<String, Radio>,
}

#[derive(Deserialize)]
struct Radio {
    channel: Option<i64>,
    airtime: Option<i64>,
    neighbors: Option<i64>,
}

#[derive(Deserialize)]
struct Client {
    mac: Option<String>,
    name: Option<String>,
    #[serde(default)]
    wired: bool,
    ap: Option<String>,
    ip: Option<String>,
    signal: Option<i64>,
    radio: Option<String>,
    sat: Option<i64>,
    #[serde(default)]
    tx_bytes: Option<i64>,
    #[serde(default)]
    rx_bytes: Option<i64>,
}

fn band(rssi: i64) -> &'static str {
    match rssi {
        r if r > -50 => "excellent RSSI",
        r if r > -60 => "strong RSSI",
        r if r > -67 => "good RSSI",
        r if r > -72 => "fair RSSI",
        _ => "weak RSSI",
    }
}

fn human(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1e9 {
        format!("{:.1} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.0} MB", b / 1e6)
    } else {
        format!("{:.0} KB", b / 1e3)
    }
}

fn load(file: Option<PathBuf>) -> Result<LoadedSnapshot> {
    let path = file.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(format!("{home}/.cache/netops/audit-history.jsonl"))
    });
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {}",
            operator_text(path.as_os_str().to_string_lossy().as_ref())
        )
    })?;
    let last = text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .context("audit history is empty")?;
    let snapshot = serde_json::from_str(last).context("parsing the latest audit snapshot")?;
    Ok(LoadedSnapshot {
        source: path,
        snapshot,
    })
}

fn age(ts: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .ok();
    age_at(ts, now)
}

fn age_at(ts: i64, now: Option<i64>) -> String {
    let Some(now) = now else {
        return "age unavailable: system clock is before Unix epoch".into();
    };
    if ts > now {
        let delta = ts - now;
        let amount = if delta < 60 {
            format!("{delta}s")
        } else {
            format!("{}m", delta / 60)
        };
        return format!("{amount} in the future; clock skew or timestamp error");
    }
    let m = (now - ts) / 60;
    if m < 60 {
        format!("{m}m ago")
    } else {
        format!("{}h{}m ago", m / 60, m % 60)
    }
}

fn print_snapshot_header(s: &Snapshot, source: &Path) {
    println!(
        "saved controller compatibility snapshot — source {} — timestamp {} unix ({})",
        operator_text(&source.display().to_string()),
        s.ts,
        age(s.ts)
    );
}

fn cmd_net(s: &Snapshot, source: &Path) {
    print_snapshot_header(s, source);
    println!(
        "{} wireless / {} wired clients, reported satisfaction min {} / avg {}, reported WAN status {}",
        s.clients_wireless,
        s.clients_wired,
        s.sat_min.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        s.sat_avg.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        s.wan_status
            .as_deref()
            .map(operator_text)
            .unwrap_or_else(|| "?".into()),
    );
    println!("\naccess points:");
    for (name, ap) in s.aps.iter().take(AP_LIST_ITEMS) {
        let mut radios = String::new();
        for (band_name, r) in ap.radios.iter().take(OPERATOR_LIST_ITEMS) {
            let ch = r
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            let at = r
                .airtime
                .map(|value| format!("{value}%"))
                .unwrap_or_else(|| "?".into());
            radios.push_str(&format!(" {}=ch{ch}/{at}", operator_text(band_name)));
        }
        if ap.radios.len() > OPERATOR_LIST_ITEMS {
            radios.push_str(&format!(
                " … +{} radio(s)",
                ap.radios.len() - OPERATOR_LIST_ITEMS
            ));
        }
        let mesh = if ap.uplink.as_deref() == Some("wireless") {
            "  [reported wireless uplink; capacity impact not measured]"
        } else {
            ""
        };
        let name = operator_text(name);
        println!(
            "  {name:32} up {:>5.1}h  {} clients {}{}",
            ap.uptime_h,
            ap.clients,
            radios.trim(),
            mesh
        );
        for (band_name, r) in ap.radios.iter().take(OPERATOR_LIST_ITEMS) {
            if let Some(at) = r.airtime.filter(|value| *value > 75) {
                println!(
                    "      {}: reported airtime {at}% exceeds the 75% review threshold; client impact not measured",
                    operator_text(band_name)
                );
            }
            if let Some(neigh) = r.neighbors.filter(|value| *value > 100) {
                println!(
                    "      {}: reported neighbor count {neigh} exceeds the 100-AP review threshold; overlap and impact not established",
                    operator_text(band_name)
                );
            }
        }
    }
    if s.aps.len() > AP_LIST_ITEMS {
        println!(
            "  … +{} access point(s) omitted",
            s.aps.len() - AP_LIST_ITEMS
        );
    }
    let mut weak: Vec<&Client> = s
        .clients
        .iter()
        .filter(|c| !c.wired && c.signal.map(|v| v <= -72).unwrap_or(false))
        .collect();
    weak.sort_by_key(|c| c.signal.unwrap_or(0));
    if !weak.is_empty() {
        println!("\nclients with reported RSSI ≤ -72 dBm (cause not inferred):");
        for c in weak.iter().take(WEAK_CLIENT_LIST_ITEMS) {
            println!(
                "  {:20} {} dBm on {}",
                operator_text(c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?")),
                c.signal.unwrap_or(0),
                operator_text(c.ap.as_deref().unwrap_or("?"))
            );
        }
        if weak.len() > WEAK_CLIENT_LIST_ITEMS {
            println!(
                "  … +{} client(s) omitted",
                weak.len() - WEAK_CLIENT_LIST_ITEMS
            );
        }
    }
}

fn cmd_device(s: &Snapshot, source: &Path, query: &str) {
    print_snapshot_header(s, source);
    match match_clients(s, query) {
        ClientMatch::Exact(client) => print_client_details(s, client),
        ClientMatch::UniquePartial(client) => {
            println!(
                "unique substring roster match for {:?}:",
                operator_text(query)
            );
            print_client_details(s, client);
        }
        ClientMatch::Ambiguous(clients) => print_ambiguous_clients(query, &clients),
        ClientMatch::None => println!(
            "no client matching {:?} in the saved snapshot ({} clients)",
            operator_text(query),
            s.clients.len()
        ),
    }
}

fn print_client_details(s: &Snapshot, c: &Client) {
    let nm = operator_text(c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?"));
    println!(
        "{nm}  ({})",
        operator_text(c.ip.as_deref().unwrap_or("no reported IP"))
    );
    if c.wired {
        println!(
            "  reported wired attachment {}",
            operator_text(c.ap.as_deref().unwrap_or("?"))
        );
    } else {
        let ap = operator_text(c.ap.as_deref().unwrap_or("?"));
        match c.signal {
            Some(rssi) => println!(
                "  reported attachment {ap} ({}), {rssi} dBm — {}",
                operator_text(c.radio.as_deref().unwrap_or("?")),
                band(rssi)
            ),
            None => println!("  reported attachment {ap}"),
        }
        if let Some(sat) = c.sat {
            let display_band = if sat >= 90 {
                "high"
            } else if sat >= 70 {
                "mid"
            } else {
                "low"
            };
            println!(
                "  reported controller satisfaction score {sat} ({display_band} display band: high ≥90, mid 70–89, low <70)"
            );
        }
        if let Some(ap_name) = &c.ap {
            if let Some(ap) = s.aps.get(ap_name) {
                if let Some((b, r)) = ap
                    .radios
                    .iter()
                    .find(|(b, _)| Some(b.as_str()) == c.radio.as_deref())
                {
                    if let Some(at) = r.airtime {
                        let note = if at > 75 {
                            " — above the 75% review threshold; client impact not measured"
                        } else {
                            " — at or below the 75% review threshold"
                        };
                        println!(
                            "  {} {} reported airtime {at}%{note}",
                            operator_text(ap_name),
                            operator_text(b)
                        );
                    }
                }
            }
        }
    }
    let tx = c.tx_bytes.unwrap_or(0);
    let rx = c.rx_bytes.unwrap_or(0);
    if tx + rx > 0 {
        println!(
            "  reported byte counters: {} sent / {} received (counter interval not recorded)",
            human(tx),
            human(rx)
        );
    }
}

fn print_ambiguous_clients(query: &str, clients: &[&Client]) {
    println!(
        "{} roster candidates match {:?}; refine the query:",
        clients.len(),
        operator_text(query)
    );
    for client in clients.iter().take(OPERATOR_LIST_ITEMS) {
        println!(
            "  {}  {}  {}",
            operator_text(
                client
                    .name
                    .as_deref()
                    .or(client.mac.as_deref())
                    .unwrap_or("?")
            ),
            operator_text(client.ip.as_deref().unwrap_or("no reported IP")),
            operator_text(client.ap.as_deref().unwrap_or("no reported attachment"))
        );
    }
    if clients.len() > OPERATOR_LIST_ITEMS {
        println!(
            "  … +{} candidate(s) omitted",
            clients.len() - OPERATOR_LIST_ITEMS
        );
    }
}

fn cmd_here(s: &Snapshot, source: &Path) {
    print_snapshot_header(s, source);
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().split('.').next().unwrap_or("").to_string())
        .unwrap_or_default();
    if host.is_empty() {
        println!("could not resolve the local hostname");
        return;
    }
    match match_clients(s, &host) {
        ClientMatch::Exact(client) => {
            println!(
                "exact roster match for local hostname {:?}; controller naming is not verified device identity:",
                operator_text(&host)
            );
            print_client_details(s, client);
        }
        ClientMatch::UniquePartial(client) => {
            println!(
                "one substring roster candidate for local hostname {:?}; device identity is not verified:",
                operator_text(&host)
            );
            print_client_details(s, client);
        }
        ClientMatch::Ambiguous(clients) => print_ambiguous_clients(&host, &clients),
        ClientMatch::None => {
            println!(
                "no roster match for local hostname {:?}; controller naming may differ.",
                operator_text(&host)
            );
            println!("wireless roster candidates, strongest reported RSSI first:");
            let mut wl: Vec<&Client> = s
                .clients
                .iter()
                .filter(|c| !c.wired && c.signal.is_some())
                .collect();
            wl.sort_by_key(|client| std::cmp::Reverse(client.signal));
            if wl.is_empty() {
                println!("  none with reported RSSI in this saved snapshot");
            } else {
                for c in wl.iter().take(OPERATOR_LIST_ITEMS) {
                    println!(
                        "  {:20} {} dBm  {}",
                        operator_text(c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?")),
                        c.signal.expect("filtered to clients with reported RSSI"),
                        operator_text(c.ap.as_deref().unwrap_or("?"))
                    );
                }
                if wl.len() > OPERATOR_LIST_ITEMS {
                    println!(
                        "  … +{} candidate(s) omitted",
                        wl.len() - OPERATOR_LIST_ITEMS
                    );
                }
            }
        }
    }
}

fn cmd_evidence(log: &PathBuf) -> Result<()> {
    let state = netbraid_replay::read_jsonl(log).with_context(|| {
        format!(
            "replaying {}",
            operator_text(log.as_os_str().to_string_lossy().as_ref())
        )
    })?;
    let exact_keys = state
        .records
        .iter()
        .map(netbraid_replay::HostPathObservationV0::context_key)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let changed = state
        .transitions
        .iter()
        .filter(|transition| {
            transition.relation == netbraid_replay::ContextRelationV0::ContextChanged
        })
        .count();
    let compatible = state
        .transitions
        .iter()
        .filter(|transition| {
            transition.relation == netbraid_replay::ContextRelationV0::CompatibleContext
        })
        .count();
    println!(
        "{} record(s), {exact_keys} exact key variant(s), {changed} confirmed context transition(s), {compatible} compatible/incomplete transition(s)",
        state.records.len()
    );
    if let Some(latest) = state.records.last() {
        let recurrence = netbraid_replay::summarize_context_recurrence(&state.records, latest);
        println!(
            "latest: {} via {} ({})",
            latest
                .path
                .interface
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unknown interface".into()),
            latest
                .path
                .next_hop
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unknown next hop".into()),
            operator_text(&latest.record_id)
        );
        println!(
            "source: observer {} / adapter {} {}",
            operator_text(&latest.source.observer_id),
            operator_text(&latest.source.adapter),
            operator_text(&latest.source.adapter_version)
        );
        println!(
            "order: event {} ms unix / acquired {} ms unix / source sequence {}",
            latest.order.event_time_unix_ms,
            latest.order.acquired_time_unix_ms,
            latest.order.source_sequence
        );
        println!(
            "policy: {}{}",
            collection_mode_label(latest.policy.mode),
            if latest.policy.active_actions.is_empty() {
                String::new()
            } else {
                format!(
                    " / actions {}",
                    evidence_list(&latest.policy.active_actions, "none")
                )
            }
        );
        println!(
            "coverage: {} / observed {} / missing {}",
            coverage_state_label(latest.coverage.state),
            evidence_list(&latest.coverage.observed_sources, "none"),
            evidence_list(&latest.coverage.missing_sources, "none")
        );
        println!(
            "network: {} / link {} / association {} / BSSID {}",
            network_name_text(&latest.path.network_name),
            latest
                .path
                .link_type
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unknown".into()),
            latest
                .path
                .association_id
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into()),
            latest
                .path
                .associated_bssid
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into())
        );
        println!(
            "boundary: next-hop link address {} / prefixes {} / resolvers {}",
            latest
                .path
                .next_hop_link_address
                .as_deref()
                .map(operator_text)
                .unwrap_or_else(|| "unavailable".into()),
            evidence_list(&latest.path.address_prefixes, "none"),
            evidence_list(&latest.path.resolvers, "none")
        );
        println!(
            "history: {} prior exact key match(es) [{}], {} compatible prior observation(s), {} prior BSSID attachment variant(s) [{}]",
            recurrence.exact_prior_observations,
            exact_context_match_label(recurrence.exact_context_match),
            recurrence.compatible_prior_observations,
            recurrence.distinct_prior_associated_bssids,
            attachment_corroboration_label(recurrence.attachment_corroboration),
        );
        if let Some(transition) = state.transitions.last() {
            println!(
                "transition: {} / changed dimensions {}",
                context_relation_label(transition.relation),
                if transition.changed_dimensions.is_empty() {
                    "none".into()
                } else {
                    evidence_list(&transition.changed_dimensions, "none")
                }
            );
        }
    }
    Ok(())
}

fn operator_text(value: &str) -> String {
    let mut rendered = String::new();
    for character in value.chars().take(OPERATOR_TEXT_CHARS) {
        if character.is_control() {
            rendered.extend(character.escape_default());
        } else {
            rendered.push(character);
        }
    }
    if value.chars().count() > OPERATOR_TEXT_CHARS {
        rendered.push('…');
    }
    rendered
}

fn evidence_list<T: AsRef<str>>(values: &[T], empty: &str) -> String {
    if values.is_empty() {
        empty.into()
    } else {
        let mut rendered = values
            .iter()
            .take(OPERATOR_LIST_ITEMS)
            .map(|value| operator_text(value.as_ref()))
            .collect::<Vec<_>>()
            .join(", ");
        if values.len() > OPERATOR_LIST_ITEMS {
            rendered.push_str(&format!(", … +{} more", values.len() - OPERATOR_LIST_ITEMS));
        }
        rendered
    }
}

fn collection_mode_label(mode: netbraid_replay::CollectionModeV0) -> &'static str {
    match mode {
        netbraid_replay::CollectionModeV0::PassiveHostLocal => "passive_host_local",
        netbraid_replay::CollectionModeV0::ActiveBounded => "active_bounded",
    }
}

fn coverage_state_label(state: netbraid_replay::CoverageStateV0) -> &'static str {
    match state {
        netbraid_replay::CoverageStateV0::Complete => "complete",
        netbraid_replay::CoverageStateV0::Partial => "partial",
        netbraid_replay::CoverageStateV0::Unavailable => "unavailable",
    }
}

fn network_name_text(name: &netbraid_replay::NetworkNameV0) -> String {
    match name.visibility {
        netbraid_replay::NetworkNameVisibilityV0::Observed => format!(
            "observed {:?}",
            operator_text(name.value.as_deref().unwrap_or_default())
        ),
        netbraid_replay::NetworkNameVisibilityV0::Restricted => {
            "restricted by platform policy".into()
        }
        netbraid_replay::NetworkNameVisibilityV0::Unavailable => "unavailable".into(),
    }
}

fn context_relation_label(relation: netbraid_replay::ContextRelationV0) -> &'static str {
    match relation {
        netbraid_replay::ContextRelationV0::FirstObservation => "first_observation",
        netbraid_replay::ContextRelationV0::SameContext => "same_context",
        netbraid_replay::ContextRelationV0::CompatibleContext => "compatible_context",
        netbraid_replay::ContextRelationV0::ContextChanged => "context_changed",
    }
}

fn exact_context_match_label(value: netbraid_replay::ExactContextMatchV0) -> &'static str {
    match value {
        netbraid_replay::ExactContextMatchV0::NoPriorExactKeyMatch => "no prior exact key match",
        netbraid_replay::ExactContextMatchV0::UnanchoredExactKeyMatch => {
            "unanchored exact key match; no recurring network-context claim"
        }
        netbraid_replay::ExactContextMatchV0::AnchoredExactRecurrence => {
            "anchored exact recurrence via gateway link address"
        }
    }
}

fn attachment_corroboration_label(
    value: netbraid_replay::AttachmentCorroborationV0,
) -> &'static str {
    match value {
        netbraid_replay::AttachmentCorroborationV0::NotObserved => {
            "attachment corroboration unavailable"
        }
        netbraid_replay::AttachmentCorroborationV0::NotSeenBefore => {
            "current BSSID not seen in prior exact key matches"
        }
        netbraid_replay::AttachmentCorroborationV0::SeenBefore => {
            "current BSSID seen in a prior exact key match"
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Evidence { log } => return cmd_evidence(log),
        Cmd::Pcap(args) => return pcap::run(args),
        Cmd::Scenario(args) => return scenario::run(args),
        _ => {}
    }
    let loaded = load(cli.file)?;
    match cli.cmd {
        Cmd::Net => cmd_net(&loaded.snapshot, &loaded.source),
        Cmd::Device { query } => cmd_device(&loaded.snapshot, &loaded.source, &query),
        Cmd::Here => cmd_here(&loaded.snapshot, &loaded.source),
        Cmd::Evidence { .. } => unreachable!("evidence command returned before snapshot loading"),
        Cmd::Pcap(_) => unreachable!("pcap command returned before snapshot loading"),
        Cmd::Scenario(_) => unreachable!("scenario command returned before snapshot loading"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_bands_read_in_plain_language() {
        assert_eq!(band(-42), "excellent RSSI");
        assert_eq!(band(-65), "good RSSI");
        assert_eq!(band(-76), "weak RSSI");
    }

    #[test]
    fn human_bytes_scale() {
        assert_eq!(human(2_300_000_000), "2.3 GB");
        assert_eq!(human(5_500_000), "6 MB");
    }

    #[test]
    fn evidence_labels_distinguish_key_match_from_anchored_recurrence() {
        assert_eq!(
            exact_context_match_label(
                netbraid_replay::ExactContextMatchV0::UnanchoredExactKeyMatch
            ),
            "unanchored exact key match; no recurring network-context claim"
        );
        assert_eq!(
            exact_context_match_label(
                netbraid_replay::ExactContextMatchV0::AnchoredExactRecurrence
            ),
            "anchored exact recurrence via gateway link address"
        );
        assert_eq!(
            attachment_corroboration_label(netbraid_replay::AttachmentCorroborationV0::SeenBefore),
            "current BSSID seen in a prior exact key match"
        );
    }

    #[test]
    fn evidence_projection_uses_schema_vocabulary_and_escapes_controls() {
        assert_eq!(
            collection_mode_label(netbraid_replay::CollectionModeV0::PassiveHostLocal),
            "passive_host_local"
        );
        assert_eq!(
            coverage_state_label(netbraid_replay::CoverageStateV0::Partial),
            "partial"
        );
        assert_eq!(
            context_relation_label(netbraid_replay::ContextRelationV0::ContextChanged),
            "context_changed"
        );
        assert_eq!(operator_text("observer\n\u{1b}"), "observer\\n\\u{1b}");
        assert_eq!(
            network_name_text(&netbraid_replay::NetworkNameV0 {
                visibility: netbraid_replay::NetworkNameVisibilityV0::Restricted,
                value: None,
            }),
            "restricted by platform policy"
        );
    }

    #[test]
    fn client_matching_prioritizes_exact_values_and_reports_ambiguity() {
        let snapshot = Snapshot {
            ts: 1,
            aps: BTreeMap::new(),
            clients: vec![
                test_client("arc", "192.0.2.1"),
                test_client("arcade", "192.0.2.2"),
            ],
            clients_wireless: 2,
            clients_wired: 0,
            sat_min: None,
            sat_avg: None,
            wan_status: None,
        };
        assert!(matches!(
            match_clients(&snapshot, "ARC"),
            ClientMatch::Exact(client) if client.name.as_deref() == Some("arc")
        ));
        assert!(matches!(
            match_clients(&snapshot, "cade"),
            ClientMatch::UniquePartial(client) if client.name.as_deref() == Some("arcade")
        ));
        assert!(matches!(
            match_clients(&snapshot, "ar"),
            ClientMatch::Ambiguous(clients) if clients.len() == 2
        ));
    }

    #[test]
    fn snapshot_age_calls_out_future_timestamps() {
        assert_eq!(
            age_at(1_030, Some(1_000)),
            "30s in the future; clock skew or timestamp error"
        );
        assert_eq!(age_at(1_000, Some(1_120)), "2m ago");
        assert!(age_at(1_000, None).contains("age unavailable"));
    }

    #[test]
    fn operator_lists_are_bounded_and_escape_controls() {
        let values = (0..10)
            .map(|index| format!("source-{index}\n"))
            .collect::<Vec<_>>();
        let rendered = evidence_list(&values, "none");
        assert!(rendered.contains("source-0\\n"));
        assert!(rendered.contains("source-7\\n"));
        assert!(!rendered.contains("source-8"));
        assert!(rendered.ends_with("… +2 more"));
    }

    #[test]
    fn parses_a_real_shaped_snapshot() {
        // mirrors the netops/audit schema: nullable telemetry, wired+wireless roster
        let j = r#"{"ts":1,"clients_wireless":2,"clients_wired":1,"sat_min":96,"wan_status":"ok",
            "aps":{"AP1":{"uptime_h":51.5,"uplink":"wire","clients":2,
                "radios":{"na":{"channel":48,"airtime":7,"neighbors":19}}}},
            "clients":[{"name":"MacBookPro","ip":"192.168.1.35","ap":"AP1","radio":"na","signal":-42,"sat":100,"tx_bytes":100},
                       {"name":"nas","wired":true,"ap":"SW1"}]}"#;
        let s: Snapshot = serde_json::from_str(j).expect("snapshot parses");
        assert_eq!(s.clients_wireless, 2);
        assert_eq!(s.clients.len(), 2);
        assert!(s.clients.iter().any(|c| c.wired));
        assert_eq!(s.aps["AP1"].radios["na"].airtime, Some(7));
    }

    fn test_client(name: &str, ip: &str) -> Client {
        Client {
            mac: None,
            name: Some(name.into()),
            wired: false,
            ap: None,
            ip: Some(ip.into()),
            signal: None,
            radio: None,
            sat: None,
            tx_bytes: None,
            rx_bytes: None,
        }
    }
}
