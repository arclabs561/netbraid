// Compatibility reader for the latest saved netops audit snapshot. It interprets
// signal, congestion, and client placement from one local JSONL record; it does not
// capture traffic, query a controller, or implement netmon's gated evidence/replay
// core.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "netmon",
    about = "Inspect the latest saved netops audit snapshot"
)]
struct Cli {
    /// audit-history.jsonl to read (default: ~/.cache/netops/audit-history.jsonl)
    #[arg(long, global = true)]
    file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Network overview: APs, congestion + its cause, clients, anything off.
    Net,
    /// One device's situation (name/MAC/IP substring) and whether it's well-placed.
    Device { query: String },
    /// This machine's situation (resolves the local hostname against the roster).
    Here,
    /// Replay an experimental v0 host-path evidence JSONL log.
    Evidence {
        /// Path to a netmon.host_path_observation.v0 JSONL log.
        log: PathBuf,
    },
}

fn find_client<'a>(s: &'a Snapshot, query: &str) -> Option<&'a Client> {
    let q = query.to_lowercase();
    s.clients.iter().find(|c| {
        [c.name.as_deref(), c.mac.as_deref(), c.ip.as_deref()]
            .iter()
            .flatten()
            .any(|v| v.to_lowercase().contains(&q))
    })
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
        r if r > -50 => "excellent (right next to the AP)",
        r if r > -60 => "strong",
        r if r > -67 => "good",
        r if r > -72 => "fair",
        _ => "weak (far from the AP / through walls)",
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

fn load(file: Option<PathBuf>) -> Result<Snapshot> {
    let path = file.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(format!("{home}/.cache/netops/audit-history.jsonl"))
    });
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let last = text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .context("audit history is empty")?;
    serde_json::from_str(last).context("parsing the latest audit snapshot")
}

fn age(ts: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(ts);
    let m = (now - ts).max(0) / 60;
    if m < 60 {
        format!("{m}m ago")
    } else {
        format!("{}h{}m ago", m / 60, m % 60)
    }
}

fn cmd_net(s: &Snapshot) {
    println!(
        "network snapshot ({}) — {} wireless / {} wired clients, satisfaction min {} / avg {}, WAN {}",
        age(s.ts),
        s.clients_wireless,
        s.clients_wired,
        s.sat_min.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        s.sat_avg.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        s.wan_status.as_deref().unwrap_or("?"),
    );
    println!("\naccess points:");
    for (name, ap) in &s.aps {
        let mut radios = String::new();
        for (band_name, r) in &ap.radios {
            let ch = r
                .channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            let at = r.airtime.unwrap_or(0);
            radios.push_str(&format!(" {band_name}=ch{ch}/{at}%"));
        }
        let mesh = if ap.uplink.as_deref() == Some("wireless") {
            "  [wireless mesh — throughput cost]"
        } else {
            ""
        };
        println!(
            "  {name:32} up {:>5.1}h  {} clients {}{}",
            ap.uptime_h,
            ap.clients,
            radios.trim(),
            mesh
        );
        for (band_name, r) in &ap.radios {
            let at = r.airtime.unwrap_or(0);
            let neigh = r.neighbors.unwrap_or(0);
            if at > 75 {
                println!("      ⚠ {band_name} congested: {at}% airtime (channel is busy — clients will feel it)");
            }
            if neigh > 100 {
                println!("      ⚠ {band_name} crowded: shares its channel with {neigh} neighbor APs (environmental, steer to 5/6 GHz)");
            }
        }
    }
    let mut weak: Vec<&Client> = s
        .clients
        .iter()
        .filter(|c| !c.wired && c.signal.map(|v| v <= -72).unwrap_or(false))
        .collect();
    weak.sort_by_key(|c| c.signal.unwrap_or(0));
    if !weak.is_empty() {
        println!("\nweak clients (≤ -72 dBm — likely sticky or far):");
        for c in weak {
            println!(
                "  {:20} {} dBm on {}",
                c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?"),
                c.signal.unwrap_or(0),
                c.ap.as_deref().unwrap_or("?")
            );
        }
    }
}

fn cmd_device(s: &Snapshot, query: &str) {
    let Some(c) = find_client(s, query) else {
        println!(
            "no device matching '{query}' in the latest snapshot ({} clients)",
            s.clients.len()
        );
        return;
    };
    let nm = c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?");
    println!("{nm}  ({})", c.ip.as_deref().unwrap_or("no ip"));
    if c.wired {
        println!("  wired on {}", c.ap.as_deref().unwrap_or("?"));
    } else {
        let ap = c.ap.as_deref().unwrap_or("?");
        match c.signal {
            Some(rssi) => println!(
                "  on {ap} ({}), {rssi} dBm — {}",
                c.radio.as_deref().unwrap_or("?"),
                band(rssi)
            ),
            None => println!("  on {ap}"),
        }
        if let Some(sat) = c.sat {
            let verdict = if sat >= 90 {
                "healthy"
            } else if sat >= 70 {
                "okay"
            } else {
                "poor — investigate"
            };
            println!("  satisfaction {sat} ({verdict})");
        }
        // context: how busy is the AP it's on?
        if let Some(ap_name) = &c.ap {
            if let Some(ap) = s.aps.get(ap_name) {
                if let Some((b, r)) = ap
                    .radios
                    .iter()
                    .find(|(b, _)| Some(b.as_str()) == c.radio.as_deref())
                {
                    let at = r.airtime.unwrap_or(0);
                    let note = if at > 75 {
                        " — congested, your device shares the wait"
                    } else {
                        " — healthy"
                    };
                    println!("  {ap_name} {b} is at {at}% airtime{note}");
                }
            }
        }
    }
    let tx = c.tx_bytes.unwrap_or(0);
    let rx = c.rx_bytes.unwrap_or(0);
    if tx + rx > 0 {
        println!(
            "  this session: {} sent / {} received",
            human(tx),
            human(rx)
        );
    }
}

fn cmd_here(s: &Snapshot) {
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
    if find_client(s, &host).is_some() {
        println!("this device ('{host}'):");
        cmd_device(s, &host);
    } else {
        println!("no roster match for this host ('{host}'); UniFi may name it differently.");
        println!("your wireless devices, strongest first (try: netmon device <name>):");
        let mut wl: Vec<&Client> = s
            .clients
            .iter()
            .filter(|c| !c.wired && c.signal.is_some())
            .collect();
        wl.sort_by_key(|client| std::cmp::Reverse(client.signal));
        for c in wl.iter().take(8) {
            println!(
                "  {:20} {} dBm  {}",
                c.name.as_deref().or(c.mac.as_deref()).unwrap_or("?"),
                c.signal.unwrap_or(0),
                c.ap.as_deref().unwrap_or("?")
            );
        }
    }
}

fn cmd_evidence(log: &PathBuf) -> Result<()> {
    let state =
        netmon_replay::read_jsonl(log).with_context(|| format!("replaying {}", log.display()))?;
    let exact_keys = state
        .records
        .iter()
        .map(netmon_replay::HostPathObservationV0::context_key)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let changed = state
        .transitions
        .iter()
        .filter(|transition| {
            transition.relation == netmon_replay::ContextRelationV0::ContextChanged
        })
        .count();
    let compatible = state
        .transitions
        .iter()
        .filter(|transition| {
            transition.relation == netmon_replay::ContextRelationV0::CompatibleContext
        })
        .count();
    println!(
        "{} record(s), {exact_keys} exact key variant(s), {changed} confirmed context transition(s), {compatible} compatible/incomplete transition(s)",
        state.records.len()
    );
    if let Some(latest) = state.records.last() {
        let recurrence = netmon_replay::summarize_context_recurrence(&state.records, latest);
        println!(
            "latest: {} via {} ({})",
            latest
                .path
                .interface
                .as_deref()
                .unwrap_or("unknown interface"),
            latest
                .path
                .next_hop
                .as_deref()
                .unwrap_or("unknown next hop"),
            latest.record_id
        );
        println!(
            "history: {} prior exact key match(es) [{}], {} compatible prior observation(s), {} prior BSSID attachment variant(s) [{}]",
            recurrence.exact_prior_observations,
            exact_context_match_label(recurrence.exact_context_match),
            recurrence.compatible_prior_observations,
            recurrence.distinct_prior_associated_bssids,
            attachment_corroboration_label(recurrence.attachment_corroboration),
        );
    }
    Ok(())
}

fn exact_context_match_label(value: netmon_replay::ExactContextMatchV0) -> &'static str {
    match value {
        netmon_replay::ExactContextMatchV0::NoPriorExactKeyMatch => "no prior exact key match",
        netmon_replay::ExactContextMatchV0::UnanchoredExactKeyMatch => {
            "unanchored exact key match; no recurring network-context claim"
        }
        netmon_replay::ExactContextMatchV0::AnchoredExactRecurrence => {
            "anchored exact recurrence via gateway link address"
        }
    }
}

fn attachment_corroboration_label(value: netmon_replay::AttachmentCorroborationV0) -> &'static str {
    match value {
        netmon_replay::AttachmentCorroborationV0::NotObserved => {
            "attachment corroboration unavailable"
        }
        netmon_replay::AttachmentCorroborationV0::NotSeenBefore => {
            "current BSSID not seen in prior exact key matches"
        }
        netmon_replay::AttachmentCorroborationV0::SeenBefore => {
            "current BSSID seen in a prior exact key match"
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::Evidence { log } = &cli.cmd {
        return cmd_evidence(log);
    }
    let snap = load(cli.file)?;
    match cli.cmd {
        Cmd::Net => cmd_net(&snap),
        Cmd::Device { query } => cmd_device(&snap, &query),
        Cmd::Here => cmd_here(&snap),
        Cmd::Evidence { .. } => unreachable!("evidence command returned before snapshot loading"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_bands_read_in_plain_language() {
        assert!(band(-42).starts_with("excellent"));
        assert_eq!(band(-65), "good");
        assert!(band(-76).starts_with("weak"));
    }

    #[test]
    fn human_bytes_scale() {
        assert_eq!(human(2_300_000_000), "2.3 GB");
        assert_eq!(human(5_500_000), "6 MB");
    }

    #[test]
    fn evidence_labels_distinguish_key_match_from_anchored_recurrence() {
        assert_eq!(
            exact_context_match_label(netmon_replay::ExactContextMatchV0::UnanchoredExactKeyMatch),
            "unanchored exact key match; no recurring network-context claim"
        );
        assert_eq!(
            exact_context_match_label(netmon_replay::ExactContextMatchV0::AnchoredExactRecurrence),
            "anchored exact recurrence via gateway link address"
        );
        assert_eq!(
            attachment_corroboration_label(netmon_replay::AttachmentCorroborationV0::SeenBefore),
            "current BSSID seen in a prior exact key match"
        );
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
}
