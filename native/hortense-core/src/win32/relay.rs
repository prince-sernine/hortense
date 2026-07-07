use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use serde_json::json;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};

use crate::event::{new_id, DetectionEvent};
use super::authenticode::{publisher_from_path, publisher_matches_trusted, PublisherInfo};
use super::util::{
    is_allowlisted, normalize_path, path_matches_any, process_image_path, process_name_equals,
};

const AF_INET: u32 = 2;
const TCP_LISTEN: u32 = 2;
const TCP_ESTABLISHED: u32 = 5;

fn tcp_table_v6(_state: u32) -> Vec<MIB_TCP6ROW_OWNER_PID> {
    // GetExtendedTcp6Table is not exported by the MinGW iphlpapi import library.
    // IPv4 listener/peer scans cover the PC-to-phone relay threat model for v0.3.
    Vec::new()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindScope {
    Localhost,
    AllInterfaces,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayTrustAction {
    Suppress,
    Downgrade,
    Flag,
}

#[derive(Clone, Debug)]
struct RelayTarget {
    name: String,
    path: String,
    publisher: PublisherInfo,
}

pub struct RelayScanConfig<'a> {
    pub allowlist: &'a [String],
    pub allowlist_path_substrings: &'a [String],
    // Kept for call-site/signature stability. Relays are no longer meeting-gated in
    // native code; surfacing is decided in Python (scanner._surface_relays).
    #[allow(dead_code)]
    pub interview_processes: &'a [String],
    pub trust_publishers: &'a [String],
    pub tier2_publishers: &'a [String],
    pub companion_processes: &'a [String],
    pub trust_path_prefixes: &'a [String],
    pub suspicious_path_prefixes: &'a [String],
    pub process_names: &'a [String],
    pub path_substrings: &'a [String],
    pub process_rules: &'a [String],
}

pub fn scan(config: RelayScanConfig<'_>) -> Vec<DetectionEvent> {
    // Relays are always scanned. Surfacing is decided in Python (scanner.run_scan):
    // meeting-active or the owning product cluster is a retained tier (anomaly/threat).
    // `interview_processes` stays on the config for signature stability but is no longer
    // a hard gate here.
    let mut events = Vec::new();
    let mut seen_listeners = HashSet::new();
    let mut seen_peers = HashSet::new();
    let mut publisher_cache: HashMap<String, PublisherInfo> = HashMap::new();

    for row in tcp_listeners_v4() {
        if let Some(event) = inspect_listener(
            row.dwOwningPid,
            &format_ipv4(row.dwLocalAddr),
            network_port(row.dwLocalPort),
            &config,
            &mut publisher_cache,
        ) {
            let key = listener_key(&event);
            if seen_listeners.insert(key) {
                events.push(event);
            }
        }
    }

    for row in tcp_listeners_v6() {
        if let Some(event) = inspect_listener(
            row.dwOwningPid,
            &format_ipv6(&row.ucLocalAddr),
            network_port(row.dwLocalPort),
            &config,
            &mut publisher_cache,
        ) {
            let key = listener_key(&event);
            if seen_listeners.insert(key) {
                events.push(event);
            }
        }
    }

    for (pid, remote_ip) in tcp_established_v4() {
        let key = format!("{pid}:{remote_ip}");
        if !seen_peers.insert(key) {
            continue;
        }
        if !is_nearby_peer(&remote_ip) {
            continue;
        }
        if let Some(event) = inspect_intranet_peer(pid, &remote_ip, &config, &mut publisher_cache) {
            events.push(event);
        }
    }

    for (pid, remote_ip) in tcp_established_v6() {
        let key = format!("{pid}:{remote_ip}");
        if !seen_peers.insert(key) {
            continue;
        }
        if !is_nearby_peer_v6(&remote_ip) {
            continue;
        }
        if let Some(event) = inspect_intranet_peer(pid, &remote_ip, &config, &mut publisher_cache) {
            events.push(event);
        }
    }

    apply_shape_upgrades(&mut events);
    events
}

fn listener_key(event: &DetectionEvent) -> String {
    format!(
        "{}:{}:{}",
        event.pid.unwrap_or(0),
        event
            .metadata
            .get("local_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        event
            .metadata
            .get("bind_scope")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    )
}

fn inspect_listener(
    pid: u32,
    local_address: &str,
    local_port: u16,
    config: &RelayScanConfig<'_>,
    cache: &mut HashMap<String, PublisherInfo>,
) -> Option<DetectionEvent> {
    let target = resolve_target(pid, cache)?;
    let bind_scope = classify_bind(local_address);
    let (action, trust_tier) = evaluate_trust(&target, config);

    if action == RelayTrustAction::Suppress {
        return None;
    }

    let mut severity = match bind_scope {
        BindScope::AllInterfaces | BindScope::Other => "medium",
        BindScope::Localhost => "low",
    };
    if action == RelayTrustAction::Downgrade {
        severity = "low";
    }

    let mut confidence = "medium";
    let mut strong_shape = false;
    if bind_scope == BindScope::AllInterfaces
        && path_is_suspicious(&target.path, config.suspicious_path_prefixes)
        && !publisher_matches_trusted(
            target.publisher.publisher.as_deref(),
            config.trust_publishers,
        )
    {
        strong_shape = true;
        confidence = "strong";
        severity = "high";
    }

    let bind_label = match bind_scope {
        BindScope::Localhost => "localhost",
        BindScope::AllInterfaces => "all-interfaces",
        BindScope::Other => "other",
    };

    Some(DetectionEvent {
        id: new_id(
            "stealth_relay",
            &format!(
                "listener:{}:{}:{}:{}",
                pid,
                local_port,
                bind_label,
                normalize_path(&target.path)
            ),
        ),
        severity: severity.into(),
        category: "stealth_relay".into(),
        title: "Stealth relay listener during interview session".into(),
        detail: format!(
            "{0} listening on {1}:{2} ({3}, trust={4}, publisher={5})",
            target.name,
            local_address,
            local_port,
            bind_label,
            trust_tier,
            target
                .publisher
                .publisher
                .as_deref()
                .unwrap_or("unknown")
        ),
        process_name: Some(target.name.clone()),
        process_path: Some(target.path.clone()),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({
            "signal": "listener",
            "local_address": local_address,
            "local_port": local_port,
            "bind_scope": bind_label,
            "publisher": target.publisher.publisher,
            "signed": target.publisher.signed,
            "signature_valid": target.publisher.signature_valid,
            "trust_tier": trust_tier,
            "confidence": confidence,
            "strong_shape": strong_shape,
            "relay_pid": pid,
        }),
    })
}

fn inspect_intranet_peer(
    pid: u32,
    remote_ip: &str,
    config: &RelayScanConfig<'_>,
    cache: &mut HashMap<String, PublisherInfo>,
) -> Option<DetectionEvent> {
    let target = resolve_target(pid, cache)?;
    let (action, trust_tier) = evaluate_trust(&target, config);
    if action == RelayTrustAction::Suppress {
        return None;
    }

    let mut severity = "medium";
    if action == RelayTrustAction::Downgrade {
        severity = "low";
    }

    Some(DetectionEvent {
        id: new_id("stealth_relay", &format!("intranet:{pid}:{remote_ip}")),
        severity: severity.into(),
        category: "stealth_relay".into(),
        title: "Stealth relay intranet connection during interview session".into(),
        detail: format!(
            "{0} has an established TCP connection to nearby peer {1} (trust={2})",
            target.name, remote_ip, trust_tier
        ),
        process_name: Some(target.name.clone()),
        process_path: Some(target.path.clone()),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({
            "signal": "intranet",
            "remote_ip": remote_ip,
            "publisher": target.publisher.publisher,
            "signed": target.publisher.signed,
            "signature_valid": target.publisher.signature_valid,
            "trust_tier": trust_tier,
            "confidence": "medium",
            "relay_pid": pid,
        }),
    })
}

fn resolve_target(pid: u32, cache: &mut HashMap<String, PublisherInfo>) -> Option<RelayTarget> {
    let path = process_image_path(pid)?;
    let name = super::util::basename(&path);
    let publisher = cache
        .entry(normalize_path(&path))
        .or_insert_with(|| publisher_from_path(&path))
        .clone();
    Some(RelayTarget {
        name,
        path,
        publisher,
    })
}

fn evaluate_trust(
    target: &RelayTarget,
    config: &RelayScanConfig<'_>,
) -> (RelayTrustAction, &'static str) {
    // Cheat signature first: never suppress known threat needles.
    if path_matches_any(Some(&target.path), config.process_names)
        || path_matches_any(Some(&target.path), config.path_substrings)
    {
        return (RelayTrustAction::Flag, "cheat");
    }

    if is_companion_process(&target.name, &target.path, &target.publisher, config) {
        return (RelayTrustAction::Suppress, "companion");
    }

    if is_allowlisted(
        &target.name,
        Some(&target.path),
        config.allowlist,
        config.allowlist_path_substrings,
    ) {
        return (RelayTrustAction::Suppress, "trusted");
    }

    let trusted_pub = target.publisher.signature_valid
        && publisher_matches_trusted(
            target.publisher.publisher.as_deref(),
            config.trust_publishers,
        );
    let trusted_path = path_is_trusted(&target.path, config.trust_path_prefixes);
    let suspicious_path = path_is_suspicious(&target.path, config.suspicious_path_prefixes);
    let microsoft = target
        .publisher
        .publisher
        .as_deref()
        .map(|p| p.eq_ignore_ascii_case("Microsoft Corporation"))
        .unwrap_or(false);
    let user_data = normalize_path(&target.path).contains("\\appdata\\")
        || normalize_path(&target.path).contains("\\users\\");

    if microsoft && user_data && !trusted_path {
        return (RelayTrustAction::Downgrade, "unknown");
    }

    if is_tier2_consumer_process(target, config) {
        return (RelayTrustAction::Suppress, "tier2-consumer");
    }

    if trusted_pub && trusted_path && !suspicious_path {
        return (RelayTrustAction::Suppress, "trusted");
    }
    if trusted_pub && suspicious_path {
        return (RelayTrustAction::Downgrade, "unknown");
    }
    if suspicious_path {
        return (RelayTrustAction::Flag, "suspicious");
    }
    (RelayTrustAction::Flag, "unknown")
}

fn is_tier2_consumer_process(target: &RelayTarget, config: &RelayScanConfig<'_>) -> bool {
    if !target.publisher.signature_valid {
        return false;
    }
    let publisher = target.publisher.publisher.as_deref();
    if !publisher_matches_trusted(publisher, config.tier2_publishers) {
        return false;
    }

    config.process_rules.iter().any(|rule| {
        let mut parts = rule.splitn(3, '\t');
        let name = parts.next().unwrap_or_default();
        let publisher_rule = parts.next().unwrap_or_default();
        let path_prefix = parts.next().unwrap_or_default();
        process_name_equals(&target.name, name)
            && publisher_matches_trusted(publisher, &[publisher_rule.to_string()])
            && path_is_trusted(&target.path, &[path_prefix.to_string()])
    })
}

fn is_companion_process(
    name: &str,
    path: &str,
    publisher: &PublisherInfo,
    config: &RelayScanConfig<'_>,
) -> bool {
    if process_name_equals(name, "QuickShare.exe") {
        let pub_ok = publisher_matches_trusted(
            publisher.publisher.as_deref(),
            config.trust_publishers,
        ) || normalize_path(path).contains("\\program files\\windowsapps\\");
        let smartbar = normalize_path(path).contains("\\appdata\\local\\smartbar\\");
        return pub_ok && !smartbar;
    }

    config
        .companion_processes
        .iter()
        .any(|entry| process_name_equals(name, entry))
}

fn path_is_trusted(path: &str, prefixes: &[String]) -> bool {
    let p = normalize_path(path);
    prefixes
        .iter()
        .any(|prefix| p.contains(&normalize_path(prefix)))
}

fn path_is_suspicious(path: &str, prefixes: &[String]) -> bool {
    let p = normalize_path(path);
    prefixes
        .iter()
        .any(|prefix| p.contains(&normalize_path(prefix)))
}

pub fn classify_bind(address: &str) -> BindScope {
    let lower = address.trim().to_ascii_lowercase();
    if lower == "0.0.0.0"
        || lower == "::"
        || lower == "[::]"
        || lower == "0000:0000:0000:0000:0000:0000:0000:0000"
    {
        return BindScope::AllInterfaces;
    }
    if lower.starts_with("127.") || lower == "::1" || lower == "[::1]" {
        return BindScope::Localhost;
    }
    BindScope::Other
}

pub fn is_nearby_peer(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    let [a, b, _c, _d] = [parts[0], parts[1], parts[2], parts[3]];
    if a == 10 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    false
}

pub fn is_nearby_peer_v6(ip: &str) -> bool {
    let trimmed = ip.trim_matches(['[', ']']);
    if let Ok(addr) = trimmed.parse::<Ipv6Addr>() {
        if addr.is_loopback() {
            return false;
        }
        if let Some(v4) = addr.to_ipv4_mapped() {
            return is_nearby_peer(&v4.to_string());
        }
        if (addr.segments()[0] & 0xfe00) == 0xfc00 {
            return true;
        }
        if (addr.segments()[0] & 0xffc0) == 0xfe80 {
            return true;
        }
    }
    false
}

fn install_root_key(path: &str) -> String {
    let normalized = normalize_path(path);
    if normalized.is_empty() {
        return String::new();
    }
    normalized
        .rsplit_once('\\')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or(normalized)
}

fn apply_shape_upgrades(events: &mut [DetectionEvent]) {
    let listener_roots: HashSet<String> = events
        .iter()
        .filter(|e| e.metadata.get("signal").and_then(|v| v.as_str()) == Some("listener"))
        .filter_map(|e| e.process_path.as_deref().map(install_root_key))
        .filter(|k| !k.is_empty())
        .collect();
    let intranet_roots: HashSet<String> = events
        .iter()
        .filter(|e| e.metadata.get("signal").and_then(|v| v.as_str()) == Some("intranet"))
        .filter_map(|e| e.process_path.as_deref().map(install_root_key))
        .filter(|k| !k.is_empty())
        .collect();

    for event in events.iter_mut() {
        if event.category != "stealth_relay" {
            continue;
        }
        let Some(path) = event.process_path.as_deref() else {
            continue;
        };
        let root = install_root_key(path);
        if root.is_empty() {
            continue;
        }

        if listener_roots.contains(&root) && intranet_roots.contains(&root) {
            event.severity = "high".into();
            event.title = "Suspicious stealth relay correlated with intranet peer activity".into();
            if let Some(meta) = event.metadata.as_object_mut() {
                meta.insert("confidence".into(), json!("strong"));
            }
        } else if event
            .metadata
            .get("strong_shape")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            event.severity = "high".into();
            event.title = "Suspicious stealth relay shape during interview session".into();
        }
    }
}

fn format_ipv4(raw: u32) -> String {
    let addr = raw.to_be_bytes();
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

fn format_ipv6(raw: &[u8; 16]) -> String {
    let segments: Vec<String> = raw
        .chunks_exact(2)
        .map(|chunk| format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])))
        .collect();
    format!("[{}]", segments.join(":"))
}

fn network_port(raw: u32) -> u16 {
    ((raw & 0xFF) as u16) << 8 | ((raw >> 8) & 0xFF) as u16
}

fn tcp_listeners_v4() -> Vec<MIB_TCPROW_OWNER_PID> {
    tcp_table_v4(TCP_LISTEN)
}

fn tcp_established_v4() -> Vec<(u32, String)> {
    tcp_table_v4(TCP_ESTABLISHED)
        .into_iter()
        .filter_map(|row| {
            let ip = format_ipv4(row.dwRemoteAddr);
            if ip == "0.0.0.0" {
                None
            } else {
                Some((row.dwOwningPid, ip))
            }
        })
        .collect()
}

fn tcp_listeners_v6() -> Vec<MIB_TCP6ROW_OWNER_PID> {
    tcp_table_v6(TCP_LISTEN)
}

fn tcp_established_v6() -> Vec<(u32, String)> {
    tcp_table_v6(TCP_ESTABLISHED)
        .into_iter()
        .map(|row| (row.dwOwningPid, format_ipv6(&row.ucRemoteAddr)))
        .collect()
}

fn tcp_table_v4(state: u32) -> Vec<MIB_TCPROW_OWNER_PID> {
    let mut size = 0u32;
    let mut buffer = Vec::new();
    loop {
        unsafe {
            let status = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if status != NO_ERROR.0 && status != ERROR_INSUFFICIENT_BUFFER.0 {
                return Vec::new();
            }
        }
        if size == 0 {
            return Vec::new();
        }
        buffer.resize(size as usize, 0);
        unsafe {
            let status = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if status == NO_ERROR.0 {
                break;
            }
            if status != ERROR_INSUFFICIENT_BUFFER.0 {
                return Vec::new();
            }
        }
    }
    unsafe {
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
            .iter()
            .filter(|row| row.dwState == state)
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_scope_all_interfaces() {
        assert_eq!(classify_bind("0.0.0.0"), BindScope::AllInterfaces);
        assert_eq!(classify_bind("::"), BindScope::AllInterfaces);
    }

    #[test]
    fn bind_scope_localhost() {
        assert_eq!(classify_bind("127.0.0.1"), BindScope::Localhost);
        assert_eq!(classify_bind("::1"), BindScope::Localhost);
    }

    #[test]
    fn nearby_peer_rfc1918_and_cgnat() {
        assert!(is_nearby_peer("192.168.1.10"));
        assert!(is_nearby_peer("10.0.0.5"));
        assert!(is_nearby_peer("172.16.0.2"));
        assert!(is_nearby_peer("100.64.0.1"));
        assert!(!is_nearby_peer("8.8.8.8"));
    }

    #[test]
    fn tier2_consumer_spotify_suppresses_appdata_listener() {
        let allowlist = vec![];
        let allow_paths = vec![];
        let interview = vec![];
        let trust_publishers = vec!["Spotify AB".to_string()];
        let tier2 = vec!["Spotify AB".to_string()];
        let companion = vec![];
        let trust_paths = vec![r"\program files\".to_string()];
        let suspicious = vec![r"\appdata\roaming\".to_string()];
        let process_names = vec!["weatherttracker.exe".to_string()];
        let path_substrings = vec![r"\weathertracker\".to_string()];
        let rules = vec![format!(
            "{}\t{}\t{}",
            "Spotify.exe", "Spotify AB", r"\appdata\roaming\spotify\"
        )];
        let config = RelayScanConfig {
            allowlist: &allowlist,
            allowlist_path_substrings: &allow_paths,
            interview_processes: &interview,
            trust_publishers: &trust_publishers,
            tier2_publishers: &tier2,
            companion_processes: &companion,
            trust_path_prefixes: &trust_paths,
            suspicious_path_prefixes: &suspicious,
            process_names: &process_names,
            path_substrings: &path_substrings,
            process_rules: &rules,
        };
        let target = RelayTarget {
            name: "Spotify.exe".into(),
            path: r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe".into(),
            publisher: PublisherInfo {
                publisher: Some("Spotify AB".into()),
                signed: true,
                signature_valid: true,
            },
        };

        assert_eq!(
            evaluate_trust(&target, &config),
            (RelayTrustAction::Suppress, "tier2-consumer")
        );
    }

    #[test]
    fn fake_spotify_does_not_suppress() {
        let allowlist = vec![];
        let allow_paths = vec![];
        let interview = vec![];
        let trust_publishers = vec!["Spotify AB".to_string()];
        let tier2 = vec!["Spotify AB".to_string()];
        let companion = vec![];
        let trust_paths = vec![r"\program files\".to_string()];
        let suspicious = vec![r"\appdata\roaming\".to_string()];
        let process_names = vec![];
        let path_substrings = vec![];
        let rules = vec![format!(
            "{}\t{}\t{}",
            "Spotify.exe", "Spotify AB", r"\appdata\roaming\spotify\"
        )];
        let config = RelayScanConfig {
            allowlist: &allowlist,
            allowlist_path_substrings: &allow_paths,
            interview_processes: &interview,
            trust_publishers: &trust_publishers,
            tier2_publishers: &tier2,
            companion_processes: &companion,
            trust_path_prefixes: &trust_paths,
            suspicious_path_prefixes: &suspicious,
            process_names: &process_names,
            path_substrings: &path_substrings,
            process_rules: &rules,
        };
        let target = RelayTarget {
            name: "Spotifiy.exe".into(),
            path: r"C:\Users\me\AppData\Roaming\Spotify\Spotifiy.exe".into(),
            publisher: PublisherInfo {
                publisher: None,
                signed: false,
                signature_valid: false,
            },
        };

        assert_eq!(
            evaluate_trust(&target, &config),
            (RelayTrustAction::Flag, "suspicious")
        );
    }
}
