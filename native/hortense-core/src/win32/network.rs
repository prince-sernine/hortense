use std::collections::HashSet;
use std::net::ToSocketAddrs;

use serde_json::json;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};

use crate::event::{new_id, DetectionEvent};
use super::interview::session_active;
use super::util::{is_allowlisted, process_image_path};

const AF_INET: u32 = 2;
const TCP_ESTABLISHED: u32 = 5;

pub fn scan(
    domains: Vec<String>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
) -> Vec<DetectionEvent> {
    if !session_active(&interview_processes) {
        return Vec::new();
    }

    let target_ips = resolve_domains(&domains);
    if target_ips.is_empty() {
        return Vec::new();
    }

    let connections = tcp_connections();
    let mut events = Vec::new();
    let mut seen = HashSet::new();

    for (pid, remote_ip) in connections {
        if !target_ips.contains(&remote_ip) {
            continue;
        }
        let key = format!("{pid}:{remote_ip}");
        if !seen.insert(key) {
            continue;
        }
        if let Some(event) =
            inspect_connection(pid, &remote_ip, &allowlist, &allowlist_path_substrings)
        {
            events.push(event);
        }
    }

    events
}

fn resolve_domains(domains: &[String]) -> HashSet<String> {
    let mut ips = HashSet::new();
    for domain in domains {
        let target = format!("{}:443", domain.trim());
        if let Ok(addrs) = target.to_socket_addrs() {
            for addr in addrs {
                ips.insert(addr.ip().to_string());
            }
        }
    }
    ips
}

fn tcp_connections() -> Vec<(u32, String)> {
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
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        rows.iter()
            .filter_map(|row| remote_endpoint(row).map(|ip| (row.dwOwningPid, ip)))
            .collect()
    }
}

unsafe fn remote_endpoint(row: &MIB_TCPROW_OWNER_PID) -> Option<String> {
    if row.dwState != TCP_ESTABLISHED {
        return None;
    }
    let addr = row.dwRemoteAddr.to_be_bytes();
    if addr == [0, 0, 0, 0] {
        return None;
    }
    Some(format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]))
}

fn inspect_connection(
    pid: u32,
    remote_ip: &str,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
) -> Option<DetectionEvent> {
    let path = process_image_path(pid)?;
    let name = super::util::basename(&path);
    if is_allowlisted(
        &name,
        Some(&path),
        allowlist,
        allowlist_path_substrings,
    ) {
        return None;
    }

    Some(DetectionEvent {
        id: new_id("network", &format!("{pid}:{remote_ip}")),
        severity: "medium".into(),
        category: "network".into(),
        title: "Outbound connection to known AI API host".into(),
        detail: format!("{name} connected to {remote_ip} while interview software is running."),
        process_name: Some(name),
        process_path: Some(path),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({ "remote_ip": remote_ip }),
    })
}
