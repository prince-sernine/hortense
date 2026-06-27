use std::collections::HashMap;

use serde_json::json;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::event::{new_id, DetectionEvent};
use super::util::{
    is_allowlisted, normalize_token, path_matches_any, path_matches_needle, process_image_path,
    wide_to_string,
};

struct ProcRecord {
    pid: u32,
    parent_pid: u32,
    exe: String,
    path: Option<String>,
}

pub fn scan(
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> Vec<DetectionEvent> {
    let needles: Vec<String> = process_names.into_iter().map(|n| normalize_token(&n)).collect();
    let path_needles: Vec<String> = path_substrings
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let tree_roots: Vec<String> = process_tree_roots
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();

    let records = collect_processes();
    let mut flagged: HashMap<u32, String> = HashMap::new();

    for record in &records {
        if is_trusted(record, &allowlist, &allowlist_path_substrings) {
            continue;
        }
        if let Some(reason) = direct_match(record, &needles, &path_needles, &tree_roots) {
            flagged.insert(record.pid, reason);
        }
    }

    expand_process_tree(
        &records,
        &mut flagged,
        &allowlist,
        &allowlist_path_substrings,
        &tree_roots,
    );

    flagged
        .into_iter()
        .filter_map(|(pid, reason)| build_event(pid, &reason, &records))
        .collect()
}

fn collect_processes() -> Vec<ProcRecord> {
    let mut records = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return records,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                records.push(ProcRecord {
                    pid,
                    parent_pid: entry.th32ParentProcessID,
                    exe: wide_to_string(&entry.szExeFile),
                    path: process_image_path(pid),
                });
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    records
}

fn is_trusted(record: &ProcRecord, allowlist: &[String], allowlist_path_substrings: &[String]) -> bool {
    is_allowlisted(
        &record.exe,
        record.path.as_deref(),
        allowlist,
        allowlist_path_substrings,
    )
}

fn direct_match(
    record: &ProcRecord,
    needles: &[String],
    path_needles: &[String],
    tree_roots: &[String],
) -> Option<String> {
    let exe_l = normalize_token(&record.exe);

    if needles.iter().any(|n| exe_l.contains(n)) {
        return Some("process name signature".into());
    }

    if path_matches_any(record.path.as_deref(), path_needles) {
        return Some("install path signature".into());
    }

    if path_matches_any(record.path.as_deref(), tree_roots) {
        return Some("cheat install tree".into());
    }

    None
}

fn expand_process_tree(
    records: &[ProcRecord],
    flagged: &mut HashMap<u32, String>,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
    tree_roots: &[String],
) {
    loop {
        let mut added = false;
        for record in records {
            if flagged.contains_key(&record.pid) || is_trusted(record, allowlist, allowlist_path_substrings) {
                continue;
            }

            if flagged.contains_key(&record.parent_pid) {
                flagged.insert(record.pid, "cheat process tree".into());
                added = true;
                continue;
            }

            if shares_install_root(record, records, flagged, tree_roots) {
                flagged.insert(record.pid, "cheat install tree".into());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}

fn shares_install_root(
    record: &ProcRecord,
    records: &[ProcRecord],
    flagged: &HashMap<u32, String>,
    tree_roots: &[String],
) -> bool {
    let Some(path) = record.path.as_deref() else {
        return false;
    };

    tree_roots.iter().any(|root| {
        if !path_matches_needle(Some(path), root) {
            return false;
        }
        records.iter().any(|candidate| {
            flagged.contains_key(&candidate.pid)
                && path_matches_needle(candidate.path.as_deref(), root)
        })
    })
}

fn build_event(pid: u32, reason: &str, records: &[ProcRecord]) -> Option<DetectionEvent> {
    let record = records.iter().find(|r| r.pid == pid)?;
    Some(DetectionEvent {
        id: new_id("process", &format!("{pid}:{}", normalize_token(&record.exe))),
        severity: "high".into(),
        category: "process".into(),
        title: format!("Known interview-assist process ({reason})"),
        detail: format!("Running process matched community signature: {}", record.exe),
        process_name: Some(record.exe.clone()),
        process_path: record.path.clone(),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({ "match_reason": reason }),
    })
}
