use std::collections::{HashMap, HashSet};

use serde_json::json;
use windows::core::Interface;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Media::Audio::{
    eCapture, AudioSessionStateActive, IAudioSessionControl2, IAudioSessionManager2,
    IMMDeviceEnumerator, MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use super::util::{
    is_allowlisted, normalize_token, path_matches_any, process_image_path, wide_to_string,
};
use crate::event::{new_id, DetectionEvent};

#[derive(Clone, Debug)]
struct ProcRecord {
    pid: u32,
    parent_pid: u32,
    exe: String,
    path: Option<String>,
}

#[derive(Clone, Debug)]
struct Attribution {
    record: ProcRecord,
    reason: String,
}

#[derive(Clone, Debug)]
struct CaptureSession {
    pid: u32,
    endpoint_source: String,
}

pub fn scan(
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    _interview_processes: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> Vec<DetectionEvent> {
    let process_names: Vec<String> = process_names
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let path_substrings: Vec<String> = path_substrings
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let process_tree_roots: Vec<String> = process_tree_roots
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let records = collect_processes();
    let records_by_pid: HashMap<u32, ProcRecord> = records
        .iter()
        .map(|record| (record.pid, record.clone()))
        .collect();

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    match unsafe { active_capture_sessions() } {
        Ok(capturing) => capture_pids(&capturing)
            .into_iter()
            .filter_map(|pid| {
                inspect_capture_pid(
                    pid,
                    &records_by_pid,
                    &allowlist,
                    &allowlist_path_substrings,
                    &process_names,
                    &path_substrings,
                    &process_tree_roots,
                )
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

pub fn diagnostics(
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> Vec<serde_json::Value> {
    let process_names: Vec<String> = process_names
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let path_substrings: Vec<String> = path_substrings
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let process_tree_roots: Vec<String> = process_tree_roots
        .into_iter()
        .map(|n| normalize_token(&n))
        .collect();
    let records = collect_processes();
    let records_by_pid: HashMap<u32, ProcRecord> = records
        .iter()
        .map(|record| (record.pid, record.clone()))
        .collect();

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    let sessions = match unsafe { active_capture_sessions() } {
        Ok(sessions) => sessions,
        Err(err) => {
            return vec![json!({
                "error": format!("{err:?}"),
                "final_action": "enumeration_error",
            })]
        }
    };

    let mut sources_by_pid: HashMap<u32, Vec<String>> = HashMap::new();
    for session in sessions {
        sources_by_pid
            .entry(session.pid)
            .or_default()
            .push(session.endpoint_source);
    }
    let mut rows: Vec<serde_json::Value> = sources_by_pid
        .into_iter()
        .map(|(pid, endpoint_sources)| {
            diagnostic_for_pid(
                pid,
                endpoint_sources,
                &records_by_pid,
                &allowlist,
                &allowlist_path_substrings,
                &process_names,
                &path_substrings,
                &process_tree_roots,
            )
        })
        .collect();
    rows.sort_by_key(|row| row.get("pid").and_then(|pid| pid.as_u64()).unwrap_or(0));
    rows
}

unsafe fn active_capture_sessions() -> windows::core::Result<Vec<CaptureSession>> {
    let enumerator: IMMDeviceEnumerator = CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
    let endpoints = enumerator.EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)?;
    let endpoint_count = endpoints.GetCount()?;
    let mut sessions = Vec::new();

    for endpoint_index in 0..endpoint_count {
        let device = endpoints.Item(endpoint_index)?;
        if device.GetState()? != DEVICE_STATE_ACTIVE {
            continue;
        }
        let endpoint_source = format!("capture_endpoint:{endpoint_index}");
        let session_manager = device.Activate::<IAudioSessionManager2>(CLSCTX_ALL, None)?;
        let session_enumerator = session_manager.GetSessionEnumerator()?;
        let session_count = session_enumerator.GetCount()?;

        for session_index in 0..session_count {
            let control = session_enumerator.GetSession(session_index)?;
            if control.GetState()? != AudioSessionStateActive {
                continue;
            }
            let control2: IAudioSessionControl2 = control.cast()?;
            let pid = control2.GetProcessId()?;
            if pid != 0 {
                sessions.push(CaptureSession {
                    pid,
                    endpoint_source: endpoint_source.clone(),
                });
            }
        }
    }

    Ok(sessions)
}

fn capture_pids(sessions: &[CaptureSession]) -> Vec<u32> {
    let mut pids: Vec<u32> = sessions
        .iter()
        .map(|session| session.pid)
        .collect::<HashSet<u32>>()
        .into_iter()
        .collect();
    pids.sort_unstable();
    pids
}

fn inspect_capture_pid(
    pid: u32,
    records_by_pid: &HashMap<u32, ProcRecord>,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
    process_names: &[String],
    path_substrings: &[String],
    process_tree_roots: &[String],
) -> Option<DetectionEvent> {
    let record = records_by_pid.get(&pid).cloned().or_else(|| {
        let path = process_image_path(pid)?;
        Some(ProcRecord {
            pid,
            parent_pid: 0,
            exe: super::util::basename(&path),
            path: Some(path),
        })
    })?;

    let attribution = suspicious_attribution(
        record.pid,
        records_by_pid,
        process_names,
        path_substrings,
        process_tree_roots,
    );

    if is_allowlisted(
        &record.exe,
        record.path.as_deref(),
        allowlist,
        allowlist_path_substrings,
    ) && attribution.is_none()
    {
        return None;
    }

    if let Some(attribution) = attribution {
        return Some(build_attributed_event(&record, &attribution));
    }

    Some(DetectionEvent {
        id: new_id("microphone", &pid.to_string()),
        severity: "medium".into(),
        category: "microphone".into(),
        title: "Unattributed microphone capture by non-allowlisted process".into(),
        detail: format!(
            "Non-allowlisted process holds an active audio capture session: {}",
            record.exe
        ),
        process_name: Some(record.exe.clone()),
        process_path: record.path.clone(),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({
            "session_state": "active",
            "audio_owner_pid": record.pid,
            "audio_owner_process_name": record.exe,
            "confidence": "heuristic"
        }),
    })
}

fn diagnostic_for_pid(
    pid: u32,
    endpoint_sources: Vec<String>,
    records_by_pid: &HashMap<u32, ProcRecord>,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
    process_names: &[String],
    path_substrings: &[String],
    process_tree_roots: &[String],
) -> serde_json::Value {
    let record = records_by_pid.get(&pid).cloned().or_else(|| {
        let path = process_image_path(pid)?;
        Some(ProcRecord {
            pid,
            parent_pid: 0,
            exe: super::util::basename(&path),
            path: Some(path),
        })
    });
    let Some(record) = record else {
        return json!({
            "pid": pid,
            "endpoint_sources": endpoint_sources,
            "final_action": "missing_process",
        });
    };

    let attribution = suspicious_attribution(
        record.pid,
        records_by_pid,
        process_names,
        path_substrings,
        process_tree_roots,
    );
    let allowlisted = is_allowlisted(
        &record.exe,
        record.path.as_deref(),
        allowlist,
        allowlist_path_substrings,
    );
    let final_action = if attribution.is_some() {
        "attributed"
    } else if allowlisted {
        "suppressed_allowlisted"
    } else {
        "emitted"
    };
    let attributed = attribution.as_ref().map(|item| &item.record);

    json!({
        "pid": pid,
        "endpoint_sources": endpoint_sources,
        "process_name": record.exe,
        "process_path": record.path,
        "allowlisted": allowlisted,
        "attribution_reason": attribution.as_ref().map(|item| item.reason.clone()),
        "attributed_pid": attributed.map(|item| item.pid),
        "attributed_process_name": attributed.map(|item| item.exe.clone()),
        "attributed_process_path": attributed.and_then(|item| item.path.clone()),
        "final_action": final_action,
    })
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

fn suspicious_attribution(
    pid: u32,
    records_by_pid: &HashMap<u32, ProcRecord>,
    process_names: &[String],
    path_substrings: &[String],
    process_tree_roots: &[String],
) -> Option<Attribution> {
    let mut current_pid = Some(pid);
    let mut seen = HashSet::new();
    let mut depth = 0;

    while let Some(candidate_pid) = current_pid {
        if depth > 32 || !seen.insert(candidate_pid) {
            break;
        }
        depth += 1;

        let record = records_by_pid.get(&candidate_pid)?;
        if let Some(reason) =
            suspicious_match(record, process_names, path_substrings, process_tree_roots)
        {
            return Some(Attribution {
                record: record.clone(),
                reason,
            });
        }

        current_pid = if record.parent_pid == 0 {
            None
        } else {
            Some(record.parent_pid)
        };
    }

    None
}

fn suspicious_match(
    record: &ProcRecord,
    process_names: &[String],
    path_substrings: &[String],
    process_tree_roots: &[String],
) -> Option<String> {
    let exe_l = normalize_token(&record.exe);

    if process_names.iter().any(|needle| exe_l.contains(needle)) {
        return Some("process name signature".into());
    }

    if path_matches_any(record.path.as_deref(), path_substrings) {
        return Some("install path signature".into());
    }

    if path_matches_any(record.path.as_deref(), process_tree_roots) {
        return Some("process tree signature".into());
    }

    None
}

fn build_attributed_event(audio_owner: &ProcRecord, attribution: &Attribution) -> DetectionEvent {
    let attributed = &attribution.record;
    let confidence = if audio_owner.pid == attributed.pid {
        "medium"
    } else {
        "medium"
    };
    let detail = if audio_owner.pid == attributed.pid {
        format!(
            "Suspicious process holds an active audio capture session: {}",
            audio_owner.exe
        )
    } else {
        format!(
            "Audio capture is owned by {}, but its process tree points to {}.",
            audio_owner.exe, attributed.exe
        )
    };

    DetectionEvent {
        id: new_id(
            "microphone",
            &format!("{}:{}", audio_owner.pid, attributed.pid),
        ),
        severity: "medium".into(),
        category: "microphone".into(),
        title: "Microphone capture attributed to suspicious host".into(),
        detail,
        process_name: Some(attributed.exe.clone()),
        process_path: attributed.path.clone(),
        pid: Some(audio_owner.pid),
        hwnd: None,
        window_title: None,
        metadata: json!({
            "session_state": "active",
            "audio_owner_pid": audio_owner.pid,
            "audio_owner_process_name": audio_owner.exe,
            "audio_owner_process_path": audio_owner.path,
            "attributed_pid": attributed.pid,
            "attributed_process_name": attributed.exe,
            "attributed_process_path": attributed.path,
            "attribution_reason": attribution.reason,
            "confidence": confidence
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32, parent_pid: u32, exe: &str, path: &str) -> ProcRecord {
        ProcRecord {
            pid,
            parent_pid,
            exe: exe.into(),
            path: Some(path.into()),
        }
    }

    fn by_pid(records: Vec<ProcRecord>) -> HashMap<u32, ProcRecord> {
        records
            .into_iter()
            .map(|record| (record.pid, record))
            .collect()
    }

    #[test]
    fn attributes_webview_audio_to_suspicious_parent() {
        let records = by_pid(vec![
            record(
                10,
                0,
                "Lynccontainer.exe",
                r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            ),
            record(
                20,
                10,
                "msedgewebview2.exe",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
            ),
            record(
                30,
                20,
                "msedgewebview2.exe",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
            ),
        ]);

        let attribution = suspicious_attribution(30, &records, &["lynccontainer".into()], &[], &[])
            .expect("webview audio should trace back to LinkJobAI host");

        assert_eq!(attribution.record.pid, 10);
        assert_eq!(attribution.reason, "process name signature");
    }

    #[test]
    fn keeps_separate_webview_trees_apart() {
        let records = by_pid(vec![
            record(
                10,
                0,
                "Lynccontainer.exe",
                r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            ),
            record(
                20,
                10,
                "msedgewebview2.exe",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
            ),
            record(
                30,
                0,
                "WhatsApp.Root.exe",
                r"C:\Program Files\WindowsApps\WhatsApp.Root.exe",
            ),
            record(
                40,
                30,
                "msedgewebview2.exe",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
            ),
        ]);

        let attribution = suspicious_attribution(40, &records, &["lynccontainer".into()], &[], &[]);

        assert!(attribution.is_none());
    }

    #[test]
    fn capture_pids_dedupes_across_endpoints() {
        let pids = capture_pids(&[
            CaptureSession {
                pid: 40,
                endpoint_source: "capture_endpoint:0".into(),
            },
            CaptureSession {
                pid: 10,
                endpoint_source: "capture_endpoint:0".into(),
            },
            CaptureSession {
                pid: 40,
                endpoint_source: "capture_endpoint:1".into(),
            },
        ]);

        assert_eq!(pids, vec![10, 40]);
    }

    #[test]
    fn diagnostic_marks_allowlisted_capture_as_suppressed() {
        let records = by_pid(vec![record(
            10,
            0,
            "Zoom.exe",
            r"C:\Users\me\AppData\Roaming\Zoom\bin\Zoom.exe",
        )]);

        let row = diagnostic_for_pid(
            10,
            vec!["capture_endpoint:0".into()],
            &records,
            &["zoom.exe".into()],
            &[],
            &["lynccontainer".into()],
            &[],
            &[],
        );

        assert_eq!(row["final_action"], "suppressed_allowlisted");
        assert_eq!(row["allowlisted"], true);
    }

    #[test]
    fn diagnostic_marks_helper_capture_as_attributed() {
        let records = by_pid(vec![
            record(
                10,
                0,
                "Lynccontainer.exe",
                r"C:\Users\me\AppData\Local\Lynccontainer\Lynccontainer.exe",
            ),
            record(
                20,
                10,
                "msedgewebview2.exe",
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
            ),
        ]);

        let row = diagnostic_for_pid(
            20,
            vec!["capture_endpoint:1".into()],
            &records,
            &["msedgewebview2.exe".into()],
            &[],
            &["lynccontainer".into()],
            &[],
            &[],
        );

        assert_eq!(row["final_action"], "attributed");
        assert_eq!(row["attributed_pid"], 10);
        assert_eq!(row["attribution_reason"], "process name signature");
    }
}
