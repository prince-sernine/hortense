use std::collections::{HashMap, HashSet};

use serde_json::json;
use windows::core::Interface;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Media::Audio::{
    eCapture, eConsole, AudioSessionStateActive, IAudioSessionControl2, IMMDeviceEnumerator,
    MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use super::interview::session_active;
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

pub fn scan(
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> Vec<DetectionEvent> {
    if !session_active(&interview_processes) {
        return Vec::new();
    }

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

    match unsafe { active_capture_pids() } {
        Ok(capturing) => capturing
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

unsafe fn active_capture_pids() -> windows::core::Result<HashSet<u32>> {
    let enumerator: IMMDeviceEnumerator = CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
    let device = enumerator.GetDefaultAudioEndpoint(eCapture, eConsole)?;
    if device.GetState()? != DEVICE_STATE_ACTIVE {
        return Ok(HashSet::new());
    }

    let session_manager =
        device.Activate::<windows::Win32::Media::Audio::IAudioSessionManager2>(CLSCTX_ALL, None)?;

    let enumerator = session_manager.GetSessionEnumerator()?;
    let count = enumerator.GetCount()?;
    let mut pids = HashSet::new();

    for index in 0..count {
        let control = enumerator.GetSession(index)?;
        if control.GetState()? != AudioSessionStateActive {
            continue;
        }
        let control2: IAudioSessionControl2 = control.cast()?;
        let pid = control2.GetProcessId()?;
        if pid != 0 {
            pids.insert(pid);
        }
    }

    Ok(pids)
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
        title: "Unattributed microphone capture during interview session".into(),
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
}
