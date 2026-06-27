use std::collections::HashSet;

use serde_json::json;
use windows::core::Interface;
use windows::Win32::Media::Audio::{
    eCapture, eConsole, AudioSessionStateActive, IAudioSessionControl2, IMMDeviceEnumerator,
    MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED};

use crate::event::{new_id, DetectionEvent};
use super::interview::session_active;
use super::util::{is_allowlisted, process_image_path};

pub fn scan(
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
) -> Vec<DetectionEvent> {
    if !session_active(&interview_processes) {
        return Vec::new();
    }

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    match unsafe { active_capture_pids() } {
        Ok(capturing) => capturing
            .into_iter()
            .filter_map(|pid| inspect_capture_pid(pid, &allowlist, &allowlist_path_substrings))
            .collect(),
        Err(_) => Vec::new(),
    }
}

unsafe fn active_capture_pids() -> windows::core::Result<HashSet<u32>> {
    let enumerator: IMMDeviceEnumerator =
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
    let device = enumerator.GetDefaultAudioEndpoint(eCapture, eConsole)?;
    if device.GetState()? != DEVICE_STATE_ACTIVE {
        return Ok(HashSet::new());
    }

    let session_manager = device.Activate::<windows::Win32::Media::Audio::IAudioSessionManager2>(
        CLSCTX_ALL,
        None,
    )?;

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
        id: new_id("microphone", &pid.to_string()),
        severity: "medium".into(),
        category: "microphone".into(),
        title: "Active microphone capture during interview app session".into(),
        detail: format!("Process holds an active audio capture session: {name}"),
        process_name: Some(name),
        process_path: Some(path),
        pid: Some(pid),
        hwnd: None,
        window_title: None,
        metadata: json!({ "session_state": "active" }),
    })
}
