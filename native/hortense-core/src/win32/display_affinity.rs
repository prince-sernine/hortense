use std::cell::RefCell;

use serde_json::json;
use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowDisplayAffinity, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
};

use crate::event::{new_id, DetectionEvent};
use super::util::{is_allowlisted, process_image_path, wide_to_string};

const WDA_NONE: u32 = 0;

struct ScanContext {
    events: RefCell<Vec<DetectionEvent>>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
}

pub fn scan(allowlist: Vec<String>, allowlist_path_substrings: Vec<String>) -> Vec<DetectionEvent> {
    let ctx = ScanContext {
        events: RefCell::new(Vec::new()),
        allowlist,
        allowlist_path_substrings,
    };
    unsafe {
        let _ = EnumWindows(Some(enum_window), LPARAM(&ctx as *const _ as isize));
    }
    ctx.events.into_inner()
}

unsafe extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx = &*(lparam.0 as *const ScanContext);
    if let Some(event) = inspect_window(hwnd, &ctx.allowlist, &ctx.allowlist_path_substrings) {
        ctx.events.borrow_mut().push(event);
    }
    TRUE
}

fn inspect_window(
    hwnd: HWND,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
) -> Option<DetectionEvent> {
    if !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return None;
    }

    let mut affinity: u32 = 0;
    unsafe {
        if GetWindowDisplayAffinity(hwnd, &mut affinity).is_err() {
            return None;
        }
    }

    if affinity == WDA_NONE {
        return None;
    }

    let label = match affinity {
        v if v == WDA_EXCLUDEFROMCAPTURE.0 => "WDA_EXCLUDEFROMCAPTURE",
        v if v == WDA_MONITOR.0 => "WDA_MONITOR",
        _ => "WDA_UNKNOWN",
    };

    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }

    let process_path = process_image_path(pid);
    let process_name = process_path.as_ref().map(|p| super::util::basename(p));

    if process_name.as_ref().is_some_and(|name| {
        is_allowlisted(
            name,
            process_path.as_deref(),
            allowlist,
            allowlist_path_substrings,
        )
    }) {
        return None;
    }

    let title = window_title(hwnd);

    let severity = if affinity == WDA_EXCLUDEFROMCAPTURE.0 {
        "high"
    } else {
        "medium"
    };

    Some(DetectionEvent {
        id: new_id("display_affinity", &format!("{hwnd:?}:{pid}")),
        severity: severity.into(),
        category: "display_affinity".into(),
        title: format!("Window excluded from screen capture ({label})"),
        detail: format!(
            "A visible top-level window uses display affinity {label}. \
             Content may be invisible to Zoom/Teams screen share."
        ),
        process_name,
        process_path,
        pid: Some(pid),
        hwnd: Some(hwnd.0 as isize),
        window_title: title,
        metadata: json!({ "affinity": label, "affinity_raw": affinity }),
    })
}

fn window_title(hwnd: HWND) -> Option<String> {
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let read = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if read == 0 {
        return None;
    }
    Some(wide_to_string(&buf[..read as usize]))
}
