use std::cell::RefCell;

use serde_json::json;
use windows::Win32::Foundation::{BOOL, HWND, LPARAM, RECT, TRUE};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowLongPtrW, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, SM_CYVIRTUALSCREEN, SM_CXVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, SM_XVIRTUALSCREEN, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_EX_TRANSPARENT,
};

use crate::event::{new_id, DetectionEvent};
use super::util::{is_allowlisted, process_image_path, wide_to_string};

struct ScanContext {
    events: RefCell<Vec<DetectionEvent>>,
    virtual_x: i32,
    virtual_y: i32,
    virtual_w: i32,
    virtual_h: i32,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
}

pub fn scan(allowlist: Vec<String>, allowlist_path_substrings: Vec<String>) -> Vec<DetectionEvent> {
    let (virtual_x, virtual_y, virtual_w, virtual_h) = virtual_screen_bounds();
    let ctx = ScanContext {
        events: RefCell::new(Vec::new()),
        virtual_x,
        virtual_y,
        virtual_w,
        virtual_h,
        allowlist,
        allowlist_path_substrings,
    };
    unsafe {
        let _ = EnumWindows(Some(enum_window), LPARAM(&ctx as *const _ as isize));
    }
    ctx.events.into_inner()
}

fn virtual_screen_bounds() -> (i32, i32, i32, i32) {
    unsafe {
        let x = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(SM_YVIRTUALSCREEN);
        let w = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let h = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(SM_CYVIRTUALSCREEN);
        (x, y, w.max(1), h.max(1))
    }
}

unsafe extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx = &*(lparam.0 as *const ScanContext);
    if let Some(event) = inspect_overlay(
        hwnd,
        ctx.virtual_x,
        ctx.virtual_y,
        ctx.virtual_w,
        ctx.virtual_h,
        &ctx.allowlist,
        &ctx.allowlist_path_substrings,
    ) {
        ctx.events.borrow_mut().push(event);
    }
    TRUE
}

fn inspect_overlay(
    hwnd: HWND,
    virtual_x: i32,
    virtual_y: i32,
    virtual_w: i32,
    virtual_h: i32,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
) -> Option<DetectionEvent> {
    if !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return None;
    }

    let ex_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 };
    let layered = ex_style & WS_EX_LAYERED.0 != 0;
    let topmost = ex_style & WS_EX_TOPMOST.0 != 0;
    let transparent = ex_style & WS_EX_TRANSPARENT.0 != 0;
    let no_activate = ex_style & WS_EX_NOACTIVATE.0 != 0;
    let tool_window = ex_style & WS_EX_TOOLWINDOW.0 != 0;

    let mut score = 0u8;
    if layered {
        score += 2;
    }
    if topmost {
        score += 2;
    }
    if transparent {
        score += 2;
    }
    if no_activate {
        score += 1;
    }
    if tool_window {
        score += 1;
    }

    let mut rect = RECT::default();
    if unsafe { GetWindowRect(hwnd, &mut rect).is_err() } {
        return None;
    }

    let width = (rect.right - rect.left).max(0);
    let height = (rect.bottom - rect.top).max(0);
    if width == 0 || height == 0 {
        return None;
    }

    let visible_area = clipped_area(&rect, virtual_x, virtual_y, virtual_w, virtual_h);
    if visible_area == 0 {
        return None;
    }

    let coverage =
        visible_area as f64 / (virtual_w as f64 * virtual_h as f64);
    if coverage > 0.15 {
        score += 2;
    } else if coverage > 0.05 {
        score += 1;
    }

    // Need layered + (topmost or transparent) and some coverage signal.
    if score < 5 || !layered || !(topmost || transparent) {
        return None;
    }

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

    let severity = if score >= 7 && coverage > 0.1 {
        "high"
    } else {
        "medium"
    };

    Some(DetectionEvent {
        id: new_id("overlay", &format!("{hwnd:?}:{pid}")),
        severity: severity.into(),
        category: "overlay".into(),
        title: "Suspicious overlay-style window".into(),
        detail: "Layered, topmost/click-through window covering meaningful screen area.".into(),
        process_name,
        process_path,
        pid: Some(pid),
        hwnd: Some(hwnd.0 as isize),
        window_title: title,
        metadata: json!({
            "score": score,
            "coverage": coverage,
            "ex_style": format!("0x{ex_style:X}"),
            "layered": layered,
            "topmost": topmost,
            "transparent": transparent,
        }),
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

fn clipped_area(rect: &RECT, virtual_x: i32, virtual_y: i32, virtual_w: i32, virtual_h: i32) -> i64 {
    let left = rect.left.max(virtual_x);
    let top = rect.top.max(virtual_y);
    let right = rect.right.min(virtual_x + virtual_w);
    let bottom = rect.bottom.min(virtual_y + virtual_h);
    let width = (right - left).max(0) as i64;
    let height = (bottom - top).max(0) as i64;
    width * height
}
