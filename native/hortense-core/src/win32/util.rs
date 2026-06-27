use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn wide_to_string(raw: &[u16]) -> String {
    let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    OsString::from_wide(&raw[..len])
        .to_string_lossy()
        .into_owned()
}

pub fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let path = image_path_from_handle(handle);
        let _ = CloseHandle(handle);
        path
    }
}

fn image_path_from_handle(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize];
    let mut size = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .ok()?;
    }
    Some(wide_to_string(&buffer[..size as usize]))
}

pub fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn normalize_path(path: &str) -> String {
    normalize_token(&path.replace('/', "\\"))
}

/// Exact executable name match (e.g. interview_processes, allowlist names).
pub fn process_name_equals(name: &str, target: &str) -> bool {
    normalize_token(name) == normalize_token(target)
}

pub fn is_allowlisted(
    name: &str,
    path: Option<&str>,
    allowlist: &[String],
    allowlist_path_substrings: &[String],
) -> bool {
    let name_l = normalize_token(name);
    let path_l = path.map(normalize_path);

    if allowlist.iter().any(|entry| {
        let e = normalize_token(entry);
        name_l == e || name_l.ends_with(&format!("\\{e}"))
    }) {
        return true;
    }

    if let Some(p) = path_l.as_ref() {
        if allowlist.iter().any(|entry| {
            let e = normalize_token(entry);
            p.ends_with(&format!("\\{e}")) || p.ends_with(&e)
        }) {
            return true;
        }

        if allowlist_path_substrings
            .iter()
            .any(|entry| p.contains(&normalize_path(entry)))
        {
            return true;
        }
    }

    false
}

/// Phrase needles (spaces) use substring match; single tokens use path segment boundaries.
pub fn path_matches_needle(path: Option<&str>, needle: &str) -> bool {
    let Some(path) = path else {
        return false;
    };
    let n = normalize_token(needle);
    if n.is_empty() {
        return false;
    }
    if n.contains(' ') {
        return normalize_path(path).contains(&n);
    }
    path_contains_segment(path, needle)
}

pub fn path_contains_segment(path: &str, needle: &str) -> bool {
    let p = normalize_path(path);
    let n = normalize_token(needle);
    if n.is_empty() {
        return false;
    }

    if p.split('\\').any(|segment| {
        segment == n
            || segment.starts_with(&format!("{n}-"))
            || segment.starts_with(&format!("{n}."))
    }) {
        return true;
    }

    p.contains(&format!("\\{n}\\"))
        || p.ends_with(&format!("\\{n}"))
        || p.ends_with(&format!("\\{n}-"))
}

pub fn path_matches_any(path: Option<&str>, needles: &[String]) -> bool {
    needles
        .iter()
        .any(|needle| path_matches_needle(path, needle))
}

pub fn basename(path: &str) -> String {
    PathBuf::from(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_match_install_root() {
        let path = r"C:\Users\me\AppData\Local\Programs\cluely-v2\Cluely.exe";
        assert!(path_contains_segment(path, "cluely-v2"));
        assert!(path_contains_segment(path, "cluely"));
    }

    #[test]
    fn segment_rejects_accidental_substring() {
        let path = r"C:\Users\me\Documents\my-cluely-notes\readme.txt";
        assert!(!path_contains_segment(path, "cluely"));
    }

    #[test]
    fn phrase_needle_uses_substring() {
        let path = r"C:\Tools\interview assist\helper.exe";
        assert!(path_matches_needle(
            Some(path),
            "interview assist"
        ));
    }

    #[test]
    fn interview_process_exact_match_only() {
        assert!(process_name_equals("chrome.exe", "chrome.exe"));
        assert!(!process_name_equals("maliciouschrome.exe", "chrome.exe"));
        assert!(!process_name_equals("fakezoom.exe", "zoom.exe"));
    }
}
