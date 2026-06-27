use std::collections::HashSet;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use super::util::{normalize_token, process_name_equals, wide_to_string};

pub fn session_active(interview_processes: &[String]) -> bool {
    if interview_processes.is_empty() {
        return false;
    }

    let targets: HashSet<String> = interview_processes
        .iter()
        .map(|p| normalize_token(p))
        .collect();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut active = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe = wide_to_string(&entry.szExeFile);
                if targets
                    .iter()
                    .any(|target| process_name_equals(&exe, target))
                {
                    active = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        active
    }
}
