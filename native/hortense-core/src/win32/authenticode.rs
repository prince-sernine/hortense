use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFreeCertificateContext, CertGetNameStringW, CryptQueryObject, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_CONTENT_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use super::util::normalize_token;

const CERT_NAME_ATTR_TYPE_VALUE: u32 = 3;
const COMMON_NAME_OID: &[u8] = b"2.5.4.3\0";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublisherInfo {
    pub publisher: Option<String>,
    pub signed: bool,
    pub signature_valid: bool,
}

pub fn publisher_from_path(path: &str) -> PublisherInfo {
    let wide: Vec<u16> = Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut info = PublisherInfo::default();
    let mut cert_store = HCERTSTORE::default();
    let mut cert_context: *const CERT_CONTEXT = std::ptr::null();
    let mut content_type = CERT_QUERY_CONTENT_TYPE::default();

    unsafe {
        let status = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            Some(&mut content_type),
            None,
            Some(&mut cert_store),
            None,
            Some(&mut cert_context as *mut _ as *mut *mut core::ffi::c_void),
        );

        if status.is_err() || cert_context.is_null() {
            return info;
        }

        info.signed = true;
        info.signature_valid = verify_authenticode(&wide);
        info.publisher = cert_subject_display(cert_context);

        let _ = CertFreeCertificateContext(Some(cert_context));
        if !cert_store.is_invalid() {
            let _ = CertCloseStore(cert_store, 0);
        }
    }

    info
}

unsafe fn verify_authenticode(wide_path: &[u16]) -> bool {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info as *mut _,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = WinVerifyTrust(
        HWND::default(),
        &mut action,
        &mut trust_data as *mut _ as *mut core::ffi::c_void,
    );
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(
        HWND::default(),
        &mut action,
        &mut trust_data as *mut _ as *mut core::ffi::c_void,
    );
    result == 0
}

unsafe fn cert_subject_display(cert_context: *const CERT_CONTEXT) -> Option<String> {
    cert_name(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, None).or_else(|| {
        cert_name(
            cert_context,
            CERT_NAME_ATTR_TYPE_VALUE,
            Some(COMMON_NAME_OID.as_ptr().cast()),
        )
    })
}

unsafe fn cert_name(
    cert_context: *const CERT_CONTEXT,
    name_type: u32,
    type_para: Option<*const core::ffi::c_void>,
) -> Option<String> {
    let mut buffer = vec![0u16; 512];
    let len = CertGetNameStringW(
        cert_context,
        name_type,
        0,
        type_para,
        Some(&mut buffer),
    );
    if len <= 1 {
        return None;
    }
    let subject = super::util::wide_to_string(&buffer[..len as usize - 1]);
    if subject.is_empty() {
        None
    } else {
        Some(subject)
    }
}

pub fn publisher_matches_trusted(publisher: Option<&str>, trust_publishers: &[String]) -> bool {
    let Some(publisher) = publisher else {
        return false;
    };
    let hay = normalize_token(publisher);
    trust_publishers
        .iter()
        .any(|entry| hay.contains(&normalize_token(entry)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_match_is_substring_and_case_insensitive() {
        let trusted = vec!["Zoom Video Communications, Inc.".into()];
        assert!(publisher_matches_trusted(
            Some("CN=Zoom Video Communications, Inc."),
            &trusted
        ));
        assert!(!publisher_matches_trusted(Some("Evil Corp"), &trusted));
    }
}
