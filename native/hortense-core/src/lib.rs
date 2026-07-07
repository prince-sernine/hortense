mod event;
mod win32;

use pyo3::prelude::*;

use event::DetectionEvent;

fn events_to_py(py: Python<'_>, events: Vec<DetectionEvent>) -> PyResult<Vec<Py<PyAny>>> {
    events
        .into_iter()
        .map(|e| e.into_py_dict(py).map(|d| d.into()))
        .collect()
}

#[pyfunction]
fn platform() -> &'static str {
    "win32"
}

#[pyfunction]
#[pyo3(signature = (allowlist=None, allowlist_path_substrings=None))]
fn scan_display_affinity(
    py: Python<'_>,
    allowlist: Option<Vec<String>>,
    allowlist_path_substrings: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
    let events = win32::display_affinity::scan(
        allowlist.unwrap_or_default(),
        allowlist_path_substrings.unwrap_or_default(),
    );
    events_to_py(py, events)
}

#[pyfunction]
#[pyo3(signature = (allowlist=None, allowlist_path_substrings=None))]
fn scan_overlays(
    py: Python<'_>,
    allowlist: Option<Vec<String>>,
    allowlist_path_substrings: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
    let events = win32::overlay::scan(
        allowlist.unwrap_or_default(),
        allowlist_path_substrings.unwrap_or_default(),
    );
    events_to_py(py, events)
}

#[pyfunction]
#[pyo3(signature = (process_names, path_substrings, allowlist, allowlist_path_substrings=None, process_tree_roots=None))]
fn scan_processes(
    py: Python<'_>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Option<Vec<String>>,
    process_tree_roots: Option<Vec<String>>,
) -> PyResult<Vec<Py<PyAny>>> {
    let events = win32::process::scan(
        process_names,
        path_substrings,
        allowlist,
        allowlist_path_substrings.unwrap_or_default(),
        process_tree_roots.unwrap_or_default(),
    );
    events_to_py(py, events)
}

#[pyfunction]
#[pyo3(signature = (allowlist, allowlist_path_substrings, interview_processes, process_names, path_substrings, process_tree_roots))]
fn scan_microphone_sessions(
    py: Python<'_>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> PyResult<Vec<Py<PyAny>>> {
    let events = win32::microphone::scan(
        allowlist,
        allowlist_path_substrings,
        interview_processes,
        process_names,
        path_substrings,
        process_tree_roots,
    );
    events_to_py(py, events)
}

#[pyfunction]
#[pyo3(signature = (allowlist, allowlist_path_substrings, process_names, path_substrings, process_tree_roots))]
fn microphone_diagnostics(
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_tree_roots: Vec<String>,
) -> PyResult<Vec<String>> {
    Ok(win32::microphone::diagnostics(
        allowlist,
        allowlist_path_substrings,
        process_names,
        path_substrings,
        process_tree_roots,
    )
    .into_iter()
    .map(|row| row.to_string())
    .collect())
}

#[pyfunction]
#[pyo3(signature = (domains, allowlist, allowlist_path_substrings, interview_processes))]
fn scan_network(
    py: Python<'_>,
    domains: Vec<String>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
) -> PyResult<Vec<Py<PyAny>>> {
    let events = win32::network::scan(
        domains,
        allowlist,
        allowlist_path_substrings,
        interview_processes,
    );
    events_to_py(py, events)
}

#[pyfunction]
fn interview_session_active(interview_processes: Vec<String>) -> bool {
    win32::interview::session_active(&interview_processes)
}

#[pyfunction]
#[pyo3(signature = (
    allowlist,
    allowlist_path_substrings,
    interview_processes,
    trust_publishers,
    tier2_publishers,
    companion_processes,
    trust_path_prefixes,
    suspicious_path_prefixes,
    process_names,
    path_substrings,
    process_rules,
))]
fn scan_stealth_relays(
    py: Python<'_>,
    allowlist: Vec<String>,
    allowlist_path_substrings: Vec<String>,
    interview_processes: Vec<String>,
    trust_publishers: Vec<String>,
    tier2_publishers: Vec<String>,
    companion_processes: Vec<String>,
    trust_path_prefixes: Vec<String>,
    suspicious_path_prefixes: Vec<String>,
    process_names: Vec<String>,
    path_substrings: Vec<String>,
    process_rules: Vec<String>,
) -> PyResult<Vec<Py<PyAny>>> {
    let config = win32::relay::RelayScanConfig {
        allowlist: &allowlist,
        allowlist_path_substrings: &allowlist_path_substrings,
        interview_processes: &interview_processes,
        trust_publishers: &trust_publishers,
        tier2_publishers: &tier2_publishers,
        companion_processes: &companion_processes,
        trust_path_prefixes: &trust_path_prefixes,
        suspicious_path_prefixes: &suspicious_path_prefixes,
        process_names: &process_names,
        path_substrings: &path_substrings,
        process_rules: &process_rules,
    };
    let events = win32::relay::scan(config);
    events_to_py(py, events)
}

#[pyfunction]
fn process_snapshot(py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
    use pyo3::types::PyDict;
    let out: Vec<Py<PyAny>> = win32::process::snapshot()
        .into_iter()
        .map(|(pid, parent_pid, exe, path)| {
            let dict = PyDict::new_bound(py);
            dict.set_item("pid", pid).unwrap();
            dict.set_item("parent_pid", parent_pid).unwrap();
            dict.set_item("exe", exe).unwrap();
            dict.set_item("path", path).unwrap();
            dict.into_any().unbind()
        })
        .collect();
    Ok(out)
}

#[pyfunction]
fn signer_info(py: Python<'_>, path: String) -> PyResult<Py<PyAny>> {
    use pyo3::types::PyDict;
    let info = win32::authenticode::publisher_from_path(&path);
    let dict = PyDict::new_bound(py);
    dict.set_item("publisher", info.publisher)?;
    dict.set_item("signed", info.signed)?;
    dict.set_item("signature_valid", info.signature_valid)?;
    Ok(dict.into_any().unbind())
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(platform, m)?)?;
    m.add_function(wrap_pyfunction!(scan_display_affinity, m)?)?;
    m.add_function(wrap_pyfunction!(scan_overlays, m)?)?;
    m.add_function(wrap_pyfunction!(scan_processes, m)?)?;
    m.add_function(wrap_pyfunction!(scan_microphone_sessions, m)?)?;
    m.add_function(wrap_pyfunction!(microphone_diagnostics, m)?)?;
    m.add_function(wrap_pyfunction!(scan_network, m)?)?;
    m.add_function(wrap_pyfunction!(interview_session_active, m)?)?;
    m.add_function(wrap_pyfunction!(scan_stealth_relays, m)?)?;
    m.add_function(wrap_pyfunction!(process_snapshot, m)?)?;
    m.add_function(wrap_pyfunction!(signer_info, m)?)?;
    Ok(())
}
