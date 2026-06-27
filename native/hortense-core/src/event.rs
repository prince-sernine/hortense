use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct DetectionEvent {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub pid: Option<u32>,
    pub hwnd: Option<isize>,
    pub window_title: Option<String>,
    pub metadata: serde_json::Value,
}

impl DetectionEvent {
    pub fn into_py_dict(self, py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
        let dict = PyDict::new_bound(py);
        dict.set_item("id", self.id)?;
        dict.set_item("severity", self.severity)?;
        dict.set_item("category", self.category)?;
        dict.set_item("title", self.title)?;
        dict.set_item("detail", self.detail)?;
        dict.set_item("process_name", self.process_name)?;
        dict.set_item("process_path", self.process_path)?;
        dict.set_item("pid", self.pid)?;
        dict.set_item("hwnd", self.hwnd)?;
        dict.set_item("window_title", self.window_title)?;
        dict.set_item("metadata", self.metadata.to_string())?;
        Ok(dict)
    }
}

pub fn new_id(category: &str, key: &str) -> String {
    format!("{category}:{key}")
}
