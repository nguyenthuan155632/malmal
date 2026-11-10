use serde::Serialize;

use crate::detect::FileType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable machine-readable identifier, e.g. `pdf.javascript`.
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    /// Byte offset in the scanned input, when the finding has one.
    pub offset: Option<u64>,
}

impl Finding {
    pub fn new(code: &'static str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            offset: None,
        }
    }

    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset as u64);
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    /// Type derived from the content itself.
    pub detected_type: FileType,
    /// Types the filename and Content-Type claimed; empty when neither was recognized.
    pub declared_types: Vec<FileType>,
    /// Size of the input as given, before any truncation to the size limit.
    pub size: u64,
    /// Lowercase hex SHA-256 of the input as given.
    pub sha256: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn has(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }
}
