use serde::Serialize;

use crate::detect::FileType;

/// What to do with the file. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Nothing was found, or only informational findings.
    Clean,
    /// Something is off, or the file could not be analyzed to the end.
    /// Reject it unless a person has looked at it.
    Suspicious,
    /// The file carries active content, a payload or an executable.
    Malicious,
}

/// How serious a finding is. The policy turns the worst one into a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing; does not affect the verdict.
    Info,
    /// Unusual, and harmless on its own.
    Low,
    /// A risk, or a part of the file that could not be inspected.
    Medium,
    /// Active content or a hidden payload.
    High,
    /// An executable, or a file known to be malicious.
    Critical,
}

/// One thing the scanner noticed about a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Finding {
    /// Stable machine-readable identifier, e.g. `pdf.javascript`. The codes
    /// are listed in `docs/findings.md`; new ones may be added in a minor
    /// release, existing ones keep their meaning.
    pub code: &'static str,
    /// How serious the finding is, after the policy's overrides.
    pub severity: Severity,
    /// Human-readable detail. The wording is not stable; match on `code`.
    pub message: String,
    /// Byte offset in the scanned input, when the finding has one.
    pub offset: Option<u64>,
}

impl Finding {
    /// A finding without an offset.
    pub fn new(code: &'static str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            offset: None,
        }
    }

    /// Attach the byte offset the finding refers to.
    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset as u64);
        self
    }
}

/// The result of scanning one file.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Report {
    /// The policy's decision, derived from the findings.
    pub verdict: Verdict,
    /// Type derived from the content itself.
    pub detected_type: FileType,
    /// Types the filename and Content-Type claimed; empty when neither was recognized.
    pub declared_types: Vec<FileType>,
    /// Size of the input as given, before any truncation to the size limit.
    pub size: u64,
    /// Lowercase hex SHA-256 of the input as given.
    pub sha256: String,
    /// Everything that was noticed, in the order it was found.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether any finding carries this code.
    pub fn has(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }
}
