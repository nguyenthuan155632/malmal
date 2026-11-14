use std::collections::HashMap;
use std::fmt;

use crate::detect::FileType;
use crate::report::{CODES, Finding, Severity, Verdict};

/// Turns findings into a verdict and decides which file types are accepted.
#[derive(Debug, Clone)]
pub struct Policy {
    malicious_at: Severity,
    suspicious_at: Severity,
    overrides: HashMap<String, Severity>,
    allowed: Vec<FileType>,
}

const DEFAULT_ALLOWED: &[FileType] = &[
    FileType::Jpeg,
    FileType::Png,
    FileType::Gif,
    FileType::Webp,
    FileType::Bmp,
    FileType::Tiff,
    FileType::Psd,
    FileType::Heif,
    FileType::Avif,
    FileType::Jxl,
    FileType::Ico,
    FileType::Svg,
    FileType::Pdf,
    FileType::PostScript,
];

impl Default for Policy {
    /// High and above is malicious, Low and Medium are suspicious.
    fn default() -> Self {
        Self {
            malicious_at: Severity::High,
            suspicious_at: Severity::Low,
            overrides: HashMap::new(),
            allowed: DEFAULT_ALLOWED.to_vec(),
        }
    }
}

impl Policy {
    /// Like the default, but Medium findings are already malicious.
    pub fn strict() -> Self {
        Self {
            malicious_at: Severity::Medium,
            ..Self::default()
        }
    }

    /// Replace the severity of every finding with this code.
    pub fn with_override(mut self, code: impl Into<String>, severity: Severity) -> Self {
        self.overrides.insert(code.into(), severity);
        self
    }

    /// Report every finding with this code at Info, so that it leaves a file
    /// clean. Unlike [`Policy::with_override`], the code must be one the
    /// scanner reports, and not a limit: a file that was not analyzed to
    /// the end is never clean.
    pub fn allow(self, code: &str) -> Result<Self, AllowError> {
        match CODES.iter().find(|&&known| known == code) {
            Some(&code) if code.starts_with("limit.") => Err(AllowError::Limit(code)),
            Some(&code) => Ok(self.with_override(code, Severity::Info)),
            None => Err(AllowError::Unknown(code.to_string())),
        }
    }

    /// Replace the set of accepted file types.
    pub fn with_allowed_types(mut self, types: impl IntoIterator<Item = FileType>) -> Self {
        self.allowed = types.into_iter().collect();
        self
    }

    /// Whether files of this type are accepted.
    pub fn is_allowed(&self, file_type: FileType) -> bool {
        self.allowed.contains(&file_type)
    }

    /// Apply severity overrides in place and compute the verdict.
    pub fn apply(&self, findings: &mut [Finding]) -> Verdict {
        let mut verdict = Verdict::Clean;
        for finding in findings {
            if let Some(&severity) = self.overrides.get(finding.code) {
                finding.severity = severity;
            }
            if finding.severity >= self.malicious_at {
                verdict = Verdict::Malicious;
            } else if finding.severity >= self.suspicious_at {
                verdict = verdict.max(Verdict::Suspicious);
            }
        }
        verdict
    }
}

/// Why [`Policy::allow`] refused a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowError {
    /// The scanner reports no such code.
    Unknown(String),
    /// A `limit.*` code: raise the limit instead.
    Limit(&'static str),
}

impl fmt::Display for AllowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(code) => write!(
                f,
                "unknown finding code {code:?}; the codes are listed in docs/findings.md"
            ),
            Self::Limit(code) => write!(
                f,
                "{code} cannot be allowed: a file that was not analyzed to the end is never \
                 clean; raise the limit instead"
            ),
        }
    }
}

impl std::error::Error for AllowError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding::new("test.code", severity, "test")
    }

    #[test]
    fn only_codes_the_scanner_reports_are_allowed() {
        let policy = Policy::strict().allow("pdf.xfa").unwrap();
        let mut findings = [Finding::new("pdf.xfa", Severity::Medium, "form")];
        assert_eq!(policy.apply(&mut findings), Verdict::Clean);
        assert_eq!(findings[0].severity, Severity::Info);

        let error = Policy::default().allow("pdf.embeddedFile").unwrap_err();
        assert_eq!(error, AllowError::Unknown("pdf.embeddedFile".into()));
        assert!(error.to_string().contains("unknown finding code"));
        assert!(Policy::default().allow("").is_err());
        assert_eq!(
            Policy::default().allow("limit.time").unwrap_err(),
            AllowError::Limit("limit.time")
        );
    }

    #[test]
    fn verdict_follows_the_worst_finding() {
        let policy = Policy::default();
        assert_eq!(policy.apply(&mut []), Verdict::Clean);
        assert_eq!(policy.apply(&mut [finding(Severity::Info)]), Verdict::Clean);
        assert_eq!(
            policy.apply(&mut [finding(Severity::Low), finding(Severity::Medium)]),
            Verdict::Suspicious
        );
        assert_eq!(
            policy.apply(&mut [finding(Severity::High), finding(Severity::Low)]),
            Verdict::Malicious
        );
    }

    #[test]
    fn strict_promotes_medium_to_malicious() {
        assert_eq!(
            Policy::strict().apply(&mut [finding(Severity::Medium)]),
            Verdict::Malicious
        );
        assert_eq!(
            Policy::strict().apply(&mut [finding(Severity::Low)]),
            Verdict::Suspicious
        );
    }

    #[test]
    fn overrides_rewrite_severity() {
        let policy = Policy::default().with_override("test.code", Severity::Info);
        let mut findings = [finding(Severity::Critical)];
        assert_eq!(policy.apply(&mut findings), Verdict::Clean);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn allowed_types_can_be_narrowed() {
        assert!(Policy::default().is_allowed(FileType::Pdf));
        assert!(!Policy::default().is_allowed(FileType::Zip));
        let images_only = Policy::default().with_allowed_types([FileType::Png]);
        assert!(!images_only.is_allowed(FileType::Pdf));
    }
}
