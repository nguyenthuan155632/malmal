use std::collections::HashMap;

use crate::detect::FileType;
use crate::report::{Finding, Severity, Verdict};

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

    /// Replace the set of accepted file types.
    pub fn with_allowed_types(mut self, types: impl IntoIterator<Item = FileType>) -> Self {
        self.allowed = types.into_iter().collect();
        self
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding::new("test.code", severity, "test")
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
