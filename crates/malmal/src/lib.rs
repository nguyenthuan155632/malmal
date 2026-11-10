//! Scanner for uploaded files: images, SVG, PDF and PostScript.
//!
//! ```
//! use malmal::{ScanHints, Scanner, Verdict};
//!
//! let scanner = Scanner::builder().build();
//! let hints = ScanHints { filename: Some("photo.jpg"), content_type: Some("image/jpeg") };
//! let report = scanner.scan_bytes(b"\x7fELF\x02\x01\x01", hints);
//! assert_eq!(report.verdict, Verdict::Malicious);
//! ```

#![forbid(unsafe_code)]

pub mod detect;
pub mod hashlist;
mod image;
pub mod limits;
pub mod payload;
mod pdf;
pub mod policy;
mod ps;
pub mod report;
mod svg;
#[cfg(feature = "yara")]
mod yara;

use std::io::{self, Read};

use sha2::{Digest, Sha256};

pub use detect::FileType;
pub use hashlist::{HashList, HashListError};
pub use limits::{Budget, LimitExceeded, Limits};
pub use policy::Policy;
pub use report::{Finding, Report, Severity, Verdict};
#[cfg(feature = "yara")]
pub use yara::{YaraError, YaraRules};

use payload::{PayloadKind, Scope};

/// What the uploader claimed about the file. Never trusted, only checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanHints<'a> {
    pub filename: Option<&'a str>,
    pub content_type: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct Scanner {
    limits: Limits,
    policy: Policy,
    hashlist: HashList,
    #[cfg(feature = "yara")]
    yara: Option<YaraRules>,
}

#[derive(Debug, Clone, Default)]
pub struct ScannerBuilder {
    scanner: Scanner,
}

impl ScannerBuilder {
    pub fn limits(mut self, limits: Limits) -> Self {
        self.scanner.limits = limits;
        self
    }

    pub fn policy(mut self, policy: Policy) -> Self {
        self.scanner.policy = policy;
        self
    }

    pub fn hashlist(mut self, hashlist: HashList) -> Self {
        self.scanner.hashlist = hashlist;
        self
    }

    /// Match every scanned file against these YARA rules.
    #[cfg(feature = "yara")]
    pub fn yara(mut self, rules: YaraRules) -> Self {
        self.scanner.yara = Some(rules);
        self
    }

    pub fn build(self) -> Scanner {
        self.scanner
    }
}

impl Scanner {
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    /// Scan from a reader, buffering at most one byte past the size limit.
    /// For oversized input the reported size and hash cover only what was read.
    pub fn scan_reader(&self, reader: impl Read, hints: ScanHints<'_>) -> io::Result<Report> {
        let mut data = Vec::new();
        reader
            .take(self.limits.max_file_size.saturating_add(1))
            .read_to_end(&mut data)?;
        Ok(self.scan_bytes(&data, hints))
    }

    pub fn scan_bytes(&self, data: &[u8], hints: ScanHints<'_>) -> Report {
        let mut findings = Vec::new();
        let size = data.len() as u64;
        let digest: [u8; 32] = Sha256::digest(data).into();

        if self.hashlist.contains(&digest) {
            findings.push(Finding::new(
                "hash.blocklisted",
                Severity::Critical,
                "SHA-256 is on the blocklist",
            ));
        }

        let data = if size > self.limits.max_file_size {
            findings.push(Finding::new(
                "limit.size",
                Severity::Medium,
                format!(
                    "file exceeds the {} byte limit; only the start was analyzed",
                    self.limits.max_file_size
                ),
            ));
            &data[..self.limits.max_file_size as usize]
        } else {
            data
        };

        let mut budget = Budget::new(&self.limits);
        let mut detected = detect::detect(data);
        // SVGZ: a gzip member is only acceptable as a wrapper around an SVG.
        let mut inflated = None;
        if detected == FileType::Gzip {
            match svg::gunzip(data, self.limits.max_file_size, &mut budget) {
                Ok(inner) if detect::detect(&inner) == FileType::Svg => {
                    detected = FileType::Svg;
                    inflated = Some(inner);
                }
                Ok(_) | Err(svg::GunzipError::Corrupt) => {}
                Err(svg::GunzipError::Limit) => {
                    findings.push(LimitExceeded::Decompression.finding())
                }
            }
        }
        let data = inflated.as_deref().unwrap_or(data);

        let declared_types = self.check_claims(detected, hints, &mut findings);
        self.check_type(detected, &mut findings);
        self.analyze_content(data, detected, &mut budget, &mut findings);
        // Interpreters run PostScript whether or not it starts with `%!`, so
        // a file that claims to be PostScript is analyzed as such even when
        // the content is not recognizable.
        if detected == FileType::Unknown && declared_types.contains(&FileType::PostScript) {
            ps::analyze(data, &self.limits, &mut budget, &mut findings);
        }

        #[cfg(feature = "yara")]
        if let Some(rules) = &self.yara {
            rules.scan(data, self.limits.max_duration, &mut findings);
        }

        let verdict = self.policy.apply(&mut findings);
        Report {
            verdict,
            detected_type: detected,
            declared_types,
            size,
            sha256: to_hex(&digest),
            findings,
        }
    }

    /// Checks that depend only on the bytes, shared by top-level and
    /// embedded files.
    fn analyze_content(
        &self,
        data: &[u8],
        detected: FileType,
        budget: &mut Budget,
        findings: &mut Vec<Finding>,
    ) {
        check_payloads(data, detected, findings);
        match detected {
            FileType::Svg => svg::analyze(data, budget, findings),
            FileType::Pdf => {
                let mut nested =
                    |inner: &[u8], budget: &mut Budget, findings: &mut Vec<Finding>| {
                        self.scan_embedded(inner, budget, findings)
                    };
                pdf::analyze(data, budget, findings, &mut nested);
            }
            FileType::PostScript => ps::analyze(data, &self.limits, budget, findings),
            _ => image::analyze(data, detected, &self.limits, budget, findings),
        }
    }

    /// Scan a file carried inside another one. Attachments may be of any
    /// type, so only executables and active content are reported, not
    /// unknown or disallowed types.
    fn scan_embedded(&self, data: &[u8], budget: &mut Budget, findings: &mut Vec<Finding>) {
        let detected = detect::detect(data);
        if detected.is_executable() {
            findings.push(Finding::new(
                "type.executable",
                Severity::Critical,
                format!("content is an executable ({})", detected.as_str()),
            ));
        }
        self.analyze_content(data, detected, budget, findings);
    }

    /// Compare the content against the filename and Content-Type claims.
    fn check_claims(
        &self,
        detected: FileType,
        hints: ScanHints<'_>,
        findings: &mut Vec<Finding>,
    ) -> Vec<FileType> {
        let mut declared = Vec::new();
        let mut check = |source: &str, claim: &str, types: Option<&'static [FileType]>| {
            let Some(types) = types else { return };
            for &file_type in types {
                if !declared.contains(&file_type) {
                    declared.push(file_type);
                }
            }
            if !types.contains(&detected) {
                findings.push(Finding::new(
                    "type.mismatch",
                    Severity::Medium,
                    format!(
                        "{source} {claim:?} does not match {} content",
                        detected.as_str()
                    ),
                ));
            }
        };

        if let Some(ext) = hints.filename.and_then(detect::extension) {
            check("extension", ext, detect::types_for_extension(ext));
        }
        if let Some(content_type) = hints.content_type {
            check(
                "Content-Type",
                content_type,
                detect::types_for_mime(content_type),
            );
        }
        if let Some(ext) = hints.filename.and_then(detect::dangerous_extension) {
            findings.push(Finding::new(
                "name.dangerous_extension",
                Severity::High,
                format!("filename contains the executable extension {ext:?}"),
            ));
        }
        declared
    }

    fn check_type(&self, detected: FileType, findings: &mut Vec<Finding>) {
        if detected.is_executable() {
            findings.push(Finding::new(
                "type.executable",
                Severity::Critical,
                format!("content is an executable ({})", detected.as_str()),
            ));
        } else if detected == FileType::Unknown {
            findings.push(Finding::new(
                "type.unknown",
                Severity::Medium,
                "content type could not be identified",
            ));
        } else if !self.policy.is_allowed(detected) {
            findings.push(Finding::new(
                "type.not_allowed",
                Severity::Medium,
                format!("{} files are not accepted by policy", detected.as_str()),
            ));
        }
    }
}

fn check_payloads(data: &[u8], detected: FileType, findings: &mut Vec<Finding>) {
    // Markup and PostScript formats are judged by their own analyzers; in a
    // raster image, including its metadata and any appended bytes, no code of
    // any kind has a reason to exist.
    let scope = if detected.is_raster_image() {
        Scope::Binary
    } else {
        Scope::Mixed
    };
    for hit in payload::scan(data, scope) {
        let (code, message) = match hit.kind {
            PayloadKind::Php => ("payload.php", "PHP opening tag in file content"),
            PayloadKind::Script => (
                "payload.script",
                "browser-executable markup inside an image",
            ),
            PayloadKind::Template => ("payload.template", "ASP/JSP template tag inside an image"),
        };
        findings.push(Finding::new(code, Severity::High, message).at(hit.offset));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(DIGITS[(byte >> 4) as usize] as char);
        hex.push(DIGITS[(byte & 0xF) as usize] as char);
    }
    hex
}
