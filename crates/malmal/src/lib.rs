//! Scanner for uploaded files: images, SVG, PDF and PostScript.
//!
//! A [`Scanner`] takes the bytes of an upload and what the uploader claimed
//! about it, and returns a [`Report`]: a [`Verdict`] and the [`Finding`]s it
//! rests on. It checks that the file is the type it claims to be, that it
//! carries no active content, and that it is structurally sound. A file that
//! cannot be analyzed to the end is never reported clean.
//!
//! ```
//! use malmal::{ScanHints, Scanner, Verdict};
//!
//! let scanner = Scanner::builder().build();
//! let hints = ScanHints { filename: Some("photo.jpg"), content_type: Some("image/jpeg") };
//! let report = scanner.scan_bytes(b"\x7fELF\x02\x01\x01", hints);
//! assert_eq!(report.verdict, Verdict::Malicious);
//! assert!(report.has("type.executable"));
//! ```
//!
//! The type is told from the content; the file name and `Content-Type` in
//! [`ScanHints`] are claims to check, never to trust. Reject every file
//! whose verdict is not [`Verdict::Clean`]: a suspicious file is one the
//! scanner could not clear, not one it found harmless.
//!
//! # What is checked
//!
//! | Content | [`FileType`] | Looked for |
//! |---|---|---|
//! | JPEG, PNG and APNG, GIF, WebP, BMP, TIFF and BigTIFF, ICO, JPEG XL | `Jpeg`, `Png`, `Gif`, `Webp`, `Bmp`, `Tiff`, `Ico`, `Jxl` | broken structure, more pixels than [`Limits::max_pixels`], code in metadata, data after the image, a second format in the same bytes |
//! | PSD and PSB, HEIC, AVIF | `Psd`, `Heif`, `Avif` | the same, of the container: the pixel data is not decoded |
//! | SVG | `Svg` | scripts, event handlers, `javascript:` and `data:` addresses, entities, embedded HTML, resources fetched from elsewhere |
//! | PDF, and Illustrator files from version 9 on | `Pdf` | JavaScript, actions that run by themselves, launches, PostScript, XFA forms, attachments (each scanned in turn), encryption, obfuscated names, renderer bombs, broken structure |
//! | PostScript, EPS, older Illustrator files | `PostScript` | file and device access, shell pipes, interpreter internals, code built at run time |
//!
//! Every file is also checked for executables, server-side code (PHP, ASP,
//! JSP) and its SHA-256 against a [`HashList`]. Any other content is
//! `type.unknown`: office documents, archives and video are out of scope.
//!
//! # Verdicts and policy
//!
//! Each [`Finding`] has a code, a [`Severity`] and a message. The
//! [`Policy`] turns the worst severity into the verdict:
//!
//! | Policy | Info | Low, Medium | High, Critical |
//! |---|---|---|---|
//! | [`Policy::default`] | clean | suspicious | malicious |
//! | [`Policy::strict`] | clean | suspicious (Low), malicious (Medium) | malicious |
//!
//! [`Policy::allow`] lets one code through, at Info, for files that carry a
//! feature on purpose, such as attachments in e-invoices; the rest of the
//! file is still checked. [`Policy::with_override`] sets the severity of a
//! code, and [`Policy::with_allowed_types`] narrows the accepted types.
//!
//! ```
//! use malmal::{FileType, Limits, Policy, ScanHints, Scanner};
//!
//! let policy = Policy::default()
//!     .allow("pdf.embedded_file")?
//!     .with_allowed_types([FileType::Jpeg, FileType::Png, FileType::Pdf]);
//! let limits = Limits {
//!     max_file_size: 16 << 20,
//!     ..Limits::default()
//! };
//! let scanner = Scanner::builder()
//!     .policy(policy)
//!     .limits(limits)
//!     .pdf_passwords(["statement password"])
//!     .build();
//! let report = scanner.scan_bytes(b"<svg/>", ScanHints::default());
//! assert!(report.has("type.not_allowed"));
//! # Ok::<(), malmal::AllowError>(())
//! ```
//!
//! # Finding codes
//!
//! [`report::CODES`] lists every code. What each one means, its severity
//! and what to do about it are in
//! [`docs/findings.md`](https://github.com/nguyenthuan155632/malmal/blob/main/docs/findings.md).
//! A code keeps its meaning, and new codes arrive in minor releases.
//! Messages are for people and may be reworded at any time.
//!
//! # Limits
//!
//! [`Limits`] bound the file size, what compressed data may expand to, how
//! deep embedded files are followed, the pixels an image may declare and
//! the time a scan may take. What exceeds a limit is a `limit.*` finding,
//! so a file that was not analyzed to the end is never clean; `limit.*`
//! codes cannot be allowed. The work a scan does follows the size of the
//! file: a structure that would cost more is cut off with
//! `limit.complexity`.
//!
//! The time limit is checked between steps, and a step cannot be stopped
//! from outside. Where a scan must never run on, scan in a process that can
//! be ended, as the `malmald` daemon of
//! [`malmal-cli`](https://crates.io/crates/malmal-cli) does.
//!
//! [`Scanner::scan_bytes`] takes the file whole. For a large file, map it
//! rather than read it, so that its pages stay the kernel's to drop; what a
//! scan holds beyond the file is then what the structure costs, not the
//! size: a 1 GB PDF is scanned in less than 96 MB.
//!
//! # Threads
//!
//! A [`Scanner`] holds no per-scan state. Build one and share it between
//! threads, or clone it, which is cheap. A scan is CPU work: in an async
//! service, run it on a blocking thread.
//!
//! # Stability
//!
//! [`FileType`], [`Report`] and [`Finding`] may grow, so match on them with
//! a wildcard.
//!
//! # Features
//!
//! - `cdr`: rebuild raster images from their pixels with
//!   [`Scanner::sanitize`], so that nothing but the picture is kept. Off by
//!   default; it adds the codecs of the `image` crate to the build.
//! - `cdr-svg`: with `cdr`, also filter SVG files down to what draws a
//!   picture.
//! - `cdr-pdf`: with `cdr`, also render each page of a PDF and write a new
//!   PDF of nothing but the pictures of its pages.
//! - `yara`: match files against YARA rules with [`YaraRules`]. Off by
//!   default; it adds a WebAssembly runtime to the build.
//!
//! The command-line scanner, the daemon (HTTP, a Unix socket, the ClamAV
//! protocol and ICAP) and the C and Python bindings are in the
//! [repository](https://github.com/nguyenthuan155632/malmal).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "cdr")]
#[cfg_attr(docsrs, doc(cfg(feature = "cdr")))]
pub mod cdr;
pub mod detect;
/// SHA-256 blocklists.
pub mod hashlist;
mod image;
/// Resource limits for a scan.
pub mod limits;
mod payload;
mod pdf;
/// Accepted file types and the mapping from findings to a verdict.
pub mod policy;
mod ps;
/// The result of a scan.
pub mod report;
mod svg;
mod work;
#[cfg(feature = "yara")]
mod yara;

use std::io::{self, Read};

use sha2::{Digest, Sha256};

pub use detect::FileType;
pub use hashlist::{HashList, HashListError};
use limits::Budget;
pub use limits::{Limits, MemoryLimit};
pub use policy::{AllowError, Policy};
pub use report::{Finding, Report, Severity, Verdict};
#[cfg(feature = "yara")]
#[cfg_attr(docsrs, doc(cfg(feature = "yara")))]
pub use yara::{YaraError, YaraRules};

use payload::{PayloadKind, Scope};

/// What the uploader claimed about the file. Never trusted, only checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanHints<'a> {
    /// The name the file was uploaded under.
    pub filename: Option<&'a str>,
    /// The `Content-Type` the client sent for it.
    pub content_type: Option<&'a str>,
}

/// A configured scanner. It holds no per-scan state: build one and share
/// it between threads, or clone it, which is cheap.
#[derive(Debug, Clone, Default)]
pub struct Scanner {
    limits: Limits,
    policy: Policy,
    hashlist: HashList,
    without_hash: bool,
    pdf_passwords: Passwords,
    memory: Option<MemoryLimit>,
    #[cfg(feature = "yara")]
    yara: Option<YaraRules>,
}

/// Passwords are kept out of `Debug` output, which ends up in logs.
#[derive(Clone, Default)]
struct Passwords(Vec<Vec<u8>>);

impl std::fmt::Debug for Passwords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Passwords({} hidden)", self.0.len())
    }
}

/// Builds a [`Scanner`]; everything left unset keeps its default.
#[derive(Debug, Clone, Default)]
pub struct ScannerBuilder {
    scanner: Scanner,
}

impl ScannerBuilder {
    /// Replace the resource limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.scanner.limits = limits;
        self
    }

    /// Replace the policy that accepts file types and turns findings into
    /// a verdict.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.scanner.policy = policy;
        self
    }

    /// Do not hash the files. [`Report::sha256`] is then empty. Hashing is
    /// the slowest pass over a large file wherever the processor has no
    /// instructions for it, and a service that does not record the hash
    /// can leave it out. A blocklist needs the hash, and brings it back.
    pub fn without_hash(mut self) -> Self {
        self.scanner.without_hash = true;
        self
    }

    /// Report files whose SHA-256 is on this list as `hash.blocklisted`.
    pub fn hashlist(mut self, hashlist: HashList) -> Self {
        self.scanner.hashlist = hashlist;
        self
    }

    /// Passwords to try on encrypted PDFs, after the empty one. Each is
    /// tried as the user password and as the owner password; a document one
    /// of them opens is decrypted and inspected like any other. At most 32
    /// are used.
    ///
    /// Revisions 2 to 4 of the PDF security handler take the password in
    /// PDFDocEncoding and later ones in UTF-8; pass both spellings of a
    /// password with characters outside ASCII.
    pub fn pdf_passwords<P: Into<Vec<u8>>>(
        mut self,
        passwords: impl IntoIterator<Item = P>,
    ) -> Self {
        self.scanner.pdf_passwords = Passwords(passwords.into_iter().map(Into::into).collect());
        self
    }

    /// Stop a scan that holds more memory than `limit` allows, with
    /// `limit.memory`. See [`MemoryLimit`] for how it is measured.
    pub fn memory_limit(mut self, limit: MemoryLimit) -> Self {
        self.scanner.memory = Some(limit);
        self
    }

    /// Match every scanned file against these YARA rules.
    #[cfg(feature = "yara")]
    pub fn yara(mut self, rules: YaraRules) -> Self {
        self.scanner.yara = Some(rules);
        self
    }

    /// Finish building.
    pub fn build(self) -> Scanner {
        self.scanner
    }
}

/// Files at least this large are hashed, and searched for payloads, on
/// threads of their own while the format is analyzed.
const APART: usize = 4 << 20;

impl Scanner {
    /// Start from the defaults: every supported type accepted, the default
    /// policy and limits, no blocklist.
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    /// The limits this scanner was built with.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Replace the memory limit of a scanner already built, `None` for none:
    /// see [`ScannerBuilder::memory_limit`].
    pub fn set_memory_limit(&mut self, limit: Option<MemoryLimit>) {
        self.memory = limit;
    }

    /// Scan a file and, if it is clean and of a type that can be, write it
    /// anew. The result is the file to store in place of the upload; an
    /// error means there is nothing to store. See [`cdr`] for what is
    /// rebuilt and how.
    ///
    /// The new file is scanned as well. Pixels are kept, and a picture can
    /// be drawn whose pixels, written out, spell another file: one that
    /// was hidden by the compression of the upload and is not by that of
    /// the new file. Such a result is refused with
    /// [`cdr::Error::Unclean`].
    #[cfg(feature = "cdr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cdr")))]
    pub fn sanitize(
        &self,
        data: &[u8],
        hints: ScanHints<'_>,
        options: &cdr::Options,
    ) -> Result<cdr::Sanitized, cdr::Error> {
        let report = self.scan_bytes(data, hints);
        if report.verdict != Verdict::Clean {
            return Err(cdr::Error::Rejected(Box::new(report)));
        }
        let image = cdr::rebuild_with(data, &self.limits, options, &self.pdf_passwords.0)?;
        let rebuilt = self.scan_bytes(&image.data, ScanHints::default());
        if rebuilt.verdict != Verdict::Clean {
            return Err(cdr::Error::Unclean(Box::new(rebuilt)));
        }
        Ok(cdr::Sanitized { report, image })
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

    /// Scan a file held in memory. This never fails and never panics on
    /// hostile input; what could not be analyzed is a finding.
    pub fn scan_bytes(&self, data: &[u8], hints: ScanHints<'_>) -> Report {
        let mut findings = Vec::new();
        let size = data.len() as u64;

        // Hashing is the slowest pass over a large file and needs nothing
        // from the others, so it runs beside them.
        let hash = || -> [u8; 32] { Sha256::digest(data).into() };
        let wanted = !self.without_hash || !self.hashlist.is_empty();
        let (digest, (detected, declared_types)) = if !wanted {
            (None, self.analyze(data, hints, &mut findings))
        } else if data.len() < APART {
            (Some(hash()), self.analyze(data, hints, &mut findings))
        } else {
            std::thread::scope(|scope| {
                let hashing = std::thread::Builder::new().spawn_scoped(scope, hash);
                let analysis = self.analyze(data, hints, &mut findings);
                // Where no thread can be had, the file is hashed here.
                let digest = hashing
                    .ok()
                    .and_then(|thread| thread.join().ok())
                    .unwrap_or_else(hash);
                (Some(digest), analysis)
            })
        };
        if digest.is_some_and(|digest| self.hashlist.contains(&digest)) {
            findings.insert(
                0,
                Finding::new(
                    "hash.blocklisted",
                    Severity::Critical,
                    "SHA-256 is on the blocklist",
                ),
            );
        }

        let verdict = self.policy.apply(&mut findings);
        Report {
            verdict,
            detected_type: detected,
            declared_types,
            size,
            sha256: digest
                .as_ref()
                .map(|digest| to_hex(digest))
                .unwrap_or_default(),
            findings,
        }
    }

    /// Everything a scan does but hash the file; returns the detected type
    /// and the declared ones.
    fn analyze(
        &self,
        data: &[u8],
        hints: ScanHints<'_>,
        findings: &mut Vec<Finding>,
    ) -> (FileType, Vec<FileType>) {
        let data = if data.len() as u64 > self.limits.max_file_size {
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

        let mut budget = Budget::new(&self.limits).with_memory(self.memory);
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
                Err(svg::GunzipError::Limit) => findings.push(budget.decode_limit().finding()),
            }
        }
        let data = inflated.as_deref().unwrap_or(data);

        let declared_types = self.check_claims(detected, hints, findings);
        self.check_type(detected, findings);
        self.analyze_content(data, detected, &mut budget, findings);
        // Interpreters run PostScript whether or not it starts with `%!`, so
        // a file that claims to be PostScript is analyzed as such even when
        // the content is not recognizable.
        if detected == FileType::Unknown && declared_types.contains(&FileType::PostScript) {
            ps::analyze(data, &self.limits, &mut budget, findings);
        }

        #[cfg(feature = "yara")]
        if let Some(rules) = &self.yara {
            rules.scan(data, self.limits.max_duration, findings);
        }
        (detected, declared_types)
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
        if data.len() < APART {
            check_payloads(data, detected, findings);
            return self.analyze_format(data, detected, budget, findings);
        }
        // The search for payloads reads every byte and nothing else, so on
        // a large file it runs beside the analysis of the format.
        let search = || {
            let mut found = Vec::new();
            check_payloads(data, detected, &mut found);
            found
        };
        std::thread::scope(|scope| {
            let searching = std::thread::Builder::new().spawn_scoped(scope, search);
            let before = findings.len();
            self.analyze_format(data, detected, budget, findings);
            let found = searching
                .ok()
                .and_then(|thread| thread.join().ok())
                .unwrap_or_else(search);
            findings.splice(before..before, found);
        });
    }

    fn analyze_format(
        &self,
        data: &[u8],
        detected: FileType,
        budget: &mut Budget,
        findings: &mut Vec<Finding>,
    ) {
        match detected {
            FileType::Svg => svg::analyze(data, budget, findings),
            FileType::Pdf => {
                let mut nested =
                    |inner: &[u8], budget: &mut Budget, findings: &mut Vec<Finding>| {
                        self.scan_embedded(inner, budget, findings)
                    };
                pdf::analyze(
                    data,
                    budget,
                    findings,
                    &self.pdf_passwords.0,
                    self.limits.max_pixels,
                    &mut nested,
                );
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
        // The rules saw the container, where this file may be compressed.
        #[cfg(feature = "yara")]
        if let Some(rules) = &self.yara {
            rules.scan(data, self.limits.max_duration, findings);
        }
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
