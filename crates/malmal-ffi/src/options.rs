//! The JSON options of `malmal_scanner_new_json` and `malmal_sanitize_json`.
//!
//! Every key is optional, and a key this library does not know is an error,
//! so that a misspelt option is not silently left at its default.

use std::time::Duration;

use malmal::cdr::{Inks, Options, PageImage, Profiles};
use malmal::{FileType, HashList, Limits, Policy, Scanner};
use serde::Deserialize;

/// What one scan may hold unless told otherwise: the default of the
/// commands' `--max-memory`.
pub const DEFAULT_MAX_MEMORY: u64 = 512 << 20;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerOptions {
    /// `default`, `strict` or `documents`.
    policy: Option<String>,
    /// Finding codes reported at Info.
    #[serde(default)]
    allow: Vec<String>,
    /// The accepted file types; every supported type when absent.
    types: Option<Vec<String>>,
    /// A SHA-256 blocklist, one hex digest per line.
    hashlist: Option<String>,
    /// Passwords to try on encrypted PDFs: text, or an array of bytes for
    /// one that is not UTF-8.
    #[serde(default)]
    pdf_passwords: Vec<Password>,
    max_size: Option<u64>,
    max_decompressed: Option<u64>,
    max_pixels: Option<u64>,
    max_depth: Option<u32>,
    /// Seconds, the cooperative limit of one scan.
    scan_timeout: Option<f64>,
    /// Bytes one scan may hold; 0 for no limit.
    max_memory: Option<u64>,
    #[serde(default)]
    without_hash: bool,
    /// Seconds after which `malmal_scan` stops waiting for a scan.
    wait: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Password {
    Text(String),
    Bytes(Vec<u8>),
}

impl Password {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

/// A scanner built from its options, and how long a scan is waited for.
pub struct Built {
    pub scanner: Scanner,
    pub max_memory: u64,
    pub wait: Option<Duration>,
}

fn seconds(name: &str, value: f64) -> Result<Duration, String> {
    Duration::try_from_secs_f64(value)
        .ok()
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("{name} has to be a positive number of seconds"))
}

impl ScannerOptions {
    pub fn parse(json: &str) -> Result<Self, String> {
        let json = json.trim();
        if json.is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(json).map_err(|e| format!("options: {e}"))
    }

    pub fn build(self) -> Result<Built, String> {
        let name = self.policy.as_deref().unwrap_or("default");
        let mut policy = Policy::named(name).ok_or_else(|| {
            format!("unknown policy {name:?}; the policies are default, strict and documents")
        })?;
        if let Some(types) = &self.types {
            let types = types
                .iter()
                .map(|name| {
                    FileType::from_name(name).ok_or_else(|| format!("unknown file type {name:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            policy = policy.with_allowed_types(types);
        }
        for code in &self.allow {
            policy = policy.allow(code).map_err(|e| e.to_string())?;
        }

        let mut limits = Limits::default();
        let positive = |name: &str, value: u64| {
            if value == 0 {
                Err(format!("{name} has to be positive"))
            } else {
                Ok(value)
            }
        };
        if let Some(value) = self.max_size {
            limits.max_file_size = positive("max_size", value)?;
        }
        if let Some(value) = self.max_decompressed {
            limits.max_decompressed = positive("max_decompressed", value)?;
        }
        if let Some(value) = self.max_pixels {
            limits.max_pixels = positive("max_pixels", value)?;
        }
        if let Some(value) = self.max_depth {
            limits.max_depth = value;
        }
        if let Some(value) = self.scan_timeout {
            limits.max_duration = seconds("scan_timeout", value)?;
        }
        let wait = self.wait.map(|value| seconds("wait", value)).transpose()?;

        let hashlist =
            HashList::parse(self.hashlist.as_deref().unwrap_or("")).map_err(|e| e.to_string())?;
        let mut builder = Scanner::builder()
            .policy(policy)
            .limits(limits)
            .hashlist(hashlist)
            .pdf_passwords(self.pdf_passwords.iter().map(Password::as_bytes));
        if self.without_hash {
            builder = builder.without_hash();
        }
        Ok(Built {
            scanner: builder.build(),
            max_memory: self.max_memory.unwrap_or(DEFAULT_MAX_MEMORY),
            wait,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizeOptions {
    jpeg_quality: Option<u8>,
    /// The types to rebuild; every type this build can when absent.
    types: Option<Vec<String>>,
    /// Keep the inks of a CMYK image as inks.
    #[serde(default)]
    keep_cmyk: bool,
    /// Keep colours of an RGB profile other than sRGB in it.
    #[serde(default)]
    keep_profile: bool,
    pdf_dpi: Option<u16>,
    /// Keep a page as JPEG where that is smaller.
    #[serde(default)]
    pdf_jpeg: bool,
    pdf_text: Option<bool>,
    pdf_vector_text: Option<bool>,
}

impl SanitizeOptions {
    pub fn parse(json: &str) -> Result<Options, String> {
        let json = json.trim();
        let parsed: Self = if json.is_empty() {
            Self::default()
        } else {
            serde_json::from_str(json).map_err(|e| format!("options: {e}"))?
        };
        let mut options = Options::default();
        if let Some(quality) = parsed.jpeg_quality {
            if !(1..=100).contains(&quality) {
                return Err("jpeg_quality has to be from 1 to 100".into());
            }
            options.jpeg_quality = quality;
        }
        if let Some(types) = parsed.types {
            let types = types
                .iter()
                .map(|name| {
                    FileType::from_name(name).ok_or_else(|| format!("unknown file type {name:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            options.types = Some(types);
        }
        if let Some(dpi) = parsed.pdf_dpi {
            if !(36..=600).contains(&dpi) {
                return Err("pdf_dpi has to be from 36 to 600".into());
            }
            options.pdf_dpi = dpi;
        }
        if parsed.keep_cmyk {
            options.inks = Inks::Keep;
        }
        if parsed.keep_profile {
            options.profiles = Profiles::Keep;
        }
        if parsed.pdf_jpeg {
            options.pdf_pages = PageImage::Jpeg;
        }
        if let Some(text) = parsed.pdf_text {
            options.pdf_text = text;
        }
        if let Some(vector) = parsed.pdf_vector_text {
            options.pdf_vector_text = vector;
        }
        Ok(options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Built, String> {
        ScannerOptions::parse(json)?.build()
    }

    #[test]
    fn every_option_is_taken() {
        let built = build(
            r#"{"policy": "documents", "allow": ["pdf.javascript"], "types": ["pdf", "png"],
                "pdf_passwords": ["secret", [233, 116, 233]], "max_size": 1024, "max_decompressed": 2048,
                "max_pixels": 100, "max_depth": 2, "scan_timeout": 1.5, "max_memory": 0,
                "without_hash": true, "wait": 30}"#,
        )
        .unwrap();
        let limits = built.scanner.limits();
        assert_eq!(limits.max_file_size, 1024);
        assert_eq!(limits.max_decompressed, 2048);
        assert_eq!(limits.max_pixels, 100);
        assert_eq!(limits.max_depth, 2);
        assert_eq!(limits.max_duration, Duration::from_millis(1500));
        assert_eq!(built.max_memory, 0);
        assert_eq!(built.wait, Some(Duration::from_secs(30)));

        let defaults = build("  ").unwrap();
        assert_eq!(defaults.max_memory, DEFAULT_MAX_MEMORY);
        assert!(defaults.wait.is_none());
        assert!(build("{}").is_ok());
    }

    #[test]
    fn mistakes_are_errors() {
        for (json, expected) in [
            (r#"{"polcy": "strict"}"#, "unknown field `polcy`"),
            (r#"{"policy": "lenient"}"#, "unknown policy"),
            (r#"{"types": ["docx"]}"#, "unknown file type"),
            (r#"{"allow": ["limit.time"]}"#, "never"),
            (r#"{"allow": ["pdf.embeddedfile"]}"#, "unknown finding code"),
            (r#"{"max_size": 0}"#, "max_size has to be positive"),
            (r#"{"wait": 0}"#, "wait has to be a positive"),
            (
                r#"{"scan_timeout": -1}"#,
                "scan_timeout has to be a positive",
            ),
            (r#"{"hashlist": "not a digest"}"#, ""),
            ("[", "options:"),
        ] {
            let error = build(json)
                .err()
                .unwrap_or_else(|| panic!("{json} was taken"));
            assert!(error.contains(expected), "{json}: {error}");
        }
    }

    #[test]
    fn sanitize_options() {
        let options = SanitizeOptions::parse(
            r#"{"jpeg_quality": 70, "types": ["png"], "pdf_dpi": 100, "pdf_jpeg": true,
                "keep_cmyk": true, "keep_profile": true, "pdf_text": false, "pdf_vector_text": false}"#,
        )
        .unwrap();
        assert_eq!(options.jpeg_quality, 70);
        assert_eq!(options.types, Some(vec![FileType::Png]));
        assert_eq!(options.pdf_dpi, 100);
        assert_eq!(options.pdf_pages, PageImage::Jpeg);
        assert_eq!(options.inks, Inks::Keep);
        assert_eq!(options.profiles, Profiles::Keep);
        assert!(!options.pdf_text && !options.pdf_vector_text);
        assert_eq!(SanitizeOptions::parse("").unwrap().jpeg_quality, 90);
        for json in [
            r#"{"jpeg_quality": 0}"#,
            r#"{"pdf_dpi": 20}"#,
            r#"{"dpi": 100}"#,
        ] {
            assert!(SanitizeOptions::parse(json).is_err(), "{json}");
        }
    }
}
