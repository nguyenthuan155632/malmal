//! Structural checks for raster images. Each format module walks the file to
//! its logical end without decoding pixels; everything past that point, and
//! everything that fails to parse, is reported.

mod bmp;
mod gif;
mod ico;
mod isobmff;
mod jpeg;
mod jxl;
mod png;
mod psd;
mod tiff;
mod trailer;
mod webp;

use crate::detect::{self, FileType};
use crate::limits::{Budget, LimitExceeded, Limits};
use crate::payload::find;
use crate::report::{Finding, Severity};

/// What a format parser learned about a well-formed image.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Offset one past the last byte the format accounts for, when the format
    /// defines one.
    pub end: Option<usize>,
    /// Width and height in pixels.
    pub dimensions: Option<(u64, u64)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed {
    pub offset: usize,
    pub reason: &'static str,
}

impl Malformed {
    pub fn new(offset: usize, reason: &'static str) -> Self {
        Self { offset, reason }
    }

    pub fn truncated(offset: usize) -> Self {
        Self::new(offset, "file ends in the middle of the image structure")
    }
}

/// Shared state for parsers that decode embedded data.
pub(crate) struct Ctx<'a> {
    pub budget: &'a mut Budget,
    pub findings: &'a mut Vec<Finding>,
}

impl Ctx<'_> {
    /// Record an exhausted limit once per scan.
    pub fn limit_exceeded(&mut self, limit: LimitExceeded) {
        if !self.findings.iter().any(|f| f.code == limit.code()) {
            self.findings.push(limit.finding());
        }
    }
}

pub(crate) fn analyze(
    data: &[u8],
    file_type: FileType,
    limits: &Limits,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
) {
    let parsed = match file_type {
        FileType::Jpeg => jpeg::parse(data),
        FileType::Png => png::parse(data, &mut Ctx { budget, findings }),
        FileType::Gif => gif::parse(data),
        FileType::Webp => webp::parse(data),
        FileType::Bmp => bmp::parse(data),
        FileType::Tiff => tiff::parse(data),
        FileType::Psd => psd::parse(data),
        FileType::Heif | FileType::Avif => isobmff::parse(data),
        FileType::Jxl => jxl::parse(data, &mut Ctx { budget, findings }),
        FileType::Ico => ico::parse(data, &mut Ctx { budget, findings }),
        _ => return,
    };
    match parsed {
        Ok(layout) => {
            check_dimensions(layout.dimensions, limits, findings);
            if let Some(end) = layout.end {
                check_trailing(data, end, findings);
            }
        }
        Err(malformed) => findings.push(
            Finding::new("image.malformed", Severity::Medium, malformed.reason)
                .at(malformed.offset),
        ),
    }
    check_polyglot(data, findings);
}

fn check_dimensions(dimensions: Option<(u64, u64)>, limits: &Limits, findings: &mut Vec<Finding>) {
    let Some((width, height)) = dimensions else {
        return;
    };
    if width == 0 || height == 0 {
        findings.push(Finding::new(
            "image.malformed",
            Severity::Medium,
            "image has a zero dimension",
        ));
    } else if width.saturating_mul(height) > limits.max_pixels {
        findings.push(Finding::new(
            "image.pixel_bomb",
            Severity::Medium,
            format!(
                "{width}x{height} pixels exceeds the {} pixel limit",
                limits.max_pixels
            ),
        ));
    }
}

fn check_trailing(data: &[u8], end: usize, findings: &mut Vec<Finding>) {
    let Some(trailing) = data.get(end..) else {
        return;
    };
    // Zero or whitespace padding is common and carries nothing.
    let padding = trailing
        .iter()
        .take_while(|b| **b == 0 || b.is_ascii_whitespace())
        .count();
    if padding == trailing.len() {
        return;
    }
    // Both known trailers begin with zero bytes, so try before the padding too.
    let recognized =
        trailer::recognize(trailing).or_else(|| trailer::recognize(&trailing[padding..]));
    if let Some(content) = recognized {
        findings.push(
            Finding::new(
                "image.vendor_trailer",
                Severity::Info,
                format!("{} bytes of {content} after the image", trailing.len()),
            )
            .at(end),
        );
        return;
    }
    findings.push(
        Finding::new(
            "image.trailing_data",
            Severity::Low,
            format!("{} bytes after the end of the image", trailing.len()),
        )
        .at(end),
    );
    let appended = detect::detect(&trailing[padding..]);
    if appended != FileType::Unknown && !appended.is_raster_image() {
        findings.push(
            Finding::new(
                "image.polyglot",
                Severity::High,
                format!("data after the image is a {} file", appended.as_str()),
            )
            .at(end + padding),
        );
    }
}

/// Formats that are located from somewhere other than offset 0 and so can
/// coexist with a valid image even when it has no detectable trailing data.
fn check_polyglot(data: &[u8], findings: &mut Vec<Finding>) {
    if findings.iter().any(|f| f.code == "image.polyglot") {
        return;
    }
    if let Some(offset) = find(&data[..data.len().min(1024)], b"%PDF-") {
        findings.push(
            Finding::new(
                "image.polyglot",
                Severity::High,
                "PDF header inside the image; the file also opens as a PDF",
            )
            .at(offset),
        );
    } else if let Some(offset) = detect::zip_end_record(data) {
        findings.push(
            Finding::new(
                "image.polyglot",
                Severity::High,
                "ZIP end-of-central-directory record closes the file; it also opens as an archive",
            )
            .at(offset),
        );
    }
}

fn bytes<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    data.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

pub(crate) fn be16(data: &[u8], offset: usize) -> Option<u16> {
    bytes(data, offset).map(u16::from_be_bytes)
}

pub(crate) fn le16(data: &[u8], offset: usize) -> Option<u16> {
    bytes(data, offset).map(u16::from_le_bytes)
}

pub(crate) fn be32(data: &[u8], offset: usize) -> Option<u32> {
    bytes(data, offset).map(u32::from_be_bytes)
}

pub(crate) fn le32(data: &[u8], offset: usize) -> Option<u32> {
    bytes(data, offset).map(u32::from_le_bytes)
}

pub(crate) fn le24(data: &[u8], offset: usize) -> Option<u32> {
    bytes::<3>(data, offset).map(|[a, b, c]| u32::from_le_bytes([a, b, c, 0]))
}
