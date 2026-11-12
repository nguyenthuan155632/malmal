//! JPEG XL: a bare codestream, or one wrapped in boxes together with
//! metadata. Only the size header of the codestream is read; the image data
//! behind it is entropy-coded and has no end that can be found without
//! decoding it. Metadata boxes stored Brotli-compressed are decompressed and
//! searched like the rest of the file.

use std::io::Read;

use super::isobmff::{self, BoxAt};
use super::{Ctx, Layout, Malformed, be32};
use crate::limits::LimitExceeded;
use crate::payload::{self, Scope};
use crate::report::{Finding, Severity};

const CODESTREAM_SIGNATURE: &[u8] = b"\xFF\x0A";
/// No legitimate Exif or XMP box decompresses to more than this.
const MAX_METADATA: u64 = 16 << 20;

pub(crate) fn parse(data: &[u8], ctx: &mut Ctx<'_>) -> Result<Layout, Malformed> {
    if data.starts_with(CODESTREAM_SIGNATURE) {
        return Ok(Layout {
            end: None,
            dimensions: Some(size_header(data, 0)?),
        });
    }

    let mut codestream = None;
    let mut compressed = Vec::new();
    let end = isobmff::top_level(data, |found: &BoxAt<'_>| {
        match found.kind {
            b"jxlc" => {
                codestream.get_or_insert(found.body);
            }
            // A part of the codestream, after its sequence number.
            b"jxlp" if be32(&data[..found.end], found.body).is_some_and(|n| n << 1 == 0) => {
                codestream.get_or_insert(found.body + 4);
            }
            b"brob" => compressed.push((found.body, found.end)),
            _ => {}
        }
        Ok(())
    })?;
    for (body, end) in compressed {
        scan_compressed(data, body, end, ctx)?;
    }
    let Some(start) = codestream else {
        return Err(Malformed::new(0, "JPEG XL container has no codestream"));
    };
    if !data[start..].starts_with(CODESTREAM_SIGNATURE) {
        return Err(Malformed::new(start, "JPEG XL codestream is malformed"));
    }
    Ok(Layout {
        end: Some(end),
        dimensions: Some(size_header(data, start)?),
    })
}

/// Decompress the `brob` box at `body..end` under the scan budget and look
/// for code in the result. The box is the type of the box it stands for,
/// then that box's contents as a Brotli stream.
fn scan_compressed(
    data: &[u8],
    body: usize,
    end: usize,
    ctx: &mut Ctx<'_>,
) -> Result<(), Malformed> {
    let corrupt = || Malformed::new(body, "corrupt compressed metadata box");
    let stream = data[..end].get(body + 4..).ok_or_else(corrupt)?;
    let limit = ctx.budget.remaining().min(MAX_METADATA);
    let mut plain = Vec::new();
    let read = brotli_decompressor::Decompressor::new(stream, 4096)
        .take(limit + 1)
        .read_to_end(&mut plain);
    if read.is_err() {
        return Err(corrupt());
    }
    if plain.len() as u64 > limit {
        let _ = ctx.budget.consume(limit);
        ctx.limit_exceeded(LimitExceeded::Decompression);
        return Ok(());
    }
    let _ = ctx.budget.consume(plain.len() as u64);
    if !payload::scan(&plain, Scope::Binary).is_empty() {
        ctx.findings.push(
            Finding::new(
                "image.metadata.payload",
                Severity::High,
                "code hidden in a compressed JPEG XL metadata box",
            )
            .at(body - 8),
        );
    }
    Ok(())
}

/// Width and height from the size header after the signature at `start`.
/// Fields are packed least significant bit first.
fn size_header(data: &[u8], start: usize) -> Result<(u64, u64), Malformed> {
    let bytes = &data[start + CODESTREAM_SIGNATURE.len()..];
    let mut at = 0usize;
    let mut bits = |count: usize| -> Option<u64> {
        let mut value = 0u64;
        for shift in 0..count {
            let bit = bytes.get(at / 8)? >> (at % 8) & 1;
            value |= (bit as u64) << shift;
            at += 1;
        }
        Some(value)
    };
    // Either a multiple of 8 up to 256, or a selector for the field width.
    let dimension = |small: bool, bits: &mut dyn FnMut(usize) -> Option<u64>| {
        if small {
            Some((bits(5)? + 1) * 8)
        } else {
            let width = [9, 13, 18, 30][bits(2)? as usize];
            Some(bits(width)? + 1)
        }
    };
    let read = (|| {
        let small = bits(1)? == 1;
        let height = dimension(small, &mut bits)?;
        // The width is either spelled out or follows from an aspect ratio.
        let width = match bits(3)? {
            0 => dimension(small, &mut bits)?,
            1 => height,
            2 => height * 12 / 10,
            3 => height * 4 / 3,
            4 => height * 3 / 2,
            5 => height * 16 / 9,
            6 => height * 5 / 4,
            _ => height * 2,
        };
        Some((width, height))
    })();
    read.ok_or(Malformed::truncated(data.len()))
}

#[cfg(test)]
mod tests {
    use super::super::isobmff::tests::boxed;
    use super::*;
    use crate::limits::{Budget, Limits};

    fn run(data: &[u8]) -> (Result<Layout, Malformed>, Vec<&'static str>) {
        run_within(data, &Limits::default())
    }

    fn run_within(data: &[u8], limits: &Limits) -> (Result<Layout, Malformed>, Vec<&'static str>) {
        let mut budget = Budget::new(limits);
        let mut findings = Vec::new();
        let mut ctx = Ctx {
            budget: &mut budget,
            findings: &mut findings,
        };
        let result = parse(data, &mut ctx);
        (result, findings.iter().map(|f| f.code).collect())
    }

    /// Pack `(value, width)` fields least significant bit first.
    fn pack(fields: &[(u64, usize)]) -> Vec<u8> {
        let mut out = CODESTREAM_SIGNATURE.to_vec();
        let mut at = 0;
        for &(value, width) in fields {
            for shift in 0..width {
                if at % 8 == 0 {
                    out.push(0);
                }
                *out.last_mut().unwrap() |= ((value >> shift & 1) as u8) << (at % 8);
                at += 1;
            }
        }
        out
    }

    /// A Brotli stream holding `data` (under 64 KiB) uncompressed.
    pub(crate) fn brotli_stored(data: &[u8]) -> Vec<u8> {
        // Window bits, not last, four length nibbles, the length, uncompressed.
        let header = (data.len() as u32 - 1) << 4 | 1 << 20;
        let mut out = header.to_le_bytes()[..3].to_vec();
        out.extend_from_slice(data);
        // A last, empty meta-block.
        out.push(3);
        out
    }

    fn compressed_box(kind: &[u8; 4], contents: &[u8]) -> Vec<u8> {
        boxed(b"brob", &[&kind[..], &brotli_stored(contents)].concat())
    }

    const SIGNATURE_BOX: &[u8] = b"\0\0\0\x0CJXL \r\n\x87\n";

    #[test]
    fn reads_every_size_encoding() {
        // Multiples of 8: height (4+1)*8, explicit width (9+1)*8.
        let small = pack(&[(1, 1), (4, 5), (0, 3), (9, 5)]);
        assert_eq!(run(&small).0.unwrap().dimensions, Some((80, 40)));
        // 13-bit height 3000, ratio 3 (4:3).
        let ratio = pack(&[(0, 1), (1, 2), (2999, 13), (3, 3)]);
        assert_eq!(run(&ratio).0.unwrap().dimensions, Some((4000, 3000)));
        // 30-bit fields.
        let huge = pack(&[(0, 1), (3, 2), (99_999, 30), (0, 3), (3, 2), (199_999, 30)]);
        let layout = run(&huge).0.unwrap();
        assert_eq!(layout.dimensions, Some((200_000, 100_000)));
        assert_eq!(layout.end, None);
        assert!(run(b"\xFF\x0A\x00").0.is_err());
    }

    #[test]
    fn reads_the_container() {
        let codestream = pack(&[(1, 1), (4, 5), (1, 3)]);
        let mut data = SIGNATURE_BOX.to_vec();
        data.extend(boxed(b"ftyp", b"jxl \0\0\0\0jxl "));
        data.extend(boxed(b"jxlc", &codestream));
        let end = data.len();
        data.extend_from_slice(b"\0\0\0\0<appended>");
        let (layout, findings) = run(&data);
        assert_eq!(
            layout,
            Ok(Layout {
                end: Some(end),
                dimensions: Some((40, 40)),
            })
        );
        assert!(findings.is_empty());

        // The codestream in parts, with compressed metadata between them.
        let mut parts = SIGNATURE_BOX.to_vec();
        parts.extend(boxed(b"jxlp", &[&[0; 4][..], &codestream].concat()));
        parts.extend(compressed_box(
            b"xml ",
            b"<x:xmpmeta>a photograph</x:xmpmeta>",
        ));
        parts.extend(boxed(b"jxlp", b"\x80\0\0\x01rest"));
        let (layout, findings) = run(&parts);
        assert_eq!(layout.unwrap().dimensions, Some((40, 40)));
        assert!(findings.is_empty());
    }

    #[test]
    fn searches_compressed_metadata() {
        let container = |metadata: Vec<u8>| {
            let mut data = SIGNATURE_BOX.to_vec();
            data.extend(boxed(b"jxlc", &pack(&[(1, 1), (4, 5), (1, 3)])));
            data.extend(metadata);
            data
        };
        let hidden = container(compressed_box(b"xml ", b"<?php system($_GET['c']); ?>"));
        let (layout, findings) = run(&hidden);
        assert!(layout.is_ok());
        assert_eq!(findings, ["image.metadata.payload"]);

        let corrupt = container(boxed(b"brob", b"Exif\xFF\xFF\xFF\xFF"));
        assert_eq!(
            run(&corrupt).0.unwrap_err().reason,
            "corrupt compressed metadata box"
        );
        let empty = container(boxed(b"brob", b"Ex"));
        assert!(run(&empty).0.is_err());

        let limits = Limits {
            max_decompressed: 100,
            ..Limits::default()
        };
        let large = container(compressed_box(b"Exif", &[b'a'; 1000]));
        assert_eq!(run_within(&large, &limits).1, ["limit.decompression"]);
    }

    #[test]
    fn rejects_broken_containers() {
        let mut empty = SIGNATURE_BOX.to_vec();
        empty.extend(boxed(b"ftyp", b"jxl \0\0\0\0jxl "));
        assert_eq!(
            run(&empty).0.unwrap_err().reason,
            "JPEG XL container has no codestream"
        );
        let mut other = empty.clone();
        other.extend(boxed(b"jxlc", b"not a codestream"));
        assert_eq!(
            run(&other).0.unwrap_err().reason,
            "JPEG XL codestream is malformed"
        );
        let mut cut = empty;
        cut.extend(boxed(b"jxlc", b"\xFF\x0A"));
        cut.extend_from_slice(b"\0\0\x10\0jxlp");
        assert!(run(&cut).0.is_err());
    }
}
