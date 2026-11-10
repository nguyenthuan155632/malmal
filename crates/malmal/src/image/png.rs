use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_zlib_with_limit};

use super::{Ctx, Layout, Malformed, be32};
use crate::limits::LimitExceeded;
use crate::payload::{self, Scope};
use crate::report::{Finding, Severity};

const SIGNATURE_LEN: usize = 8;
/// No legitimate text or colour profile chunk inflates to more than this.
const MAX_INFLATED_CHUNK: u64 = 16 << 20;

pub(crate) fn parse(data: &[u8], ctx: &mut Ctx<'_>) -> Result<Layout, Malformed> {
    let mut pos = SIGNATURE_LEN;
    let mut dimensions = None;
    let mut seen_image_data = false;
    loop {
        let length = be32(data, pos).ok_or(Malformed::truncated(pos))? as usize;
        let body_start = pos + 8;
        let body_end = body_start + length;
        let Some(stored_crc) = be32(data, body_end) else {
            return Err(Malformed::truncated(pos));
        };
        let kind = &data[pos + 4..body_start];
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return Err(Malformed::new(pos, "invalid PNG chunk type"));
        }
        // A fuzzer cannot guess checksums; let it past them to reach the rest.
        if !cfg!(fuzzing) && crc32(&data[pos + 4..body_end]) != stored_crc {
            return Err(Malformed::new(pos, "PNG chunk checksum mismatch"));
        }
        let body = &data[body_start..body_end];

        if pos == SIGNATURE_LEN {
            if kind != b"IHDR" || length != 13 {
                return Err(Malformed::new(pos, "PNG does not start with an IHDR chunk"));
            }
            let width = be32(body, 0).unwrap_or(0);
            let height = be32(body, 4).unwrap_or(0);
            dimensions = Some((width as u64, height as u64));
        }
        match kind {
            b"IDAT" => seen_image_data = true,
            b"IEND" => {
                if !seen_image_data {
                    return Err(Malformed::new(pos, "PNG has no image data"));
                }
                return Ok(Layout {
                    end: Some(body_end + 4),
                    dimensions,
                });
            }
            b"zTXt" | b"iTXt" | b"iCCP" => {
                if let Some(compressed) = compressed_part(kind, body) {
                    scan_compressed(compressed, pos, ctx)?;
                }
            }
            _ => {}
        }
        pos = body_end + 4;
    }
}

/// The zlib stream inside a text or profile chunk, if it has one.
fn compressed_part<'a>(kind: &[u8], body: &'a [u8]) -> Option<&'a [u8]> {
    let after_nul = |bytes: &'a [u8]| {
        let nul = bytes.iter().position(|&b| b == 0)?;
        bytes.get(nul + 1..)
    };
    let rest = after_nul(body)?;
    if kind == b"iTXt" {
        // compression flag, method, language\0, translated keyword\0, text
        let (&flag, rest) = rest.split_first()?;
        if flag != 1 {
            return None;
        }
        after_nul(after_nul(rest.get(1..)?)?)
    } else {
        // compression method, data
        rest.get(1..)
    }
}

/// Inflate a chunk under the scan budget and look for code in the result;
/// uncompressed chunks are already covered by the whole-file payload scan.
fn scan_compressed(compressed: &[u8], chunk: usize, ctx: &mut Ctx<'_>) -> Result<(), Malformed> {
    let limit = ctx.budget.remaining().min(MAX_INFLATED_CHUNK);
    match decompress_to_vec_zlib_with_limit(compressed, limit as usize) {
        Ok(inflated) => {
            let _ = ctx.budget.consume(inflated.len() as u64);
            if !payload::scan(&inflated, Scope::Binary).is_empty() {
                ctx.findings.push(
                    Finding::new(
                        "image.metadata.payload",
                        Severity::High,
                        "code hidden in a compressed PNG metadata chunk",
                    )
                    .at(chunk),
                );
            }
            Ok(())
        }
        Err(error) if error.status == TINFLStatus::HasMoreOutput => {
            let _ = ctx.budget.consume(limit);
            ctx.limit_exceeded(LimitExceeded::Decompression);
            Ok(())
        }
        Err(_) => Err(Malformed::new(chunk, "corrupt compressed PNG chunk")),
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        CRC_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8)
    })
}

#[cfg(test)]
mod tests {
    use miniz_oxide::deflate::compress_to_vec_zlib;

    use super::*;
    use crate::limits::{Budget, Limits};

    fn chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out.extend_from_slice(&crc32(&out[4..]).to_be_bytes());
        out
    }

    fn png(extra: &[u8]) -> Vec<u8> {
        let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
        data.extend(chunk(b"IHDR", b"\0\0\0\x04\0\0\0\x03\x08\x06\0\0\0"));
        data.extend_from_slice(extra);
        data.extend(chunk(b"IDAT", b"\x78\x9c\x63\x00\x00\x00\x01\x00\x01"));
        data.extend(chunk(b"IEND", b""));
        data
    }

    fn run(data: &[u8], limits: &Limits) -> (Result<Layout, Malformed>, Vec<&'static str>) {
        let mut budget = Budget::new(limits);
        let mut findings = Vec::new();
        let result = parse(
            data,
            &mut Ctx {
                budget: &mut budget,
                findings: &mut findings,
            },
        );
        (result, findings.iter().map(|f| f.code).collect())
    }

    fn ztxt(text: &[u8]) -> Vec<u8> {
        let mut body = b"Comment\0\0".to_vec();
        body.extend(compress_to_vec_zlib(text, 6));
        chunk(b"zTXt", &body)
    }

    #[test]
    fn crc_matches_reference_value() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }

    #[test]
    fn finds_end_and_dimensions() {
        let mut data = png(b"");
        let end = data.len();
        data.extend_from_slice(b"appended");
        let (result, findings) = run(&data, &Limits::default());
        assert_eq!(
            result,
            Ok(Layout {
                end: Some(end),
                dimensions: Some((4, 3)),
            })
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_corruption() {
        let limits = Limits::default();
        let data = png(b"");
        assert!(run(&data[..data.len() - 1], &limits).0.is_err());

        let mut bad_crc = data.clone();
        bad_crc[20] ^= 1;
        assert_eq!(
            run(&bad_crc, &limits).0.unwrap_err().reason,
            "PNG chunk checksum mismatch"
        );

        let mut no_idat = b"\x89PNG\r\n\x1a\n".to_vec();
        no_idat.extend(chunk(b"IHDR", &[0; 13]));
        no_idat.extend(chunk(b"IEND", b""));
        assert!(run(&no_idat, &limits).0.is_err());
    }

    #[test]
    fn finds_code_in_compressed_text() {
        let limits = Limits::default();
        let (result, findings) = run(&png(&ztxt(b"<?php system($_GET[0]);")), &limits);
        assert!(result.is_ok());
        assert_eq!(findings, ["image.metadata.payload"]);

        let (_, findings) = run(&png(&ztxt(b"Taken in Da Nang, 2026")), &limits);
        assert!(findings.is_empty());

        let mut itxt = b"XML:com.adobe.xmp\0\x01\0en\0\0".to_vec();
        itxt.extend(compress_to_vec_zlib(b"<a href='javascript:alert(1)'>", 6));
        let (_, findings) = run(&png(&chunk(b"iTXt", &itxt)), &limits);
        assert_eq!(findings, ["image.metadata.payload"]);
    }

    #[test]
    fn decompression_bomb_hits_the_budget() {
        let limits = Limits {
            max_decompressed: 1024,
            ..Limits::default()
        };
        let (result, findings) = run(&png(&ztxt(&vec![b'A'; 100_000])), &limits);
        assert!(result.is_ok());
        assert_eq!(findings, ["limit.decompression"]);
    }

    #[test]
    fn corrupt_compressed_chunk_is_malformed() {
        let (result, _) = run(
            &png(&chunk(b"zTXt", b"Comment\0\0not zlib")),
            &Limits::default(),
        );
        assert_eq!(result.unwrap_err().reason, "corrupt compressed PNG chunk");
    }
}
