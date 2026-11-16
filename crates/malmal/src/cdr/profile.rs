//! A colour profile, written anew, put into a rebuilt PNG, JPEG or WebP,
//! for pixels that are kept in the colours it describes.

use super::{Rebuilt, riff_chunk};
use crate::detect::FileType;

/// The CRC of PNG chunks (ISO 3309).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `rebuilt` with the profile `icc` in it, or `None` if its file cannot
/// carry one for its pixels: a profile of grey for pixels in colour, or of
/// colours for grey ones, a WebP (always in colour) under one of grey, or
/// a type other than these.
pub(super) fn attach(rebuilt: Rebuilt, icc: &[u8]) -> Option<Rebuilt> {
    let grey = super::colour::is_grey(icc);
    let data = match rebuilt.file_type {
        FileType::Png => png(&rebuilt.data, icc, grey)?,
        FileType::Jpeg => jpeg(&rebuilt.data, icc, grey)?,
        FileType::Webp if !grey => webp(&rebuilt.data, icc, rebuilt.width, rebuilt.height)?,
        _ => return None,
    };
    Some(Rebuilt { data, ..rebuilt })
}

/// `rebuilt`, a PNG, with a `cICP` chunk after its header: primaries,
/// transfer, matrix and range, as ITU-T H.273 numbers them.
pub(super) fn cicp(rebuilt: Rebuilt, cicp: [u8; 4]) -> Option<Rebuilt> {
    if rebuilt.file_type != FileType::Png {
        return None;
    }
    let data = png_chunk(&rebuilt.data, b"cICP", &cicp)?;
    Some(Rebuilt { data, ..rebuilt })
}

/// The PNG `data` with a chunk `name` of `body` after its header.
fn png_chunk(data: &[u8], name: &[u8; 4], body: &[u8]) -> Option<Vec<u8>> {
    // Signature, then the header chunk of 13 bytes and its length, name
    // and CRC.
    let header_end = 8 + 8 + 13 + 4;
    if data.get(12..16)? != b"IHDR" {
        return None;
    }
    let mut chunk = u32::try_from(body.len()).ok()?.to_be_bytes().to_vec();
    chunk.extend_from_slice(name);
    chunk.extend_from_slice(body);
    let crc = crc32(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    Some([data.get(..header_end)?, &chunk, &data[header_end..]].concat())
}

/// An `iCCP` chunk after the header, which has to say the pixels are of
/// the kind the profile is for: an RGB profile says nothing of grey, nor a
/// grey one of colours.
fn png(data: &[u8], icc: &[u8], grey: bool) -> Option<Vec<u8>> {
    let fits = match data.get(25)? {
        0 | 4 => grey,
        2 | 3 | 6 => !grey,
        _ => false,
    };
    if !fits {
        return None;
    }
    let mut body = b"ICC Profile\0\0".to_vec();
    body.extend_from_slice(&miniz_oxide::deflate::compress_to_vec_zlib(icc, 9));
    png_chunk(data, b"iCCP", &body)
}

/// `APP2` segments after the first segment, which is the `JFIF` or
/// `Adobe` one the encoders here write.
fn jpeg(data: &[u8], icc: &[u8], grey: bool) -> Option<Vec<u8>> {
    if data.get(..2)? != [0xFF, 0xD8] || !matches!(data.get(3)?, 0xE0 | 0xEE) {
        return None;
    }
    // One component for a profile of grey, three for one of colours.
    if (components(data)? == 1) != grey {
        return None;
    }
    let first = 4 + usize::from(u16::from_be_bytes([*data.get(4)?, *data.get(5)?]));
    let mut out = data.get(..first)?.to_vec();
    let pieces = icc.chunks(65_519);
    let count = u8::try_from(pieces.len()).ok()?;
    for (index, piece) in pieces.enumerate() {
        out.extend_from_slice(&[0xFF, 0xE2]);
        out.extend_from_slice(&u16::try_from(piece.len() + 16).ok()?.to_be_bytes());
        out.extend_from_slice(b"ICC_PROFILE\0");
        out.extend_from_slice(&[index as u8 + 1, count]);
        out.extend_from_slice(piece);
    }
    out.extend_from_slice(&data[first..]);
    Some(out)
}

/// The number of components of the frame of a JPEG.
fn components(data: &[u8]) -> Option<u8> {
    let mut at = 2;
    loop {
        if *data.get(at)? != 0xFF {
            return None;
        }
        let marker = *data.get(at + 1)?;
        let length = usize::from(u16::from_be_bytes([*data.get(at + 2)?, *data.get(at + 3)?]));
        if matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            return data.get(at + 9).copied();
        }
        at += 2 + length;
    }
}

/// The chunks of a WebP file after its header, by name.
fn chunks(file: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut rest = file.get(12..)?;
    let mut found = Vec::new();
    while !rest.is_empty() {
        let length = u32::from_le_bytes(rest.get(4..8)?.try_into().ok()?) as usize;
        found.push((rest.get(..4)?, rest.get(8..8 + length)?));
        rest = rest.get(8 + length + length % 2..).unwrap_or_default();
    }
    Some(found)
}

/// A WebP still with an `ICCP` chunk, and the `EXIF` chunk `exif` if one
/// is given, laid out as the extended format has them.
pub(super) fn webp_with(
    data: &[u8],
    icc: Option<&[u8]>,
    exif: Option<&[u8]>,
    width: u32,
    height: u32,
) -> Option<Vec<u8>> {
    if data.get(..4)? != b"RIFF" || data.get(8..12)? != b"WEBP" {
        return None;
    }
    let found = chunks(data)?;
    let mut flags = 0u8;
    let mut pictures = Vec::new();
    for (name, payload) in &found {
        match *name {
            b"VP8X" => flags |= payload.first()? & 0x10,
            b"ALPH" | b"VP8 " => pictures.push((*name, *payload)),
            b"VP8L" => {
                // A lossless picture says in its header whether it uses
                // transparency.
                let header = u32::from_le_bytes(payload.get(1..5)?.try_into().ok()?);
                if header >> 28 & 1 == 1 {
                    flags |= 0x10;
                }
                pictures.push((*name, *payload));
            }
            // A rebuilt still has nothing else.
            _ => return None,
        }
    }
    if icc.is_some() {
        flags |= 0x20;
    }
    if exif.is_some() {
        flags |= 0x08;
    }
    let size = |v: u32| v.saturating_sub(1).to_le_bytes();
    let (w, h) = (size(width), size(height));
    let mut body = b"WEBP".to_vec();
    riff_chunk(
        &mut body,
        b"VP8X",
        &[flags, 0, 0, 0, w[0], w[1], w[2], h[0], h[1], h[2]],
    )
    .ok()?;
    if let Some(icc) = icc {
        riff_chunk(&mut body, b"ICCP", icc).ok()?;
    }
    for (name, payload) in pictures {
        riff_chunk(&mut body, name.try_into().ok()?, payload).ok()?;
    }
    if let Some(exif) = exif {
        riff_chunk(&mut body, b"EXIF", exif).ok()?;
    }
    let mut file = Vec::with_capacity(body.len() + 8);
    riff_chunk(&mut file, b"RIFF", &body).ok()?;
    Some(file)
}

fn webp(data: &[u8], icc: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    webp_with(data, Some(icc), None, width, height)
}

/// Exif of nothing but an orientation, 1 to 8: a TIFF header and one
/// directory of one entry.
pub(super) fn orientation_exif(orientation: u16) -> Vec<u8> {
    let mut exif = b"II*\0".to_vec();
    exif.extend_from_slice(&8u32.to_le_bytes());
    exif.extend_from_slice(&1u16.to_le_bytes());
    // Orientation, SHORT, one of them, in the entry itself.
    exif.extend_from_slice(&0x0112u16.to_le_bytes());
    exif.extend_from_slice(&3u16.to_le_bytes());
    exif.extend_from_slice(&1u32.to_le_bytes());
    exif.extend_from_slice(&orientation.to_le_bytes());
    exif.extend_from_slice(&[0, 0]);
    // No directory follows.
    exif.extend_from_slice(&0u32.to_le_bytes());
    exif
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_of_a_png_end_chunk() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }
}
