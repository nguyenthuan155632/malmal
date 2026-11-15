//! A lossy WebP file put together anew around its pictures rewritten.
//!
//! Each VP8 picture is written again symbol for symbol (see `vp8`), its
//! transparency is coded again without loss from what it decodes to, and
//! the container is built from nothing but the size of the canvas, and,
//! for an animation, the number of plays, its background and where, how
//! long and how each frame is drawn. Metadata, unknown chunks and whatever
//! follows a chunk are left behind. The file is kept only if it decodes to
//! every pixel the original does; otherwise the caller rebuilds from pixels.

use std::io::Cursor;

use image::codecs::webp::{WebPDecoder, WebPEncoder};
use image::metadata::Orientation;
use image::{AnimationDecoder, DynamicImage, ExtendedColorType, ImageDecoder};

use super::{Deadline, Error, Rebuilt, ToSrgb, riff_chunk, vp8, vp8l_chunk};
use crate::detect::FileType;
use crate::limits::Limits;

fn broken() -> Error {
    Error::Decode("WebP container is broken".into())
}

/// The chunks of a RIFF body, by name.
/// Chunks by name, each with its payload.
type Chunks<'a> = Vec<(&'a [u8], &'a [u8])>;

fn chunks(mut body: &[u8]) -> Result<Chunks<'_>, Error> {
    let mut found = Vec::new();
    while body.len() >= 8 {
        let length = u32::from_le_bytes(body[4..8].try_into().map_err(|_| broken())?) as usize;
        let payload = body.get(8..8 + length).ok_or_else(broken)?;
        found.push((&body[..4], payload));
        body = body.get(8 + length + length % 2..).unwrap_or_default();
    }
    Ok(found)
}

/// One picture: its VP8 frame, and its transparency coded or not.
struct Picture<'a> {
    vp8: &'a [u8],
    alpha: Option<&'a [u8]>,
}

impl<'a> Picture<'a> {
    /// The picture among `chunks`, if it is lossy.
    fn among(chunks: &[(&'a [u8], &'a [u8])]) -> Option<Self> {
        let find = |name: &[u8]| chunks.iter().find(|(n, _)| *n == name).map(|(_, p)| *p);
        if find(b"VP8L").is_some() {
            return None;
        }
        Some(Self {
            vp8: find(b"VP8 ")?,
            alpha: find(b"ALPH"),
        })
    }

    /// The size its frame says it is.
    fn size(&self) -> Result<(u32, u32), Error> {
        let header = self.vp8.get(6..10).ok_or_else(broken)?;
        let width = u16::from_le_bytes([header[0], header[1]]) & 0x3FFF;
        let height = u16::from_le_bytes([header[2], header[3]]) & 0x3FFF;
        Ok((width.into(), height.into()))
    }

    /// Its chunks written anew: transparency, then the frame.
    fn rewritten(&self, deadline: Deadline) -> Result<(Vec<u8>, bool), Error> {
        let mut out = Vec::new();
        if let Some(alpha) = self.alpha {
            let (width, height) = self.size()?;
            let levels = alpha_of(alpha, self.vp8, width, height)?;
            riff_chunk(&mut out, b"ALPH", &alpha_chunk(&levels, width, height)?)?;
        }
        riff_chunk(&mut out, b"VP8 ", &vp8::rewrite(self.vp8, deadline)?)?;
        Ok((out, self.alpha.is_some()))
    }
}

/// The transparency of a picture, as a WebP decoder reads it.
fn alpha_of(alpha: &[u8], vp8: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let size = |v: u32| v.saturating_sub(1).to_le_bytes();
    let (w, h) = (size(width), size(height));
    let mut body = b"WEBP".to_vec();
    riff_chunk(
        &mut body,
        b"VP8X",
        &[0x10, 0, 0, 0, w[0], w[1], w[2], h[0], h[1], h[2]],
    )?;
    riff_chunk(&mut body, b"ALPH", alpha)?;
    riff_chunk(&mut body, b"VP8 ", vp8)?;
    let mut file = Vec::new();
    riff_chunk(&mut file, b"RIFF", &body)?;
    let decoder = WebPDecoder::new(Cursor::new(file)).map_err(super::decode_error)?;
    let image = DynamicImage::from_decoder(decoder).map_err(super::decode_error)?;
    Ok(image.into_rgba8().pixels().map(|p| p[3]).collect())
}

/// An `ALPH` payload of `levels`: lossless, or as they are if that is
/// smaller. Neither filtered nor marked as reduced.
fn alpha_chunk(levels: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let mut file = Vec::new();
    WebPEncoder::new_lossless(&mut file)
        .encode(levels, width, height, ExtendedColorType::L8)
        .map_err(super::encode_error)?;
    // A lossless stream without its five bytes of signature and size.
    let packed = vp8l_chunk(&file)
        .and_then(|stream| stream.get(5..))
        .filter(|stream| stream.len() < levels.len());
    Ok(match packed {
        Some(stream) => [&[1][..], stream].concat(),
        None => [&[0][..], levels].concat(),
    })
}

/// The lossy WebP in `data` rebuilt around its pictures, or `None` if it is
/// not lossy, or shows other than what its pictures code: colours of a
/// profile other than sRGB's, or turned by its metadata.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
) -> Result<Option<Rebuilt>, Error> {
    if data.get(..4) != Some(b"RIFF") || data.get(8..12) != Some(b"WEBP") {
        return Err(broken());
    }
    let length = u32::from_le_bytes(data[4..8].try_into().map_err(|_| broken())?) as usize;
    let body = data
        .get(12..8 + length.max(4))
        .or_else(|| data.get(12..))
        .ok_or_else(broken)?;
    let found = chunks(body)?;

    let mut decoder = WebPDecoder::new(Cursor::new(data)).map_err(super::decode_error)?;
    let icc = decoder.icc_profile().map_err(super::decode_error)?;
    if icc.is_some_and(|icc| ToSrgb::new(Some(icc)).is_some())
        || decoder
            .orientation()
            .is_ok_and(|o| o != Orientation::NoTransforms)
    {
        return Ok(None);
    }
    let (width, height) = decoder.dimensions();
    let animated = decoder.has_animation();

    let mut body = b"WEBP".to_vec();
    let mut frames = 1;
    if animated {
        let anim = found
            .iter()
            .find(|(n, _)| *n == b"ANIM")
            .map(|(_, p)| *p)
            .and_then(|p| p.get(..6))
            .ok_or_else(broken)?;
        let mut chunks_out = Vec::new();
        riff_chunk(&mut chunks_out, b"ANIM", anim)?;
        let mut transparent = false;
        frames = 0;
        for (_, frame) in found.iter().filter(|(n, _)| *n == b"ANMF") {
            deadline.check()?;
            let placing = frame.get(..16).ok_or_else(broken)?;
            let inner = chunks(&frame[16..])?;
            let Some(picture) = Picture::among(&inner) else {
                return Ok(None);
            };
            let (rewritten, alpha) = picture.rewritten(deadline)?;
            transparent |= alpha;
            // Where, how long and how it is drawn, without the bits that
            // mean nothing.
            let mut out = placing[..15].to_vec();
            out.push(placing[15] & 0b11);
            out.extend_from_slice(&rewritten);
            riff_chunk(&mut chunks_out, b"ANMF", &out)?;
            frames += 1;
        }
        if frames == 0 {
            return Err(broken());
        }
        let size = |v: u32| v.saturating_sub(1).to_le_bytes();
        let (w, h) = (size(width), size(height));
        let flags = 0x02 | if transparent { 0x10 } else { 0 };
        riff_chunk(
            &mut body,
            b"VP8X",
            &[flags, 0, 0, 0, w[0], w[1], w[2], h[0], h[1], h[2]],
        )?;
        body.extend_from_slice(&chunks_out);
    } else {
        let Some(picture) = Picture::among(&found) else {
            return Ok(None);
        };
        let (rewritten, alpha) = picture.rewritten(deadline)?;
        if alpha {
            let size = |v: u32| v.saturating_sub(1).to_le_bytes();
            let (w, h) = (size(width), size(height));
            riff_chunk(
                &mut body,
                b"VP8X",
                &[0x10, 0, 0, 0, w[0], w[1], w[2], h[0], h[1], h[2]],
            )?;
        }
        body.extend_from_slice(&rewritten);
    }
    let pixels = u64::from(width) * u64::from(height) * u64::from(frames);
    if pixels > limits.max_pixels || pixels.saturating_mul(4) > limits.max_decompressed {
        return Err(Error::TooLarge);
    }
    let mut file = Vec::with_capacity(body.len() + 8);
    riff_chunk(&mut file, b"RIFF", &body)?;

    deadline.check()?;
    if !same(data, &file, animated)? {
        return Ok(None);
    }
    Ok(Some(Rebuilt {
        data: file,
        file_type: FileType::Webp,
        width,
        height,
        frames,
    }))
}

/// Whether two WebP files decode to the same pixels, frame for frame.
fn same(one: &[u8], other: &[u8], animated: bool) -> Result<bool, Error> {
    let open =
        |data: &[u8]| WebPDecoder::new(Cursor::new(data.to_vec())).map_err(super::decode_error);
    if !animated {
        let read = |data: &[u8]| -> Result<DynamicImage, Error> {
            DynamicImage::from_decoder(open(data)?).map_err(super::decode_error)
        };
        let (one, other) = (read(one)?, read(other)?);
        return Ok(one.color() == other.color() && one.as_bytes() == other.as_bytes());
    }
    let mut one = open(one)?.into_frames();
    let mut other = open(other)?.into_frames();
    loop {
        match (one.next(), other.next()) {
            (None, None) => return Ok(true),
            (Some(a), Some(b)) => {
                let (a, b) = (
                    a.map_err(super::decode_error)?,
                    b.map_err(super::decode_error)?,
                );
                if a.delay() != b.delay() || a.buffer() != b.buffer() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
}
