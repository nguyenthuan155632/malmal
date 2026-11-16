//! GIF, written again from its own palettes and indices.
//!
//! Every frame keeps its place, size, colour table, transparent index,
//! delay and disposal; its indices are compressed anew. Nothing else of the
//! file is carried over: comments, application extensions other than the
//! loop count, plain text extensions, bytes after the trailer. Decoding a
//! GIF to full colour and quantising it again would change pixels wherever
//! frames laid over one another show more than 256 colours, and would store
//! every frame whole. A colour profile is applied to the colour tables, or
//! kept, written anew, if it is to be.

use std::io::Cursor;
use std::num::NonZeroU64;

use gif::{ColorOutput, DecodeOptions, Encoder, MemoryLimit, Repeat};
use moxcms::Layout;

use super::{Deadline, Error, Limits, Rebuilt, ToSrgb, colour};
use crate::detect::FileType;

fn decode_error(error: gif::DecodingError) -> Error {
    match error {
        gif::DecodingError::MemoryLimit => Error::TooLarge,
        other => Error::Decode(other.to_string()),
    }
}

fn encode_error(error: gif::EncodingError) -> Error {
    Error::Encode(error.to_string())
}

/// The GIF in `data`, rebuilt; its colours kept in a profile other than
/// sRGB's if `keep_profile` and it can be written anew.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_profile: bool,
) -> Result<Rebuilt, Error> {
    let mut options = DecodeOptions::new();
    options.set_color_output(ColorOutput::Indexed);
    options.set_memory_limit(match NonZeroU64::new(limits.max_decompressed) {
        Some(bytes) => MemoryLimit::Bytes(bytes),
        None => return Err(Error::TooLarge),
    });
    let mut decoder = options.read_info(Cursor::new(data)).map_err(decode_error)?;
    let (width, height) = (decoder.width(), decoder.height());
    if width == 0 || height == 0 {
        return Err(Error::Decode("image has a zero dimension".into()));
    }
    if width as u64 * height as u64 > limits.max_pixels {
        return Err(Error::TooLarge);
    }

    let mut frames = Vec::new();
    let mut held = 0u64;
    while let Some(frame) = decoder.read_next_frame().map_err(decode_error)? {
        deadline.check()?;
        held += frame.buffer.len() as u64;
        if held > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        let mut frame = frame.clone();
        // The decoder hands the rows over in order; they are written so.
        frame.interlaced = false;
        frames.push(frame);
    }
    if frames.is_empty() {
        return Err(Error::Decode("image has no frames".into()));
    }

    // A colour profile is applied to the colour tables, which hold every
    // colour the pixels can have.
    let mut global = decoder.global_palette().map(<[u8]>::to_vec);
    let icc = decoder.icc_profile().map(<[u8]>::to_vec);
    let kept = icc
        .as_deref()
        .filter(|icc| keep_profile && ToSrgb::new(Some(icc.to_vec())).is_some())
        .and_then(colour::rewritten_rgb);
    if kept.is_none()
        && let Some(colors) = ToSrgb::new(icc)
    {
        if colors.grey {
            return Err(Error::Decode("a GIF with a grey colour profile".into()));
        }
        let tables = global
            .iter_mut()
            .chain(frames.iter_mut().filter_map(|f| f.palette.as_mut()));
        for table in tables {
            let whole = table.len() / 3 * 3;
            colors
                .eight(&mut table[..whole], Layout::Rgb)
                .ok_or_else(|| Error::Decode("colour profile does not apply".into()))?;
        }
    }

    let mut out = Vec::new();
    {
        let mut encoder = Encoder::new(&mut out, width, height, global.as_deref().unwrap_or(&[]))
            .map_err(encode_error)?;
        // The decoder says `Finite(0)` when the file has no loop count: it
        // plays once, and a loop count of 0 would make it play for ever.
        match decoder.repeat() {
            Repeat::Finite(0) => {}
            repeat => encoder.set_repeat(repeat).map_err(encode_error)?,
        }
        // The profile as an application extension, in blocks of 255.
        if let Some(icc) = &kept {
            let mut blocks: Vec<&[u8]> = vec![b"ICCRGBG1012"];
            blocks.extend(icc.chunks(255));
            encoder
                .write_raw_extension(gif::Extension::Application.into(), &blocks)
                .map_err(encode_error)?;
        }
        for frame in &frames {
            deadline.check()?;
            encoder.write_frame(frame).map_err(encode_error)?;
        }
    }
    Ok(Rebuilt {
        data: out,
        file_type: FileType::Gif,
        width: width.into(),
        height: height.into(),
        frames: frames.len() as u32,
    })
}
