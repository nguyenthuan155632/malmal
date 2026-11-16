//! Animated PNG, written again frame by frame as the file has them.
//!
//! Each frame keeps its samples, colour type and depth (a palette, 16 bits,
//! fewer than 8), its place and size, its delay and how it is blended and
//! disposed of; a first image that is no part of the animation stays so.
//! Laid over one another and written whole at 8 bits, as they were before,
//! frames lost half their bits and took more room.

use std::io::Cursor;

use moxcms::Layout;
use png::{BitDepth, ColorType, Transformations};

use super::{Deadline, Error, Limits, Rebuilt, ToSrgb, colour, profile};
use crate::detect::FileType;

fn decode_error(error: png::DecodingError) -> Error {
    match error {
        png::DecodingError::LimitsExceeded => Error::TooLarge,
        other => Error::Decode(other.to_string()),
    }
}

fn encode_error(error: png::EncodingError) -> Error {
    Error::Encode(error.to_string())
}

/// What a colour profile does to the samples of an image.
enum Profile {
    /// Nothing: there is none, or it is not for this kind of image.
    None,
    /// Through the colour table.
    Palette(ToSrgb),
    /// Sample by sample.
    Samples(ToSrgb, Layout),
}

fn profile(info: &png::Info<'_>) -> Result<Profile, Error> {
    let Some(colors) = ToSrgb::new(info.icc_profile.as_ref().map(|icc| icc.to_vec())) else {
        return Ok(Profile::None);
    };
    let keyed = info.trns.is_some();
    let deep = matches!(info.bit_depth, BitDepth::Eight | BitDepth::Sixteen);
    Ok(match (info.color_type, colors.grey) {
        (ColorType::Indexed, false) => Profile::Palette(colors),
        (ColorType::Rgb, false) if !keyed => Profile::Samples(colors, Layout::Rgb),
        (ColorType::Rgba, false) => Profile::Samples(colors, Layout::Rgba),
        (ColorType::Grayscale, true) if deep && !keyed => Profile::Samples(colors, Layout::Gray),
        (ColorType::GrayscaleAlpha, true) => Profile::Samples(colors, Layout::GrayAlpha),
        // A colour that marks transparency would have to be moved with the
        // rest, and might then mark pixels it did not; grey of fewer than 8
        // bits would come out of the profile at 8.
        (ColorType::Rgb, false) | (ColorType::Grayscale, true) => {
            return Err(Error::Decode(
                "colour profile cannot be applied as stored".into(),
            ));
        }
        // A profile for grey says nothing of colours, nor one for colours
        // of grey.
        _ => Profile::None,
    })
}

/// Apply `colors` to the samples of one frame, of `depth` bits each.
fn convert(
    colors: &ToSrgb,
    layout: Layout,
    samples: &mut [u8],
    depth: BitDepth,
) -> Result<(), Error> {
    let failed = || Error::Decode("colour profile does not apply".into());
    if depth == BitDepth::Sixteen {
        let mut wide: Vec<u16> = samples
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        colors.sixteen(&mut wide, layout).ok_or_else(failed)?;
        for (pair, sample) in samples.as_chunks_mut::<2>().0.iter_mut().zip(wide) {
            *pair = sample.to_be_bytes();
        }
        Ok(())
    } else {
        colors.eight(samples, layout).ok_or_else(failed)
    }
}

/// The animated PNG in `data`, rebuilt; its colours or shades kept in a
/// profile other than sRGB's if `keep_profile` and it can be written anew.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_profile: bool,
) -> Result<Rebuilt, Error> {
    let mut decoder = png::Decoder::new_with_limits(
        Cursor::new(data),
        png::Limits {
            bytes: usize::try_from(limits.max_decompressed).unwrap_or(usize::MAX),
        },
    );
    decoder.set_transformations(Transformations::IDENTITY);
    let mut reader = decoder.read_info().map_err(decode_error)?;
    let info = reader.info();
    let (width, height) = (info.width, info.height);
    if width == 0 || height == 0 {
        return Err(Error::Decode("image has a zero dimension".into()));
    }
    if width as u64 * height as u64 > limits.max_pixels {
        return Err(Error::TooLarge);
    }
    let control = info
        .animation_control()
        .ok_or_else(|| Error::Decode("image is not animated".into()))?;
    let (count, plays) = (control.num_frames, control.num_plays);
    // A first image without frame control is shown by viewers that do not
    // animate, and is no part of the animation.
    let still_first = info.frame_control().is_none();
    let (color, depth) = (info.color_type, info.bit_depth);
    let pixel_dims = info.pixel_dims;
    let mut palette = info.palette.as_ref().map(|p| p.to_vec());
    let trns = info.trns.as_ref().map(|t| t.to_vec());
    let grey = matches!(color, ColorType::Grayscale | ColorType::GrayscaleAlpha);
    let kept = info
        .icc_profile
        .as_ref()
        .filter(|icc| keep_profile && ToSrgb::new(Some(icc.to_vec())).is_some())
        .and_then(|icc| colour::rewritten_screen(icc, if grey { 1 } else { 3 }));
    let profile = match kept {
        Some(_) => Profile::None,
        None => profile(info)?,
    };
    if let (Profile::Palette(colors), Some(palette)) = (&profile, palette.as_mut()) {
        let whole = palette.len() / 3 * 3;
        colors
            .eight(&mut palette[..whole], Layout::Rgb)
            .ok_or_else(|| Error::Decode("colour profile does not apply".into()))?;
    }

    let size = reader.output_buffer_size().ok_or(Error::TooLarge)?;
    let mut buffer = vec![0; size];
    // Every frame is held until the file is written.
    let mut images: Vec<(Option<png::FrameControl>, Vec<u8>)> = Vec::new();
    let mut held = 0u64;
    let total = count as usize + usize::from(still_first);
    for _ in 0..total {
        deadline.check()?;
        let read = reader.next_frame(&mut buffer).map_err(decode_error)?;
        let mut samples = buffer[..read.buffer_size()].to_vec();
        held += samples.len() as u64;
        if held > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        if let Profile::Samples(colors, layout) = &profile {
            convert(colors, *layout, &mut samples, depth)?;
        }
        let control = reader.info().frame_control().copied();
        // The first image of all is the one without frame control.
        let control = if still_first && images.is_empty() {
            None
        } else {
            Some(control.ok_or_else(|| Error::Decode("frame without frame control".into()))?)
        };
        images.push((control, samples));
    }

    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(color);
    encoder.set_depth(depth);
    if let Some(palette) = palette {
        encoder.set_palette(palette);
    }
    if let Some(trns) = trns {
        encoder.set_trns(trns);
    }
    encoder.set_compression(png::Compression::Balanced);
    encoder.set_filter(png::Filter::Adaptive);
    encoder.set_pixel_dims(pixel_dims);
    encoder.set_animated(count, plays).map_err(encode_error)?;
    encoder.set_sep_def_img(still_first).map_err(encode_error)?;
    let mut writer = encoder.write_header().map_err(encode_error)?;
    for (control, samples) in &images {
        deadline.check()?;
        // Back to the whole image, from which any place and size fit.
        writer.reset_frame_position().map_err(encode_error)?;
        writer.reset_frame_dimension().map_err(encode_error)?;
        if let Some(control) = control {
            writer
                .set_frame_dimension(control.width, control.height)
                .map_err(encode_error)?;
            writer
                .set_frame_position(control.x_offset, control.y_offset)
                .map_err(encode_error)?;
            writer
                .set_frame_delay(control.delay_num, control.delay_den)
                .map_err(encode_error)?;
            writer
                .set_blend_op(control.blend_op)
                .map_err(encode_error)?;
            writer
                .set_dispose_op(control.dispose_op)
                .map_err(encode_error)?;
        }
        writer.write_image_data(samples).map_err(encode_error)?;
    }
    writer.finish().map_err(encode_error)?;
    let rebuilt = Rebuilt {
        data: out,
        file_type: FileType::Png,
        width,
        height,
        frames: count,
    };
    match kept {
        Some(icc) => profile::attach(rebuilt, &icc)
            .ok_or_else(|| Error::Encode("the PNG cannot carry the profile".into())),
        None => Ok(rebuilt),
    }
}
