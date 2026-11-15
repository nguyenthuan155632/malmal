//! An animated JPEG XL, as an animated PNG of all its frames.
//!
//! Each frame the file shows is drawn whole, with the frames under it, at
//! 8 bits a channel or, if the file holds more, at 16; it keeps how long it
//! is shown, and the animation how many times it plays.

use std::io::Cursor;

use image::metadata::Orientation;
use image::{DynamicImage, ImageBuffer};
use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, RenderingIntent};
use moxcms::Layout;

use super::{Deadline, Error, Rebuilt, ToSrgb};
use crate::detect::FileType;
use crate::limits::Limits;

fn decode_error(error: impl std::fmt::Display) -> Error {
    Error::Decode(error.to_string())
}

/// The animation in `data`, or `None` if it is a still image.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
) -> Result<Option<Rebuilt>, Error> {
    let budget = usize::try_from(limits.max_decompressed).unwrap_or(usize::MAX);
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(budget))
        .read(Cursor::new(data))
        .map_err(decode_error)?;
    let metadata = &image.image_header().metadata;
    let Some((per_second, tick, plays)) = metadata
        .animation
        .as_ref()
        .map(|a| (a.tps_numerator, a.tps_denominator, a.num_loops))
    else {
        return Ok(None);
    };
    let frames = image.num_loaded_keyframes();
    if frames < 2 {
        return Ok(None);
    }
    let deep = metadata.bit_depth.bits_per_sample() > 8;
    let orientation = Orientation::from_exif(metadata.orientation as u8);
    let (width, height) = (image.width(), image.height());
    if width as u64 * height as u64 * frames as u64 > limits.max_pixels {
        return Err(Error::TooLarge);
    }
    // Inks are drawn as the colours they make.
    if image.pixel_format().has_black() {
        image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    }
    let colors = ToSrgb::new(Some(image.rendered_icc()));

    let mut pictures = Vec::with_capacity(frames);
    let mut held = 0u64;
    for index in 0..frames {
        deadline.check()?;
        let render = image.render_frame(index).map_err(decode_error)?;
        // A tick is the file's fraction of a second; delays are kept in
        // milliseconds.
        let ticks = u64::from(render.duration());
        let shown = match per_second {
            0 => 0,
            per_second => ticks * 1000 * u64::from(tick) / u64::from(per_second),
        };
        let mut stream = render.stream();
        let (w, h, channels) = (stream.width(), stream.height(), stream.channels() as usize);
        let count = w as usize * h as usize * channels;
        held += count as u64 * if deep { 2 } else { 1 };
        if held > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        let (grey, alpha) = match channels {
            1 => (true, false),
            2 => (true, true),
            3 => (false, false),
            4 => (false, true),
            _ => {
                return Err(Error::Decode(
                    "frame has channels this does not read".into(),
                ));
            }
        };
        let layout = match (grey, alpha) {
            (true, false) => Layout::Gray,
            (true, true) => Layout::GrayAlpha,
            (false, false) => Layout::Rgb,
            (false, true) => Layout::Rgba,
        };
        let mut picture: DynamicImage = if deep {
            let mut samples = vec![0u16; count];
            stream.write_to_buffer(&mut samples);
            if let Some(colors) = &colors
                && colors.grey == grey
            {
                let _ = colors.sixteen(&mut samples, layout);
            }
            match (grey, alpha) {
                (true, false) => {
                    ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageLuma16)
                }
                (true, true) => {
                    ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageLumaA16)
                }
                (false, false) => {
                    ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageRgb16)
                }
                (false, true) => {
                    ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageRgba16)
                }
            }
        } else {
            let mut samples = vec![0u8; count];
            stream.write_to_buffer(&mut samples);
            if let Some(colors) = &colors
                && colors.grey == grey
            {
                let _ = colors.eight(&mut samples, layout);
            }
            match (grey, alpha) {
                (true, false) => ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageLuma8),
                (true, true) => ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageLumaA8),
                (false, false) => ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageRgb8),
                (false, true) => ImageBuffer::from_raw(w, h, samples).map(DynamicImage::ImageRgba8),
            }
        }
        .ok_or_else(|| Error::Decode("frame is not what the image says".into()))?;
        if let Some(orientation) = orientation {
            picture.apply_orientation(orientation);
        }
        pictures.push((picture, shown));
    }

    let (width, height) = (pictures[0].0.width(), pictures[0].0.height());
    if pictures
        .iter()
        .any(|(p, _)| (p.width(), p.height()) != (width, height))
    {
        return Err(Error::Decode("frames differ in size".into()));
    }
    let data = write(&pictures, width, height, plays, deadline)?;
    Ok(Some(Rebuilt {
        data,
        file_type: FileType::Png,
        width,
        height,
        frames: frames as u32,
    }))
}

fn write(
    pictures: &[(DynamicImage, u64)],
    width: u32,
    height: u32,
    plays: u32,
    deadline: Deadline,
) -> Result<Vec<u8>, Error> {
    use png::{BitDepth, ColorType};

    let failed = |error: png::EncodingError| Error::Encode(error.to_string());
    let (color, depth) = match &pictures[0].0 {
        DynamicImage::ImageLuma8(_) => (ColorType::Grayscale, BitDepth::Eight),
        DynamicImage::ImageLumaA8(_) => (ColorType::GrayscaleAlpha, BitDepth::Eight),
        DynamicImage::ImageRgb8(_) => (ColorType::Rgb, BitDepth::Eight),
        DynamicImage::ImageRgba8(_) => (ColorType::Rgba, BitDepth::Eight),
        DynamicImage::ImageLuma16(_) => (ColorType::Grayscale, BitDepth::Sixteen),
        DynamicImage::ImageLumaA16(_) => (ColorType::GrayscaleAlpha, BitDepth::Sixteen),
        DynamicImage::ImageRgb16(_) => (ColorType::Rgb, BitDepth::Sixteen),
        _ => (ColorType::Rgba, BitDepth::Sixteen),
    };
    let mut data = Vec::new();
    let mut encoder = png::Encoder::new(&mut data, width, height);
    encoder.set_color(color);
    encoder.set_depth(depth);
    encoder.set_compression(png::Compression::Balanced);
    encoder.set_filter(png::Filter::Adaptive);
    encoder
        .set_animated(pictures.len() as u32, plays)
        .map_err(failed)?;
    let mut writer = encoder.write_header().map_err(failed)?;
    for (picture, shown) in pictures {
        deadline.check()?;
        // A fraction of a second, in 16 bits each way.
        let (numerator, denominator) = match u16::try_from(*shown) {
            Ok(milliseconds) => (milliseconds, 1000),
            Err(_) => ((*shown / 1000).min(u16::MAX.into()) as u16, 1),
        };
        writer
            .set_frame_delay(numerator, denominator)
            .map_err(failed)?;
        let wide = |samples: &[u16]| samples.iter().flat_map(|s| s.to_be_bytes()).collect();
        let bytes: Vec<u8> = match picture {
            DynamicImage::ImageLuma16(i) => wide(i.as_raw()),
            DynamicImage::ImageLumaA16(i) => wide(i.as_raw()),
            DynamicImage::ImageRgb16(i) => wide(i.as_raw()),
            DynamicImage::ImageRgba16(i) => wide(i.as_raw()),
            other => other.as_bytes().to_vec(),
        };
        writer.write_image_data(&bytes).map_err(failed)?;
    }
    writer.finish().map_err(failed)?;
    Ok(data)
}
