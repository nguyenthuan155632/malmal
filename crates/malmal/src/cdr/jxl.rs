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

/// The JPEG file a JPEG XL made from one keeps the means to give back, or
/// `None` if it keeps none. It is for the caller to rebuild as a JPEG: what
/// it holds besides the picture (metadata, data after the image) goes then.
///
/// The JPEG is given only if it shows what the JPEG XL does, within what
/// two decoders of the same coefficients differ by: `jxl-oxide` puts some
/// files together wrong, and panics on others.
pub(super) fn original_jpeg(data: &[u8], limits: &Limits) -> Option<Vec<u8>> {
    use jxl_oxide::JpegReconstructionStatus;

    let budget = usize::try_from(limits.max_decompressed).unwrap_or(usize::MAX);
    let attempt = || {
        let image = JxlImage::builder()
            .alloc_tracker(AllocTracker::with_limit(budget))
            .read(Cursor::new(data))
            .ok()?;
        if image.jpeg_reconstruction_status() != JpegReconstructionStatus::Available {
            return None;
        }
        let pixels = u64::from(image.width()) * u64::from(image.height());
        if pixels > limits.max_pixels {
            return None;
        }
        let mut out = Capped {
            out: Vec::new(),
            most: budget,
        };
        image.reconstruct_jpeg(&mut out).ok()?;
        shows_the_same(data, &out.out).then_some(out.out)
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt))
        .ok()
        .flatten()
}

/// Whether `jpeg` decodes to the picture the JPEG XL in `data` shows.
fn shows_the_same(data: &[u8], jpeg: &[u8]) -> bool {
    use image::ImageDecoder;
    use image::codecs::jpeg::JpegDecoder;
    use jxl_oxide::integration::JxlDecoder;

    let shown = |decoder: Result<_, _>| -> Option<image::RgbImage> {
        let mut decoder: Box<dyn ImageDecoder> = decoder.ok()?;
        let orientation = decoder.orientation().ok();
        let mut image = DynamicImage::from_decoder(decoder).ok()?;
        if let Some(orientation) = orientation {
            image.apply_orientation(orientation);
        }
        Some(image.into_rgb8())
    };
    let boxed = |d: Box<dyn ImageDecoder>| d;
    let (Some(one), Some(other)) = (
        shown(
            JxlDecoder::new(Cursor::new(data))
                .map(|d| boxed(Box::new(d)))
                .map_err(|_| ()),
        ),
        shown(
            JpegDecoder::new(Cursor::new(jpeg))
                .map(|d| boxed(Box::new(d)))
                .map_err(|_| ()),
        ),
    ) else {
        return false;
    };
    if one.dimensions() != other.dimensions() {
        return false;
    }
    let apart: Vec<u8> = one
        .as_raw()
        .iter()
        .zip(other.as_raw())
        .map(|(a, b)| a.abs_diff(*b))
        .collect();
    let most = apart.iter().copied().max().unwrap_or(0);
    let mean = apart.iter().map(|&d| u64::from(d)).sum::<u64>() as f64 / apart.len().max(1) as f64;
    most <= 16 && mean <= 2.0
}

/// Bytes written, refused past `most`.
struct Capped {
    out: Vec<u8>,
    most: usize,
}

impl std::io::Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.out.len() + bytes.len() > self.most {
            return Err(std::io::Error::other("too large"));
        }
        self.out.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The JPEG XL in `data` with the body of its `jbrd` box replaced by
    /// `body`.
    fn with_jbrd(data: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 8 <= data.len() {
            let size = u32::from_be_bytes(data[at..at + 4].try_into().unwrap()) as usize;
            let size = if size == 0 { data.len() - at } else { size };
            if &data[at + 4..at + 8] == b"jbrd" {
                out.extend_from_slice(&(body.len() as u32 + 8).to_be_bytes());
                out.extend_from_slice(b"jbrd");
                out.extend_from_slice(body);
            } else {
                out.extend_from_slice(&data[at..at + size]);
            }
            at += size;
        }
        out
    }

    /// Reconstruction data that is short or wrong is an error of the
    /// decoder, never a panic in it (tirr-c/jxl-oxide#512): this calls it
    /// without the guard `original_jpeg` has.
    #[test]
    fn broken_reconstruction_data_does_not_panic() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        for name in ["from-jpeg-comment.jxl", "from-progressive-jpeg.jxl"] {
            let data = std::fs::read(format!("{clean}/{name}")).unwrap();
            let image = JxlImage::builder().read(Cursor::new(&data)).unwrap();
            let mut jpeg = Vec::new();
            image.reconstruct_jpeg(&mut jpeg).unwrap();
            // The body of the box, found by its name.
            let at = data.windows(4).position(|w| w == b"jbrd").unwrap();
            let size = u32::from_be_bytes(data[at - 4..at].try_into().unwrap()) as usize;
            let body = &data[at + 4..at - 4 + size];
            let mut broken: Vec<Vec<u8>> = (0..body.len()).map(|n| body[..n].to_vec()).collect();
            for i in 0..body.len() {
                for value in [0x00, 0xFF, body[i] ^ 0x01, body[i] ^ 0x80] {
                    let mut changed = body.to_vec();
                    changed[i] = value;
                    broken.push(changed);
                }
            }
            // Each try decodes the image, so they are shared between threads.
            let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
            std::thread::scope(|scope| {
                for share in broken.chunks(broken.len().div_ceil(threads)) {
                    let data = &data;
                    scope.spawn(move || {
                        for body in share {
                            let file = with_jbrd(data, body);
                            let Ok(image) = JxlImage::builder().read(Cursor::new(&file)) else {
                                continue;
                            };
                            let mut out = Vec::new();
                            let _ = image.reconstruct_jpeg(&mut out);
                        }
                    });
                }
            });
        }
    }
}
