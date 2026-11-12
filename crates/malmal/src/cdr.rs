//! Content disarm and reconstruction for raster images: the image is decoded
//! to pixels and a new file is written from them. Whatever the scanner cannot
//! see, the new file does not have: metadata, colour profiles, comments,
//! unknown chunks, data after the image, a second format hiding in the same
//! bytes.
//!
//! [`Scanner::sanitize`](crate::Scanner::sanitize) scans a file and rebuilds
//! it when it is clean; [`rebuild`] is the second half alone. Scan first: the
//! decoders here are memory-safe Rust, but the scanner is what refuses a
//! file built to exhaust them.
//!
//! ```
//! use malmal::cdr::{Error, Options};
//! use malmal::{ScanHints, Scanner};
//!
//! fn accept(scanner: &Scanner, upload: &[u8], hints: ScanHints<'_>) -> Result<Vec<u8>, String> {
//!     match scanner.sanitize(upload, hints, &Options::default()) {
//!         // `image.file_type` names what to store it as.
//!         Ok(sanitized) => Ok(sanitized.image.data),
//!         Err(Error::Rejected(report)) => {
//!             let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
//!             Err(format!("not clean: {}", codes.join(", ")))
//!         }
//!         // Not an image that can be rebuilt, too large, or not decodable.
//!         Err(other) => Err(other.to_string()),
//!     }
//! }
//!
//! let scanner = Scanner::builder().pdf_passwords(["a candidate"]).build();
//! assert!(accept(&scanner, b"\x7fELF\x02\x01\x01", ScanHints::default()).is_err());
//! ```
//!
//! | Input | Output |
//! |---|---|
//! | JPEG | JPEG, re-compressed at [`Options::jpeg_quality`], rotated as its Exif orientation says |
//! | PNG | PNG; an animated one keeps every frame, at 8 bits a channel |
//! | GIF | GIF, every frame |
//! | WebP | lossless WebP, every frame of an animated one |
//! | BMP, TIFF, ICO | PNG; of an icon, the largest image |
//!
//! An animation keeps its frame delays and the number of times it plays.
//! Every other type is refused with [`Error::Unsupported`] rather than
//! rebuilt in part.
//!
//! The new file has no colour profile, so it is read as sRGB. The pixels of
//! an image with an RGB profile are converted to sRGB to keep their colours,
//! as far as sRGB can show them; any other profile is dropped as it is.
//!
//! What it does not do: pixels are kept, so anything encoded in them is too.

use std::fmt;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use image::codecs::bmp::BmpDecoder;
use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::codecs::ico::IcoDecoder;
use image::codecs::jpeg::{JpegDecoder, JpegEncoder};
use image::codecs::png::{CompressionType, FilterType, PngDecoder, PngEncoder};
use image::codecs::tiff::TiffDecoder;
use image::codecs::webp::{WebPDecoder, WebPEncoder};
use image::metadata::{LoopCount, Orientation};
use image::{
    AnimationDecoder, DynamicImage, ExtendedColorType, Frame, ImageDecoder, ImageError, RgbaImage,
};
use moxcms::{ColorProfile, DataColorSpace, Layout, TransformExecutor, TransformOptions};

use crate::detect::{self, FileType};
use crate::limits::Limits;
use crate::report::Report;

/// How images are written.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// Quality of rebuilt JPEG files, 1 to 100.
    pub jpeg_quality: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self { jpeg_quality: 90 }
    }
}

/// An image written anew from the pixels of another.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rebuilt {
    /// The new file.
    pub data: Vec<u8>,
    /// Its type, which is not always the type of the input.
    pub file_type: FileType,
    /// Width in pixels, after any rotation.
    pub width: u32,
    /// Height in pixels, after any rotation.
    pub height: u32,
    /// Number of frames; 1 unless the image is animated.
    pub frames: u32,
}

/// A file that was scanned, found clean and rebuilt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Sanitized {
    /// The report on the original file. Its verdict is clean.
    pub report: Report,
    /// The file to keep in place of the original.
    pub image: Rebuilt,
}

/// Why there is no rebuilt file. In every case the original is not to be
/// accepted in its place.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The scan did not come back clean.
    Rejected(Box<Report>),
    /// The file is not an image this module rebuilds.
    Unsupported {
        /// What the file is.
        file_type: FileType,
        /// What about it is not supported.
        reason: &'static str,
    },
    /// The decoded image would exceed the pixel or memory limit.
    TooLarge,
    /// Rebuilding took longer than the time limit.
    TimedOut,
    /// The image could not be decoded.
    Decode(String),
    /// The image could not be written.
    Encode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(report) => {
                let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
                write!(f, "file is not clean: {}", codes.join(", "))
            }
            Self::Unsupported { file_type, reason } => {
                write!(f, "{} cannot be rebuilt: {reason}", file_type.as_str())
            }
            Self::TooLarge => f.write_str("decoded image exceeds the configured limits"),
            Self::TimedOut => f.write_str("rebuilding exceeded the configured time limit"),
            Self::Decode(problem) => write!(f, "image cannot be decoded: {problem}"),
            Self::Encode(problem) => write!(f, "image cannot be written: {problem}"),
        }
    }
}

impl std::error::Error for Error {}

fn decode_error(error: ImageError) -> Error {
    match error {
        ImageError::Limits(_) => Error::TooLarge,
        other => Error::Decode(other.to_string()),
    }
}

fn encode_error(error: ImageError) -> Error {
    Error::Encode(error.to_string())
}

/// The format a still image is written in.
#[derive(Clone, Copy)]
enum Output {
    Jpeg(u8),
    Png,
    Webp,
}

/// The format an animation is written in.
#[derive(Clone, Copy)]
enum Animated {
    Gif,
    Png,
    Webp,
}

/// When the new file has to be on its way; `None` is never.
#[derive(Clone, Copy)]
struct Deadline(Option<Instant>);

impl Deadline {
    fn check(self) -> Result<(), Error> {
        match self.0 {
            Some(deadline) if Instant::now() > deadline => Err(Error::TimedOut),
            _ => Ok(()),
        }
    }
}

/// Decode `data` and write a new image from its pixels. See the
/// [module documentation](self) for what comes out.
///
/// An image declaring more than `limits.max_pixels` pixels, or needing more
/// than `limits.max_decompressed` bytes of memory to decode, is refused with
/// [`Error::TooLarge`]. `limits.max_duration` is checked between the frames
/// of an animation and before a file is written, so one large frame can run
/// past it; then the answer is [`Error::TimedOut`].
pub fn rebuild(data: &[u8], limits: &Limits, options: &Options) -> Result<Rebuilt, Error> {
    // The codecs are not this crate's; a bug in one must not take the
    // caller down with it.
    catch_unwind(AssertUnwindSafe(|| rebuild_inner(data, limits, options)))
        .unwrap_or_else(|_| Err(Error::Decode("the decoder failed".into())))
}

fn rebuild_inner(data: &[u8], limits: &Limits, options: &Options) -> Result<Rebuilt, Error> {
    let file_type = detect::detect(data);
    let unsupported = |reason| Error::Unsupported { file_type, reason };
    let deadline = Deadline(Instant::now().checked_add(limits.max_duration));
    let input = Cursor::new(data);
    match file_type {
        FileType::Jpeg => {
            let quality = options.jpeg_quality.clamp(1, 100);
            let decoder = JpegDecoder::new(input).map_err(decode_error)?;
            still(decoder, limits, deadline, Output::Jpeg(quality))
        }
        FileType::Png => {
            let mut decoder = PngDecoder::new(input).map_err(decode_error)?;
            if !decoder.is_apng().map_err(decode_error)? {
                return still(decoder, limits, deadline, Output::Png);
            }
            let canvas = Canvas::of(&mut decoder, limits)?;
            let decoder = decoder.apng().map_err(decode_error)?;
            animation(decoder, canvas, limits, deadline, Animated::Png)
        }
        FileType::Webp => {
            let mut decoder = WebPDecoder::new(input).map_err(decode_error)?;
            if !decoder.has_animation() {
                return still(decoder, limits, deadline, Output::Webp);
            }
            let canvas = Canvas::of(&mut decoder, limits)?;
            animation(decoder, canvas, limits, deadline, Animated::Webp)
        }
        FileType::Gif => {
            let mut decoder = GifDecoder::new(input).map_err(decode_error)?;
            let canvas = Canvas::of(&mut decoder, limits)?;
            animation(decoder, canvas, limits, deadline, Animated::Gif)
        }
        FileType::Bmp => still(
            BmpDecoder::new(input).map_err(decode_error)?,
            limits,
            deadline,
            Output::Png,
        ),
        FileType::Tiff => still(
            TiffDecoder::new(input).map_err(decode_error)?,
            limits,
            deadline,
            Output::Png,
        ),
        FileType::Ico => still(
            IcoDecoder::new(input).map_err(decode_error)?,
            limits,
            deadline,
            Output::Png,
        ),
        _ => Err(unsupported("not a raster image this module decodes")),
    }
}

/// Turns the pixels of an image with an RGB colour profile into sRGB, which
/// is what a file without a profile is taken to be.
struct ToSrgb {
    profile: ColorProfile,
    srgb: ColorProfile,
}

impl ToSrgb {
    /// Pixels converted at a time; the copy made of them is this large.
    const BATCH: usize = 1 << 16;

    /// `None` when there is nothing to convert: no profile, one that does
    /// not parse or is not RGB, or one that describes sRGB itself.
    fn new(icc: Option<Vec<u8>>) -> Option<Self> {
        let profile = ColorProfile::new_from_slice(&icc?).ok()?;
        if profile.color_space != DataColorSpace::Rgb {
            return None;
        }
        let colors = Self {
            profile,
            srgb: ColorProfile::new_srgb(),
        };
        // Shades of grey and of each primary. A profile that moves none of
        // them by more than rounding is sRGB, and the pixels stay as they
        // are: a lossless image keeps every bit.
        let probe: Vec<u8> = (0..=255)
            .flat_map(|v| [v, v, v, v, 0, 0, 0, v, 0, 0, 0, v])
            .collect();
        let mut converted = probe.clone();
        colors.eight(&mut converted, Layout::Rgb)?;
        let moved = |(a, b): (&u8, &u8)| a.abs_diff(*b) > 1;
        probe.iter().zip(&converted).any(moved).then_some(colors)
    }

    fn eight(&self, pixels: &mut [u8], layout: Layout) -> Option<()> {
        let options = TransformOptions::default();
        let transform = self
            .profile
            .create_transform_8bit(layout, &self.srgb, layout, options)
            .ok()?;
        Self::convert(&*transform, pixels, layout)
    }

    fn sixteen(&self, pixels: &mut [u16], layout: Layout) -> Option<()> {
        let options = TransformOptions::default();
        let transform = self
            .profile
            .create_transform_16bit(layout, &self.srgb, layout, options)
            .ok()?;
        Self::convert(&*transform, pixels, layout)
    }

    fn convert<T: Copy + Default>(
        transform: &dyn TransformExecutor<T>,
        pixels: &mut [T],
        layout: Layout,
    ) -> Option<()> {
        let channels = if layout == Layout::Rgba { 4 } else { 3 };
        let mut converted = vec![T::default(); Self::BATCH * channels];
        for batch in pixels.chunks_mut(Self::BATCH * channels) {
            let converted = &mut converted[..batch.len()];
            transform.transform(batch, converted).ok()?;
            batch.copy_from_slice(converted);
        }
        Some(())
    }

    /// Grey images are left alone: an RGB profile says nothing about them.
    fn image(&self, image: &mut DynamicImage) {
        // A profile this cannot apply is one the pixels are kept without.
        let _ = match image {
            DynamicImage::ImageRgb8(pixels) => self.eight(pixels, Layout::Rgb),
            DynamicImage::ImageRgba8(pixels) => self.eight(pixels, Layout::Rgba),
            DynamicImage::ImageRgb16(pixels) => self.sixteen(pixels, Layout::Rgb),
            DynamicImage::ImageRgba16(pixels) => self.sixteen(pixels, Layout::Rgba),
            _ => None,
        };
    }
}

/// What is known of an image before its pixels are read.
struct Canvas {
    width: u32,
    height: u32,
    colors: Option<ToSrgb>,
}

impl Canvas {
    /// Refuse an image the limits do not allow, and tell the decoder how
    /// much memory it may use.
    fn of(decoder: &mut impl ImageDecoder, limits: &Limits) -> Result<Self, Error> {
        let (width, height) = decoder.dimensions();
        if width as u64 * height as u64 > limits.max_pixels
            || decoder.total_bytes() > limits.max_decompressed
        {
            return Err(Error::TooLarge);
        }
        let mut decoder_limits = image::Limits::default();
        decoder_limits.max_alloc = Some(limits.max_decompressed);
        decoder.set_limits(decoder_limits).map_err(decode_error)?;
        Ok(Self {
            width,
            height,
            colors: ToSrgb::new(decoder.icc_profile().ok().flatten()),
        })
    }
}

fn still(
    mut decoder: impl ImageDecoder,
    limits: &Limits,
    deadline: Deadline,
    output: Output,
) -> Result<Rebuilt, Error> {
    let canvas = Canvas::of(&mut decoder, limits)?;
    // The orientation lives in metadata the new file will not have.
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut image = DynamicImage::from_decoder(decoder).map_err(decode_error)?;
    if let Some(colors) = &canvas.colors {
        colors.image(&mut image);
    }
    image.apply_orientation(orientation);
    deadline.check()?;

    let mut data = Vec::new();
    let file_type = match output {
        Output::Jpeg(quality) => {
            // The format stores 8-bit grey or colour and nothing else.
            let image = match image {
                DynamicImage::ImageLuma8(_) | DynamicImage::ImageRgb8(_) => image.clone(),
                _ if image.color().has_color() => image.to_rgb8().into(),
                _ => image.to_luma8().into(),
            };
            JpegEncoder::new_with_quality(&mut data, quality)
                .encode_image(&image)
                .map_err(encode_error)?;
            FileType::Jpeg
        }
        Output::Png => {
            // Floating-point samples have no place in a PNG.
            let image = match image {
                DynamicImage::ImageRgb32F(_) => image.to_rgb16().into(),
                DynamicImage::ImageRgba32F(_) => image.to_rgba16().into(),
                _ => image.clone(),
            };
            // The encoder's own default trades size for speed.
            let encoder = PngEncoder::new_with_quality(
                &mut data,
                CompressionType::Default,
                FilterType::Adaptive,
            );
            image.write_with_encoder(encoder).map_err(encode_error)?;
            FileType::Png
        }
        Output::Webp => {
            let image: DynamicImage = if image.color().has_alpha() {
                image.to_rgba8().into()
            } else {
                image.to_rgb8().into()
            };
            image
                .write_with_encoder(WebPEncoder::new_lossless(&mut data))
                .map_err(encode_error)?;
            FileType::Webp
        }
    };
    Ok(Rebuilt {
        data,
        file_type,
        width: image.width(),
        height: image.height(),
        frames: 1,
    })
}

fn animation<'a>(
    decoder: impl AnimationDecoder<'a>,
    canvas: Canvas,
    limits: &Limits,
    deadline: Deadline,
    output: Animated,
) -> Result<Rebuilt, Error> {
    let Canvas { width, height, .. } = canvas;
    let plays = match decoder.loop_count() {
        LoopCount::Infinite => None,
        LoopCount::Finite(count) => Some(count.get()),
    };
    // Every frame is held as a full canvas until the file is written.
    let frame_bytes = width as u64 * height as u64 * 4;
    let mut frames = Vec::new();
    for frame in decoder.into_frames() {
        deadline.check()?;
        if (frames.len() as u64 + 1).saturating_mul(frame_bytes) > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        let mut frame = frame.map_err(decode_error)?;
        if let Some(colors) = &canvas.colors {
            // As for a still image, a profile that cannot be applied is dropped.
            let _ = colors.eight(frame.buffer_mut(), Layout::Rgba);
        }
        frames.push(frame);
    }
    if frames.is_empty() {
        return Err(Error::Decode("image has no frames".into()));
    }
    let count = frames.len() as u32;

    let (data, file_type) = match output {
        Animated::Gif => {
            let mut data = Vec::new();
            let mut encoder = GifEncoder::new_with_speed(&mut data, 10);
            if count > 1 {
                // The decoder reports a GIF that plays once as one that loops.
                let repeat = match plays {
                    Some(plays) => Repeat::Finite(plays.min(u16::MAX.into()) as u16),
                    None => Repeat::Infinite,
                };
                encoder.set_repeat(repeat).map_err(encode_error)?;
            }
            encoder.encode_frames(frames).map_err(encode_error)?;
            drop(encoder);
            (data, FileType::Gif)
        }
        Animated::Png => {
            let pictures = covering(&frames, width, height)?;
            (
                apng(&pictures, width, height, plays, deadline)?,
                FileType::Png,
            )
        }
        Animated::Webp => {
            let pictures = covering(&frames, width, height)?;
            let data = match pictures[..] {
                [(picture, _)] => webp_bitstream(picture)?,
                _ => animated_webp(&pictures, width, height, plays, deadline)?,
            };
            (data, FileType::Webp)
        }
    };
    Ok(Rebuilt {
        data,
        file_type,
        width,
        height,
        frames: count,
    })
}

/// Each frame's picture and how long it is shown, in milliseconds. The
/// writers below place every frame over the whole image, so each has to
/// cover it.
fn covering(frames: &[Frame], width: u32, height: u32) -> Result<Vec<(&RgbaImage, u32)>, Error> {
    let whole = |frame: &Frame| frame.buffer().dimensions() == (width, height);
    if !frames.iter().all(whole) {
        return Err(Error::Decode("a frame does not cover the image".into()));
    }
    let shown = |frame: &Frame| {
        let (numerator, denominator) = frame.delay().numer_denom_ms();
        numerator / denominator.max(1)
    };
    Ok(frames
        .iter()
        .map(|frame| (frame.buffer(), shown(frame)))
        .collect())
}

/// A PNG of one frame, or an animated one of several.
fn apng(
    pictures: &[(&RgbaImage, u32)],
    width: u32,
    height: u32,
    plays: Option<u32>,
    deadline: Deadline,
) -> Result<Vec<u8>, Error> {
    let failed = |error: png::EncodingError| Error::Encode(error.to_string());
    let animated = pictures.len() > 1;
    let mut data = Vec::new();
    let mut encoder = png::Encoder::new(&mut data, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    if animated {
        // In the file, 0 plays is forever.
        encoder
            .set_animated(pictures.len() as u32, plays.unwrap_or(0))
            .map_err(failed)?;
    }
    let mut writer = encoder.write_header().map_err(failed)?;
    for (picture, shown) in pictures {
        deadline.check()?;
        if animated {
            // A fraction of a second, in 16 bits each way.
            let (numerator, denominator) = match u16::try_from(*shown) {
                Ok(milliseconds) => (milliseconds, 1000),
                Err(_) => ((*shown / 1000).min(u16::MAX.into()) as u16, 1),
            };
            writer
                .set_frame_delay(numerator, denominator)
                .map_err(failed)?;
        }
        writer.write_image_data(picture.as_raw()).map_err(failed)?;
    }
    writer.finish().map_err(failed)?;
    Ok(data)
}

/// A lossless WebP file of one picture.
fn webp_bitstream(picture: &RgbaImage) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    WebPEncoder::new_lossless(&mut data)
        .encode(
            picture.as_raw(),
            picture.width(),
            picture.height(),
            ExtendedColorType::Rgba8,
        )
        .map_err(encode_error)?;
    Ok(data)
}

/// Append a RIFF chunk, padded to an even length.
fn riff_chunk(out: &mut Vec<u8>, name: &[u8; 4], payload: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::Encode("image is too large for its container".into()))?;
    out.extend_from_slice(name);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        out.push(0);
    }
    Ok(())
}

/// The `VP8L` chunk of a lossless WebP file: the picture itself.
fn vp8l_chunk(file: &[u8]) -> Option<&[u8]> {
    let mut rest = file.get(12..)?;
    loop {
        let length = u32::from_le_bytes(rest.get(4..8)?.try_into().ok()?) as usize;
        let payload = rest.get(8..8 + length)?;
        if &rest[..4] == b"VP8L" {
            return Some(payload);
        }
        rest = rest.get(8 + length + length % 2..)?;
    }
}

/// An animated WebP file. The encoder writes still pictures only, so the
/// container is put together here: a header, the animation's parameters,
/// and a frame chunk around each lossless picture.
fn animated_webp(
    pictures: &[(&RgbaImage, u32)],
    width: u32,
    height: u32,
    plays: Option<u32>,
    deadline: Deadline,
) -> Result<Vec<u8>, Error> {
    // Sizes are stored less one, in 24 bits, like every number of a frame.
    let u24 = |value: u32| {
        let bytes = value.min(0xFF_FFFF).to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    };
    let size = [u24(width.saturating_sub(1)), u24(height.saturating_sub(1))].concat();

    let mut transparent = false;
    let mut chunks = Vec::new();
    // A background colour nothing shows, and the number of plays; 0 is forever.
    let plays = plays.unwrap_or(0).min(u16::MAX.into()) as u16;
    let parameters = [&[0; 4][..], &plays.to_le_bytes()].concat();
    riff_chunk(&mut chunks, b"ANIM", &parameters)?;
    for (picture, shown) in pictures {
        deadline.check()?;
        transparent |= picture.pixels().any(|pixel| pixel[3] != u8::MAX);
        let file = webp_bitstream(picture)?;
        let bitstream = vp8l_chunk(&file)
            .ok_or_else(|| Error::Encode("the encoder wrote no lossless picture".into()))?;
        // At the top left corner, replacing what was there, not blended with it.
        let mut frame = [&[0; 6][..], &size, &u24(*shown), &[0b10]].concat();
        riff_chunk(&mut frame, b"VP8L", bitstream)?;
        riff_chunk(&mut chunks, b"ANMF", &frame)?;
    }

    const ANIMATION: u8 = 0x02;
    const ALPHA: u8 = 0x10;
    let flags = ANIMATION | if transparent { ALPHA } else { 0 };
    let mut body = b"WEBP".to_vec();
    riff_chunk(&mut body, b"VP8X", &[&[flags, 0, 0, 0][..], &size].concat())?;
    body.extend_from_slice(&chunks);
    let mut data = Vec::with_capacity(body.len() + 8);
    riff_chunk(&mut data, b"RIFF", &body)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use image::codecs::gif::GifEncoder;
    use image::{Delay, Frame, ImageFormat, Rgb, RgbImage, Rgba, RgbaImage};

    use super::*;

    const PAYLOAD: &[u8] = b"<?php system($_GET['c']); ?>";

    fn picture() -> RgbImage {
        RgbImage::from_fn(48, 32, |x, y| {
            Rgb([x as u8 * 5, y as u8 * 7, (x + y) as u8])
        })
    }

    fn encoded(image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    fn run(data: &[u8]) -> Result<Rebuilt, Error> {
        rebuild(data, &Limits::default(), &Options::default())
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A PNG with `PAYLOAD` in a text chunk before the image data.
    fn png_with_text_chunk(png: &[u8]) -> Vec<u8> {
        let mut body = b"tEXtComment\0".to_vec();
        body.extend_from_slice(PAYLOAD);
        let mut hasher = png::chunk_crc();
        hasher(&body);
        let mut chunk = (body.len() as u32 - 4).to_be_bytes().to_vec();
        chunk.extend_from_slice(&body);
        chunk.extend_from_slice(&hasher(&[]).to_be_bytes());
        // After the signature and the 25-byte IHDR chunk.
        [&png[..33], &chunk, &png[33..]].concat()
    }

    mod png {
        /// A running CRC-32: feed it bytes, read the value so far.
        pub(super) fn chunk_crc() -> impl FnMut(&[u8]) -> u32 {
            let mut crc = !0u32;
            move |bytes: &[u8]| {
                for &byte in bytes {
                    crc ^= byte as u32;
                    for _ in 0..8 {
                        crc = if crc & 1 != 0 {
                            0xEDB8_8320 ^ (crc >> 1)
                        } else {
                            crc >> 1
                        };
                    }
                }
                !crc
            }
        }
    }

    #[test]
    fn lossless_formats_keep_their_pixels_and_lose_the_rest() {
        let original = DynamicImage::from(picture());
        for (format, output) in [
            (ImageFormat::Png, FileType::Png),
            (ImageFormat::WebP, FileType::Webp),
            (ImageFormat::Bmp, FileType::Png),
            (ImageFormat::Tiff, FileType::Png),
            (ImageFormat::Ico, FileType::Png),
        ] {
            // An icon holds its image with an alpha channel.
            let source = match format {
                ImageFormat::Ico => original.to_rgba8().into(),
                _ => original.clone(),
            };
            let mut data = encoded(&source, format);
            data.extend_from_slice(PAYLOAD);
            let rebuilt = run(&data).unwrap_or_else(|error| panic!("{format:?}: {error}"));
            assert_eq!(rebuilt.file_type, output, "{format:?}");
            assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (48, 32, 1));
            assert_eq!(detect::detect(&rebuilt.data), output);
            assert!(!contains(&rebuilt.data, PAYLOAD), "{format:?}");
            let pixels = image::load_from_memory(&rebuilt.data).unwrap();
            assert_eq!(pixels.to_rgb8(), picture(), "{format:?}");
        }
    }

    #[test]
    fn metadata_is_not_carried_over() {
        let png = png_with_text_chunk(&encoded(&picture().into(), ImageFormat::Png));
        assert!(contains(&png, PAYLOAD));
        let rebuilt = run(&png).unwrap();
        assert!(!contains(&rebuilt.data, PAYLOAD));
        assert_eq!(
            image::load_from_memory(&rebuilt.data).unwrap().to_rgb8(),
            picture()
        );

        // A JPEG comment segment, right after the start-of-image marker.
        let jpeg = encoded(&picture().into(), ImageFormat::Jpeg);
        let mut comment = vec![0xFF, 0xFE];
        comment.extend_from_slice(&(PAYLOAD.len() as u16 + 2).to_be_bytes());
        comment.extend_from_slice(PAYLOAD);
        let jpeg = [&jpeg[..2], &comment, &jpeg[2..]].concat();
        let rebuilt = run(&jpeg).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Jpeg);
        assert_eq!((rebuilt.width, rebuilt.height), (48, 32));
        assert!(!contains(&rebuilt.data, PAYLOAD));
    }

    #[test]
    fn transparency_and_depth_survive() {
        let transparent =
            RgbaImage::from_fn(8, 8, |x, y| Rgba([x as u8, y as u8, 9, x as u8 * 30]));
        for format in [ImageFormat::Png, ImageFormat::WebP] {
            let rebuilt = run(&encoded(&transparent.clone().into(), format)).unwrap();
            let pixels = image::load_from_memory(&rebuilt.data).unwrap();
            assert_eq!(pixels.to_rgba8(), transparent, "{format:?}");
        }
        let deep = image::ImageBuffer::<image::Luma<u16>, _>::from_fn(4, 4, |x, y| {
            image::Luma([(x * 1000 + y * 7) as u16])
        });
        let rebuilt = run(&encoded(&deep.clone().into(), ImageFormat::Png)).unwrap();
        let pixels = image::load_from_memory(&rebuilt.data).unwrap();
        assert_eq!(pixels.to_luma16(), deep);
    }

    #[test]
    fn jpeg_is_rotated_as_its_orientation_says() {
        let jpeg = encoded(&picture().into(), ImageFormat::Jpeg);
        // An Exif segment whose only entry is orientation 6: rotate 90 degrees.
        let mut exif = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\x01".to_vec();
        exif.extend_from_slice(b"\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0");
        let mut segment = vec![0xFF, 0xE1];
        segment.extend_from_slice(&(exif.len() as u16 + 2).to_be_bytes());
        segment.extend_from_slice(&exif);
        let rotated = run(&[&jpeg[..2], &segment, &jpeg[2..]].concat()).unwrap();
        assert_eq!((rotated.width, rotated.height), (32, 48));
        assert!(!contains(&rotated.data, b"Exif"));
    }

    #[test]
    fn animations_keep_their_frames() {
        let mut gif = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut gif);
            for shade in [0u8, 120, 240] {
                let frame = RgbaImage::from_pixel(6, 4, Rgba([shade, 0, 255 - shade, 255]));
                let delay = Delay::from_numer_denom_ms(100, 1);
                encoder
                    .encode_frame(Frame::from_parts(frame, 0, 0, delay))
                    .unwrap();
            }
        }
        gif.extend_from_slice(PAYLOAD);
        let rebuilt = run(&gif).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Gif);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (6, 4, 3));
        assert!(!contains(&rebuilt.data, PAYLOAD));
        let decoder = GifDecoder::new(Cursor::new(&rebuilt.data[..])).unwrap();
        let frames = decoder.into_frames().collect_frames().unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames[1].buffer().get_pixel(0, 0),
            &Rgba([120, 0, 135, 255])
        );
        assert_eq!(frames[1].delay().numer_denom_ms(), (100, 1));
    }

    fn shades() -> Vec<(RgbaImage, u32)> {
        [(0u8, 40), (120, 250), (240, 1000)]
            .into_iter()
            .map(|(shade, shown)| {
                let picture = RgbaImage::from_fn(6, 4, |x, _| {
                    Rgba([shade, x as u8 * 40, 255 - shade, 255 - x as u8 * 50])
                });
                (picture, shown)
            })
            .collect()
    }

    /// What a decoder makes of an animation: each frame and its delay.
    fn played<'a>(decoder: impl AnimationDecoder<'a>) -> (Vec<(RgbaImage, u32)>, Option<u32>) {
        let plays = match decoder.loop_count() {
            LoopCount::Infinite => None,
            LoopCount::Finite(count) => Some(count.get()),
        };
        let frames = decoder.into_frames().collect_frames().unwrap();
        let shown = |frame: &Frame| {
            let (numerator, denominator) = frame.delay().numer_denom_ms();
            numerator / denominator
        };
        let frames = frames
            .iter()
            .map(|frame| (frame.buffer().clone(), shown(frame)))
            .collect();
        (frames, plays)
    }

    fn scans_clean(data: &[u8]) -> bool {
        let report = crate::Scanner::builder()
            .build()
            .scan_bytes(data, crate::ScanHints::default());
        report.verdict == crate::Verdict::Clean
    }

    #[test]
    fn animated_png_and_webp_keep_frames_delays_and_plays() {
        let shades = shades();
        let pictures: Vec<(&RgbaImage, u32)> = shades
            .iter()
            .map(|(picture, shown)| (picture, *shown))
            .collect();
        let never = Deadline(None);

        let mut png = apng(&pictures, 6, 4, Some(3), never).unwrap();
        png.extend_from_slice(PAYLOAD);
        let rebuilt = run(&png).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Png);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (6, 4, 3));
        assert!(!contains(&rebuilt.data, PAYLOAD));
        assert!(scans_clean(&rebuilt.data));
        let decoder = PngDecoder::new(Cursor::new(&rebuilt.data[..])).unwrap();
        assert_eq!(played(decoder.apng().unwrap()), (shades.clone(), Some(3)));

        let mut webp = animated_webp(&pictures, 6, 4, None, never).unwrap();
        webp.extend_from_slice(PAYLOAD);
        let rebuilt = run(&webp).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Webp);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (6, 4, 3));
        assert!(!contains(&rebuilt.data, PAYLOAD));
        assert!(scans_clean(&rebuilt.data));
        let decoder = WebPDecoder::new(Cursor::new(&rebuilt.data[..])).unwrap();
        assert!(decoder.has_animation());
        assert_eq!(played(decoder), (shades, None));
    }

    /// A PNG of `pixel` carrying `profile`.
    fn tagged(pixel: Rgba<u8>, profile: &ColorProfile) -> Vec<u8> {
        use image::ImageEncoder;

        let picture = RgbaImage::from_pixel(5, 3, pixel);
        let mut data = Vec::new();
        let mut encoder = PngEncoder::new(&mut data);
        encoder.set_icc_profile(profile.encode().unwrap()).unwrap();
        encoder
            .write_image(&picture, 5, 3, ExtendedColorType::Rgba8)
            .unwrap();
        data
    }

    #[test]
    fn a_colour_profile_is_applied_not_carried() {
        let pixel = Rgba([40, 200, 90, 77]);
        let wide = tagged(pixel, &ColorProfile::new_display_p3());
        assert!(contains(&wide, b"iCCP"));
        let rebuilt = run(&wide).unwrap();
        assert!(!contains(&rebuilt.data, b"iCCP"));
        let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgba8();
        let Rgba([red, green, blue, alpha]) = *pixels.get_pixel(0, 0);
        // The same green needs less red and more green in the smaller space.
        assert!(red < 40 && green > 200, "{red} {green} {blue}");
        assert_eq!(alpha, 77);

        // sRGB under its own name changes nothing.
        let plain = tagged(pixel, &ColorProfile::new_srgb());
        let pixels = image::load_from_memory(&run(&plain).unwrap().data).unwrap();
        assert_eq!(pixels.to_rgba8().get_pixel(4, 2), &pixel);

        // Nor does a profile that is not one.
        assert!(ToSrgb::new(Some(PAYLOAD.to_vec())).is_none());
        assert!(ToSrgb::new(None).is_none());
    }

    #[test]
    fn stops_at_the_time_limit() {
        let none = Limits {
            max_duration: std::time::Duration::ZERO,
            ..Limits::default()
        };
        let png = encoded(&picture().into(), ImageFormat::Png);
        let rebuilt = rebuild(&png, &none, &Options::default());
        assert!(matches!(rebuilt, Err(Error::TimedOut)), "{rebuilt:?}");
    }

    #[test]
    fn refuses_what_it_cannot_rebuild_whole() {
        for data in [
            &b"%PDF-1.7\n"[..],
            b"<svg xmlns='http://www.w3.org/2000/svg'/>",
            b"",
        ] {
            assert!(matches!(run(data), Err(Error::Unsupported { .. })));
        }
        let png = encoded(&picture().into(), ImageFormat::Png);
        assert!(matches!(run(&png[..png.len() / 2]), Err(Error::Decode(_))));

        let small = Limits {
            max_pixels: 100,
            ..Limits::default()
        };
        assert!(matches!(
            rebuild(&png, &small, &Options::default()),
            Err(Error::TooLarge)
        ));
        let tight = Limits {
            max_decompressed: 1000,
            ..Limits::default()
        };
        assert!(matches!(
            rebuild(&png, &tight, &Options::default()),
            Err(Error::TooLarge)
        ));
    }
}
