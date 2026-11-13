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
//! an image with a profile are converted to keep their colours, as far as
//! sRGB can show them: an RGB image with an RGB profile, a grey one with a
//! grey profile, a CMYK JPEG with a CMYK profile. A profile that does not
//! fit its image, or cannot be read, is dropped as it is.
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
    AnimationDecoder, ColorType, Delay, DynamicImage, ExtendedColorType, Frame, ImageDecoder,
    ImageError, Rgba, RgbaImage,
};
use moxcms::{ColorProfile, DataColorSpace, Layout, TransformExecutor, TransformOptions};

use zune_core::bytestream::ZCursor;
use zune_core::colorspace::ColorSpace;
use zune_core::options::DecoderOptions;

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
            let output = Output::Jpeg(options.jpeg_quality.clamp(1, 100));
            if let Some(image) = cmyk_jpeg(data, limits)? {
                return write(image, deadline, output);
            }
            let decoder = JpegDecoder::new(input).map_err(decode_error)?;
            still(decoder, limits, deadline, output)
        }
        FileType::Png => {
            let mut decoder = PngDecoder::new(input).map_err(decode_error)?;
            if !decoder.is_apng().map_err(decode_error)? {
                return still(decoder, limits, deadline, Output::Png);
            }
            let canvas = Canvas::of(&mut decoder, limits)?;
            let deep = matches!(
                decoder.color_type(),
                ColorType::L16 | ColorType::La16 | ColorType::Rgb16 | ColorType::Rgba16
            );
            if deep {
                let (frames, plays) = deep_apng(data, &canvas, limits, deadline)?;
                return animated(frames, plays, canvas, deadline, Animated::Png);
            }
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

/// Turns the pixels of an image with a colour profile into sRGB, which is
/// what a file without a profile is taken to be: colours for an RGB profile,
/// shades of grey on the sRGB curve for a grey one.
struct ToSrgb {
    profile: ColorProfile,
    srgb: ColorProfile,
    grey: bool,
}

impl ToSrgb {
    /// Pixels converted at a time; the copy made of them is this large.
    const BATCH: usize = 1 << 16;

    /// `None` when there is nothing to convert: no profile, one that does
    /// not parse or is neither RGB nor grey, or one that describes sRGB
    /// itself.
    fn new(icc: Option<Vec<u8>>) -> Option<Self> {
        let profile = ColorProfile::new_from_slice(&icc?).ok()?;
        let srgb = ColorProfile::new_srgb();
        let (srgb, grey) = match profile.color_space {
            DataColorSpace::Rgb => (srgb, false),
            DataColorSpace::Gray => {
                let mut grey = ColorProfile::new_gray_with_gamma(2.2);
                grey.gray_trc = srgb.red_trc;
                (grey, true)
            }
            _ => return None,
        };
        let colors = Self {
            profile,
            srgb,
            grey,
        };
        // Shades of grey and, in colour, of each primary. A profile that
        // moves none of them by more than rounding is sRGB, and the pixels
        // stay as they are: a lossless image keeps every bit.
        let (probe, layout): (Vec<u8>, _) = if grey {
            ((0..=255).collect(), Layout::Gray)
        } else {
            let shades = (0..=255).flat_map(|v| [v, v, v, v, 0, 0, 0, v, 0, 0, 0, v]);
            (shades.collect(), Layout::Rgb)
        };
        let mut converted = probe.clone();
        colors.eight(&mut converted, layout)?;
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
        let channels = match layout {
            Layout::Gray => 1,
            Layout::GrayAlpha => 2,
            Layout::Rgba => 4,
            _ => 3,
        };
        let mut converted = vec![T::default(); Self::BATCH * channels];
        for batch in pixels.chunks_mut(Self::BATCH * channels) {
            let converted = &mut converted[..batch.len()];
            transform.transform(batch, converted).ok()?;
            batch.copy_from_slice(converted);
        }
        Some(())
    }

    /// The frame of an animation, which is always in colour.
    fn frame(&self, frame: &mut RgbaImage) {
        if !self.grey {
            // As for a still image, a profile that cannot be applied is dropped.
            let _ = self.eight(frame, Layout::Rgba);
        }
    }

    /// A profile for colour says nothing about a grey image, nor one for
    /// grey about colours; the pixels are then kept as they are.
    fn image(&self, image: &mut DynamicImage) {
        // So are those of a profile this cannot apply.
        let _ = match image {
            _ if self.grey != !image.color().has_color() => None,
            DynamicImage::ImageLuma8(pixels) => self.eight(pixels, Layout::Gray),
            DynamicImage::ImageLumaA8(pixels) => self.eight(pixels, Layout::GrayAlpha),
            DynamicImage::ImageLuma16(pixels) => self.sixteen(pixels, Layout::Gray),
            DynamicImage::ImageLumaA16(pixels) => self.sixteen(pixels, Layout::GrayAlpha),
            DynamicImage::ImageRgb8(pixels) => self.eight(pixels, Layout::Rgb),
            DynamicImage::ImageRgba8(pixels) => self.eight(pixels, Layout::Rgba),
            DynamicImage::ImageRgb16(pixels) => self.sixteen(pixels, Layout::Rgb),
            DynamicImage::ImageRgba16(pixels) => self.sixteen(pixels, Layout::Rgba),
            _ => None,
        };
    }
}

/// The picture of a CMYK JPEG whose profile says what its inks look like,
/// in sRGB. The decoder turns four inks into three colours by arithmetic,
/// which is visibly off; the profile is what a printer goes by. `None` when
/// the file is not such a JPEG, and is decoded like any other.
fn cmyk_jpeg(data: &[u8], limits: &Limits) -> Result<Option<DynamicImage>, Error> {
    let options = DecoderOptions::default()
        .set_strict_mode(false)
        .set_max_width(usize::MAX)
        .set_max_height(usize::MAX);
    let mut decoder = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(data), options);
    if decoder.decode_headers().is_err() {
        return Ok(None);
    }
    let stored = match decoder.input_colorspace() {
        Some(stored @ (ColorSpace::CMYK | ColorSpace::YCCK)) => stored,
        _ => return Ok(None),
    };
    let profile = decoder.icc_profile();
    let Some(profile) = profile.and_then(|icc| ColorProfile::new_from_slice(&icc).ok()) else {
        return Ok(None);
    };
    if profile.color_space != DataColorSpace::Cmyk {
        return Ok(None);
    }
    // Four channels in, whatever they are called.
    let Ok(transform) = profile.create_transform_8bit(
        Layout::Rgba,
        &ColorProfile::new_srgb(),
        Layout::Rgb,
        TransformOptions::default(),
    ) else {
        return Ok(None);
    };
    let Some((width, height)) = decoder.dimensions() else {
        return Ok(None);
    };
    // The inks and the colours made of them are both held for a while.
    let pixels = width as u64 * height as u64;
    if pixels > limits.max_pixels || pixels.saturating_mul(7) > limits.max_decompressed {
        return Err(Error::TooLarge);
    }

    // As stored: asked for anything else, the decoder mixes the inks itself.
    decoder.set_options(options.jpeg_set_out_colorspace(stored));
    let mut inks = decoder
        .decode()
        .map_err(|error| Error::Decode(error.to_string()))?;
    if inks.len() as u64 != pixels * 4 {
        return Err(Error::Decode("image is not what its header says".into()));
    }
    // In the file, 255 is no ink at all; a profile counts the other way.
    for ink in inks.as_chunks_mut::<4>().0 {
        if stored == ColorSpace::YCCK {
            // Three of the inks are stored the way colours are in a JPEG,
            // and come out of that the right way up.
            let [luma, blue, red] = [ink[0], ink[1], ink[2]].map(|sample| sample as f32);
            let (blue, red) = (blue - 128.0, red - 128.0);
            ink[0] = (luma + 1.402 * red).round() as u8;
            ink[1] = (luma - 0.344_136 * blue - 0.714_136 * red).round() as u8;
            ink[2] = (luma + 1.772 * blue).round() as u8;
        } else {
            for sample in &mut ink[..3] {
                *sample = u8::MAX - *sample;
            }
        }
        ink[3] = u8::MAX - ink[3];
    }
    let mut colours = vec![0; pixels as usize * 3];
    let batches = inks
        .chunks(ToSrgb::BATCH * 4)
        .zip(colours.chunks_mut(ToSrgb::BATCH * 3));
    for (inks, colours) in batches {
        if transform.transform(inks, colours).is_err() {
            return Ok(None);
        }
    }
    let Some(picture) = image::RgbImage::from_raw(width as u32, height as u32, colours) else {
        return Ok(None);
    };
    let mut image = DynamicImage::from(picture);
    let orientation = decoder
        .exif()
        .and_then(|exif| Orientation::from_exif_chunk(exif));
    image.apply_orientation(orientation.unwrap_or(Orientation::NoTransforms));
    Ok(Some(image))
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
    write(image, deadline, output)
}

/// Write a still image in the format `output` names.
fn write(image: DynamicImage, deadline: Deadline, output: Output) -> Result<Rebuilt, Error> {
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
    let plays = match decoder.loop_count() {
        LoopCount::Infinite => None,
        LoopCount::Finite(count) => Some(count.get()),
    };
    // Every frame is held as a full canvas until the file is written.
    let frame_bytes = canvas.width as u64 * canvas.height as u64 * 4;
    let mut frames = Vec::new();
    for frame in decoder.into_frames() {
        deadline.check()?;
        if (frames.len() as u64 + 1).saturating_mul(frame_bytes) > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        frames.push(frame.map_err(decode_error)?);
    }
    animated(frames, plays, canvas, deadline, output)
}

/// The frames of an animated PNG with 16 bits a channel, at 8, and the
/// number of times it plays. The `image` crate's decoder stops at these, so
/// the `png` crate reads each frame and they are laid over one another
/// here, as the APNG specification has it.
fn deep_apng(
    data: &[u8],
    canvas: &Canvas,
    limits: &Limits,
    deadline: Deadline,
) -> Result<(Vec<Frame>, Option<u32>), Error> {
    use png::{BlendOp, DisposeOp, Transformations};

    let failed = |error: png::DecodingError| Error::Decode(error.to_string());
    let mut decoder = png::Decoder::new(Cursor::new(data));
    // Eight bits and an alpha channel, whatever the file has.
    decoder.set_transformations(
        Transformations::EXPAND | Transformations::STRIP_16 | Transformations::ALPHA,
    );
    let mut reader = decoder.read_info().map_err(failed)?;
    let info = reader.info();
    let control = info
        .animation_control()
        .ok_or_else(|| Error::Decode("image is not animated".into()))?;
    let (count, plays) = (control.num_frames, control.num_plays);
    // A first image without frame control is shown by viewers that do not
    // animate, and is no part of the animation.
    let still_first = info.frame_control().is_none();

    let (width, height) = (canvas.width, canvas.height);
    let frame_bytes = width as u64 * height as u64 * 4;
    let size = reader.output_buffer_size().ok_or(Error::TooLarge)?;
    if size as u64 > limits.max_decompressed {
        return Err(Error::TooLarge);
    }
    let mut buffer = vec![0; size];
    if still_first {
        reader.next_frame(&mut buffer).map_err(failed)?;
    }

    // What is shown now, and what was before the frame last drawn.
    let mut current = RgbaImage::new(width, height);
    let mut previous = current.clone();
    let mut dispose = DisposeOp::Background;
    let mut drawn: Option<(u32, u32, u32, u32)> = None;
    let mut frames = Vec::new();
    for _ in 0..count {
        deadline.check()?;
        // The two canvases, the buffer and the frames collected so far.
        if (frames.len() as u64 + 3).saturating_mul(frame_bytes) > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        // What becomes of the frame last drawn, before the next one is.
        match (dispose, drawn) {
            (DisposeOp::None, _) => previous.clone_from(&current),
            (DisposeOp::Background, Some((left, top, wide, high))) => {
                previous.clone_from(&current);
                for y in top..top + high {
                    for x in left..left + wide {
                        current.put_pixel(x, y, Rgba([0; 4]));
                    }
                }
            }
            (DisposeOp::Background, None) => {}
            (DisposeOp::Previous, Some((left, top, wide, high))) => {
                for y in top..top + high {
                    for x in left..left + wide {
                        current.put_pixel(x, y, *previous.get_pixel(x, y));
                    }
                }
            }
            (DisposeOp::Previous, None) => {}
        }

        let read = reader.next_frame(&mut buffer).map_err(failed)?;
        let info = reader.info();
        let (left, top, wide, high, blend, delay) = match info.frame_control() {
            Some(frame) => {
                dispose = frame.dispose_op;
                // A fraction of a second; no denominator means hundredths.
                let per_second = match frame.delay_den {
                    0 => 100,
                    denominator => u32::from(denominator),
                };
                let delay = (u32::from(frame.delay_num) * 1000, per_second);
                let place = (frame.x_offset, frame.y_offset, frame.width, frame.height);
                (place.0, place.1, place.2, place.3, frame.blend_op, delay)
            }
            None => (0, 0, info.width, info.height, BlendOp::Source, (0, 1)),
        };
        let fits = |start: u32, length: u32, within: u32| {
            start.checked_add(length).is_some_and(|end| end <= within)
        };
        let channels = match read.color_type {
            png::ColorType::GrayscaleAlpha => 2,
            png::ColorType::Rgba => 4,
            _ => 0,
        };
        let rows = buffer.chunks(read.line_size.max(1));
        if !fits(left, wide, width)
            || !fits(top, high, height)
            || channels == 0
            || read.bit_depth != png::BitDepth::Eight
            || read.line_size < wide as usize * channels
            || buffer.len() / read.line_size.max(1) < high as usize
        {
            return Err(Error::Decode("a frame is not what the image says".into()));
        }
        drawn = Some((left, top, wide, high));
        for (y, row) in (top..top + high).zip(rows) {
            for (x, sample) in (left..left + wide).zip(row.chunks_exact(channels)) {
                let pixel = match *sample {
                    [grey, alpha] => Rgba([grey, grey, grey, alpha]),
                    [red, green, blue, alpha] => Rgba([red, green, blue, alpha]),
                    _ => unreachable!("two or four channels"),
                };
                match blend {
                    BlendOp::Source => current.put_pixel(x, y, pixel),
                    BlendOp::Over => over(current.get_pixel_mut(x, y), pixel),
                }
            }
        }
        let delay = Delay::from_numer_denom_ms(delay.0, delay.1);
        frames.push(Frame::from_parts(current.clone(), 0, 0, delay));
    }
    // In the file, 0 plays is forever.
    Ok((frames, (plays != 0).then_some(plays)))
}

/// Lay `top` over `under`, each as much as its alpha says.
fn over(under: &mut Rgba<u8>, top: Rgba<u8>) {
    let (top_alpha, under_alpha) = (u32::from(top[3]), u32::from(under[3]));
    // What of `under` still shows, and of both together, out of 255 * 255.
    let showing = under_alpha * (255 - top_alpha);
    let alpha = top_alpha * 255 + showing;
    if alpha == 0 {
        *under = Rgba([0; 4]);
        return;
    }
    for channel in 0..3 {
        let mixed = u32::from(top[channel]) * top_alpha * 255 + u32::from(under[channel]) * showing;
        under[channel] = ((mixed + alpha / 2) / alpha) as u8;
    }
    under[3] = ((alpha + 127) / 255) as u8;
}

/// Write the frames of an animation in the format `output` names.
fn animated(
    mut frames: Vec<Frame>,
    plays: Option<u32>,
    canvas: Canvas,
    deadline: Deadline,
    output: Animated,
) -> Result<Rebuilt, Error> {
    let Canvas { width, height, .. } = canvas;
    if frames.is_empty() {
        return Err(Error::Decode("image has no frames".into()));
    }
    if let Some(colors) = &canvas.colors {
        for frame in &mut frames {
            colors.frame(frame.buffer_mut());
        }
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

    #[test]
    fn deep_animated_png_is_laid_out_frame_by_frame() {
        // Two frames at 16 bits: a red canvas, then a half-transparent blue
        // square blended over its corner, removed again after its turn.
        let mut data = Vec::new();
        let mut encoder = ::png::Encoder::new(&mut data, 4, 4);
        encoder.set_color(::png::ColorType::Rgba);
        encoder.set_depth(::png::BitDepth::Sixteen);
        encoder.set_animated(3, 5).unwrap();
        let mut writer = encoder.write_header().unwrap();
        let samples = |pixel: [u16; 4], count: usize| -> Vec<u8> {
            let bytes = pixel.iter().flat_map(|sample| sample.to_be_bytes());
            bytes.collect::<Vec<u8>>().repeat(count)
        };
        writer.set_frame_delay(1, 4).unwrap();
        writer
            .write_image_data(&samples([0xFFFF, 0, 0, 0xFFFF], 16))
            .unwrap();
        writer.set_frame_dimension(2, 2).unwrap();
        writer.set_frame_position(1, 2).unwrap();
        writer.set_blend_op(::png::BlendOp::Over).unwrap();
        writer.set_dispose_op(::png::DisposeOp::Previous).unwrap();
        writer
            .write_image_data(&samples([0, 0, 0xFFFF, 0x8000], 4))
            .unwrap();
        writer.set_blend_op(::png::BlendOp::Source).unwrap();
        writer.set_dispose_op(::png::DisposeOp::None).unwrap();
        writer
            .write_image_data(&samples([0, 0x1234, 0, 0x4000], 4))
            .unwrap();
        writer.finish().unwrap();
        // The decoder this module otherwise uses does not take the file.
        let refused = PngDecoder::new(Cursor::new(&data[..])).unwrap().apng();
        assert!(refused.unwrap().into_frames().collect_frames().is_err());

        let rebuilt = run(&data).unwrap();
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (4, 4, 3));
        assert!(scans_clean(&rebuilt.data));
        let decoder = PngDecoder::new(Cursor::new(&rebuilt.data[..])).unwrap();
        let (frames, plays) = played(decoder.apng().unwrap());
        assert_eq!(plays, Some(5));
        let red = Rgba([255, 0, 0, 255]);
        assert!(frames[0].0.pixels().all(|pixel| *pixel == red));
        assert_eq!(frames[0].1, 250);
        // Blended over the red, inside the square only.
        assert_eq!(frames[1].0.get_pixel(1, 2), &Rgba([127, 0, 128, 255]));
        assert_eq!(frames[1].0.get_pixel(0, 2), &red);
        // The square is gone and the next one replaces what is under it.
        assert_eq!(frames[2].0.get_pixel(1, 2), &Rgba([0, 0x12, 0, 0x40]));
        assert_eq!(frames[2].0.get_pixel(3, 3), &red);
    }

    #[test]
    fn a_grey_profile_is_applied_to_grey_images_only() {
        use image::ImageEncoder;

        let dark = ColorProfile::new_gray_with_gamma(1.0).encode().unwrap();
        let grey = image::GrayImage::from_pixel(3, 3, image::Luma([64]));
        let mut data = Vec::new();
        let mut encoder = PngEncoder::new(&mut data);
        encoder.set_icc_profile(dark.clone()).unwrap();
        encoder
            .write_image(&grey, 3, 3, ExtendedColorType::L8)
            .unwrap();
        let rebuilt = image::load_from_memory(&run(&data).unwrap().data).unwrap();
        // A quarter of the light, on the sRGB curve.
        let image::Luma([shade]) = *rebuilt.to_luma8().get_pixel(1, 1);
        assert!((135..=139).contains(&shade), "{shade}");

        // The same profile on a colour image says nothing about it.
        let pixel = Rgba([64, 64, 64, 255]);
        let mut data = Vec::new();
        let mut encoder = PngEncoder::new(&mut data);
        encoder.set_icc_profile(dark).unwrap();
        let colour = RgbaImage::from_pixel(3, 3, pixel);
        encoder
            .write_image(&colour, 3, 3, ExtendedColorType::Rgba8)
            .unwrap();
        let rebuilt = image::load_from_memory(&run(&data).unwrap().data).unwrap();
        assert_eq!(rebuilt.to_rgba8().get_pixel(1, 1), &pixel);
    }

    /// The samples are white, the first ink, and black. Their profile makes
    /// the first ink red, which mixing the inks by arithmetic does not.
    #[test]
    fn cmyk_inks_get_the_colours_of_their_profile() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        // The two ways a JPEG stores four inks.
        for name in ["cmyk-profile.jpg", "ycck-profile.jpg"] {
            let data = std::fs::read(format!("{clean}/{name}")).unwrap();
            let options = Options { jpeg_quality: 100 };
            let rebuilt = rebuild(&data, &Limits::default(), &options).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Jpeg);
            assert_eq!((rebuilt.width, rebuilt.height), (24, 8), "{name}");
            assert!(!contains(&rebuilt.data, b"acsp"));
            let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
            for (x, expected) in [(3, [255, 255, 255]), (12, [255, 0, 0]), (20, [0, 0, 0])] {
                let Rgb(found) = *pixels.get_pixel(x, 4);
                let close = found.iter().zip(expected).all(|(a, b)| a.abs_diff(b) < 16);
                assert!(close, "{name} at {x}: {found:?}");
            }
        }
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
