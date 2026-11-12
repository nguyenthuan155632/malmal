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
//! | PNG | PNG |
//! | GIF | GIF, every frame, looping forever when animated |
//! | WebP | lossless WebP |
//! | BMP, TIFF, ICO | PNG; of an icon, the largest image |
//!
//! Animated PNG and WebP, and every other type, are refused with
//! [`Error::Unsupported`] rather than rebuilt in part.
//!
//! What it does not do: pixels are kept, so anything encoded in them is too,
//! and a colour profile is dropped, not converted, so an image in a wide
//! gamut loses some saturation.

use std::fmt;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use image::codecs::bmp::BmpDecoder;
use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::codecs::ico::IcoDecoder;
use image::codecs::jpeg::{JpegDecoder, JpegEncoder};
use image::codecs::png::{CompressionType, FilterType, PngDecoder, PngEncoder};
use image::codecs::tiff::TiffDecoder;
use image::codecs::webp::{WebPDecoder, WebPEncoder};
use image::metadata::Orientation;
use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageError};

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

/// Decode `data` and write a new image from its pixels. See the
/// [module documentation](self) for what comes out.
///
/// An image declaring more than `limits.max_pixels` pixels, or needing more
/// than `limits.max_decompressed` bytes of memory to decode, is refused with
/// [`Error::TooLarge`]. `limits.max_duration` is not enforced here.
pub fn rebuild(data: &[u8], limits: &Limits, options: &Options) -> Result<Rebuilt, Error> {
    // The codecs are not this crate's; a bug in one must not take the
    // caller down with it.
    catch_unwind(AssertUnwindSafe(|| rebuild_inner(data, limits, options)))
        .unwrap_or_else(|_| Err(Error::Decode("the decoder failed".into())))
}

fn rebuild_inner(data: &[u8], limits: &Limits, options: &Options) -> Result<Rebuilt, Error> {
    let file_type = detect::detect(data);
    let unsupported = |reason| Error::Unsupported { file_type, reason };
    let input = Cursor::new(data);
    match file_type {
        FileType::Jpeg => {
            let quality = options.jpeg_quality.clamp(1, 100);
            let decoder = JpegDecoder::new(input).map_err(decode_error)?;
            still(decoder, limits, Output::Jpeg(quality))
        }
        FileType::Png => {
            let decoder = PngDecoder::new(input).map_err(decode_error)?;
            if decoder.is_apng().map_err(decode_error)? {
                return Err(unsupported("animated PNG"));
            }
            still(decoder, limits, Output::Png)
        }
        FileType::Webp => {
            let decoder = WebPDecoder::new(input).map_err(decode_error)?;
            if decoder.has_animation() {
                return Err(unsupported("animated WebP"));
            }
            still(decoder, limits, Output::Webp)
        }
        FileType::Gif => animation(GifDecoder::new(input).map_err(decode_error)?, limits),
        FileType::Bmp => still(
            BmpDecoder::new(input).map_err(decode_error)?,
            limits,
            Output::Png,
        ),
        FileType::Tiff => still(
            TiffDecoder::new(input).map_err(decode_error)?,
            limits,
            Output::Png,
        ),
        FileType::Ico => still(
            IcoDecoder::new(input).map_err(decode_error)?,
            limits,
            Output::Png,
        ),
        _ => Err(unsupported("not a raster image this module decodes")),
    }
}

/// Refuse an image the limits do not allow, and tell the decoder how much
/// memory it may use.
fn apply_limits(decoder: &mut impl ImageDecoder, limits: &Limits) -> Result<(), Error> {
    let (width, height) = decoder.dimensions();
    if width as u64 * height as u64 > limits.max_pixels
        || decoder.total_bytes() > limits.max_decompressed
    {
        return Err(Error::TooLarge);
    }
    let mut decoder_limits = image::Limits::default();
    decoder_limits.max_alloc = Some(limits.max_decompressed);
    decoder.set_limits(decoder_limits).map_err(decode_error)
}

fn still(
    mut decoder: impl ImageDecoder,
    limits: &Limits,
    output: Output,
) -> Result<Rebuilt, Error> {
    apply_limits(&mut decoder, limits)?;
    // The orientation lives in metadata the new file will not have.
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut image = DynamicImage::from_decoder(decoder).map_err(decode_error)?;
    image.apply_orientation(orientation);

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

fn animation(mut decoder: GifDecoder<Cursor<&[u8]>>, limits: &Limits) -> Result<Rebuilt, Error> {
    apply_limits(&mut decoder, limits)?;
    let (width, height) = decoder.dimensions();
    // Every frame is held as a full canvas until the file is written.
    let frame_bytes = width as u64 * height as u64 * 4;
    let mut frames = Vec::new();
    for frame in decoder.into_frames() {
        if (frames.len() as u64 + 1).saturating_mul(frame_bytes) > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
        frames.push(frame.map_err(decode_error)?);
    }
    if frames.is_empty() {
        return Err(Error::Decode("image has no frames".into()));
    }
    let count = frames.len() as u32;

    let mut data = Vec::new();
    {
        let mut encoder = GifEncoder::new_with_speed(&mut data, 10);
        if count > 1 {
            encoder.set_repeat(Repeat::Infinite).map_err(encode_error)?;
        }
        encoder.encode_frames(frames).map_err(encode_error)?;
    }
    Ok(Rebuilt {
        data,
        file_type: FileType::Gif,
        width,
        height,
        frames: count,
    })
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
