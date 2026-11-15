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
//! | JPEG | JPEG of the same coefficients, rotated as its Exif orientation says; where that cannot be done without loss, re-compressed at [`Options::jpeg_quality`] at most |
//! | PNG | PNG; an animated one keeps every frame, at its own depth |
//! | GIF | GIF of the same palettes and indices, every frame |
//! | WebP | lossy WebP of the same coded picture, every frame; lossless WebP of a lossless one |
//! | BMP | PNG |
//! | TIFF | PNG of its one page; TIFF of every page if it has more |
//! | ICO | ICO of every image, each a PNG |
//! | PSD, PSB | PNG of the composite image Photoshop saves with the layers |
//! | JPEG XL | PNG; animated PNG of every frame of an animation |
//! | AVIF | PNG of its primary image |
//! | SVG, with the `cdr-svg` feature | SVG, filtered down to what draws a picture |
//! | PDF, with the `cdr-pdf` feature | PDF in which every page is a picture of the page, with its text, which does not draw |
//!
//! An animation keeps its frame delays and the number of times it plays.
//! Every other type is refused with [`Error::Unsupported`] rather than
//! rebuilt in part.
//!
//! Where it can, the picture is written anew without being decoded and
//! coded again, so nothing of it is lost:
//!
//! - A JPEG keeps its quantised coefficients: they are read and written
//!   again with tables of their own. One whose colour profile has to be
//!   applied, or whose rotation cuts through its blocks, is re-compressed
//!   instead, at no coarser a quantisation than it had.
//! - A lossy WebP keeps every symbol its VP8 coder coded: modes,
//!   quantisers and coefficients are read and coded again at the same
//!   probabilities, and the file is kept only if it decodes to every pixel
//!   the original does. Its transparency is coded again without loss.
//! - A GIF keeps its palettes, the indices of its pixels and how each
//!   frame is drawn over the last; an animated PNG keeps them too, at its
//!   own depth.
//!
//! A PNG of 256 colours or fewer is written indexed when that is smaller,
//! and the pixel density of the original is kept. TIFF is read in every
//! compression libtiff writes, CCITT fax, LZMA and Zstandard among them,
//! and at any depth from 1 to 64 bits; reduced copies of a page and masks
//! are left out. AVIF is decoded by `filmcraft-av1`, which gives the
//! samples libdav1d gives, then put together from its grid, alpha image,
//! clean aperture, rotation and mirroring.
//!
//! The new file has no colour profile, so it is read as sRGB. The pixels of
//! an image with a profile are converted to keep their colours, as far as
//! sRGB can show them: an RGB image with an RGB profile, a grey one with a
//! grey profile, a CMYK JPEG, TIFF or PSD with a CMYK profile, an AVIF with
//! the primaries and transfer it names. CIE L*a*b* is converted from the
//! white the file names, D50 otherwise. A profile that does not fit its
//! image, or cannot be read, is dropped as it is.
//!
//! With [`Inks::Keep`], a CMYK JPEG, TIFF or PSD keeps its inks instead:
//! a JPEG its coefficients, a TIFF or PSD its samples, written as a TIFF.
//! Its profile is kept too, written anew from the tags that say what the
//! inks look like, which are copied byte for byte and checked to print
//! every ink as the original does; a profile that cannot be is turned into
//! sRGB as before.
//!
//! What it does not do: pixels are kept, so anything encoded in them is too.
//! That includes the bytes of another file. Where a format writes pixels
//! that do not compress as they are, a picture can be drawn that comes out
//! of [`rebuild`] as an image and, say, a PDF at once, though nothing of
//! the kind could be seen in the file it was drawn in.
//! [`Scanner::sanitize`](crate::Scanner::sanitize) scans what it has
//! rebuilt for that reason; after calling [`rebuild`] yourself, do the same.

use std::fmt;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use image::codecs::bmp::BmpDecoder;
use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::codecs::ico::IcoDecoder;
use image::codecs::jpeg::JpegDecoder;
use image::codecs::png::PngDecoder;
use image::codecs::webp::{WebPDecoder, WebPEncoder};
use image::metadata::{LoopCount, Orientation};
use image::{
    AnimationDecoder, ColorType, Delay, DynamicImage, ExtendedColorType, Frame, ImageDecoder,
    ImageError, Rgba, RgbaImage,
};
use jxl_oxide::integration::JxlDecoder;
use moxcms::{ColorProfile, DataColorSpace, Layout, TransformExecutor, TransformOptions};

use zune_core::bytestream::ZCursor;
use zune_core::colorspace::ColorSpace;
use zune_core::options::DecoderOptions;

mod apng;
mod avif;
mod colour;
mod fax;
mod gif;
mod ifd;
mod jpeg;
mod jxl;
mod palette;
mod psd;
mod strips;
mod tif;
mod tiff_out;
mod vp8;
mod webp;

use crate::detect::{self, FileType};
use crate::limits::Limits;
use crate::report::Report;

/// How images are written.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// Quality of rebuilt JPEG files, 1 to 100.
    pub jpeg_quality: u8,
    /// The types of file that are rebuilt; `None` is every type this build
    /// can. A decoder for a type you do not take is one more thing a file
    /// can be aimed at: name the ones you do, and the others are refused
    /// with [`Error::Unsupported`] before any of them is run.
    pub types: Option<Vec<FileType>>,
    /// Dots per inch at which the pages of a PDF are drawn, 36 to 600.
    pub pdf_dpi: u16,
    /// How the picture of each page is kept in a rebuilt PDF.
    pub pdf_pages: PageImage,
    /// Whether a rebuilt PDF keeps the text of its pages, where it was, as
    /// characters that can be selected, searched and copied and that do not
    /// draw: the picture is what shows. Nothing else of a font is kept.
    pub pdf_text: bool,
    /// Whether a rebuilt PDF draws text as shapes rather than as part of the
    /// picture of its page, where it can: text of one solid colour on a
    /// plain background, with nothing over it, and drawn exactly as the
    /// shapes say, which is checked against the picture. The shapes are
    /// the outlines of the glyphs, written anew; no font program is kept.
    /// Such text stays sharp at any size, and a page of it takes a fraction
    /// of the room. Other text stays in the picture.
    pub pdf_vector_text: bool,
    /// What becomes of an image of printing inks (CMYK).
    pub inks: Inks,
}

/// What becomes of an image of printing inks: a CMYK JPEG, TIFF or PSD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Inks {
    /// Turned into the sRGB colours they print as, under their colour
    /// profile, and stored as the colours of a screen.
    #[default]
    Srgb,
    /// Kept as inks, with their colour profile, so that they print as they
    /// did: a JPEG of the same coefficients, a TIFF of the same samples.
    /// The profile is written anew from the tags that describe its colours,
    /// which make exactly the colours the old one did; if it cannot be, the
    /// inks are turned into sRGB instead. Inks without a profile are kept
    /// without one.
    Keep,
}

/// How the picture of a page is kept in a rebuilt PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PageImage {
    /// Every pixel as it was drawn. Text stays sharp; a page of text takes
    /// some hundred kilobytes, a photograph several megabytes.
    #[default]
    Lossless,
    /// As a JPEG at [`Options::jpeg_quality`] where that is the smaller of
    /// the two, which it is for photographs and scans, by far, and is not
    /// for pages of text.
    Jpeg,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            jpeg_quality: 90,
            types: None,
            pdf_dpi: 150,
            pdf_pages: PageImage::Lossless,
            pdf_text: true,
            pdf_vector_text: true,
            inks: Inks::Srgb,
        }
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
    /// Width in pixels, after any rotation; 0 for an SVG or a PDF, which
    /// have none.
    pub width: u32,
    /// Height in pixels, after any rotation; 0 for an SVG or a PDF.
    pub height: u32,
    /// Number of frames of an animation, images of an icon or pages of a
    /// PDF; otherwise 1.
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
    /// The file was clean and was rebuilt, and the new file is not: the
    /// report is the one on the new file. Its pixels spell something a
    /// scan objects to, or it is of a type the policy does not accept.
    Unclean(Box<Report>),
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
            Self::Unclean(report) => {
                let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
                write!(f, "the rebuilt file is not clean: {}", codes.join(", "))
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
#[derive(Clone)]
enum Output {
    Jpeg(Box<jpeg::Settings>),
    /// With the pixel density of the original, if it had one.
    Png(Option<png::PixelDimensions>),
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
    rebuild_with(data, limits, options, &[])
}

/// [`rebuild`], with passwords to try on a PDF that needs one.
pub(crate) fn rebuild_with(
    data: &[u8],
    limits: &Limits,
    options: &Options,
    passwords: &[Vec<u8>],
) -> Result<Rebuilt, Error> {
    // The codecs are not this crate's; a bug in one must not take the
    // caller down with it.
    let run = || rebuild_inner(data, limits, options, passwords);
    catch_unwind(AssertUnwindSafe(run))
        .unwrap_or_else(|_| Err(Error::Decode("the decoder failed".into())))
}

#[cfg_attr(not(feature = "cdr-pdf"), allow(unused_variables))]
fn rebuild_inner(
    data: &[u8],
    limits: &Limits,
    options: &Options,
    passwords: &[Vec<u8>],
) -> Result<Rebuilt, Error> {
    let file_type = detect::detect(data);
    let deadline = Deadline(Instant::now().checked_add(limits.max_duration));
    let wanted = |types: &Vec<FileType>| types.contains(&file_type);
    if !options.types.as_ref().is_none_or(wanted) {
        let reason = "not among the types to rebuild";
        return Err(Error::Unsupported { file_type, reason });
    }
    match file_type {
        #[cfg(feature = "cdr-svg")]
        FileType::Svg => svg(data, limits, options, deadline),
        #[cfg(feature = "cdr-pdf")]
        FileType::Pdf => pdf(data, limits, options, passwords, deadline),
        _ => raster(data, file_type, limits, options, deadline),
    }
}

/// A PDF whose pages are pictures of the pages of `data`, and nothing else:
/// each page is drawn and the drawing is what the new file holds, along
/// with, if [`Options::pdf_text`] says so, the characters of its text where
/// they stood, in a font of this module's that draws nothing. Where
/// [`Options::pdf_vector_text`] says so, text that the picture shows exactly
/// as its glyphs' outlines say is taken out of the picture and drawn from
/// those outlines instead. Links and forms are gone, and so is everything
/// else a PDF can carry. A document that one of `passwords` opens comes back
/// as one that needs none.
#[cfg(feature = "cdr-pdf")]
fn pdf(
    data: &[u8],
    limits: &Limits,
    options: &Options,
    passwords: &[Vec<u8>],
    deadline: Deadline,
) -> Result<Rebuilt, Error> {
    use hayro::hayro_interpret::InterpreterSettings;
    use hayro::hayro_syntax::Pdf;
    use hayro::vello_cpu::color::palette::css::WHITE;
    use hayro::{PixmapSettings, RenderCache, RenderSettings, render};

    // The empty password first, which is the one most encrypted documents
    // have; the renderer takes passwords as text.
    let data = hayro::hayro_syntax::PdfData::from(data.to_vec());
    let open = |password: &str| Pdf::new_with_password(data.clone(), password).ok();
    let mut supplied = passwords
        .iter()
        .filter_map(|password| std::str::from_utf8(password).ok());
    let document = open("")
        .or_else(|| supplied.find_map(open))
        .ok_or_else(|| Error::Decode("the document cannot be read".into()))?;
    let scale = f32::from(options.pdf_dpi.clamp(36, 600)) / 72.0;
    let pixmap_settings = PixmapSettings {
        x_scale: scale,
        y_scale: scale,
        bg_color: WHITE,
    };
    let interpreter = InterpreterSettings::default();
    // Glyphs drawn from a cache of pictures of them land a fraction of a
    // pixel from where their outlines do, and could not be checked.
    let render_settings = RenderSettings {
        glyph_caching: !options.pdf_vector_text,
        ..RenderSettings::default()
    };
    let cache = RenderCache::new();

    let mut written = PagesPdf::default();
    for page in document.pages().iter() {
        deadline.check()?;
        // In points, of which there are 72 to the inch.
        let (width, height) = page.render_dimensions();
        let pixels = |points: f32| (points * scale) as u64;
        let area = pixels(width).saturating_mul(pixels(height));
        if !(1..=u64::from(u16::MAX)).contains(&pixels(width))
            || !(1..=u64::from(u16::MAX)).contains(&pixels(height))
            || area > limits.max_pixels
            // The drawing, the copy of it without its alpha channel, and,
            // for text drawn as shapes, a drawing of those shapes and a mark
            // for each pixel.
            || area.saturating_mul(12) > limits.max_decompressed
        {
            return Err(Error::TooLarge);
        }
        let drawn = render(
            page,
            &cache,
            &interpreter,
            &render_settings,
            &pixmap_settings,
        );
        // Opaque, on the white it was drawn on.
        let mut colours: Vec<u8> = drawn
            .data_as_u8_slice()
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|pixel| [pixel[0], pixel[1], pixel[2]])
            .collect();
        let (wide, high) = (drawn.width(), drawn.height());
        drop(drawn);
        let jpeg = (options.pdf_pages == PageImage::Jpeg).then_some(options.jpeg_quality);
        let mut text = if options.pdf_text || options.pdf_vector_text {
            deadline.check()?;
            let found = Found {
                scale: f64::from(scale),
                wide,
                high,
                shapes: options.pdf_vector_text,
            };
            text_of(page, &interpreter, height, found)
        } else {
            Vec::new()
        };
        if !options.pdf_text {
            text.iter_mut().for_each(|character| character.text.clear());
        }
        if options.pdf_vector_text {
            deadline.check()?;
            vectorise(&mut colours, wide, high, &mut text, &mut written);
        }
        let picture = Picture {
            wide,
            high,
            colours: &colours,
            jpeg,
        };
        written.page(width, height, picture, &text)?;
        if written.len() as u64 > limits.max_decompressed {
            return Err(Error::TooLarge);
        }
    }
    let pages = written.pages();
    if pages == 0 {
        return Err(Error::Decode("the document has no pages".into()));
    }
    Ok(Rebuilt {
        data: written.finish(),
        file_type: FileType::Pdf,
        width: 0,
        height: 0,
        frames: pages,
    })
}

/// How the text of a page is looked for: on a picture of it `wide` by
/// `high` pixels, `scale` pixels to the point, and with the shapes of its
/// glyphs or not.
#[cfg(feature = "cdr-pdf")]
struct Found {
    scale: f64,
    wide: u16,
    high: u16,
    shapes: bool,
}

/// The characters a page draws, each as its text, where it stands on the
/// page and how far it reaches: the transform, from a square one unit on a
/// side at the origin to the box of the character on a page `height`
/// points high whose origin is its lower left corner. With the shape of
/// each glyph that could be drawn as one, if `found` asks for them.
#[cfg(feature = "cdr-pdf")]
fn text_of(
    page: &hayro::hayro_syntax::page::Page<'_>,
    settings: &hayro::hayro_interpret::InterpreterSettings,
    height: f32,
    found: Found,
) -> Vec<Character> {
    use hayro::hayro_interpret::font::HintingCache;
    use hayro::hayro_interpret::util::TransformExt;
    use hayro::hayro_interpret::{Context, InterpreterCache, interpret_page};
    use hayro::kurbo::{Affine, Rect};

    let cache = InterpreterCache::new();
    // Pixels, from the top left corner, as the page is drawn.
    let transform = Affine::scale(found.scale) * page.initial_transform(true).to_kurbo();
    let bounds = Rect::new(0.0, 0.0, f64::from(found.wide), f64::from(found.high));
    let mut context = Context::new(transform, bounds, &cache, page.xref(), settings.clone());
    let mut characters = Characters {
        upright: Affine::new([1.0, 0.0, 0.0, -1.0, 0.0, f64::from(height)])
            * Affine::scale(1.0 / found.scale),
        hinting: found.shapes.then(HintingCache::new),
        groups: Vec::new(),
        found: Vec::new(),
    };
    interpret_page(page, &mut context, &mut characters);
    characters.found
}

/// A character of the text of a page: see [`text_of`].
#[cfg(feature = "cdr-pdf")]
struct Character {
    /// What it stands for; empty for a glyph that says nothing.
    text: String,
    place: [f64; 6],
    /// The glyph as a shape, while it can be drawn as one.
    shape: Option<Shape>,
}

/// A glyph that might be drawn as a shape rather than kept in the picture.
#[cfg(feature = "cdr-pdf")]
struct Shape {
    /// The outline, in units of which an em has a thousand.
    outline: hayro::kurbo::BezPath,
    /// The outline as the picture has it, hinted or not, and the transform
    /// that put it on the picture.
    drawn: hayro::kurbo::BezPath,
    pixels: hayro::kurbo::Affine,
    colour: [u8; 3],
    /// From the outline to the page, in thousandths.
    matrix: [f64; 6],
    /// How far the next glyph starts, in units of the outline.
    advance: f64,
    /// Its code in the fonts of the new document, once it has one.
    code: Option<usize>,
}

/// The most characters kept of a page, which is some hundred times what a
/// page of text has.
#[cfg(feature = "cdr-pdf")]
const MAX_CHARACTERS: usize = 1 << 18;

/// The most points and curves of an outline drawn as a shape; a letter has
/// some tens.
#[cfg(feature = "cdr-pdf")]
const MAX_OUTLINE: usize = 1 << 11;

/// A device that draws nothing and keeps the characters of a page.
#[cfg(feature = "cdr-pdf")]
struct Characters {
    /// From pixels on the picture to points on the page.
    upright: hayro::kurbo::Affine,
    /// For the outlines of glyphs as the renderer draws them, when shapes
    /// are wanted.
    hinting: Option<hayro::hayro_interpret::font::HintingCache>,
    /// For each transparency group drawn into: whether it is drawn as is.
    groups: Vec<bool>,
    found: Vec<Character>,
}

#[cfg(feature = "cdr-pdf")]
impl Characters {
    /// The outline of `glyph` as the renderer fills it with `transform`,
    /// and the transform it is filled with: hinted at the size it is drawn
    /// if the renderer hints it, as it does at most sizes of upright text.
    fn as_drawn(
        &self,
        glyph: &hayro::hayro_interpret::font::OutlineGlyph,
        transform: hayro::kurbo::Affine,
        hint: bool,
    ) -> (hayro::kurbo::BezPath, hayro::kurbo::Affine) {
        let [a, b, c, d, e, f] = transform.as_coeffs();
        let ppem = d.abs() * 1000.0;
        if let Some(cache) = self.hinting.as_ref().filter(|_| hint)
            && b == 0.0
            && (4.0..=128.0).contains(&ppem)
            && let Some(hinted) = glyph.hinted_outline(ppem as f32, cache)
        {
            return (
                hinted,
                hayro::kurbo::Affine::new([a, b, c, d, e, f.round()]),
            );
        }
        (glyph.outline(), transform)
    }
}

#[cfg(feature = "cdr-pdf")]
impl<'a> hayro::hayro_interpret::Device<'a> for Characters {
    fn draw_path(
        &mut self,
        _: &hayro::kurbo::BezPath,
        _: hayro::hayro_interpret::DrawProps<'a>,
        _: &hayro::hayro_interpret::DrawMode,
    ) {
    }
    fn push_clip_path(&mut self, _: &hayro::hayro_interpret::ClipPath) {}
    fn push_transparency_group(
        &mut self,
        opacity: f32,
        mask: Option<hayro::hayro_interpret::SoftMask<'a>>,
        blend: hayro::hayro_interpret::BlendMode,
    ) {
        let plain = opacity == 1.0
            && mask.is_none()
            && matches!(blend, hayro::hayro_interpret::BlendMode::Normal);
        self.groups.push(plain);
    }
    fn draw_glyph_run(
        &mut self,
        run: &hayro::hayro_interpret::font::GlyphRun<'_, 'a>,
        props: hayro::hayro_interpret::DrawProps<'a>,
        mode: &hayro::hayro_interpret::DrawMode,
    ) {
        use hayro::hayro_interpret::font::Glyph;
        use hayro::hayro_interpret::hayro_cmap::{BfString, WritingMode};
        use hayro::hayro_interpret::{BlendMode, DrawMode, Paint};
        use hayro::kurbo::{Affine, Shape as _};
        let glyphs = run.glyphs();
        // Where each glyph is drawn: from glyph space, in which an em is a
        // thousand units, to the page.
        let placed = |glyph: &hayro::hayro_interpret::font::PositionedGlyph<'_>| {
            self.upright * props.transform * glyph.transform()
        };
        // Filled in one opaque colour, as is, where shapes are wanted.
        let colour = match &props.paint {
            Paint::Color(colour) if self.hinting.is_some() => {
                let [r, g, b, a] = colour.to_rgba().to_rgba8();
                (a == 255).then_some([r, g, b])
            }
            _ => None,
        }
        .filter(|_| {
            matches!(mode, DrawMode::Fill(_))
                && props.soft_mask.is_none()
                && matches!(props.blend_mode, BlendMode::Normal)
                && self.groups.iter().all(|&plain| plain)
        });
        let hint = run.writing_mode() == WritingMode::Horizontal;
        for (index, glyph) in glyphs.iter().enumerate() {
            if self.found.len() >= MAX_CHARACTERS {
                return;
            }
            let text = match glyph.as_unicode() {
                Some(BfString::Char(character)) => character.to_string(),
                Some(BfString::String(text)) => text,
                None => String::new(),
            };
            let mut text: String = text.chars().filter(|c| !c.is_control()).collect();
            if text.len() > 32 {
                text.clear();
            }
            let place = placed(glyph);
            // The box reaches as far along as the next glyph starts, or
            // half an em for the last of the run.
            let next = glyphs.get(index + 1).map(|next| {
                let start = placed(next) * hayro::kurbo::Point::ORIGIN;
                (place.inverse() * start).x
            });
            let advance = next.filter(|x| (1.0..4000.0).contains(x)).unwrap_or(500.0);
            let shape = match (colour, &**glyph) {
                (Some(colour), Glyph::Outline(outline)) => {
                    let pixels = props.transform * glyph.transform();
                    let (drawn, pixels) = self.as_drawn(outline, pixels, hint);
                    let outline = outline.outline();
                    let matrix = (place * Affine::scale(1000.0)).as_coeffs();
                    let size = outline.elements().len();
                    (size > 0
                        && size <= MAX_OUTLINE
                        && !drawn.elements().is_empty()
                        && drawn.bounding_box().is_finite()
                        && outline.bounding_box().is_finite()
                        && matrix.iter().all(|value| value.is_finite())
                        && pixels.as_coeffs().iter().all(|value| value.is_finite()))
                    .then_some(Shape {
                        outline,
                        drawn,
                        pixels,
                        colour,
                        matrix,
                        advance,
                        code: None,
                    })
                }
                _ => None,
            };
            if text.is_empty() && shape.is_none() {
                continue;
            }
            let place = (place * Affine::scale_non_uniform(advance, 1000.0)).as_coeffs();
            if place.iter().all(|value| value.is_finite())
                && place[0] * place[3] - place[1] * place[2] != 0.0
            {
                self.found.push(Character { text, place, shape });
            }
        }
    }
    fn draw_image(
        &mut self,
        _: hayro::hayro_interpret::Image<'a, '_>,
        _: hayro::hayro_interpret::ImageDrawProps<'a>,
    ) {
    }
    fn pop_clip(&mut self) {}
    fn pop_transparency_group(&mut self) {
        self.groups.pop();
    }
}

/// How far a pixel around a glyph may be from the others around it, in
/// each channel, for the background to count as plain.
#[cfg(feature = "cdr-pdf")]
const PLAIN: u8 = 2;

/// How far a pixel of a glyph may be from the glyph's colour laid over the
/// background as much as the outline covers the pixel, in each channel.
#[cfg(feature = "cdr-pdf")]
const MATCHING: i32 = 6;

/// Take out of the picture `colours`, `wide` by `high` pixels, the glyphs
/// of `text` that it shows as their shapes say, on a plain background, and
/// as nothing else; they are then drawn as shapes, with codes of `written`.
/// The shape of every other glyph is dropped, and it stays in the picture.
#[cfg(feature = "cdr-pdf")]
fn vectorise(
    colours: &mut [u8],
    wide: u16,
    high: u16,
    text: &mut [Character],
    written: &mut PagesPdf,
) {
    use hayro::kurbo::Shape as _;
    use hayro::vello_cpu::color::palette::css::{BLACK, TRANSPARENT};
    use hayro::vello_cpu::peniko::Fill;
    use hayro::vello_cpu::{Pixmap, RasterizerSettings, RenderContext, Resources, TargetInit};

    if text.iter().all(|character| character.shape.is_none()) {
        return;
    }
    let (wide_, high_) = (usize::from(wide), usize::from(high));
    // How much of each pixel the glyphs cover, as the renderer covered it.
    let mut context = RenderContext::new(wide, high);
    context.set_paint(BLACK);
    context.set_fill_rule(Fill::NonZero);
    for shape in text.iter().filter_map(|character| character.shape.as_ref()) {
        context.set_transform(shape.pixels);
        context.fill_path(&shape.drawn);
    }
    context.flush();
    let mut covered = Pixmap::new(wide, high);
    context.render_with(
        &mut covered,
        &mut Resources::default(),
        RasterizerSettings {
            target_init: TargetInit::Clear(TRANSPARENT),
            ..Default::default()
        },
    );
    drop(context);
    let coverage = |at: usize| covered.data_as_u8_slice()[at * 4 + 3];

    // The pixels each glyph reaches, if they are all on the picture.
    let reach = |shape: &Shape| {
        let bounds = shape.pixels.transform_rect_bbox(shape.drawn.bounding_box());
        let (left, top) = (bounds.x0.floor() - 2.0, bounds.y0.floor() - 2.0);
        let (right, bottom) = (bounds.x1.ceil() + 2.0, bounds.y1.ceil() + 2.0);
        (left >= 0.0 && top >= 0.0 && right <= f64::from(wide) && bottom <= f64::from(high))
            .then_some([left as usize, top as usize, right as usize, bottom as usize])
    };
    // No more pixels looked at than eight times the picture.
    let mut budget = wide_ * high_ * 8;
    let mut backgrounds = vec![None; text.len()];
    // The pixels each glyph inks, as far as they are on the picture.
    let inks: Vec<Option<[usize; 4]>> = (text.iter())
        .map(|character| {
            let shape = character.shape.as_ref()?;
            let bounds = shape.pixels.transform_rect_bbox(shape.drawn.bounding_box());
            let left = bounds.x0.floor().clamp(0.0, f64::from(wide)) as usize;
            let top = bounds.y0.floor().clamp(0.0, f64::from(high)) as usize;
            let right = bounds.x1.ceil().clamp(0.0, f64::from(wide)) as usize;
            let bottom = bounds.y1.ceil().clamp(0.0, f64::from(high)) as usize;
            Some([left, top, right.max(left), bottom.max(top)])
        })
        .collect();
    for (index, character) in text.iter_mut().enumerate() {
        let Some(shape) = character.shape.as_ref() else {
            continue;
        };
        let plain = reach(shape).and_then(|[left, top, right, bottom]| {
            let size = (right - left) * (bottom - top);
            budget = budget.checked_sub(size)?;
            let pixel = |x: usize, y: usize| y * wide_ + x;
            let colour = |at: usize| [colours[at * 3], colours[at * 3 + 1], colours[at * 3 + 2]];
            let mut background: Option<[u8; 3]> = None;
            for y in top..bottom {
                for x in left..right {
                    let at = pixel(x, y);
                    if coverage(at) != 0 {
                        continue;
                    }
                    let here = colour(at);
                    match background {
                        None => background = Some(here),
                        Some(seen) if (0..3).all(|c| seen[c].abs_diff(here[c]) <= PLAIN) => {}
                        Some(_) => return None,
                    }
                }
            }
            let background = background?;
            for y in top..bottom {
                for x in left..right {
                    let at = pixel(x, y);
                    let cover = i32::from(coverage(at));
                    if cover == 0 {
                        continue;
                    }
                    let here = colour(at);
                    let fits = (0..3).all(|c| {
                        let laid = (cover * i32::from(shape.colour[c])
                            + (255 - cover) * i32::from(background[c])
                            + 127)
                            / 255;
                        (laid - i32::from(here[c])).abs() <= MATCHING
                    });
                    if !fits {
                        return None;
                    }
                }
            }
            Some(background)
        });
        match plain {
            Some(background) => backgrounds[index] = Some(background),
            None => character.shape = None,
        }
    }

    // A code for each glyph kept, while there are codes left.
    for character in text.iter_mut() {
        if let Some(shape) = character.shape.as_mut() {
            let drawing = shape_of(&shape.outline);
            let held = shape.outline.bounding_box();
            shape.code = written.code(&character.text, Some((drawing, held)), shape.advance);
            if shape.code.is_none() {
                character.shape = None;
            }
        }
    }

    // A glyph that stays in the picture keeps every pixel it inks, and a
    // glyph that inks one of them stays there too.
    let mut kept = vec![false; wide_ * high_];
    let mark = |kept: &mut [bool], [left, top, right, bottom]: [usize; 4]| {
        for y in top..bottom {
            kept[y * wide_ + left..y * wide_ + right].fill(true);
        }
    };
    for (index, character) in text.iter().enumerate() {
        if let (Some(inked), None) = (inks[index], &character.shape) {
            mark(&mut kept, inked);
        }
    }
    let mut rounds = 0;
    loop {
        let mut changed = false;
        for (index, character) in text.iter_mut().enumerate() {
            let Some(inked @ [left, top, right, bottom]) = inks[index] else {
                continue;
            };
            if character.shape.is_some()
                && (top..bottom).any(|y| kept[y * wide_ + left..y * wide_ + right].contains(&true))
            {
                character.shape = None;
                mark(&mut kept, inked);
                changed = true;
            }
        }
        rounds += 1;
        if !changed {
            break;
        }
        if rounds == 16 {
            // Not settled: every glyph stays in the picture.
            text.iter_mut().for_each(|character| character.shape = None);
            return;
        }
    }

    // Out of the picture with the rest.
    for (index, character) in text.iter().enumerate() {
        let (Some(_), Some([left, top, right, bottom]), Some(background)) =
            (&character.shape, inks[index], backgrounds[index])
        else {
            continue;
        };
        for y in top..bottom {
            for x in left..right {
                let at = y * wide_ + x;
                if coverage(at) != 0 {
                    colours[at * 3..at * 3 + 3].copy_from_slice(&background);
                }
            }
        }
    }
}

/// An outline as the drawing of a glyph of a Type 3 font, after the width
/// of the glyph: the outline, filled in the colour of the text. To a tenth
/// of a thousandth of an em, which is a twentieth of a pixel at a hundred
/// pixels to the em.
#[cfg(feature = "cdr-pdf")]
fn shape_of(outline: &hayro::kurbo::BezPath) -> String {
    use hayro::kurbo::{PathEl, Point};
    let number = |value: f64| (value * 10.0).round() / 10.0;
    let mut drawing = String::new();
    let mut line = |points: &[Point], operator: &str| {
        for point in points {
            drawing += &format!("{} {} ", number(point.x), number(point.y));
        }
        drawing += operator;
        drawing.push('\n');
    };
    let (mut at, mut start) = (Point::ORIGIN, Point::ORIGIN);
    for element in outline.elements() {
        match *element {
            PathEl::MoveTo(p) => {
                start = p;
                line(&[p], "m");
            }
            PathEl::LineTo(p) => line(&[p], "l"),
            // The same curve, as a cubic one.
            PathEl::QuadTo(q, p) => line(
                &[at + (q - at) * (2.0 / 3.0), p + (q - p) * (2.0 / 3.0), p],
                "c",
            ),
            PathEl::CurveTo(one, two, p) => line(&[one, two, p], "c"),
            PathEl::ClosePath => line(&[], "h"),
        }
        at = element.end_point().unwrap_or(start);
    }
    drawing + "f"
}

/// The picture of a page: `wide` by `high` pixels of `colours`, three bytes
/// to a pixel, kept pixel for pixel, or as a JPEG of the quality given if
/// that comes out smaller.
#[cfg(feature = "cdr-pdf")]
struct Picture<'c> {
    wide: u16,
    high: u16,
    colours: &'c [u8],
    jpeg: Option<u8>,
}

/// A PDF being written of which every page is one picture, and the text
/// that was on it. Objects 1 to 3 are the catalogue, the list of pages and
/// the fonts of the text; each page then takes three: itself, what it
/// draws, and the picture; the fonts come last.
#[cfg(feature = "cdr-pdf")]
#[derive(Default)]
struct PagesPdf {
    data: Vec<u8>,
    /// Where each object after the first three starts.
    offsets: Vec<usize>,
    pages: u32,
    /// What each character code of the fonts stands for and draws: code
    /// `n` is code `n % 256` of font `n / 256`.
    codes: Vec<Code>,
    coded: std::collections::HashMap<(String, Option<String>), usize>,
    /// How long the drawings of the codes are, together.
    drawn: usize,
}

/// A character code of the fonts of a rebuilt PDF.
#[cfg(feature = "cdr-pdf")]
struct Code {
    /// The text it stands for; empty for none.
    text: String,
    /// What it draws, and the box that holds that, if it draws anything.
    drawing: Option<(String, hayro::kurbo::Rect)>,
    width: f64,
}

/// Most bytes of the drawings of glyphs in a document, which is some
/// hundred times what a book's fonts take.
#[cfg(feature = "cdr-pdf")]
const MAX_DRAWN: usize = 1 << 25;

/// Most character codes the text of a document is given, 256 to a font.
#[cfg(feature = "cdr-pdf")]
const MAX_CODES: usize = 1 << 16;

#[cfg(feature = "cdr-pdf")]
impl PagesPdf {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn pages(&self) -> u32 {
        self.pages
    }

    fn object(&mut self, dictionary: &str, stream: Option<&[u8]>) {
        if self.data.is_empty() {
            // The second line tells a reader that the file is binary.
            self.data
                .extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        }
        self.offsets.push(self.data.len());
        let number = self.offsets.len() + 3;
        let head = format!("{number} 0 obj\n<< {dictionary} >>\n");
        self.data.extend_from_slice(head.as_bytes());
        if let Some(stream) = stream {
            self.data.extend_from_slice(b"stream\n");
            self.data.extend_from_slice(stream);
            self.data.extend_from_slice(b"\nendstream\n");
        }
        self.data.extend_from_slice(b"endobj\n");
    }

    /// The code of `text` drawn as `drawing`, held in `bounds`, or as
    /// nothing, if it has one or there are codes left; `width` is how far
    /// the glyph reaches, in thousandths of the size of the text, as far as
    /// the first glyph given the code does.
    fn code(
        &mut self,
        text: &str,
        drawing: Option<(String, hayro::kurbo::Rect)>,
        width: f64,
    ) -> Option<usize> {
        let key = (
            text.to_owned(),
            drawing.as_ref().map(|(drawn, _)| drawn.clone()),
        );
        if let Some(&code) = self.coded.get(&key) {
            return Some(code);
        }
        let code = self.codes.len();
        let size = drawing.as_ref().map_or(0, |(drawn, _)| drawn.len());
        if code >= MAX_CODES || self.drawn + size > MAX_DRAWN {
            return None;
        }
        self.drawn += size;
        self.codes.push(Code {
            text: text.to_owned(),
            drawing,
            width,
        });
        self.coded.insert(key, code);
        Some(code)
    }

    /// Add a page `width` by `height` points that shows `picture` over all
    /// of it, and holds `text`: the glyphs that have a code drawn over the
    /// picture, and the rest as characters that do not draw.
    fn page(
        &mut self,
        width: f32,
        height: f32,
        picture: Picture<'_>,
        text: &[Character],
    ) -> Result<(), Error> {
        let Picture {
            wide,
            high,
            colours,
            jpeg,
        } = picture;
        let first = self.offsets.len() + 4;
        self.object(
            &format!(
                "/Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] \
                 /Resources << /XObject << /P {} 0 R >> /Font 3 0 R >> /Contents {} 0 R",
                first + 2,
                first + 1
            ),
            None,
        );
        let mut paint = format!("q {width} 0 0 {height} 0 0 cm /P Do Q");
        if !text.is_empty() {
            use std::fmt::Write as _;
            // Glyphs drawn in their colour, and characters that are not
            // drawn, in a font of glyphs that would draw nothing if they
            // were.
            paint += "\nBT";
            let (mut font, mut drawn, mut colour) = (None, None, None);
            for character in text {
                let shape = character.shape.as_ref();
                let (code, place) = match shape.and_then(|shape| shape.code) {
                    Some(code) => (code, shape.map_or(character.place, |shape| shape.matrix)),
                    None if character.text.is_empty() => continue,
                    None => match self.code(&character.text, None, 1000.0) {
                        Some(code) => (code, character.place),
                        None => continue,
                    },
                };
                if font != Some(code / 256) {
                    font = Some(code / 256);
                    let _ = write!(paint, "\n/T{} 1 Tf", code / 256);
                }
                let draws = shape.is_some_and(|shape| shape.code.is_some());
                if drawn != Some(draws) {
                    drawn = Some(draws);
                    let _ = write!(paint, "\n{} Tr", if draws { 0 } else { 3 });
                }
                if let Some(shape) = shape.filter(|_| draws)
                    && colour != Some(shape.colour)
                {
                    colour = Some(shape.colour);
                    let [r, g, b] = shape
                        .colour
                        .map(|c| (f64::from(c) / 255.0 * 1000.0).round() / 1000.0);
                    let _ = write!(paint, "\n{r} {g} {b} rg");
                }
                let [a, b, c, d, e, f] = place.map(|value| (value * 1000.0).round() / 1000.0);
                let _ = write!(
                    paint,
                    "\n{a} {b} {c} {d} {e} {f} Tm <{:02X}> Tj",
                    code % 256
                );
            }
            paint += "\nET";
        }
        let paint = miniz_oxide::deflate::compress_to_vec_zlib(paint.as_bytes(), 6);
        self.object(
            &format!("/Filter /FlateDecode /Length {}", paint.len()),
            Some(&paint),
        );

        // A page of black on white needs one channel, not three.
        let grey = colours
            .as_chunks::<3>()
            .0
            .iter()
            .all(|pixel| pixel[0] == pixel[1] && pixel[1] == pixel[2]);
        let (space, samples) = if grey {
            ("/DeviceGray", colours.iter().step_by(3).copied().collect())
        } else {
            ("/DeviceRGB", colours.to_vec())
        };
        let mut filter = "/FlateDecode";
        let mut packed = miniz_oxide::deflate::compress_to_vec_zlib(&samples, 6);
        if let Some(quality) = jpeg {
            let kind = if grey {
                ExtendedColorType::L8
            } else {
                ExtendedColorType::Rgb8
            };
            let picture = match kind {
                ExtendedColorType::L8 => {
                    image::GrayImage::from_raw(wide.into(), high.into(), samples)
                        .map(DynamicImage::from)
                }
                _ => image::RgbImage::from_raw(wide.into(), high.into(), samples)
                    .map(DynamicImage::from),
            }
            .ok_or_else(|| Error::Encode("page picture of the wrong size".into()))?;
            let settings = jpeg::Settings::new(quality);
            let lossy = jpeg::encode(&picture, &settings, Deadline(None))?;
            if lossy.len() < packed.len() {
                (filter, packed) = ("/DCTDecode", lossy);
            }
        }
        self.object(
            &format!(
                "/Type /XObject /Subtype /Image /Width {wide} /Height {high} \
                 /ColorSpace {space} /BitsPerComponent 8 /Filter {filter} /Length {}",
                packed.len()
            ),
            Some(&packed),
        );
        self.pages += 1;
        Ok(())
    }

    /// Write the fonts of the text: each a Type 3 font of 256 glyphs, each
    /// one drawn as its code says, or as nothing an em wide, with what each
    /// one stands for.
    fn fonts(&mut self) -> Vec<usize> {
        use std::fmt::Write as _;
        let fonts = self.codes.len().div_ceil(256);
        if fonts == 0 {
            return Vec::new();
        }
        let nothing = self.offsets.len() + 4;
        self.object("/Length 9", Some(b"1000 0 d0"));
        let names: String = (0..256)
            .map(|code| format!("/g{code}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut numbers = Vec::new();
        for font in 0..fonts {
            let range = font * 256..self.codes.len().min(font * 256 + 256);
            // The drawings of the glyphs, and the box that holds them all,
            // which some readers draw no glyph beyond.
            let mut procs = String::new();
            let mut widths = String::new();
            let mut bounds = hayro::kurbo::Rect::new(0.0, -200.0, 1000.0, 800.0);
            for code in 0..256 {
                let mut number = nothing;
                let mut width = 1000.0;
                if let Some(at) = range.clone().nth(code) {
                    width = self.codes[at].width;
                    if let Some((drawing, held)) = self.codes[at].drawing.take() {
                        bounds = bounds.union(held);
                        let drawing = format!("{} 0 d0\n{drawing}", (width * 10.0).round() / 10.0);
                        let packed =
                            miniz_oxide::deflate::compress_to_vec_zlib(drawing.as_bytes(), 6);
                        number = self.offsets.len() + 4;
                        self.object(
                            &format!("/Filter /FlateDecode /Length {}", packed.len()),
                            Some(&packed),
                        );
                    }
                }
                let _ = write!(procs, "/g{code} {number} 0 R ");
                let _ = write!(widths, "{} ", (width * 10.0).round() / 10.0);
            }
            let codes = &self.codes[range];
            let mut map = String::from(
                "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n\
                 /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
                 /CMapName /Adobe-Identity-UCS def /CMapType 2 def\n\
                 1 begincodespacerange <00> <FF> endcodespacerange\n",
            );
            let said: Vec<(usize, &str)> = (codes.iter().enumerate())
                .filter(|(_, code)| !code.text.is_empty())
                .map(|(at, code)| (at, code.text.as_str()))
                .collect();
            for chunk in said.chunks(100) {
                let _ = writeln!(map, "{} beginbfchar", chunk.len());
                for &(at, text) in chunk {
                    let units: String = text
                        .encode_utf16()
                        .map(|unit| format!("{unit:04X}"))
                        .collect();
                    let _ = writeln!(map, "<{at:02X}> <{units}>");
                }
                map += "endbfchar\n";
            }
            map += "endcmap CMapName currentdict /CMap defineresource pop end end";
            let packed = miniz_oxide::deflate::compress_to_vec_zlib(map.as_bytes(), 6);
            let unicode = self.offsets.len() + 4;
            self.object(
                &format!("/Filter /FlateDecode /Length {}", packed.len()),
                Some(&packed),
            );
            numbers.push(self.offsets.len() + 4);
            self.object(
                &format!(
                    "/Type /Font /Subtype /Type3 /FontBBox [{} {} {} {}] \
                     /FontMatrix [0.001 0 0 0.001 0 0] /Resources << >> \
                     /CharProcs << {procs}>> /Encoding << /Type /Encoding /Differences [0 {names}] >> \
                     /FirstChar 0 /LastChar 255 /Widths [{widths}] /ToUnicode {unicode} 0 R",
                    bounds.x0.floor(),
                    bounds.y0.floor(),
                    bounds.x1.ceil(),
                    bounds.y1.ceil()
                ),
                None,
            );
        }
        numbers
    }

    fn finish(mut self) -> Vec<u8> {
        let pages = self.pages();
        let fonts = self.fonts();
        let kids: Vec<String> = (0..pages)
            .map(|page| format!("{} 0 R", 4 + page * 3))
            .collect();
        let catalogue = self.data.len();
        self.data
            .extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        let list = self.data.len();
        let entry = format!(
            "2 0 obj\n<< /Type /Pages /Count {pages} /Kids [{}] >>\nendobj\n",
            kids.join(" ")
        );
        self.data.extend_from_slice(entry.as_bytes());
        let resources = self.data.len();
        let named: Vec<String> = (fonts.iter().enumerate())
            .map(|(index, number)| format!("/T{index} {number} 0 R"))
            .collect();
        let entry = format!("3 0 obj\n<< {} >>\nendobj\n", named.join(" "));
        self.data.extend_from_slice(entry.as_bytes());

        // The table of where every object is, which a reader starts from.
        let table = self.data.len();
        let mut tail = format!("xref\n0 {}\n0000000000 65535 f \n", self.offsets.len() + 4);
        for offset in [catalogue, list, resources].iter().chain(&self.offsets) {
            tail += &format!("{offset:010} 00000 n \n");
        }
        tail += &format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{table}\n%%EOF\n",
            self.offsets.len() + 4
        );
        self.data.extend_from_slice(tail.as_bytes());
        self.data
    }
}

/// An SVG with nothing in it but what draws: elements and attributes that
/// are not on the filter's list are left out, scripts and links to other
/// sites among them. A raster image carried inside is rebuilt like one that
/// stands alone, or left out.
#[cfg(feature = "cdr-svg")]
fn svg(
    data: &[u8],
    limits: &Limits,
    options: &Options,
    deadline: Deadline,
) -> Result<Rebuilt, Error> {
    use svg_hush::data_url_filter::DataUrlFilterResult;

    use crate::limits::Budget;
    use crate::report::Severity;

    let mut filter = svg_hush::Filter::new();
    let budget = &mut Budget::new(limits);
    let (limits, options) = (limits.clone(), options.clone());
    filter.set_data_url_filter(move |url| {
        let Ok((image, _)) = url.decode_to_vec() else {
            return DataUrlFilterResult::Drop;
        };
        // By what it is, not by what the URL calls it.
        let (file_type, mime_type) = match detect::detect(&image) {
            FileType::Jpeg => (FileType::Jpeg, "image/jpeg"),
            FileType::Png => (FileType::Png, "image/png"),
            FileType::Gif => (FileType::Gif, "image/gif"),
            FileType::Webp => (FileType::Webp, "image/webp"),
            _ => return DataUrlFilterResult::Drop,
        };
        match raster(&image, file_type, &limits, &options, deadline) {
            Ok(rebuilt) if rebuilt.file_type == file_type => DataUrlFilterResult::Rewrite {
                mime_type: mime_type.into(),
                data: rebuilt.data,
            },
            _ => DataUrlFilterResult::Drop,
        }
    });
    let mut filtered = Vec::new();
    filter
        .filter(data, &mut filtered)
        .map_err(|error| Error::Decode(error.to_string()))?;
    deadline.check()?;
    // The filter and this crate's analyzer are two readings of one format.
    // Where the second still objects to what the first let through, they
    // disagree about the file, and nobody should have to pick a side.
    let mut left = Vec::new();
    crate::svg::analyze(&filtered, budget, &mut left);
    if left.iter().any(|finding| finding.severity > Severity::Info) {
        return Err(Error::Decode(
            "active content is left after filtering".into(),
        ));
    }
    Ok(Rebuilt {
        data: filtered,
        file_type: FileType::Svg,
        width: 0,
        height: 0,
        frames: 1,
    })
}

/// A raster image written anew from its pixels.
fn raster(
    data: &[u8],
    file_type: FileType,
    limits: &Limits,
    options: &Options,
    deadline: Deadline,
) -> Result<Rebuilt, Error> {
    let unsupported = |reason| Error::Unsupported { file_type, reason };
    let input = Cursor::new(data);
    let density = palette::density_of(data, file_type);
    match file_type {
        FileType::Jpeg => {
            let mut settings = jpeg::Settings::new(options.jpeg_quality);
            match jpeg::read(data, limits, deadline) {
                Ok(mut coefficients) => {
                    settings.source = coefficients.source();
                    // A profile that changes the colours is applied to the
                    // pixels; the coefficients are only kept as they are,
                    // and inks only if they are to stay inks, with a profile
                    // that can be written anew.
                    let icc = coefficients.icc.take();
                    let profile = if coefficients.inks() {
                        match (options.inks, icc) {
                            (Inks::Keep, None) => Some(None),
                            (Inks::Keep, Some(icc)) => colour::rewritten_cmyk(&icc).map(Some),
                            (_, _) => None,
                        }
                    } else {
                        ToSrgb::new(icc).is_none().then_some(None)
                    };
                    if let Some(profile) = profile
                        && coefficients.orient()
                        && let Some(data) = coefficients.write(profile.as_deref())
                    {
                        let (width, height) = coefficients.dimensions();
                        return Ok(Rebuilt {
                            data,
                            file_type: FileType::Jpeg,
                            width,
                            height,
                            frames: 1,
                        });
                    }
                }
                Err(refusal) => {
                    if let Some(answer) = refusal.answer() {
                        return Err(answer);
                    }
                }
            }
            let output = Output::Jpeg(Box::new(settings));
            if let Some(image) = cmyk_jpeg(data, limits)? {
                return write(image, deadline, output);
            }
            let decoder = JpegDecoder::new(input).map_err(decode_error)?;
            still(decoder, limits, deadline, output)
        }
        FileType::Png => {
            let mut decoder = PngDecoder::new(input).map_err(decode_error)?;
            if !decoder.is_apng().map_err(decode_error)? {
                return still(decoder, limits, deadline, Output::Png(density));
            }
            // Frame by frame as the file has them, where that can be done.
            match apng::rebuild(data, limits, deadline) {
                Err(Error::Decode(_) | Error::Encode(_)) => {}
                done => return done,
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
            // A lossy picture keeps what its coder coded, if that shows
            // every pixel as the original does.
            match webp::rebuild(data, limits, deadline) {
                Ok(Some(rebuilt)) => return Ok(rebuilt),
                Ok(None) | Err(Error::Decode(_) | Error::Encode(_)) => {}
                Err(other) => return Err(other),
            }
            let mut decoder = WebPDecoder::new(input).map_err(decode_error)?;
            if !decoder.has_animation() {
                return still(decoder, limits, deadline, Output::Webp);
            }
            let canvas = Canvas::of(&mut decoder, limits)?;
            animation(decoder, canvas, limits, deadline, Animated::Webp)
        }
        FileType::Gif => {
            // Pixels laid over pixels can show more than a GIF's 256
            // colours, which full colour written back would have to lose.
            match gif::rebuild(data, limits, deadline) {
                Err(Error::Decode(_) | Error::Encode(_)) => {}
                done => return done,
            }
            let mut decoder = GifDecoder::new(input).map_err(decode_error)?;
            let canvas = Canvas::of(&mut decoder, limits)?;
            animation(decoder, canvas, limits, deadline, Animated::Gif)
        }
        FileType::Bmp => still(
            BmpDecoder::new(input).map_err(decode_error)?,
            limits,
            deadline,
            Output::Png(density),
        ),
        FileType::Tiff => tif::rebuild(data, limits, deadline, options.inks == Inks::Keep),
        FileType::Psd => {
            match psd::composite(data, limits, deadline, options.inks == Inks::Keep)? {
                psd::Composite::Colours(picture) => {
                    write(picture.image, deadline, Output::Png(picture.density))
                }
                psd::Composite::Inks(kept) => {
                    let mut pages = tiff_out::Pages::new(limits)?;
                    pages.add_inks(&kept, deadline)?;
                    pages.finish()
                }
            }
        }
        FileType::Ico => match icon(data, limits, deadline) {
            Err(Error::Decode(_) | Error::Encode(_)) => still(
                // One image of it, if not all of them can be read.
                IcoDecoder::new(input).map_err(decode_error)?,
                limits,
                deadline,
                Output::Png(density),
            ),
            other => other,
        },
        // There is no encoder for it here; a PNG keeps every pixel.
        FileType::Jxl => {
            if let Some(animation) = jxl::rebuild(data, limits, deadline)? {
                return Ok(animation);
            }
            still(
                JxlDecoder::new(input).map_err(decode_error)?,
                limits,
                deadline,
                Output::Png(density),
            )
        }
        // There is no AV1 encoder here; a PNG keeps every pixel.
        FileType::Avif => {
            let image = avif::read(data, limits, deadline)?;
            write(image, deadline, Output::Png(None))
        }
        _ => Err(unsupported("not a type this build rebuilds")),
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
        Self::of(ColorProfile::new_from_slice(&icc?).ok()?)
    }

    /// As `new`, from a profile already read.
    fn of(profile: ColorProfile) -> Option<Self> {
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
        // Some decoders take such a file and make frames of their own size.
        if width == 0 || height == 0 {
            return Err(Error::Decode("image has a zero dimension".into()));
        }
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
    decoder: impl ImageDecoder,
    limits: &Limits,
    deadline: Deadline,
    output: Output,
) -> Result<Rebuilt, Error> {
    write(picture(decoder, limits)?, deadline, output)
}

/// The pixels of a still image, in sRGB and the right way up.
fn picture(mut decoder: impl ImageDecoder, limits: &Limits) -> Result<DynamicImage, Error> {
    let canvas = Canvas::of(&mut decoder, limits)?;
    // The orientation lives in metadata the new file will not have.
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut image = DynamicImage::from_decoder(decoder).map_err(decode_error)?;
    if let Some(colors) = &canvas.colors {
        colors.image(&mut image);
    }
    image.apply_orientation(orientation);
    Ok(image)
}

/// An icon with every image of the original, each written anew as a PNG.
fn icon(data: &[u8], limits: &Limits, deadline: Deadline) -> Result<Rebuilt, Error> {
    use image::codecs::ico::{IcoEncoder, IcoFrame};

    let broken = || Error::Decode("icon directory is out of bounds".into());
    let le32 = |bytes: &[u8], at: usize| {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize
    };
    let count = u16::from_le_bytes(
        data.get(4..6)
            .ok_or_else(broken)?
            .try_into()
            .unwrap_or_default(),
    );
    let mut seen = std::collections::HashSet::new();
    let mut pictures = Vec::new();
    let mut pixels = 0u64;
    for index in 0..count as usize {
        let at = 6 + index * 16;
        let entry = data.get(at..at + 16).ok_or_else(broken)?;
        let (size, offset) = (le32(entry, 8), le32(entry, 12));
        let image = offset
            .checked_add(size)
            .and_then(|end| data.get(offset..end))
            .ok_or_else(broken)?;
        // An entry that names an image another one does adds nothing.
        if !seen.insert((offset, size)) {
            continue;
        }
        // An icon of this one image alone, for the decoder to read.
        let mut single = vec![0, 0, 1, 0, 1, 0];
        single.extend_from_slice(&entry[..12]);
        single.extend_from_slice(&22u32.to_le_bytes());
        single.extend_from_slice(image);
        let decoder = IcoDecoder::new(Cursor::new(&single[..])).map_err(decode_error)?;
        let picture = picture(decoder, limits)?.into_rgba8();
        pixels += picture.width() as u64 * picture.height() as u64;
        if pixels > limits.max_pixels {
            return Err(Error::TooLarge);
        }
        deadline.check()?;
        pictures.push(picture);
    }
    let mut encoded = Vec::new();
    for picture in &pictures {
        let (width, height) = picture.dimensions();
        let png = palette::smallest(&DynamicImage::from(picture.clone()), None)
            .ok_or_else(|| Error::Encode("no PNG holds these pixels".into()))?;
        encoded.push((png, width, height));
    }
    let frames = encoded
        .iter()
        .map(|(png, width, height)| {
            IcoFrame::with_encoded(&png[..], *width, *height, ExtendedColorType::Rgba8)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(encode_error)?;
    let mut out = Vec::new();
    IcoEncoder::new(&mut out)
        .encode_images(&frames)
        .map_err(encode_error)?;
    let largest = pictures
        .iter()
        .map(|p| p.dimensions())
        .max_by_key(|&(w, h)| w as u64 * h as u64)
        .ok_or_else(broken)?;
    Ok(Rebuilt {
        data: out,
        file_type: FileType::Ico,
        width: largest.0,
        height: largest.1,
        frames: pictures.len() as u32,
    })
}

/// Write a still image in the format `output` names.
fn write(image: DynamicImage, deadline: Deadline, output: Output) -> Result<Rebuilt, Error> {
    deadline.check()?;
    let (width, height) = (image.width(), image.height());
    let mut data = Vec::new();
    // The pixels are held once: an image that has to be converted gives
    // way to what it is converted to, and one that has not is not copied.
    let file_type = match output {
        Output::Jpeg(settings) => {
            // The format stores 8-bit grey or colour and nothing else.
            let image: DynamicImage = match image {
                DynamicImage::ImageLuma8(_) | DynamicImage::ImageRgb8(_) => image,
                _ if image.color().has_color() => image.into_rgb8().into(),
                _ => image.into_luma8().into(),
            };
            data = jpeg::encode(&image, &settings, deadline)?;
            FileType::Jpeg
        }
        Output::Png(density) => {
            data = palette::smallest(&image, density)
                .ok_or_else(|| Error::Encode("no PNG holds these pixels".into()))?;
            FileType::Png
        }
        Output::Webp => {
            let image: DynamicImage = if image.color().has_alpha() {
                image.into_rgba8().into()
            } else {
                image.into_rgb8().into()
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
        width,
        height,
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
    use image::codecs::png::PngEncoder;
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
            (ImageFormat::Ico, FileType::Ico),
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
        // Every frame as it was: 16 bits, its place, delay, blend and
        // disposal, and the number of plays.
        let frames = |data: &[u8]| {
            let mut decoder = ::png::Decoder::new(Cursor::new(data));
            decoder.set_transformations(::png::Transformations::IDENTITY);
            let mut reader = decoder.read_info().unwrap();
            let plays = reader.info().animation_control().unwrap().num_plays;
            let mut buffer = vec![0; reader.output_buffer_size().unwrap()];
            let mut frames = Vec::new();
            for _ in 0..3 {
                let read = reader.next_frame(&mut buffer).unwrap();
                let mut control = *reader.info().frame_control().unwrap();
                control.sequence_number = 0;
                let depth = reader.info().bit_depth;
                frames.push((control, depth, buffer[..read.buffer_size()].to_vec()));
            }
            (frames, plays)
        };
        let (before, after) = (frames(&data), frames(&rebuilt.data));
        assert_eq!(after.1, 5);
        assert_eq!(format!("{before:?}"), format!("{after:?}"));
        assert_eq!(after.0[2].2[..8], [0, 0, 0x12, 0x34, 0, 0, 0x40, 0]);
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

    #[cfg(feature = "cdr-svg")]
    #[test]
    fn svg_keeps_what_draws_and_nothing_else() {
        use base64::Engine;

        let mut png = encoded(&picture().into(), ImageFormat::Png);
        png.extend_from_slice(PAYLOAD);
        let embedded = base64::engine::general_purpose::STANDARD.encode(&png);
        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
                 width="48" height="32" onload="alert(1)">
              <script>alert(document.cookie)</script>
              <rect width="10" height="10" fill="#f00" onclick="alert(2)"/>
              <a xlink:href="https://example.com/phish"><circle r="4"/></a>
              <image href="https://tracker.example/pixel.png" width="1" height="1"/>
              <image xlink:href="data:image/png;base64,{embedded}" width="48" height="32"/>
              <image href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" width="1" height="1"/>
              <foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="//evil"/></body></foreignObject>
            </svg>"##
        );
        let rebuilt = run(svg.as_bytes()).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Svg);
        let text = String::from_utf8(rebuilt.data.clone()).unwrap();
        for gone in [
            "script",
            "alert",
            "onload",
            "onclick",
            "example",
            "tracker",
            "foreignObject",
            "iframe",
            "text/html",
        ] {
            assert!(!text.contains(gone), "{gone} in {text}");
        }
        assert!(text.contains("<rect") && text.contains("<circle"), "{text}");
        assert!(scans_clean(&rebuilt.data), "{text}");

        // The picture inside is one rebuilt from its pixels.
        let start = text.find("data:image/png;base64,").expect(&text) + 22;
        let end = start + text[start..].find('"').unwrap();
        let inner = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&text[start..end])
            .unwrap();
        assert!(!contains(&inner, PAYLOAD));
        assert_eq!(
            image::load_from_memory(&inner).unwrap().to_rgb8(),
            picture()
        );

        assert!(matches!(run(b"<svg"), Err(Error::Decode(_))));
    }

    #[cfg(feature = "cdr-pdf")]
    #[test]
    fn pdf_pages_come_back_as_pictures() {
        let corpus = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus");
        let read = |name: &str| std::fs::read(format!("{corpus}/{name}")).unwrap();

        let rebuilt = run(&read("clean/page.pdf")).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Pdf);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (0, 0, 1));
        assert!(rebuilt.data.starts_with(b"%PDF-1.7\n"));
        assert!(rebuilt.data.ends_with(b"%%EOF\n"));
        assert!(scans_clean(&rebuilt.data));
        // It is a document a reader takes: this one, to begin with.
        let again = run(&rebuilt.data).unwrap();
        assert_eq!(again.frames, 1);

        // Twice the dots each way is four times the picture.
        let size = |dpi| {
            let options = Options {
                pdf_dpi: dpi,
                ..Options::default()
            };
            let rebuilt = rebuild(&read("clean/page.pdf"), &Limits::default(), &options);
            let data = rebuilt.unwrap().data;
            let width = data.windows(7).position(|w| w == b"/Width ").unwrap() + 7;
            let digits: String = data[width..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .map(|&byte| byte as char)
                .collect();
            digits.parse::<u32>().unwrap()
        };
        assert_eq!(size(144), size(72) * 2);

        // What a page does is not in a picture of it.
        let script = read("malicious/javascript.pdf");
        assert!(contains(&script, b"/JavaScript"));
        let rebuilt = run(&script).unwrap();
        assert!(!contains(&rebuilt.data, b"JavaScript"));
        assert!(scans_clean(&rebuilt.data));

        let small = Limits {
            max_pixels: 100,
            ..Limits::default()
        };
        let refused = rebuild(&read("clean/page.pdf"), &small, &Options::default());
        assert!(matches!(refused, Err(Error::TooLarge)), "{refused:?}");
        assert!(matches!(run(b"%PDF-1.7\nnothing"), Err(Error::Decode(_))));
    }

    /// What a document says, read from the characters of its first page.
    #[cfg(feature = "cdr-pdf")]
    fn said(data: &[u8]) -> Vec<(String, [i32; 2])> {
        use hayro::hayro_syntax::Pdf;
        let document = Pdf::new(hayro::hayro_syntax::PdfData::from(data.to_vec())).unwrap();
        let page = &document.pages()[0];
        let (width, height) = page.render_dimensions();
        let settings = hayro::hayro_interpret::InterpreterSettings::default();
        let found = Found {
            scale: 1.0,
            wide: width as u16,
            high: height as u16,
            shapes: false,
        };
        (text_of(page, &settings, height, found).into_iter())
            .filter(|character| !character.text.is_empty())
            .map(|character| {
                let [.., x, y] = character.place;
                (character.text, [x.round() as i32, y.round() as i32])
            })
            .collect()
    }

    /// A document of one page, US letter, that draws `content`, with
    /// Helvetica as `/F1`.
    #[cfg(feature = "cdr-pdf")]
    fn one_page(content: &[u8]) -> Vec<u8> {
        let objects: [&[u8]; 5] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            &[
                format!("<< /Length {} >>\nstream\n", content.len()).as_bytes(),
                content,
                b"\nendstream",
            ]
            .concat(),
        ];
        let mut data = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            offsets.push(data.len());
            data.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            data.extend_from_slice(object);
            data.extend_from_slice(b"\nendobj\n");
        }
        let table = data.len();
        data.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            data.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        let tail = format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{table}\n%%EOF\n");
        data.extend_from_slice(tail.as_bytes());
        data
    }

    /// The first page of a document as a reader draws it, two pixels to
    /// the point, in levels of grey.
    #[cfg(feature = "cdr-pdf")]
    fn looks(data: &[u8]) -> Vec<u8> {
        use hayro::hayro_interpret::InterpreterSettings;
        use hayro::hayro_syntax::Pdf;
        use hayro::vello_cpu::color::palette::css::WHITE;
        use hayro::{PixmapSettings, RenderCache, RenderSettings, render};
        let document = Pdf::new(hayro::hayro_syntax::PdfData::from(data.to_vec())).unwrap();
        let settings = PixmapSettings {
            x_scale: 2.0,
            y_scale: 2.0,
            bg_color: WHITE,
        };
        let drawn = render(
            &document.pages()[0],
            &RenderCache::new(),
            &InterpreterSettings::default(),
            // Hinting moves the stems of a font's glyphs to whole pixels,
            // which a reader does for one font and not for another.
            &RenderSettings {
                hinting: false,
                ..RenderSettings::default()
            },
            &settings,
        );
        let pixels = drawn.data_as_u8_slice().as_chunks::<4>().0.iter();
        pixels.map(|pixel| pixel[1]).collect()
    }

    /// How many pixels of two drawings of the same size are more than a
    /// quarter of the way from black to white apart.
    #[cfg(feature = "cdr-pdf")]
    fn apart(one: &[u8], other: &[u8]) -> usize {
        assert_eq!(one.len(), other.len());
        (one.iter().zip(other))
            .filter(|(a, b)| a.abs_diff(**b) > 64)
            .count()
    }

    /// The picture of the first page of a rebuilt document, as written.
    #[cfg(feature = "cdr-pdf")]
    fn page_picture(data: &[u8]) -> Vec<u8> {
        let at = data.windows(6).position(|w| w == b"/Image").unwrap();
        let end = data[at..]
            .windows(9)
            .position(|w| w == b"endstream")
            .unwrap();
        data[at..at + end].to_vec()
    }

    #[cfg(feature = "cdr-pdf")]
    #[test]
    fn pdf_text_is_kept_where_it_was_and_drawn_as_shapes() {
        let data = one_page(
            b"BT /F1 24 Tf 72 700 Td (Hi there) Tj ET \
              BT /F1 18 Tf 0 1 -1 0 300 300 Tm (Up) Tj ET \
              BT /F1 9 Tf 0.8 0.1 0.1 rg 72 600 Td (small and red) Tj ET",
        );
        let before = said(&data);
        let text: String = before.iter().map(|(text, _)| text.as_str()).collect();
        assert_eq!(text, "Hi thereUpsmall and red");
        assert_eq!(before[0].1, [72, 700]);
        let blank = page_picture(&run(&one_page(b"")).unwrap().data);
        let ink = looks(&data).iter().filter(|&&grey| grey < 192).count();
        assert!(ink > 1000, "{ink}");

        let rebuilt = run(&data).unwrap().data;
        assert!(scans_clean(&rebuilt));
        assert!(contains(&rebuilt, b"/Subtype /Type3"));
        assert!(!contains(&rebuilt, b"FontFile"));
        // The same characters, where they were, upright or not.
        assert_eq!(said(&rebuilt), before);
        // Out of the picture, and drawn as they were, to the odd pixel at
        // the edge of a glyph.
        assert!(page_picture(&rebuilt) == blank);
        let off = apart(&looks(&rebuilt), &looks(&data));
        assert!(off * 50 < ink, "{off} of {ink}");

        // Kept in the picture, the characters do not draw.
        let raster = Options {
            pdf_vector_text: false,
            ..Options::default()
        };
        let pictured = rebuild(&data, &Limits::default(), &raster).unwrap().data;
        assert_eq!(said(&pictured), before);
        assert!(page_picture(&pictured) != blank);

        // Without the text, the shapes are drawn and say nothing.
        let silent = Options {
            pdf_text: false,
            ..Options::default()
        };
        let shapes = rebuild(&data, &Limits::default(), &silent).unwrap().data;
        assert_eq!(said(&shapes), []);
        assert!(page_picture(&shapes) == blank);
        assert_eq!(looks(&shapes), looks(&rebuilt));

        // With neither, a picture of the page and nothing else.
        let neither = Options {
            pdf_text: false,
            pdf_vector_text: false,
            ..Options::default()
        };
        let plain = rebuild(&data, &Limits::default(), &neither).unwrap().data;
        assert!(!contains(&plain, b"Type3"));
        assert_eq!(said(&plain), []);
        assert!(page_picture(&plain) == page_picture(&pictured));
    }

    #[cfg(feature = "cdr-pdf")]
    #[test]
    fn pdf_text_that_is_not_drawn_plainly_stays_in_the_picture() {
        let raster = Options {
            pdf_vector_text: false,
            ..Options::default()
        };
        // Whether all of it stays, and what is drawn on the page.
        for (stays, content) in [
            // Half covered by a white box drawn after it: the letters it
            // covers stay, hidden, and the others are shapes.
            (
                false,
                &b"BT /F1 24 Tf 72 700 Td (Covered) Tj ET 1 g 100 690 40 40 re f"[..],
            ),
            // Outlined, not filled.
            (true, b"BT /F1 24 Tf 1 Tr 72 600 Td (Outlined) Tj ET"),
            // On a background of two colours, which meet under it.
            (
                true,
                b"0.9 g 72 495 30 40 re f 0.6 g 102 495 60 40 re f \
                  0 g BT /F1 24 Tf 90 505 Td (W) Tj ET",
            ),
        ] {
            let shown = String::from_utf8_lossy(content);
            let data = one_page(content);
            let pictured = rebuild(&data, &Limits::default(), &raster).unwrap().data;
            let rebuilt = run(&data).unwrap().data;
            assert_eq!(said(&rebuilt), said(&data));
            let same = page_picture(&rebuilt) == page_picture(&pictured);
            assert_eq!(same, stays, "{shown}");
            // No farther from the page than the picture alone is.
            let ink = looks(&data).iter().filter(|&&grey| grey < 192).count();
            let off = apart(&looks(&rebuilt), &looks(&data));
            let pictured = apart(&looks(&pictured), &looks(&data));
            assert!(
                off <= pictured + ink / 50,
                "{shown}: {off}, {pictured} of {ink}"
            );
        }
    }

    #[cfg(feature = "cdr-pdf")]
    #[test]
    fn pdf_pages_can_be_kept_as_jpeg() {
        let corpus = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus");
        let data = std::fs::read(format!("{corpus}/clean/page.pdf")).unwrap();
        let options = Options {
            pdf_pages: PageImage::Jpeg,
            ..Options::default()
        };
        // A blank page is smaller pixel for pixel, and stays that way.
        let rebuilt = rebuild(&data, &Limits::default(), &options).unwrap();
        assert!(contains(&rebuilt.data, b"/Filter /FlateDecode"));

        // A photograph is not: shades that run into one another, with grain.
        let photograph: Vec<u8> = (0..120u32 * 80)
            .flat_map(|i| {
                let (x, y) = (i % 120, i / 120);
                let grain = i.wrapping_mul(2_654_435_761) >> 29;
                [x + y + grain, 2 * x + grain, 255 - y - grain].map(|shade| shade as u8)
            })
            .collect();
        let page = |jpeg| {
            let mut written = PagesPdf::default();
            let picture = Picture {
                wide: 120,
                high: 80,
                colours: &photograph,
                jpeg,
            };
            written.page(120.0, 80.0, picture, &[]).unwrap();
            written.finish()
        };
        let (lossless, lossy) = (page(None), page(Some(75)));
        assert!(contains(
            &lossless,
            b"/BitsPerComponent 8 /Filter /FlateDecode"
        ));
        assert!(contains(
            &lossy,
            b"/BitsPerComponent 8 /Filter /DCTDecode /Length"
        ));
        assert!(lossy.len() < lossless.len());
        // A reader takes both: this one draws them again.
        for written in [lossless, lossy] {
            assert!(scans_clean(&written));
            assert_eq!(run(&written).unwrap().frames, 1);
        }
    }

    #[cfg(feature = "cdr-pdf")]
    #[test]
    fn a_supplied_password_opens_a_pdf_for_rebuilding() {
        // Its user password is "secret", its owner password "owner".
        let data = include_bytes!("../tests/data/password-page.pdf");
        assert!(matches!(run(data), Err(Error::Decode(_))));
        for password in ["secret", "owner"] {
            let passwords = [b"wrong".to_vec(), vec![0xFF, 0xFE], password.into()];
            let rebuilt =
                rebuild_with(data, &Limits::default(), &Options::default(), &passwords).unwrap();
            assert_eq!((rebuilt.file_type, rebuilt.frames), (FileType::Pdf, 1));
            // What comes back needs no password, and shows the page.
            assert!(!contains(&rebuilt.data, b"/Encrypt"));
            assert!(scans_clean(&rebuilt.data));
            assert_eq!(run(&rebuilt.data).unwrap().frames, 1);
        }

        // Through the scanner: without the password it is not clean, so it
        // is not rebuilt; with it, it is both.
        let closed = crate::Scanner::builder().build();
        let hints = crate::ScanHints::default();
        let refused = closed.sanitize(data, hints, &Options::default());
        assert!(matches!(refused, Err(Error::Rejected(_))), "{refused:?}");
        let opened = crate::Scanner::builder().pdf_passwords(["secret"]).build();
        let sanitized = opened.sanitize(data, hints, &Options::default()).unwrap();
        assert_eq!(sanitized.image.file_type, FileType::Pdf);
    }

    #[test]
    fn rebuilds_only_the_types_asked_for() {
        let png = encoded(&picture().into(), ImageFormat::Png);
        let gif = encoded(&picture().into(), ImageFormat::Gif);
        let options = Options {
            types: Some(vec![FileType::Png]),
            ..Options::default()
        };
        assert!(rebuild(&png, &Limits::default(), &options).is_ok());
        let refused = rebuild(&gif, &Limits::default(), &options);
        assert!(
            matches!(refused, Err(Error::Unsupported { .. })),
            "{refused:?}"
        );
    }

    /// Found by fuzzing: 51 bytes on which the JPEG XL decoder indexes past
    /// the end of a list. A scan finds nothing in them.
    #[test]
    fn a_panic_in_a_decoder_is_an_error() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        let data = std::fs::read(format!("{clean}/decoder-panic.jxl")).unwrap();
        assert!(scans_clean(&data));
        let rebuilt = run(&data);
        assert!(matches!(rebuilt, Err(Error::Decode(_))), "{rebuilt:?}");
    }

    #[test]
    fn jpeg_xl_comes_back_as_png() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        for name in ["photo.jxl", "photo-container.jxl"] {
            let data = std::fs::read(format!("{clean}/{name}")).unwrap();
            let rebuilt = run(&data).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Png, "{name}");
            assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (64, 48, 1));
            assert!(scans_clean(&rebuilt.data), "{name}");
        }
    }

    /// The samples are white, the first ink, and black. Their profile makes
    /// the first ink red, which mixing the inks by arithmetic does not.
    #[test]
    fn cmyk_inks_get_the_colours_of_their_profile() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        // The two ways a JPEG stores four inks.
        for name in ["cmyk-profile.jpg", "ycck-profile.jpg"] {
            let data = std::fs::read(format!("{clean}/{name}")).unwrap();
            let options = Options {
                jpeg_quality: 100,
                ..Options::default()
            };
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

    fn corpus(name: &str) -> Vec<u8> {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        std::fs::read(format!("{clean}/{name}")).unwrap()
    }

    fn most_apart(one: &RgbImage, other: &RgbImage) -> u8 {
        assert_eq!(one.dimensions(), other.dimensions());
        one.as_raw()
            .iter()
            .zip(other.as_raw())
            .map(|(a, b)| a.abs_diff(*b))
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn jpeg_is_transcoded_without_loss() {
        let data = corpus("progressive-restart.jpg");
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Jpeg);
        let before = image::load_from_memory(&data).unwrap().to_rgb8();
        let after = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
        assert_eq!(before, after);
        // No larger than the file it came from, give or take its markers.
        assert!(
            rebuilt.data.len() <= data.len() + 64,
            "{}",
            rebuilt.data.len()
        );
    }

    #[test]
    fn jpeg_is_turned_in_its_coefficients() {
        let data = corpus("rotated-422.jpg");
        let rebuilt = run(&data).unwrap();
        assert_eq!((rebuilt.width, rebuilt.height), (32, 48));
        let turned = image::load_from_memory(&data).unwrap().rotate90().to_rgb8();
        let after = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
        assert!(most_apart(&turned, &after) <= 6);

        // Edges that cut through blocks are turned as pixels instead.
        let odd = DynamicImage::from(RgbImage::from_fn(45, 29, |x, y| {
            Rgb([x as u8 * 5, y as u8 * 7, (x + y) as u8])
        }));
        let jpeg = encoded(&odd, ImageFormat::Jpeg);
        let mut exif = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\x01".to_vec();
        exif.extend_from_slice(b"\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0");
        let mut segment = vec![0xFF, 0xE1];
        segment.extend_from_slice(&(exif.len() as u16 + 2).to_be_bytes());
        segment.extend_from_slice(&exif);
        let rebuilt = run(&[&jpeg[..2], &segment, &jpeg[2..]].concat()).unwrap();
        assert_eq!((rebuilt.width, rebuilt.height), (29, 45));
        let turned = image::load_from_memory(&jpeg).unwrap().rotate90().to_rgb8();
        let after = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
        assert!(most_apart(&turned, &after) <= 24);
    }

    #[test]
    fn few_colours_stay_indexed() {
        let colours = [[0, 0, 0], [255, 0, 0], [0, 255, 0], [9, 9, 200]];
        let picture = RgbImage::from_fn(30, 20, |x, y| {
            Rgb(colours[(((x * 7919) ^ (y * 104_729)) % 4) as usize])
        });
        let rebuilt = run(&encoded(&picture.clone().into(), ImageFormat::Png)).unwrap();
        // Colour type 3 in the header.
        assert_eq!(rebuilt.data[25], 3);
        let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
        assert_eq!(pixels, picture);
    }

    #[test]
    fn an_icon_keeps_every_image() {
        use image::codecs::ico::{IcoEncoder, IcoFrame};

        let sizes = [(16u32, 16u32), (32, 32), (48, 48)];
        let pictures: Vec<RgbaImage> = sizes
            .iter()
            .map(|&(w, h)| {
                RgbaImage::from_fn(w, h, |x, y| Rgba([x as u8 * 5, y as u8 * 5, 99, 200]))
            })
            .collect();
        let frames: Vec<IcoFrame> = pictures
            .iter()
            .map(|p| {
                IcoFrame::as_png(p.as_raw(), p.width(), p.height(), ExtendedColorType::Rgba8)
                    .unwrap()
            })
            .collect();
        let mut data = Vec::new();
        IcoEncoder::new(&mut data).encode_images(&frames).unwrap();
        data.extend_from_slice(PAYLOAD);
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Ico);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (48, 48, 3));
        assert!(!contains(&rebuilt.data, PAYLOAD));
        let largest = image::load_from_memory(&rebuilt.data).unwrap().to_rgba8();
        assert_eq!(largest, pictures[2]);
    }

    fn near(found: [u8; 3], expected: [u8; 3], by: u8) -> bool {
        found.iter().zip(expected).all(|(a, b)| a.abs_diff(b) <= by)
    }

    #[test]
    fn tiff_of_every_kind_comes_back_as_it_looks() {
        // Expected values are what ImageMagick makes of each file.
        for (name, at, expected, by) in [
            ("palette.tif", (5, 5), [222, 198, 100], 0),
            ("palette.tif", (40, 25), [218, 186, 80], 0),
            ("lab.tif", (5, 5), [222, 201, 114], 2),
            ("lab.tif", (40, 25), [221, 191, 81], 2),
            ("planar-300dpi.tif", (5, 5), [222, 201, 113], 0),
            ("planar-300dpi.tif", (40, 25), [221, 191, 80], 0),
        ] {
            let rebuilt = run(&corpus(name)).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Png, "{name}");
            assert_eq!((rebuilt.width, rebuilt.height), (48, 32), "{name}");
            let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
            let Rgb(found) = *pixels.get_pixel(at.0, at.1);
            assert!(near(found, expected, by), "{name} at {at:?}: {found:?}");
        }
        // Its map holds colours of 16 bits, and so does the picture.
        let palette = run(&corpus("palette.tif")).unwrap();
        assert_eq!((palette.data[24], palette.data[25]), (16, 2));
        // 300 dots an inch, in a pHYs chunk.
        let planar = run(&corpus("planar-300dpi.tif")).unwrap();
        let mut phys = b"pHYs".to_vec();
        phys.extend_from_slice(&11811u32.to_be_bytes());
        phys.extend_from_slice(&11811u32.to_be_bytes());
        phys.push(1);
        assert!(contains(&planar.data, &phys));
    }

    #[test]
    fn tiff_inks_get_the_colours_of_their_profile() {
        let rebuilt = run(&corpus("cmyk-profile.tif")).unwrap();
        assert_eq!((rebuilt.width, rebuilt.height), (24, 8));
        assert!(!contains(&rebuilt.data, b"acsp"));
        let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
        for (x, expected) in [(3, [255, 255, 255]), (12, [255, 0, 0]), (20, [0, 0, 0])] {
            let Rgb(found) = *pixels.get_pixel(x, 4);
            assert!(near(found, expected, 15), "at {x}: {found:?}");
        }
    }

    /// Inks as a JPEG decoder gives them, and the profile embedded.
    fn jpeg_inks(data: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        use zune_core::colorspace::ColorSpace;
        use zune_core::options::DecoderOptions;
        // Samples as they are stored, YCCK or CMYK.
        let mut decoder = zune_jpeg::JpegDecoder::new(std::io::Cursor::new(data));
        decoder.decode_headers().unwrap();
        let stored = decoder.input_colorspace().unwrap();
        let options = DecoderOptions::default().jpeg_set_out_colorspace(stored);
        let mut decoder =
            zune_jpeg::JpegDecoder::new_with_options(std::io::Cursor::new(data), options);
        let inks = decoder.decode().unwrap();
        assert!(matches!(stored, ColorSpace::CMYK | ColorSpace::YCCK));
        (inks, decoder.icc_profile())
    }

    /// Every sample of the first page of a TIFF, and its profile.
    fn tiff_samples(data: &[u8]) -> (tiff::ColorType, Vec<u8>, Option<Vec<u8>>) {
        let mut decoder = tiff::decoder::Decoder::new(std::io::Cursor::new(data)).unwrap();
        let colour = decoder.colortype().unwrap();
        let icc = decoder.get_tag_u8_vec(tiff::tags::Tag::IccProfile).ok();
        let tiff::decoder::DecodingResult::U8(samples) = decoder.read_image().unwrap() else {
            panic!("not 8 bits");
        };
        (colour, samples, icc)
    }

    #[test]
    fn inks_can_be_kept_with_their_profile() {
        let keep = Options {
            inks: Inks::Keep,
            ..Options::default()
        };
        for name in ["cmyk-profile.jpg", "ycck-profile.jpg"] {
            let data = corpus(name);
            let rebuilt = rebuild(&data, &Limits::default(), &keep).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Jpeg, "{name}");
            let (before, profile) = jpeg_inks(&data);
            let (after, kept) = jpeg_inks(&rebuilt.data);
            assert_eq!(before, after, "{name}");
            let profile = profile.unwrap();
            assert_eq!(kept, colour::rewritten_cmyk(&profile), "{name}");
        }

        let data = corpus("cmyk-profile.tif");
        let rebuilt = rebuild(&data, &Limits::default(), &keep).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Tiff);
        let (colour, before, profile) = tiff_samples(&data);
        let (kept_colour, after, kept) = tiff_samples(&rebuilt.data);
        assert_eq!(
            (colour, kept_colour),
            (tiff::ColorType::CMYK(8), tiff::ColorType::CMYK(8))
        );
        assert_eq!(before, after);
        assert_eq!(kept, colour::rewritten_cmyk(&profile.unwrap()));
        // Only what says how the inks look is left of the profile.
        assert!(!contains(kept.as_deref().unwrap(), b"inks"));

        // As sRGB, unless asked.
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Png);
    }

    /// Every page of a TIFF, as the samples the `tiff` crate reads.
    fn tiff_pages(data: &[u8]) -> Vec<(tiff::ColorType, tiff::decoder::DecodingResult)> {
        let mut decoder = tiff::decoder::Decoder::new(std::io::Cursor::new(data)).unwrap();
        let mut pages = Vec::new();
        loop {
            pages.push((decoder.colortype().unwrap(), decoder.read_image().unwrap()));
            if !decoder.more_images() {
                return pages;
            }
            decoder.next_image().unwrap();
        }
    }

    /// The samples of the fixtures, which follow a formula.
    fn pattern(x: u32, y: u32) -> [u8; 3] {
        [(x * 10) as u8, (y * 15) as u8, ((x + y) * 5) as u8]
    }

    #[test]
    fn tiff_compressed_as_the_crate_does_not_read_is_read() {
        // Zstandard, and LZMA after a delta filter.
        for name in ["rgb-zstd.tif", "rgb-lzma.tif"] {
            let rebuilt = run(&corpus(name)).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Png, "{name}");
            let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgb8();
            for (x, y, &Rgb(found)) in pixels.enumerate_pixels() {
                assert_eq!(found, pattern(x, y), "{name} at {x},{y}");
            }
        }
        // Fax, coded one row at a time and from the row before.
        for name in ["fax-g3-1d.tif", "fax-g3-2d.tif"] {
            let rebuilt = run(&corpus(name)).unwrap();
            let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_luma8();
            assert_eq!(pixels.dimensions(), (40, 20), "{name}");
            for (x, y, &image::Luma([found])) in pixels.enumerate_pixels() {
                let white = (x / 3 + y / 2) % 2 == 1;
                assert_eq!(found, if white { 255 } else { 0 }, "{name} at {x},{y}");
            }
        }
    }

    #[test]
    fn tiff_of_12_bits_is_widened_to_16() {
        let rebuilt = run(&corpus("rgb-12bit.tif")).unwrap();
        let pixels = image::load_from_memory(&rebuilt.data).unwrap();
        let DynamicImage::ImageRgb16(pixels) = pixels else {
            panic!("not 16 bits: {:?}", pixels.color());
        };
        for (x, y, &Rgb(found)) in pixels.enumerate_pixels() {
            let stored = [x * 170, y * 250, (x + y) * 100].map(|v| v as u16);
            assert_eq!(found.map(|v| v >> 4), stored, "at {x},{y}");
        }
    }

    #[test]
    fn tiff_pages_are_kept_as_pages() {
        let rebuilt = run(&corpus("pages.tif")).unwrap();
        assert_eq!((rebuilt.file_type, rebuilt.frames), (FileType::Tiff, 2));
        let pages = tiff_pages(&rebuilt.data);
        let [(first, one), (second, two)] = &pages[..] else {
            panic!("{} pages", pages.len());
        };
        // The crate reads grey with alpha as two samples of no kind.
        assert_eq!(*first, tiff::ColorType::RGB(8));
        assert!(matches!(
            second,
            tiff::ColorType::GrayA(16)
                | tiff::ColorType::Multiband {
                    bit_depth: 16,
                    num_samples: 2
                }
        ));
        let (tiff::decoder::DecodingResult::U8(one), tiff::decoder::DecodingResult::U16(two)) =
            (one, two)
        else {
            panic!("samples of the wrong kind");
        };
        for i in 0..24 * 16 {
            let (x, y) = (i % 24, i / 24);
            assert_eq!(
                one[i as usize * 3..][..3],
                pattern(x, y),
                "page 1 at {x},{y}"
            );
            let found = &two[i as usize * 2..][..2];
            assert_eq!(
                found,
                [(x * 2000) as u16, (y * 4000) as u16],
                "page 2 at {x},{y}"
            );
        }
    }

    /// Made by `cjxl -d 0` from `animation-16bit.png`: four frames of 16
    /// bits with alpha, the last three drawn over part of the one before.
    #[test]
    fn jpeg_xl_animation_keeps_every_frame() {
        let rebuilt = run(&corpus("animation-16bit.jxl")).unwrap();
        assert_eq!((rebuilt.file_type, rebuilt.frames), (FileType::Png, 4));
        let frames = |data: &[u8]| {
            let decoder = ::png::Decoder::new(std::io::Cursor::new(data.to_vec()));
            let mut reader = decoder.read_info().unwrap();
            let info = reader.info();
            assert_eq!(
                (info.bit_depth, info.color_type),
                (::png::BitDepth::Sixteen, ::png::ColorType::Rgba)
            );
            let mut frame = vec![0; reader.output_buffer_size().unwrap()];
            reader.next_frame(&mut frame).unwrap();
            let control = reader.info().frame_control.unwrap();
            (frame, (control.delay_num, control.delay_den))
        };
        let (original, _) = frames(&corpus("animation-16bit.png"));
        let (first, shown) = frames(&rebuilt.data);
        assert_eq!(first, original);
        assert_eq!(shown, (500, 1000));
    }

    /// `data` with `extra` after the coded data of its `VP8 ` chunk, inside it.
    fn padded_vp8(data: &[u8], extra: &[u8]) -> Vec<u8> {
        let at = data.windows(4).position(|w| w == b"VP8 ").unwrap();
        let length = u32::from_le_bytes(data[at + 4..at + 8].try_into().unwrap()) as usize;
        let end = at + 8 + length;
        let mut out = [&data[..end], extra, &data[end + length % 2..]].concat();
        let grown = (length + extra.len()) as u32;
        out[at + 4..at + 8].copy_from_slice(&grown.to_le_bytes());
        if grown % 2 == 1 {
            out.insert(at + 8 + grown as usize, 0);
        }
        let riff = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&riff.to_le_bytes());
        out
    }

    #[test]
    fn lossy_webp_stays_lossy_and_loses_what_is_not_coded() {
        let data = padded_vp8(&corpus("lossy-alpha.webp"), PAYLOAD);
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Webp);
        assert!(contains(&rebuilt.data, b"VP8 ") && contains(&rebuilt.data, b"ALPH"));
        assert!(!contains(&rebuilt.data, PAYLOAD));
        // About the size of what it came from, not of a lossless picture.
        assert!(
            rebuilt.data.len() < data.len() + 64,
            "{}",
            rebuilt.data.len()
        );
        let before = image::load_from_memory(&data).unwrap().to_rgba8();
        let after = image::load_from_memory(&rebuilt.data).unwrap().to_rgba8();
        assert_eq!(before, after);

        let data = corpus("lossy-animation.webp");
        let rebuilt = run(&data).unwrap();
        assert_eq!((rebuilt.file_type, rebuilt.frames), (FileType::Webp, 2));
        assert!(contains(&rebuilt.data, b"VP8 ") && !contains(&rebuilt.data, b"VP8L"));
        let frames = |data: &[u8]| {
            WebPDecoder::new(Cursor::new(data.to_vec()))
                .unwrap()
                .into_frames()
                .map(|frame| {
                    let frame = frame.unwrap();
                    (frame.delay(), frame.into_buffer())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(frames(&data), frames(&rebuilt.data));
    }

    #[test]
    fn avif_comes_back_as_png() {
        let data = [&corpus("colours.avif")[..], PAYLOAD].concat();
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Png);
        assert_eq!((rebuilt.width, rebuilt.height), (48, 32));
        assert!(!contains(&rebuilt.data, PAYLOAD));
    }

    /// The composite has the colours matted with white; the file says it is
    /// transparent by a negative layer count.
    #[test]
    fn psd_transparency_is_taken_off_its_white() {
        let rebuilt = run(&corpus("transparent-composite.psd")).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Png);
        assert_eq!((rebuilt.width, rebuilt.height), (40, 30));
        let pixels = image::load_from_memory(&rebuilt.data).unwrap().to_rgba8();
        for (x, y) in [(10, 3), (20, 17), (37, 29), (39, 0)] {
            let Rgba([r, g, b, a]) = *pixels.get_pixel(x, y);
            let expected = [(x * 6) as u8, (y * 8) as u8, (x * y) as u8];
            assert_eq!(a as u32, (x * 7).min(255), "alpha at {x},{y}");
            assert!(near([r, g, b], expected, 2), "at {x},{y}: {:?}", [r, g, b]);
        }
    }

    /// Two frames of 256 colours each, the second over part of the first:
    /// together more than a GIF frame can hold, which a rebuild from full
    /// colour would have to quantise.
    #[test]
    fn gif_keeps_its_palettes_and_indices() {
        let mut data = Vec::new();
        {
            let mut encoder = ::gif::Encoder::new(&mut data, 64, 32, &[]).unwrap();
            encoder.set_repeat(::gif::Repeat::Finite(3)).unwrap();
            let palette = |seed: u8| -> Vec<u8> {
                (0..=255u8)
                    .flat_map(|i| [i, i.wrapping_mul(seed), 255 - i])
                    .collect()
            };
            let mut first = ::gif::Frame::default();
            (first.width, first.height, first.delay) = (64, 32, 7);
            first.palette = Some(palette(3));
            first.buffer = (0..64 * 32)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>()
                .into();
            encoder.write_frame(&first).unwrap();
            let mut second = ::gif::Frame::default();
            (second.left, second.top, second.width, second.height) = (8, 4, 20, 16);
            second.palette = Some(palette(5));
            second.transparent = Some(0);
            second.buffer = (0..20 * 16)
                .map(|i| (i * 7 % 256) as u8)
                .collect::<Vec<_>>()
                .into();
            encoder.write_frame(&second).unwrap();
        }
        let original = data.clone();
        data.splice(data.len() - 1..data.len() - 1, *b"\x21\xFE\x05hello\x00");
        let rebuilt = run(&data).unwrap();
        assert_eq!(rebuilt.file_type, FileType::Gif);
        assert_eq!((rebuilt.width, rebuilt.height, rebuilt.frames), (64, 32, 2));
        assert!(!contains(&rebuilt.data, b"hello"));
        assert!(rebuilt.data.len() <= original.len());
        let frames = |data: &[u8]| -> Vec<RgbaImage> {
            let decoder = GifDecoder::new(Cursor::new(data.to_vec())).unwrap();
            decoder
                .into_frames()
                .map(|frame| frame.unwrap().into_buffer())
                .collect()
        };
        let (before, after) = (frames(&original), frames(&rebuilt.data));
        let colours: std::collections::HashSet<_> = before[1].pixels().collect();
        assert!(colours.len() > 256);
        assert_eq!(before, after);
        assert!(contains(&rebuilt.data, b"NETSCAPE2.0\x03\x01\x03\x00"));
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

    /// Found by fuzzing: the decoder takes a GIF whose screen has no height,
    /// and the file written from it had none either.
    #[test]
    fn refuses_an_image_without_area() {
        let mut gif = Vec::new();
        let frame = RgbaImage::from_pixel(6, 4, Rgba([9, 9, 9, 255]));
        GifEncoder::new(&mut gif)
            .encode_frame(Frame::from_parts(
                frame,
                0,
                0,
                Delay::from_numer_denom_ms(10, 1),
            ))
            .unwrap();
        assert!(run(&gif).is_ok());
        for dimension in [6, 8] {
            let mut flat = gif.clone();
            flat[dimension..dimension + 2].fill(0);
            let rebuilt = run(&flat);
            assert!(matches!(rebuilt, Err(Error::Decode(_))), "{rebuilt:?}");
        }
    }

    #[test]
    fn refuses_what_it_cannot_rebuild_whole() {
        for data in [
            &b"\x7fELF\x02\x01\x01\0"[..],
            b"%!PS-Adobe-3.0\nshowpage\n",
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
