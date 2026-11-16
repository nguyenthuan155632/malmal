//! TIFF, as sRGB pixels: one page as a PNG, several as a TIFF of them all.
//!
//! The `tiff` crate reads the strips and tiles and undoes their
//! compression; what the samples mean is worked out here, which covers
//! more than the `image` crate does: inks under their colour profile,
//! palettes, CIE L*a*b*, YCbCr, 1, 2 and 4-bit grey, samples of any depth
//! up to 32 bits, planar samples, premultiplied alpha, the orientation and
//! the resolution. Pages it refuses are read from a copy of the file that
//! describes them as what they are laid out as (see [`super::ifd`]):
//! palette and CIE L*a*b* called grey and RGB, samples of 12 or 24 bits
//! called more samples of 4 or 8, strips compressed in ways it does not
//! know stored uncompressed.

use std::io::Cursor;

use image::metadata::Orientation;
use image::{DynamicImage, ImageBuffer, Luma, LumaA, Rgb, Rgba};
use tiff::ColorType;
use tiff::decoder::ifd::Value;
use tiff::decoder::{Decoder, DecodingResult, Limits as TiffLimits};
use tiff::tags::Tag;

use super::ifd::{Entry, Form, SHORT};
use super::tiff_out::{InkSamples, Kept, Pages};
use super::{Deadline, Error, Rebuilt, ToSrgb, colour, palette, profile, tiff_jpeg};
use crate::detect::FileType;
use crate::limits::Limits;

/// The pixels of a page, and how many make a metre.
pub(super) struct Picture {
    pub(super) image: DynamicImage,
    pub(super) density: Option<png::PixelDimensions>,
    /// The profile the colours are in, written anew, if they are not in
    /// sRGB.
    pub(super) icc: Option<Vec<u8>>,
}

/// A page as colours, or as the inks it was.
enum Page {
    Colours(Picture),
    Inks(Kept),
}

#[derive(Clone, Copy, PartialEq)]
enum Reading {
    AsItSays,
    /// Indices into the colour map, read as grey.
    Palette,
    /// L* unsigned, a* and b* signed, read as RGB.
    CieLab,
}

/// Samples of a depth the `tiff` crate does not read, read as more
/// samples of one it does, to be taken apart here.
#[derive(Clone)]
struct Repack {
    bits: u32,
    spp: usize,
    photometric: u16,
    extra: Vec<u16>,
}

fn tiff_error(error: tiff::TiffError) -> Error {
    match error {
        tiff::TiffError::LimitsExceeded => Error::TooLarge,
        tiff::TiffError::UnsupportedError(problem) => Error::Decode(problem.to_string()),
        other => Error::Decode(other.to_string()),
    }
}

/// Tag numbers entries are moved to, out of the reader's sight.
const HIDDEN_EXTRA: u16 = 65_001;
const HIDDEN_FORMAT: u16 = 65_002;

/// Samples of one size, whatever the decoder handed over.
enum Samples {
    U8(Vec<u8>),
    U16(Vec<u16>),
    F32(Vec<f32>),
}

/// The TIFF in `data` rebuilt: its one page of colours as a PNG, or as a
/// JPEG of the coefficients its strips or tiles hold if it is compressed
/// that way, or its pages as a TIFF, inks as inks if `keep_inks`. Reduced
/// copies of a page and transparency masks are left out. Colours of an RGB
/// profile other than sRGB's are kept in it if `keep_profile`.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_inks: bool,
    keep_profile: bool,
) -> Result<Rebuilt, Error> {
    let rebuilt = pages(data, limits, deadline, keep_inks, keep_profile)?;
    if rebuilt.file_type == FileType::Png
        && let Some(jpeg) = as_jpeg(data, limits, deadline, &rebuilt, keep_profile)
    {
        return Ok(jpeg);
    }
    if rebuilt.file_type == FileType::Tiff
        && let Some(jpeg) =
            tiff_jpeg::rebuild(data, limits, deadline, &rebuilt, keep_inks, keep_profile)
    {
        return Ok(jpeg);
    }
    Ok(rebuilt)
}

/// A page of JPEG pictures put together into one, the right way up.
pub(super) struct JpegPage {
    pub(super) coefficients: super::jpeg::Coefficients,
    /// As TIFF numbers them: 1 grey, 2 RGB, 5 inks, 6 YCbCr.
    pub(super) photometric: u32,
    /// The profile of the page, written anew, if it is not sRGB.
    pub(super) profile: Option<Vec<u8>>,
}

/// The page `decoder` is at as a JPEG of the coefficients of its strips or
/// tiles put together, if they are JPEG pictures of 8-bit grey, YCbCr or
/// RGB without transparency (or of four inks, if `keep_inks`) that go
/// together without decoding, in sRGB or a profile that is to be kept and
/// can be written anew.
pub(super) fn jpeg_page<R: std::io::Read + std::io::Seek>(
    decoder: &mut Decoder<R>,
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_inks: bool,
    keep_profile: bool,
) -> Option<JpegPage> {
    let tag = |decoder: &mut Decoder<R>, tag| decoder.find_tag_unsigned::<u32>(tag).ok().flatten();
    let photometric = tag(decoder, Tag::PhotometricInterpretation)?;
    let spp = tag(decoder, Tag::SamplesPerPixel).unwrap_or(1);
    let bits = decoder
        .find_tag_unsigned_vec::<u16>(Tag::BitsPerSample)
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![1]);
    let inks = keep_inks
        && (photometric, spp) == (5, 4)
        && tag(decoder, Tag::Unknown(332)).is_none_or(|i| i == 1);
    let fits = tag(decoder, Tag::Compression) == Some(7)
        && (matches!((photometric, spp), (1, 1) | (2 | 6, 3)) || inks)
        && bits.iter().all(|&b| b == 8)
        && tag(decoder, Tag::PlanarConfiguration).is_none_or(|p| p == 1)
        && decoder.find_tag(Tag::ExtraSamples).ok().flatten().is_none();
    if !fits {
        return None;
    }
    // Colours of another profile are kept in it, written anew, or not at
    // all: the page's pixels are then converted. Inks keep theirs.
    let mut profile = None;
    if let Ok(icc) = decoder.get_tag_u8_vec(Tag::IccProfile) {
        if inks {
            profile = Some(colour::rewritten_cmyk(&icc)?);
        } else if ToSrgb::new(Some(icc.clone())).is_some() {
            if !keep_profile {
                return None;
            }
            profile = Some(colour::rewritten_screen(&icc, spp as usize)?);
        }
    }
    let (width, height) = decoder.dimensions().ok()?;
    if u64::from(width) * u64::from(height) > limits.max_pixels {
        return None;
    }
    let orientation = tag(decoder, Tag::Orientation).unwrap_or(1);
    let density = jfif_density(decoder);
    let tables = decoder.get_tag_u8_vec(Tag::JPEGTables).ok();
    let tiled = decoder.find_tag(Tag::TileOffsets).ok().flatten().is_some();
    let (offsets, counts, chunk_width, chunk_height) = if tiled {
        (
            decoder.get_tag_u64_vec(Tag::TileOffsets).ok()?,
            decoder.get_tag_u64_vec(Tag::TileByteCounts).ok()?,
            tag(decoder, Tag::TileWidth)?,
            tag(decoder, Tag::TileLength)?,
        )
    } else {
        (
            decoder.get_tag_u64_vec(Tag::StripOffsets).ok()?,
            decoder.get_tag_u64_vec(Tag::StripByteCounts).ok()?,
            width,
            tag(decoder, Tag::RowsPerStrip).map_or(height, |r| r.min(height)),
        )
    };
    if offsets.len() != counts.len() || chunk_width == 0 || chunk_height == 0 {
        return None;
    }
    let across = width.div_ceil(chunk_width);
    let mut pieces = Vec::with_capacity(offsets.len());
    for (index, (&offset, &count)) in offsets.iter().zip(&counts).enumerate() {
        deadline.check().ok()?;
        let start = usize::try_from(offset).ok()?;
        let chunk = data.get(start..start.checked_add(usize::try_from(count).ok()?)?)?;
        // A strip or tile may leave its tables to the page's.
        let stream = match &tables {
            Some(tables)
                if tables.starts_with(&[0xFF, 0xD8]) && chunk.starts_with(&[0xFF, 0xD8]) =>
            {
                let tables = tables.strip_suffix(&[0xFF, 0xD9]).unwrap_or(tables);
                [tables, &chunk[2..]].concat()
            }
            _ => chunk.to_vec(),
        };
        let piece = super::jpeg::read(&stream, limits, deadline).ok()?;
        let index = u32::try_from(index).ok()?;
        let (x, y) = (
            (index % across).checked_mul(chunk_width)?,
            (index / across).checked_mul(chunk_height)?,
        );
        pieces.push((x, y, piece));
    }
    let mut whole = super::jpeg::Coefficients::mosaic(&pieces, width, height, photometric == 2)?;
    drop(pieces);
    whole.density = density;
    whole.orientation = u8::try_from(orientation).ok()?;
    if !whole.orient() {
        return None;
    }
    Some(JpegPage {
        coefficients: whole,
        photometric,
        profile,
    })
}

/// The one page of the TIFF in `data`, whose pixels `shown` holds, as a
/// JPEG of the coefficients of its strips or tiles put together (see
/// [`jpeg_page`]), if the JPEG shows the page as `shown` does.
fn as_jpeg(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    shown: &Rebuilt,
    keep_profile: bool,
) -> Option<Rebuilt> {
    let mut decoder = Decoder::new(Cursor::new(data)).ok()?;
    let page = jpeg_page(&mut decoder, data, limits, deadline, false, keep_profile)?;
    let jpeg = page.coefficients.write(page.profile.as_deref())?;
    deadline.check().ok()?;

    // It has to show what the pixels of the page are.
    let png = image::load_from_memory(&shown.data).ok()?.into_rgb8();
    let decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(&jpeg)).ok()?;
    let shows = DynamicImage::from_decoder(decoder).ok()?.into_rgb8();
    if !close(png.as_raw(), shows.as_raw()) || png.dimensions() != shows.dimensions() {
        return None;
    }
    let (width, height) = shows.dimensions();
    Some(Rebuilt {
        data: jpeg,
        file_type: FileType::Jpeg,
        width,
        height,
        frames: 1,
    })
}

/// Samples of YCbCr, three a pixel, as RGB (ITU-R BT.601, full range).
pub(super) fn ycbcr_to_rgb(ycc: &[u8]) -> Vec<u8> {
    ycc.as_chunks::<3>()
        .0
        .iter()
        .flat_map(|s| {
            let (y, cb, cr) = (s[0] as f32, s[1] as f32 - 128.0, s[2] as f32 - 128.0);
            [
                y + 1.402 * cr,
                y - 0.344_136 * cb - 0.714_136 * cr,
                y + 1.772 * cb,
            ]
            .map(|c| c.round().clamp(0.0, 255.0) as u8)
        })
        .collect()
}

/// Whether samples decoded from coefficients kept as they were are close
/// enough to those decoded as the original was: none more than 16 apart,
/// and 2 on average.
pub(super) fn close(one: &[u8], other: &[u8]) -> bool {
    if one.len() != other.len() {
        return false;
    }
    let (mut most, mut total) = (0u8, 0u64);
    for (a, b) in one.iter().zip(other) {
        let apart = a.abs_diff(*b);
        most = most.max(apart);
        total += u64::from(apart);
    }
    most <= 16 && total as f64 <= 2.0 * one.len() as f64
}

/// The pages of `data` rebuilt from their pixels, for comparing.
#[cfg(test)]
pub(super) fn pages_for_test(data: &[u8]) -> Vec<u8> {
    pages(data, &Limits::default(), Deadline(None), false, false)
        .unwrap()
        .data
}

/// The resolution of a page, as a JPEG states it.
fn jfif_density<R: std::io::Read + std::io::Seek>(
    decoder: &mut Decoder<R>,
) -> super::jpeg::Density {
    let mut value = |tag| match decoder.find_tag(tag).ok()?? {
        Value::Rational(n, d) if d > 0 => Some(f64::from(n) / f64::from(d)),
        _ => None,
    };
    let (x, y) = (value(Tag::XResolution), value(Tag::YResolution));
    let unit = decoder
        .find_tag_unsigned::<u16>(Tag::ResolutionUnit)
        .ok()
        .flatten()
        .unwrap_or(2);
    let round = |v: f64| (v.round() >= 1.0 && v <= f64::from(u16::MAX)).then(|| v.round() as u16);
    // TIFF counts inches as 2 and centimetres as 3, JFIF as 1 and 2.
    match (x.and_then(round), y.and_then(round), unit) {
        (Some(x), Some(y), 2 | 3) => super::jpeg::Density {
            unit: (unit - 1) as u8,
            x,
            y,
        },
        _ => super::jpeg::Density::default(),
    }
}

/// The pages of the TIFF in `data` rebuilt, as [`rebuild`] says, but
/// always from their pixels.
fn pages(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_inks: bool,
    keep_profile: bool,
) -> Result<Rebuilt, Error> {
    let form = Form::of(data).ok_or_else(|| Error::Decode("not a TIFF file".into()))?;
    let pages = form.pages(data);
    if pages.is_empty() {
        return Err(Error::Decode("TIFF without an image".into()));
    }
    let mut work = data.to_vec();
    let mut pixels = 0u64;
    let mut pictures: Vec<Page> = Vec::new();
    let mut writer: Option<Pages> = None;
    for (index, &page) in pages.iter().enumerate() {
        deadline.check()?;
        let Some((entries, _)) = form.directory(data, page) else {
            break;
        };
        let find = |tag: u16| entries.iter().find(|e| e.tag == tag).copied();
        let number = |tag: u16| find(tag).and_then(|e| form.value(data, &e));
        // A smaller copy of another page, or a mask for one.
        if index > 0 && number(254).is_some_and(|kind| kind & 0b101 != 0) {
            continue;
        }
        form.point_to(&mut work, page);
        let (reading, repack) = prepare(&mut work, form, data, &entries, limits)?;
        let page = read(
            &work,
            reading,
            repack,
            limits,
            deadline,
            keep_inks,
            keep_profile,
        )?;
        let (width, height) = match &page {
            Page::Colours(picture) => (picture.image.width(), picture.image.height()),
            Page::Inks(kept) => (kept.width, kept.height),
        };
        pixels += width as u64 * height as u64;
        if pixels > limits.max_pixels {
            return Err(Error::TooLarge);
        }
        // The pages are written as they come once there is more than one,
        // or one of inks.
        let add = |pages: &mut Pages, page: &Page| match page {
            Page::Colours(picture) => pages.add(picture, deadline),
            Page::Inks(kept) => pages.add_inks(kept, deadline),
        };
        match &mut writer {
            Some(pages) => add(pages, &page)?,
            None if pictures.is_empty() && matches!(page, Page::Colours(_)) => pictures.push(page),
            None => {
                let mut pages = Pages::new(limits)?;
                for page in pictures.drain(..) {
                    add(&mut pages, &page)?;
                }
                add(&mut pages, &page)?;
                writer = Some(pages);
            }
        }
    }
    if let Some(pages) = writer {
        return pages.finish();
    }
    let Some(Page::Colours(picture)) = pictures.pop() else {
        return Err(Error::Decode("TIFF without an image".into()));
    };
    // Samples of floating point stay so, in a TIFF: a PNG would clip
    // them to black and white, and to 16 bits.
    if matches!(
        picture.image,
        DynamicImage::ImageRgb32F(_) | DynamicImage::ImageRgba32F(_)
    ) {
        let mut pages = Pages::new(limits)?;
        pages.add(&picture, deadline)?;
        return pages.finish();
    }
    let (width, height) = (picture.image.width(), picture.image.height());
    let data = palette::smallest(&picture.image, picture.density)
        .ok_or_else(|| Error::Encode("no PNG holds these pixels".into()))?;
    let rebuilt = Rebuilt {
        data,
        file_type: FileType::Png,
        width,
        height,
        frames: 1,
    };
    match &picture.icc {
        Some(icc) => profile::attach(rebuilt, icc)
            .ok_or_else(|| Error::Encode("the PNG cannot carry the profile".into())),
        None => Ok(rebuilt),
    }
}

/// Change the entries of a page in `work` so that the `tiff` crate reads
/// what it stores, and say how to make sense of what it reads.
fn prepare(
    work: &mut Vec<u8>,
    form: Form,
    data: &[u8],
    entries: &[Entry],
    limits: &Limits,
) -> Result<(Reading, Option<Repack>), Error> {
    let find = |tag: u16| entries.iter().find(|e| e.tag == tag).copied();
    let number = |tag: u16| find(tag).and_then(|e| form.value(data, &e));
    let photometric = number(262).unwrap_or(1) as u16;
    let spp = number(277).unwrap_or(1).max(1) as usize;
    let bits = number(258).unwrap_or(1) as u32;
    let planar = number(284) == Some(2);
    let compression = number(259).unwrap_or(1);

    super::strips::unpack(work, form, data, entries, compression, limits)?;

    let reading = match photometric {
        3 => Reading::Palette,
        8 => Reading::CieLab,
        _ => Reading::AsItSays,
    };
    if let Some(entry) = find(262) {
        match reading {
            Reading::Palette => form.set(work, &entry, SHORT, &[1]),
            Reading::CieLab => form.set(work, &entry, SHORT, &[2]),
            Reading::AsItSays => {}
        }
    }

    let read_as_is = matches!(bits, 8 | 16 | 32 | 64)
        || (spp == 1 && matches!(bits, 1 | 2 | 4) && matches!(photometric, 0 | 1 | 3));
    if read_as_is {
        return Ok((reading, None));
    }
    let uint = find(339).is_none_or(|e| {
        form.values(data, &e, 64)
            .is_some_and(|v| v.iter().all(|&f| f == 1))
    });
    let predicted = number(317).is_some_and(|p| p != 1);
    if !matches!(photometric, 0 | 1 | 2 | 5)
        || !uint
        || predicted
        || (planar && spp > 1)
        || bits > 32
    {
        return Err(unsupported(&format!("{bits}-bit samples of this kind")));
    }
    // The largest depth the crate reads that the samples divide into.
    let part = [8u32, 4, 2, 1]
        .into_iter()
        .find(|part| bits.is_multiple_of(*part))
        .unwrap_or(1);
    let parts = spp * (bits / part) as usize;
    let parts = u16::try_from(parts).map_err(|_| unsupported("this many samples"))?;
    let extra = find(338)
        .and_then(|e| form.values(data, &e, 64))
        .unwrap_or_default()
        .into_iter()
        .map(|v| v as u16)
        .collect();
    for (tag, value) in [(262, 1u64), (277, parts.into()), (258, part.into())] {
        if let Some(entry) = find(tag) {
            form.set(work, &entry, SHORT, &[value]);
        }
    }
    for (tag, hidden) in [(338, HIDDEN_EXTRA), (339, HIDDEN_FORMAT)] {
        if let Some(entry) = find(tag) {
            form.rename(work, &entry, hidden);
        }
    }
    Ok((
        reading,
        Some(Repack {
            bits,
            spp,
            photometric,
            extra,
        }),
    ))
}

/// Rows of `bits`-bit samples, each row starting on a byte, as 16-bit
/// samples. Whatever the byte order of the file, samples of other depths
/// than 8, 16, 32 and 64 are a stream of bits, the first the highest.
fn widen(packed: &[u8], width: usize, height: usize, repack: &Repack) -> Result<Vec<u16>, Error> {
    let bits = repack.bits as usize;
    let per_row = width * repack.spp;
    let row = (per_row * bits).div_ceil(8);
    if packed.len() < row * height {
        return Err(Error::Decode("image is not what its header says".into()));
    }
    let top = (1u64 << bits) - 1;
    let scale = |v: u64| ((v as u128 * 65_535 + top as u128 / 2) / top as u128) as u16;
    let mut out = Vec::with_capacity(per_row * height);
    for line in packed.chunks(row).take(height) {
        for index in 0..per_row {
            let mut v = 0u64;
            for bit in index * bits..(index + 1) * bits {
                v = (v << 1) | u64::from((line[bit / 8] >> (7 - bit % 8)) & 1);
            }
            out.push(scale(v));
        }
    }
    Ok(out)
}

/// The first page of `bytes`, which [`prepare`] made readable.
fn read(
    bytes: &[u8],
    reading: Reading,
    repack: Option<Repack>,
    limits: &Limits,
    deadline: Deadline,
    keep_inks: bool,
    keep_profile: bool,
) -> Result<Page, Error> {
    let mut tiff_limits = TiffLimits::default();
    let budget = usize::try_from(limits.max_decompressed).unwrap_or(usize::MAX);
    tiff_limits.decoding_buffer_size = budget;
    tiff_limits.intermediate_buffer_size = budget;
    // Colour profiles of printing presses run to a few megabytes.
    tiff_limits.ifd_value_size = budget.min(32 << 20);
    let mut decoder = Decoder::new(Cursor::new(bytes))
        .map_err(tiff_error)?
        .with_limits(tiff_limits);

    let (width, height) = decoder.dimensions().map_err(tiff_error)?;
    if width == 0 || height == 0 {
        return Err(Error::Decode("image has a zero dimension".into()));
    }
    let pixels = width as usize * height as usize;
    if pixels as u64 > limits.max_pixels {
        return Err(Error::TooLarge);
    }
    let mut colour_type = decoder.colortype().map_err(tiff_error)?;
    let mut spp = decoder
        .find_tag_unsigned::<u16>(Tag::SamplesPerPixel)
        .map_err(tiff_error)?
        .unwrap_or(1)
        .max(1) as usize;
    let planar = decoder
        .find_tag_unsigned::<u16>(Tag::PlanarConfiguration)
        .map_err(tiff_error)?
        == Some(2);
    let mut extra = decoder
        .find_tag_unsigned_vec::<u16>(Tag::ExtraSamples)
        .map_err(tiff_error)?
        .unwrap_or_default();
    let icc = decoder.get_tag_u8_vec(Tag::IccProfile).ok();
    let exif_orientation = decoder
        .find_tag_unsigned::<u16>(Tag::Orientation)
        .ok()
        .flatten();
    let orientation = exif_orientation.and_then(|o| Orientation::from_exif(o as u8));
    let density = resolution(&mut decoder);
    let colour_map = match reading {
        Reading::Palette => Some(decoder.get_tag_u16_vec(Tag::ColorMap).map_err(tiff_error)?),
        _ => None,
    };

    let white = match decoder
        .find_tag(Tag::from_u16_exhaustive(318))
        .ok()
        .flatten()
    {
        Some(Value::List(values)) => match &values[..] {
            [Value::Rational(xn, xd), Value::Rational(yn, yd), ..]
                if *xd > 0 && *yn > 0 && *yd > 0 =>
            {
                Some((*xn as f32 / *xd as f32, *yn as f32 / *yd as f32))
            }
            _ => None,
        },
        _ => None,
    };

    // Every plane of a planar image, which `read_image` does not give.
    let mut result = DecodingResult::U8(Vec::new());
    let layout = decoder
        .read_image_to_buffer(&mut result)
        .map_err(tiff_error)?;
    if result.as_buffer(0).as_bytes().len() < layout.complete_len {
        return Err(Error::TooLarge);
    }
    deadline.check()?;
    let to = |colour_type, bits| match colour_type {
        ColorType::Gray(_) => ColorType::Gray(bits),
        ColorType::RGB(_) => ColorType::RGB(bits),
        ColorType::RGBA(_) => ColorType::RGBA(bits),
        ColorType::CMYK(_) => ColorType::CMYK(bits),
        ColorType::CMYKA(_) => ColorType::CMYKA(bits),
        ColorType::Multiband { num_samples, .. } => ColorType::Multiband {
            bit_depth: bits,
            num_samples,
        },
        other => other,
    };
    let deep = |colour_type| to(colour_type, 16);
    let mut samples = match result {
        DecodingResult::U8(v) => Samples::U8(v),
        DecodingResult::U16(v) => Samples::U16(v),
        DecodingResult::F32(v) => Samples::F32(v),
        DecodingResult::I8(v) => Samples::U8(v.into_iter().map(|s| s as u8).collect()),
        DecodingResult::I16(v) => Samples::U16(v.into_iter().map(|s| s as u16).collect()),
        DecodingResult::U32(v) => {
            colour_type = deep(colour_type);
            Samples::U16(v.into_iter().map(|s| (s >> 16) as u16).collect())
        }
        DecodingResult::U64(v) => {
            colour_type = deep(colour_type);
            Samples::U16(v.into_iter().map(|s| (s >> 48) as u16).collect())
        }
        // Floating point of any width, as 32 bits.
        DecodingResult::F16(v) => {
            colour_type = to(colour_type, 32);
            Samples::F32(v.into_iter().map(|s| s.to_f32()).collect())
        }
        DecodingResult::F64(v) => {
            colour_type = to(colour_type, 32);
            Samples::F32(v.into_iter().map(|s| s as f32).collect())
        }
        _ => return Err(unsupported("samples of this type")),
    };
    // Inks, and grey with more samples, as floating point: as 16 bits.
    if let (
        ColorType::CMYK(32) | ColorType::CMYKA(32) | ColorType::Multiband { bit_depth: 32, .. },
        Samples::F32(v),
    ) = (colour_type, &samples)
    {
        let wide = v
            .iter()
            .map(|s| (s.clamp(0.0, 1.0) * 65535.0).round() as u16)
            .collect();
        colour_type = deep(colour_type);
        samples = Samples::U16(wide);
    }
    if let Some(repack) = &repack {
        let Samples::U8(packed) = &samples else {
            return Err(unsupported("samples of this depth"));
        };
        let mut wide = widen(packed, width as usize, height as usize, repack)?;
        extra.clone_from(&repack.extra);
        spp = repack.spp;
        let alpha = matches!(extra.first(), Some(1 | 2));
        colour_type = match (repack.photometric, spp - extra.len()) {
            (2, 3) if alpha => ColorType::RGBA(16),
            (2, 3) => ColorType::RGB(16),
            (5, 4) if alpha => ColorType::CMYKA(16),
            (5, 4) => ColorType::CMYK(16),
            (0 | 1, _) if spp == 1 => ColorType::Gray(16),
            (0 | 1, _) => ColorType::Multiband {
                bit_depth: 16,
                num_samples: spp as u16,
            },
            _ => return Err(unsupported("samples of this depth")),
        };
        // White was 0; the crate is told it is black.
        if repack.photometric == 0 {
            for sample in wide.iter_mut().step_by(spp) {
                *sample = 65535 - *sample;
            }
        }
        samples = Samples::U16(wide);
    }

    // Inks kept as inks, with a profile that can be written anew, or none.
    let inks = matches!(
        colour_type,
        ColorType::CMYK(8 | 16) | ColorType::CMYKA(8 | 16)
    );
    let profile = match (&icc, keep_inks && inks) {
        (_, false) => None,
        (None, true) => Some(None),
        (Some(icc), true) => colour::rewritten_cmyk(icc).map(Some),
    };
    if let Some(icc) = profile {
        let channels = if matches!(colour_type, ColorType::CMYKA(_)) {
            5
        } else {
            4
        };
        let samples = match samples {
            Samples::U8(v) => InkSamples::Eight(gather(&v, pixels, spp, planar, channels)?),
            Samples::U16(v) => InkSamples::Sixteen(gather(&v, pixels, spp, planar, channels)?),
            Samples::F32(_) => return Err(unsupported("inks of this kind")),
        };
        let mut kept = Kept {
            width,
            height,
            samples,
            alpha: (channels == 5).then_some(extra.first() == Some(&1)),
            icc,
            density,
        };
        kept.orient(exif_orientation.unwrap_or(1));
        return Ok(Page::Inks(kept));
    }

    let mut image = build(Build {
        samples,
        colour_type,
        width,
        height,
        spp,
        planar,
        associated: extra.first() == Some(&1),
        alpha: matches!(extra.first(), Some(1 | 2)),
        reading,
        colour_map,
        icc: icc.as_deref(),
        // ICC L*a*b* is relative to D50 by definition.
        lab: colour::Lab::new(match reading {
            Reading::CieLab => white.unwrap_or(colour::Lab::D50),
            _ => colour::Lab::D50,
        }),
    })?;
    deadline.check()?;
    // Inks have been turned into colours already; a profile of another
    // kind applies to the colours as they are, unless they are kept in it.
    let mut kept = None;
    if !matches!(colour_type, ColorType::CMYK(_) | ColorType::CMYKA(_))
        && let Some(colors) = ToSrgb::new(icc.clone())
    {
        let channels = if image.color().has_color() { 3 } else { 1 };
        kept = icc
            .as_deref()
            .filter(|_| keep_profile)
            .and_then(|icc| colour::rewritten_screen(icc, channels));
        if kept.is_none() {
            colors.image(&mut image);
        }
    }
    if let Some(orientation) = orientation {
        image.apply_orientation(orientation);
    }
    Ok(Page::Colours(Picture {
        image,
        density,
        icc: kept,
    }))
}

fn unsupported(what: &str) -> Error {
    Error::Decode(format!("TIFF with {what} is not supported"))
}

fn resolution<R: std::io::Read + std::io::Seek>(
    decoder: &mut Decoder<R>,
) -> Option<png::PixelDimensions> {
    let mut value = |tag| match decoder.find_tag(tag).ok()?? {
        Value::Rational(n, d) if d > 0 => Some(n as f64 / d as f64),
        Value::Float(f) => Some(f as f64),
        Value::Double(f) => Some(f),
        _ => None,
    };
    let (x, y) = (value(Tag::XResolution)?, value(Tag::YResolution)?);
    let unit = decoder
        .find_tag_unsigned::<u16>(Tag::ResolutionUnit)
        .ok()
        .flatten()
        .unwrap_or(2);
    let round = |v: f64| (v.round() >= 1.0 && v < u32::MAX as f64).then(|| v.round() as u32);
    // TIFF counts inches as 2 and centimetres as 3.
    palette::per_metre(unit.checked_sub(1)? as u8, round(x)?, round(y)?)
}

struct Build<'a> {
    samples: Samples,
    colour_type: ColorType,
    width: u32,
    height: u32,
    spp: usize,
    planar: bool,
    associated: bool,
    alpha: bool,
    reading: Reading,
    colour_map: Option<Vec<u16>>,
    icc: Option<&'a [u8]>,
    lab: colour::Lab,
}

/// The value of each of the first `channels` samples of every pixel, from
/// interleaved or planar storage.
fn gather<T: Copy + Default>(
    all: &[T],
    pixels: usize,
    spp: usize,
    planar: bool,
    channels: usize,
) -> Result<Vec<T>, Error> {
    if channels > spp || all.len() < pixels * if planar { channels } else { spp } {
        return Err(Error::Decode("image is not what its header says".into()));
    }
    let mut out = Vec::with_capacity(pixels * channels);
    for pixel in 0..pixels {
        for channel in 0..channels {
            out.push(if planar {
                all[channel * pixels + pixel]
            } else {
                all[pixel * spp + channel]
            });
        }
    }
    Ok(out)
}

/// Unpack rows of 1, 2 or 4-bit samples, each row starting on a byte.
fn unpack(packed: &[u8], width: usize, height: usize, bits: usize) -> Result<Vec<u8>, Error> {
    let row = (width * bits).div_ceil(8);
    if packed.len() < row * height {
        return Err(Error::Decode("image is not what its header says".into()));
    }
    let mut out = Vec::with_capacity(width * height);
    let mask = (1u8 << bits) - 1;
    for y in 0..height {
        let line = &packed[y * row..(y + 1) * row];
        for x in 0..width {
            let bit = x * bits;
            out.push((line[bit / 8] >> (8 - bits - bit % 8)) & mask);
        }
    }
    Ok(out)
}

/// Colour divided by alpha, where the file had multiplied them.
fn unpremultiply<const N: usize>(pixels: &mut [u8]) {
    for pixel in pixels.as_chunks_mut::<N>().0.iter_mut() {
        let alpha = pixel[N - 1] as u32;
        for c in &mut pixel[..N - 1] {
            *c = match alpha {
                0 => 0,
                _ => ((*c as u32 * 255 + alpha / 2) / alpha).min(255) as u8,
            };
        }
    }
}

fn unpremultiply16<const N: usize>(pixels: &mut [u16]) {
    for pixel in pixels.as_chunks_mut::<N>().0.iter_mut() {
        let alpha = pixel[N - 1] as u64;
        for c in &mut pixel[..N - 1] {
            *c = match alpha {
                0 => 0,
                _ => ((*c as u64 * 65535 + alpha / 2) / alpha).min(65535) as u16,
            };
        }
    }
}

fn sized<P: image::Pixel>(
    width: u32,
    height: u32,
    samples: Vec<P::Subpixel>,
) -> Result<ImageBuffer<P, Vec<P::Subpixel>>, Error> {
    ImageBuffer::from_raw(width, height, samples)
        .ok_or_else(|| Error::Decode("image is not what its header says".into()))
}

fn build(b: Build<'_>) -> Result<DynamicImage, Error> {
    let (width, height) = (b.width, b.height);
    let pixels = width as usize * height as usize;
    let image = match (b.colour_type, b.samples, b.reading) {
        (ColorType::Gray(bits @ (1 | 2 | 4 | 8)), Samples::U8(v), Reading::Palette) => {
            let indices = match bits {
                8 => gather(&v, pixels, b.spp, b.planar, 1)?,
                _ => unpack(&v, width as usize, height as usize, bits as usize)?,
            };
            let map = b.colour_map.unwrap_or_default();
            let entries = 1usize << bits;
            if map.len() < entries * 3 {
                return Err(Error::Decode("colour map is too short".into()));
            }
            let (red, green, blue) = (
                &map[..entries],
                &map[entries..2 * entries],
                &map[2 * entries..3 * entries],
            );
            // Most maps hold 8-bit colours, each times 257.
            let narrow = map[..entries * 3].iter().all(|v| v % 257 == 0);
            if narrow {
                let colours = indices.iter().flat_map(|&i| {
                    let i = i as usize;
                    [
                        (red[i] / 257) as u8,
                        (green[i] / 257) as u8,
                        (blue[i] / 257) as u8,
                    ]
                });
                DynamicImage::from(sized::<Rgb<u8>>(width, height, colours.collect())?)
            } else {
                let colours = indices.iter().flat_map(|&i| {
                    let i = i as usize;
                    [red[i], green[i], blue[i]]
                });
                DynamicImage::from(sized::<Rgb<u16>>(width, height, colours.collect())?)
            }
        }
        (_, _, Reading::Palette) => return Err(unsupported("a palette of this depth")),
        (ColorType::Gray(bits @ (1 | 2 | 4)), Samples::U8(v), _) => {
            let levels = (1u32 << bits) - 1;
            let grey = unpack(&v, width as usize, height as usize, bits as usize)?
                .into_iter()
                .map(|s| (s as u32 * 255 / levels) as u8)
                .collect();
            DynamicImage::from(sized::<Luma<u8>>(width, height, grey)?)
        }
        // Grey and more samples, the first of which may be alpha.
        (
            ColorType::Multiband {
                bit_depth: 8,
                num_samples: 2..,
            },
            Samples::U8(v),
            _,
        ) => {
            if b.alpha {
                let mut grey = gather(&v, pixels, b.spp, b.planar, 2)?;
                if b.associated {
                    unpremultiply::<2>(&mut grey);
                }
                DynamicImage::from(sized::<LumaA<u8>>(width, height, grey)?)
            } else {
                DynamicImage::from(sized::<Luma<u8>>(
                    width,
                    height,
                    gather(&v, pixels, b.spp, b.planar, 1)?,
                )?)
            }
        }
        (
            ColorType::Multiband {
                bit_depth: 16,
                num_samples: 2..,
            },
            Samples::U16(v),
            _,
        ) => {
            if b.alpha {
                let mut grey = gather(&v, pixels, b.spp, b.planar, 2)?;
                if b.associated {
                    unpremultiply16::<2>(&mut grey);
                }
                DynamicImage::from(sized::<LumaA<u16>>(width, height, grey)?)
            } else {
                DynamicImage::from(sized::<Luma<u16>>(
                    width,
                    height,
                    gather(&v, pixels, b.spp, b.planar, 1)?,
                )?)
            }
        }
        (ColorType::Gray(8), Samples::U8(v), _) => DynamicImage::from(sized::<Luma<u8>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 1)?,
        )?),
        (ColorType::Gray(16), Samples::U16(v), _) => DynamicImage::from(sized::<Luma<u16>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 1)?,
        )?),
        // There is no grey of floating point here; colours of it keep
        // every value, beyond black and white too, and are written as grey
        // again.
        (ColorType::Gray(32), Samples::F32(v), _) => {
            let grey: Vec<f32> = gather(&v, pixels, b.spp, b.planar, 1)?
                .into_iter()
                .flat_map(|s| [s; 3])
                .collect();
            DynamicImage::from(sized::<Rgb<f32>>(width, height, grey)?)
        }
        (ColorType::RGB(8), Samples::U8(v), Reading::CieLab)
        | (ColorType::RGBA(8), Samples::U8(v), Reading::CieLab) => {
            let lab = gather(&v, pixels, b.spp, b.planar, 3)?;
            let rgb = lab
                .as_chunks::<3>()
                .0
                .iter()
                .flat_map(|s| {
                    let l = s[0] as f32 * 100.0 / 255.0;
                    b.lab
                        .srgb(l, s[1] as i8 as f32, s[2] as i8 as f32)
                        .map(|c| (c * 255.0).round() as u8)
                })
                .collect();
            DynamicImage::from(sized::<Rgb<u8>>(width, height, rgb)?)
        }
        (ColorType::RGB(16), Samples::U16(v), Reading::CieLab)
        | (ColorType::RGBA(16), Samples::U16(v), Reading::CieLab) => {
            let lab = gather(&v, pixels, b.spp, b.planar, 3)?;
            let rgb = lab
                .as_chunks::<3>()
                .0
                .iter()
                .flat_map(|s| {
                    let l = s[0] as f32 * 100.0 / 65535.0;
                    let (a, bb) = (s[1] as i16 as f32 / 256.0, s[2] as i16 as f32 / 256.0);
                    b.lab.srgb(l, a, bb).map(|c| (c * 65535.0).round() as u16)
                })
                .collect();
            DynamicImage::from(sized::<Rgb<u16>>(width, height, rgb)?)
        }
        (_, _, Reading::CieLab) => return Err(unsupported("CIE L*a*b* of this depth")),
        (ColorType::Lab(8), Samples::U8(v), _) => {
            let lab = gather(&v, pixels, b.spp, b.planar, 3)?;
            let rgb = lab
                .as_chunks::<3>()
                .0
                .iter()
                .flat_map(|s| {
                    let l = s[0] as f32 * 100.0 / 255.0;
                    b.lab
                        .srgb(l, s[1] as f32 - 128.0, s[2] as f32 - 128.0)
                        .map(|c| (c * 255.0).round() as u8)
                })
                .collect();
            DynamicImage::from(sized::<Rgb<u8>>(width, height, rgb)?)
        }
        (ColorType::Lab(16), Samples::U16(v), _) => {
            let lab = gather(&v, pixels, b.spp, b.planar, 3)?;
            let rgb = lab
                .as_chunks::<3>()
                .0
                .iter()
                .flat_map(|s| {
                    let l = s[0] as f32 * 100.0 / 65535.0;
                    let (a, bb) = (s[1] as f32 / 257.0 - 128.0, s[2] as f32 / 257.0 - 128.0);
                    b.lab.srgb(l, a, bb).map(|c| (c * 65535.0).round() as u16)
                })
                .collect();
            DynamicImage::from(sized::<Rgb<u16>>(width, height, rgb)?)
        }
        (ColorType::YCbCr(8), Samples::U8(v), _) => {
            let ycc = gather(&v, pixels, b.spp, b.planar, 3)?;
            DynamicImage::from(sized::<Rgb<u8>>(width, height, ycbcr_to_rgb(&ycc))?)
        }
        (ColorType::RGB(8), Samples::U8(v), _) => DynamicImage::from(sized::<Rgb<u8>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 3)?,
        )?),
        (ColorType::RGBA(8), Samples::U8(v), _) => {
            let mut rgba = gather(&v, pixels, b.spp, b.planar, 4)?;
            if b.associated {
                unpremultiply::<4>(&mut rgba);
            }
            DynamicImage::from(sized::<Rgba<u8>>(width, height, rgba)?)
        }
        (ColorType::RGB(16), Samples::U16(v), _) => DynamicImage::from(sized::<Rgb<u16>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 3)?,
        )?),
        (ColorType::RGBA(16), Samples::U16(v), _) => {
            let mut rgba = gather(&v, pixels, b.spp, b.planar, 4)?;
            if b.associated {
                unpremultiply16::<4>(&mut rgba);
            }
            DynamicImage::from(sized::<Rgba<u16>>(width, height, rgba)?)
        }
        (ColorType::RGB(32), Samples::F32(v), _) => DynamicImage::from(sized::<Rgb<f32>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 3)?,
        )?),
        (ColorType::RGBA(32), Samples::F32(v), _) => DynamicImage::from(sized::<Rgba<f32>>(
            width,
            height,
            gather(&v, pixels, b.spp, b.planar, 4)?,
        )?),
        (ColorType::CMYK(8) | ColorType::CMYKA(8), Samples::U8(v), _) => {
            let channels = if matches!(b.colour_type, ColorType::CMYKA(_)) {
                5
            } else {
                4
            };
            let all = gather(&v, pixels, b.spp, b.planar, channels)?;
            let inks: Vec<u8> = all
                .chunks_exact(channels)
                .flat_map(|p| [p[0], p[1], p[2], p[3]])
                .collect();
            let colours = colour::inks(&inks, b.icc);
            if channels == 5 {
                let mut rgba: Vec<u8> = colours
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .zip(all.as_chunks::<5>().0.iter())
                    .flat_map(|(c, p)| [c[0], c[1], c[2], p[4]])
                    .collect();
                if b.associated {
                    unpremultiply::<4>(&mut rgba);
                }
                DynamicImage::from(sized::<Rgba<u8>>(width, height, rgba)?)
            } else {
                DynamicImage::from(sized::<Rgb<u8>>(width, height, colours)?)
            }
        }
        (ColorType::CMYK(16) | ColorType::CMYKA(16), Samples::U16(v), _) => {
            let channels = if matches!(b.colour_type, ColorType::CMYKA(_)) {
                5
            } else {
                4
            };
            let all = gather(&v, pixels, b.spp, b.planar, channels)?;
            let inks: Vec<u16> = all
                .chunks_exact(channels)
                .flat_map(|p| [p[0], p[1], p[2], p[3]])
                .collect();
            let colours = colour::inks16(&inks, b.icc);
            if channels == 5 {
                let mut rgba: Vec<u16> = colours
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .zip(all.as_chunks::<5>().0.iter())
                    .flat_map(|(c, p)| [c[0], c[1], c[2], p[4]])
                    .collect();
                if b.associated {
                    unpremultiply16::<4>(&mut rgba);
                }
                DynamicImage::from(sized::<Rgba<u16>>(width, height, rgba)?)
            } else {
                DynamicImage::from(sized::<Rgb<u16>>(width, height, colours)?)
            }
        }
        (colour_type, _, _) => return Err(unsupported(&format!("{colour_type:?} samples"))),
    };
    Ok(image)
}
