//! A TIFF of pages that are JPEG pictures, written as their coefficients.
//!
//! Each page of a TIFF compressed as JPEG (pages of grey, RGB, YCbCr, or of
//! four inks when they are kept) is its strips or tiles put together and
//! written anew as one baseline JPEG, the page's one strip. A page that
//! cannot be (another compression, extra samples, a profile not kept) is
//! the same page rebuilt from its pixels. Decoded, every page has to show
//! what the same page rebuilt from its pixels shows; otherwise the TIFF of
//! pixels is what is kept.

use std::io::Cursor;

use tiff::decoder::{Decoder, DecodingResult};

use super::tif::{JpegPage, close, jpeg_page, ycbcr_to_rgb};
use super::{Deadline, Rebuilt};
use crate::detect::FileType;
use crate::limits::Limits;

/// The TIFF in `data`, whose pages `shown` holds rebuilt from their pixels,
/// with the pages that can be JPEG pages as such, if any can.
pub(super) fn rebuild(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    shown: &Rebuilt,
    keep_inks: bool,
    keep_profile: bool,
) -> Option<Rebuilt> {
    let mut decoder = Decoder::new(Cursor::new(data)).ok()?;
    let mut pages = Vec::new();
    let mut index = 0;
    loop {
        // A smaller copy of another page, or a mask for one, is left out
        // as it is from the pixels.
        let kind = decoder
            .find_tag_unsigned::<u32>(tiff::tags::Tag::NewSubfileType)
            .ok()
            .flatten()
            .unwrap_or(0);
        if index == 0 || kind & 0b101 == 0 {
            pages.push(jpeg_page(
                &mut decoder,
                data,
                limits,
                deadline,
                keep_inks,
                keep_profile,
            ));
        }
        index += 1;
        if !decoder.more_images() {
            break;
        }
        decoder.next_image().ok()?;
    }
    if pages.len() != shown.frames as usize || pages.iter().all(Option::is_none) {
        return None;
    }
    // The others as they are from their pixels.
    let mut copies = copied(&shown.data)?.into_iter();
    let pages: Vec<Page> = pages
        .into_iter()
        .map(|page| {
            let copy = copies.next()?;
            Some(page.map_or(Page::Copied(copy), Page::Jpeg))
        })
        .collect::<Option<_>>()?;
    let file = write(&pages)?;
    deadline.check().ok()?;
    if file.len() as u64 > limits.max_decompressed {
        return None;
    }
    // Every page shows what it does from its pixels.
    let (ours, theirs) = (decoded(&file, limits)?, decoded(&shown.data, limits)?);
    if ours.len() != theirs.len()
        || !ours
            .iter()
            .zip(&theirs)
            .all(|(a, b)| a.0 == b.0 && a.1 == b.1 && close(&a.2, &b.2))
    {
        return None;
    }
    Some(Rebuilt {
        data: file,
        file_type: FileType::Tiff,
        width: shown.width,
        height: shown.height,
        frames: pages.len() as u32,
    })
}

/// A TIFF of `pages` of JPEG, if it is not too large.
pub(super) fn of_pages(
    pages: Vec<JpegPage>,
    limits: &Limits,
    deadline: Deadline,
) -> Option<Rebuilt> {
    let (width, height) = pages.first()?.coefficients.dimensions();
    let frames = u32::try_from(pages.len()).ok()?;
    let pages: Vec<Page> = pages.into_iter().map(Page::Jpeg).collect();
    let file = write(&pages)?;
    deadline.check().ok()?;
    if file.len() as u64 > limits.max_decompressed {
        return None;
    }
    Some(Rebuilt {
        data: file,
        file_type: FileType::Tiff,
        width,
        height,
        frames,
    })
}

/// A page as decoded: its colour type, size and 8-bit samples.
pub(super) type Decoded = (tiff::ColorType, (u32, u32), Vec<u8>);

/// Each page of a TIFF, decoded, YCbCr as RGB.
pub(super) fn decoded(data: &[u8], limits: &Limits) -> Option<Vec<Decoded>> {
    let mut decoder = Decoder::new(Cursor::new(data)).ok()?;
    let mut pages = Vec::new();
    let mut held = 0u64;
    loop {
        let mut colour = decoder.colortype().ok()?;
        let size = decoder.dimensions().ok()?;
        let DecodingResult::U8(mut samples) = decoder.read_image().ok()? else {
            return None;
        };
        // As it is read when it is rebuilt from its pixels.
        if colour == tiff::ColorType::YCbCr(8) {
            colour = tiff::ColorType::RGB(8);
            samples = ycbcr_to_rgb(&samples);
        }
        held += samples.len() as u64;
        if held > limits.max_decompressed {
            return None;
        }
        pages.push((colour, size, samples));
        if !decoder.more_images() {
            break;
        }
        decoder.next_image().ok()?;
    }
    Some(pages)
}

/// An entry of a directory: its tag, type, count, and value or the bytes
/// it points to.
struct Field {
    tag: u16,
    kind: u16,
    count: u32,
    bytes: Vec<u8>,
}

const SHORT: u16 = 3;
const LONG: u16 = 4;
const RATIONAL: u16 = 5;
const UNDEFINED: u16 = 7;

fn shorts(tag: u16, values: &[u16]) -> Field {
    Field {
        tag,
        kind: SHORT,
        count: values.len() as u32,
        bytes: values.iter().flat_map(|v| v.to_le_bytes()).collect(),
    }
}

fn long(tag: u16, value: u32) -> Field {
    Field {
        tag,
        kind: LONG,
        count: 1,
        bytes: value.to_le_bytes().to_vec(),
    }
}

fn rationals(tag: u16, values: &[(u32, u32)]) -> Field {
    Field {
        tag,
        kind: RATIONAL,
        count: values.len() as u32,
        bytes: values
            .iter()
            .flat_map(|(n, d)| [n.to_le_bytes(), d.to_le_bytes()].concat())
            .collect(),
    }
}

/// A page of the TIFF written: a JPEG of coefficients, or a page of the
/// TIFF rebuilt from pixels.
enum Page {
    Jpeg(JpegPage),
    Copied(Copied),
}

/// A page of a TIFF as it was written: its fields but where its strips
/// are, and its strips.
struct Copied {
    fields: Vec<Field>,
    strips: Vec<Vec<u8>>,
}

/// Each page of `data`, a classic little-endian TIFF of strips as
/// [`super::tiff_out`] writes one, to be written again elsewhere.
fn copied(data: &[u8]) -> Option<Vec<Copied>> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?));
    if data.get(..4)? != b"II*\0" {
        return None;
    }
    let mut pages = Vec::new();
    let mut next = u32_at(4)? as usize;
    while next != 0 {
        if pages.len() > 65535 {
            return None;
        }
        let count = u16_at(next)? as usize;
        let mut fields = Vec::with_capacity(count);
        let (mut offsets, mut sizes) = (None, None);
        for entry in 0..count {
            let at = next + 2 + entry * 12;
            let (tag, kind, n) = (u16_at(at)?, u16_at(at + 2)?, u32_at(at + 4)?);
            let width = match kind {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 => 4,
                5 | 10 | 12 => 8,
                _ => return None,
            };
            let length = usize::try_from(n).ok()?.checked_mul(width)?;
            let bytes = if length <= 4 {
                data.get(at + 8..at + 8 + length)?.to_vec()
            } else {
                let from = u32_at(at + 8)? as usize;
                data.get(from..from.checked_add(length)?)?.to_vec()
            };
            let values = || -> Option<Vec<usize>> {
                match kind {
                    3 => Some(
                        bytes
                            .chunks(2)
                            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
                            .collect(),
                    ),
                    4 => Some(
                        bytes
                            .chunks(4)
                            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                            .collect(),
                    ),
                    _ => None,
                }
            };
            match tag {
                273 => offsets = Some(values()?),
                279 => sizes = Some(values()?),
                // Anything else that points into the file (tiles, other
                // directories) is not what is written here.
                324 | 325 | 330 | 34665 | 34853 | 40965 => return None,
                _ => {}
            }
            if tag != 273 {
                fields.push(Field {
                    tag,
                    kind,
                    count: n,
                    bytes,
                });
            }
        }
        let (offsets, sizes) = (offsets?, sizes?);
        if offsets.len() != sizes.len() {
            return None;
        }
        let strips = offsets
            .iter()
            .zip(&sizes)
            .map(|(&at, &size)| Some(data.get(at..at.checked_add(size)?)?.to_vec()))
            .collect::<Option<_>>()?;
        pages.push(Copied { fields, strips });
        next = u32_at(next + 2 + count * 12)? as usize;
    }
    Some(pages)
}

/// A little-endian TIFF of `pages`, each one strip of a JPEG or the strips
/// of a page copied.
fn write(pages: &[Page]) -> Option<Vec<u8>> {
    let mut out = b"II*\0\0\0\0\0".to_vec();
    // Where the offset of the next directory goes.
    let mut link = 4;
    for page in pages {
        let (mut fields, strips) = match page {
            Page::Jpeg(page) => jpeg_fields(page)?,
            Page::Copied(page) => (
                page.fields
                    .iter()
                    .map(|f| Field {
                        tag: f.tag,
                        kind: f.kind,
                        count: f.count,
                        bytes: f.bytes.clone(),
                    })
                    .collect(),
                page.strips.clone(),
            ),
        };
        // The strips, each on two bytes.
        let mut offsets = Vec::with_capacity(strips.len());
        for strip in &strips {
            if out.len() % 2 == 1 {
                out.push(0);
            }
            offsets.push(u32::try_from(out.len()).ok()?);
            out.extend_from_slice(strip);
        }
        fields.push(Field {
            tag: 273,
            kind: LONG,
            count: u32::try_from(offsets.len()).ok()?,
            bytes: offsets.iter().flat_map(|o| o.to_le_bytes()).collect(),
        });
        fields.sort_by_key(|f| f.tag);
        write_directory(&mut out, &mut link, &fields)?;
    }
    Some(out)
}

/// The fields of a JPEG page but where its strip is, and its strip.
fn jpeg_fields(page: &JpegPage) -> Option<(Vec<Field>, Vec<Vec<u8>>)> {
    let jpeg = page.coefficients.write(None)?;
    let (width, height) = page.coefficients.dimensions();
    let spp: u16 = match page.photometric {
        1 => 1,
        5 => 4,
        _ => 3,
    };
    let mut fields = vec![
        long(254, 0),
        long(256, width),
        long(257, height),
        shorts(258, &vec![8; spp as usize]),
        shorts(259, &[7]),
        shorts(262, &[page.photometric as u16]),
        shorts(277, &[spp]),
        long(278, height),
        long(279, u32::try_from(jpeg.len()).ok()?),
        shorts(284, &[1]),
    ];
    let density = page.coefficients.density;
    if density.unit != 0 && density.x > 0 && density.y > 0 {
        // JPEG counts inches as 1 and centimetres as 2, TIFF as 2 and 3.
        fields.push(rationals(282, &[(u32::from(density.x), 1)]));
        fields.push(rationals(283, &[(u32::from(density.y), 1)]));
        fields.push(shorts(296, &[u16::from(density.unit) + 1]));
    }
    if page.photometric == 5 {
        fields.push(shorts(332, &[1]));
    }
    if page.photometric == 6 {
        let (h, v) = page.coefficients.subsampling()?;
        fields.push(shorts(530, &[h, v]));
        fields.push(rationals(
            532,
            &[(0, 1), (255, 1), (128, 1), (255, 1), (128, 1), (255, 1)],
        ));
    }
    if let Some(icc) = &page.profile {
        fields.push(Field {
            tag: 34675,
            kind: UNDEFINED,
            count: u32::try_from(icc.len()).ok()?,
            bytes: icc.clone(),
        });
    }
    Some((fields, vec![jpeg]))
}

/// Directory `fields`, sorted, with the values too long for their entry
/// before it, linked from `link`, which then is where its own link is.
fn write_directory(out: &mut Vec<u8>, link: &mut usize, fields: &[Field]) -> Option<()> {
    // Values too long for their entry go before the directory.
    let mut values = Vec::new();
    for field in fields {
        if field.bytes.len() > 4 {
            if out.len() % 2 == 1 {
                out.push(0);
            }
            values.push(u32::try_from(out.len()).ok()?);
            out.extend_from_slice(&field.bytes);
        } else {
            values.push(0);
        }
    }
    if out.len() % 2 == 1 {
        out.push(0);
    }
    let directory = u32::try_from(out.len()).ok()?;
    out[*link..*link + 4].copy_from_slice(&directory.to_le_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    for (field, at) in fields.iter().zip(values) {
        out.extend_from_slice(&field.tag.to_le_bytes());
        out.extend_from_slice(&field.kind.to_le_bytes());
        out.extend_from_slice(&field.count.to_le_bytes());
        let mut value = [0u8; 4];
        if field.bytes.len() > 4 {
            value = at.to_le_bytes();
        } else {
            value[..field.bytes.len()].copy_from_slice(&field.bytes);
        }
        out.extend_from_slice(&value);
    }
    *link = out.len();
    out.extend_from_slice(&[0; 4]);
    Some(())
}
