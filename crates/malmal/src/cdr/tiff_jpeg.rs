//! A TIFF of pages that are JPEG pictures, written as their coefficients.
//!
//! Each page of a TIFF compressed as JPEG (pages of grey, RGB, YCbCr, or of
//! four inks when they are kept) is its strips or tiles put together and
//! written anew as one baseline JPEG, the page's one strip. Decoded, every
//! page has to show what the same page rebuilt from its pixels shows;
//! otherwise the TIFF of pixels is what is kept.

use std::io::Cursor;

use tiff::decoder::{Decoder, DecodingResult};

use super::tif::{JpegPage, close, jpeg_page, ycbcr_to_rgb};
use super::{Deadline, Rebuilt};
use crate::detect::FileType;
use crate::limits::Limits;

/// The TIFF in `data`, whose pages `shown` holds rebuilt from their pixels,
/// as a TIFF of JPEG pages, if every page can be one.
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
            )?);
        }
        index += 1;
        if !decoder.more_images() {
            break;
        }
        decoder.next_image().ok()?;
    }
    if pages.len() != shown.frames as usize {
        return None;
    }
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
    let (width, height) = pages[0].coefficients.dimensions();
    Some(Rebuilt {
        data: file,
        file_type: FileType::Tiff,
        width,
        height,
        frames: pages.len() as u32,
    })
}

/// A page as decoded: its colour type, size and 8-bit samples.
type Decoded = (tiff::ColorType, (u32, u32), Vec<u8>);

/// Each page of a TIFF, decoded.
fn decoded(data: &[u8], limits: &Limits) -> Option<Vec<Decoded>> {
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

/// A little-endian TIFF of `pages`, each one strip of a JPEG.
fn write(pages: &[JpegPage]) -> Option<Vec<u8>> {
    let mut out = b"II*\0\0\0\0\0".to_vec();
    // Where the offset of the next directory goes.
    let mut link = 4;
    for page in pages {
        let jpeg = page.coefficients.write(None)?;
        let (width, height) = page.coefficients.dimensions();
        let spp: u16 = match page.photometric {
            1 => 1,
            5 => 4,
            _ => 3,
        };
        // The strip, on two bytes.
        if out.len() % 2 == 1 {
            out.push(0);
        }
        let strip = u32::try_from(out.len()).ok()?;
        out.extend_from_slice(&jpeg);
        let mut fields = vec![
            long(254, 0),
            long(256, width),
            long(257, height),
            shorts(258, &vec![8; spp as usize]),
            shorts(259, &[7]),
            shorts(262, &[page.photometric as u16]),
            long(273, strip),
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
        fields.sort_by_key(|f| f.tag);

        // Values too long for their entry go before the directory.
        let mut values = Vec::new();
        for field in &mut fields {
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
        out[link..link + 4].copy_from_slice(&directory.to_le_bytes());
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
        link = out.len();
        out.extend_from_slice(&[0; 4]);
    }
    Some(out)
}
