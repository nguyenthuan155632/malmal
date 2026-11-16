//! The composite image of a Photoshop document, as sRGB pixels.
//!
//! A PSD or PSB file saved with "Maximize compatibility", which is
//! Photoshop's default, ends with the whole picture flattened: one plane per
//! channel, raw or run-length encoded. That picture is what is read here;
//! the layers are not, and a file without it is refused rather than
//! flattened by blending its layers, which would be a different picture
//! wherever a blend mode, an effect or an adjustment layer is not done the
//! way Photoshop does it.

use image::{DynamicImage, ImageBuffer, Luma, LumaA, Rgb, Rgba};

use super::tiff_out::{InkSamples, Kept};
use super::{Deadline, Error, ToSrgb, colour, palette};
use crate::limits::Limits;

/// The pixels, and how many make a metre.
pub(super) struct Picture {
    pub(super) image: DynamicImage,
    pub(super) density: Option<png::PixelDimensions>,
    /// The profile the colours or shades are kept in, written anew.
    pub(super) icc: Option<Vec<u8>>,
}

fn broken(what: &str) -> Error {
    Error::Decode(format!("PSD {what}"))
}

fn be16(data: &[u8], at: usize) -> Result<u16, Error> {
    let bytes = data.get(at..at + 2).ok_or_else(|| broken("is truncated"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be32(data: &[u8], at: usize) -> Result<u32, Error> {
    let bytes = data.get(at..at + 4).ok_or_else(|| broken("is truncated"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be64(data: &[u8], at: usize) -> Result<u64, Error> {
    let bytes = data.get(at..at + 8).ok_or_else(|| broken("is truncated"))?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap_or_default()))
}

/// The bytes of a section that starts with its length, and where the next
/// one starts.
fn section(data: &[u8], at: usize, wide: bool) -> Result<(&[u8], usize), Error> {
    let (length, start) = if wide {
        (be64(data, at)?, at + 8)
    } else {
        (be32(data, at)? as u64, at + 4)
    };
    let end = usize::try_from(length)
        .ok()
        .and_then(|length| start.checked_add(length))
        .filter(|&end| end <= data.len())
        .ok_or_else(|| broken("section is out of bounds"))?;
    Ok((&data[start..end], end))
}

/// What the image resources say.
#[derive(Default)]
struct Resources<'a> {
    merged: Option<bool>,
    icc: Option<&'a [u8]>,
    density: Option<png::PixelDimensions>,
    transparent_index: Option<u16>,
    /// How each spot or alpha channel is shown, in order.
    display: Vec<Ink>,
}

/// The colour a channel of ink is shown in, and how much it covers what
/// is under it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Ink {
    colour: [f32; 3],
    solidity: f32,
}

impl Ink {
    /// From a Photoshop colour: a colour space, four 16-bit components and
    /// an opacity from 0 to 100.
    fn of(space: u16, c: [u16; 4], opacity: u16) -> Self {
        let unit = |v: u16| v as f32 / 65535.0;
        let colour = match space {
            // RGB.
            0 => [unit(c[0]), unit(c[1]), unit(c[2])],
            // Hue, saturation and brightness.
            1 => {
                let (h, sat, v) = (unit(c[0]) * 6.0, unit(c[1]), unit(c[2]));
                let f = |n: f32| {
                    let k = (n + h) % 6.0;
                    v - v * sat * k.min(4.0 - k).clamp(0.0, 1.0)
                };
                [f(5.0), f(3.0), f(1.0)]
            }
            // CMYK, with 0 for all ink.
            2 => {
                let k = unit(c[3]);
                [unit(c[0]) * k, unit(c[1]) * k, unit(c[2]) * k]
            }
            // L*a*b*: L* to 10000, a* and b* signed hundredths.
            7 => colour::Lab::new(colour::Lab::D50).srgb(
                c[0] as f32 / 100.0,
                c[1] as i16 as f32 / 100.0,
                c[2] as i16 as f32 / 100.0,
            ),
            // Grey, to 10000 for black.
            8 => [1.0 - (c[0] as f32 / 10000.0).min(1.0); 3],
            _ => [0.0; 3],
        };
        Self {
            colour,
            solidity: (opacity.min(100) as f32) / 100.0,
        }
    }

    /// The inks a document of `channels` is shown in when it says nothing:
    /// those of the process it was most likely made from.
    fn assumed(channels: usize) -> Vec<Self> {
        let ink = |colour| Self {
            colour,
            solidity: 1.0,
        };
        let process = [
            ink([0.0, 1.0, 1.0]),
            ink([1.0, 0.0, 1.0]),
            ink([1.0, 1.0, 0.0]),
            ink([0.0, 0.0, 0.0]),
        ];
        (0..channels)
            .map(|c| match channels {
                3 | 4 => process[c],
                _ => ink([0.0; 3]),
            })
            .collect()
    }
}

/// Display information, in the newer form (0x0435) or the older (0x03EF).
fn display(body: &[u8], newer: bool) -> Vec<Ink> {
    let (start, size) = if newer { (4, 13) } else { (0, 14) };
    body.get(start..)
        .unwrap_or_default()
        .chunks_exact(size)
        .map(|e| {
            let at = |i: usize| u16::from_be_bytes([e[i], e[i + 1]]);
            Ink::of(at(0), [at(2), at(4), at(6), at(8)], at(10))
        })
        .collect()
}

fn resources(mut data: &[u8]) -> Resources<'_> {
    let mut found = Resources::default();
    // A resource: signature, id, a padded Pascal name, then sized data
    // padded to an even length.
    while data.len() >= 12 && &data[..4] == b"8BIM" {
        let id = u16::from_be_bytes([data[4], data[5]]);
        let name = 1 + data[6] as usize;
        let at = 6 + name + (name & 1);
        let Ok(length) = be32(data, at) else {
            break;
        };
        let start = at + 4;
        let Some(body) = data.get(start..start + length as usize) else {
            break;
        };
        match id {
            // Version information: whether the composite is real.
            0x0421 if body.len() >= 5 => found.merged = Some(body[4] != 0),
            0x040F => found.icc = Some(body),
            // Resolution in pixels per inch, as 16.16 fixed-point numbers.
            0x03ED if body.len() >= 16 => {
                let fixed = |at: usize| {
                    let v =
                        u32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
                    (v as f64 / 65536.0).round() as u32
                };
                found.density = palette::per_metre(1, fixed(0), fixed(8));
            }
            0x0435 => found.display = display(body, true),
            0x03EF if found.display.is_empty() => found.display = display(body, false),
            0x0417 if body.len() >= 2 => {
                found.transparent_index = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            _ => {}
        }
        let next = start + length as usize + (length as usize & 1);
        data = data.get(next..).unwrap_or_default();
    }
    found
}

/// Whether the first channel past the colours of the composite is its
/// transparency, which the layer section says.
fn transparent(section: &[u8], wide: bool) -> bool {
    let read = || -> Result<bool, Error> {
        if section.is_empty() {
            return Ok(false);
        }
        let (layers, after) = self::section(section, 0, wide)?;
        // A negative layer count says so for 8-bit documents.
        if layers.len() >= 2 && (be16(layers, 0)? as i16) < 0 {
            return Ok(true);
        }
        let (_, mut at) = self::section(section, after, false)?;
        // The other blocks, one of which holds the layers of a deeper
        // document, others which say so outright.
        while at + 12 <= section.len() {
            let (signature, key) = (&section[at..at + 4], &section[at + 4..at + 8]);
            if signature != b"8BIM" && signature != b"8B64" {
                break;
            }
            let long = wide
                && matches!(
                    key,
                    b"LMsk"
                        | b"Lr16"
                        | b"Lr32"
                        | b"Layr"
                        | b"Mt16"
                        | b"Mt32"
                        | b"Mtrn"
                        | b"Alph"
                        | b"FMsk"
                        | b"lnk2"
                        | b"FEid"
                        | b"FXid"
                        | b"PxSD"
                );
            let (body, end) = self::section(section, at + 8, long)?;
            match key {
                b"Mtrn" | b"Mt16" | b"Mt32" => return Ok(true),
                b"Lr16" | b"Lr32" if body.len() >= 2 && (be16(body, 0)? as i16) < 0 => {
                    return Ok(true);
                }
                _ => {}
            }
            at = end.next_multiple_of(4);
        }
        Ok(false)
    };
    read().unwrap_or(false)
}

/// PackBits.
fn unpack(mut packed: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let mut at = 0;
    while at < out.len() {
        let (&header, rest) = packed.split_first().ok_or_else(|| broken("row is short"))?;
        let n = header as i8;
        if n >= 0 {
            let count = n as usize + 1;
            let bytes = rest.get(..count).ok_or_else(|| broken("row is short"))?;
            out.get_mut(at..at + count)
                .ok_or_else(|| broken("row is long"))?
                .copy_from_slice(bytes);
            at += count;
            packed = &rest[count..];
        } else if n != -128 {
            let count = 1 - n as isize;
            let &byte = rest.first().ok_or_else(|| broken("row is short"))?;
            out.get_mut(at..at + count as usize)
                .ok_or_else(|| broken("row is long"))?
                .fill(byte);
            at += count as usize;
            packed = &rest[1..];
        } else {
            packed = rest;
        }
    }
    Ok(())
}

fn sized<P: image::Pixel>(
    width: u32,
    height: u32,
    samples: Vec<P::Subpixel>,
) -> Result<ImageBuffer<P, Vec<P::Subpixel>>, Error> {
    ImageBuffer::from_raw(width, height, samples).ok_or_else(|| broken("planes are short"))
}

/// Undo the blend of each colour channel with white, by the alpha in the
/// channel after them.
fn unmatte(planes: &mut [u8], plane: usize, colours: usize, depth: u16, count: usize) {
    let unblend = |colour: f64, alpha: f64| ((colour - (1.0 - alpha)) / alpha).clamp(0.0, 1.0);
    for i in 0..count {
        match depth {
            8 => {
                let alpha = planes[colours * plane + i] as f64 / 255.0;
                if alpha > 0.0 && alpha < 1.0 {
                    for c in 0..colours {
                        let at = c * plane + i;
                        planes[at] =
                            (unblend(planes[at] as f64 / 255.0, alpha) * 255.0).round() as u8;
                    }
                }
            }
            16 => {
                let read = |planes: &[u8], at: usize| {
                    u16::from_be_bytes([planes[at], planes[at + 1]]) as f64 / 65535.0
                };
                let alpha = read(planes, colours * plane + i * 2);
                if alpha > 0.0 && alpha < 1.0 {
                    for c in 0..colours {
                        let at = c * plane + i * 2;
                        let value = (unblend(read(planes, at), alpha) * 65535.0).round() as u16;
                        planes[at..at + 2].copy_from_slice(&value.to_be_bytes());
                    }
                }
            }
            _ => {
                let read = |planes: &[u8], at: usize| {
                    f32::from_be_bytes([planes[at], planes[at + 1], planes[at + 2], planes[at + 3]])
                        as f64
                };
                let alpha = read(planes, colours * plane + i * 4);
                if alpha > 0.0 && alpha < 1.0 {
                    for c in 0..colours {
                        let at = c * plane + i * 4;
                        let value = unblend(read(planes, at), alpha) as f32;
                        planes[at..at + 4].copy_from_slice(&value.to_be_bytes());
                    }
                }
            }
        }
    }
}

/// The sRGB curve, for the linear light of 32-bit documents.
fn encode_srgb(linear: f32) -> f32 {
    let c = linear.clamp(0.0, 1.0);
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

/// Undo the prediction of ZIP compression, row by row: each sample is the
/// difference from the one before it. Rows of 32-bit samples hold the
/// first byte of every sample, then the second and so on, and the
/// differences are of bytes.
fn unpredict(planes: &mut [u8], row: usize, width: usize, depth: u16) -> Result<(), Error> {
    for line in planes.chunks_exact_mut(row) {
        match depth {
            8 => {
                for x in 1..line.len() {
                    line[x] = line[x].wrapping_add(line[x - 1]);
                }
            }
            16 => {
                let mut previous = 0u16;
                for pair in line.as_chunks_mut::<2>().0.iter_mut() {
                    previous = previous.wrapping_add(u16::from_be_bytes(*pair));
                    *pair = previous.to_be_bytes();
                }
            }
            32 => {
                for x in 1..line.len() {
                    line[x] = line[x].wrapping_add(line[x - 1]);
                }
                let shuffled = line.to_vec();
                for x in 0..width {
                    for byte in 0..4 {
                        line[x * 4 + byte] = shuffled[byte * width + x];
                    }
                }
            }
            _ => return Err(broken("predicts samples of this depth")),
        }
    }
    Ok(())
}

/// The composite of a document, as colours or as the inks it is.
pub(super) enum Composite {
    Colours(Picture),
    Inks(Kept),
}

/// The composite as sRGB colours.
#[cfg(test)]
pub(super) fn read(data: &[u8], limits: &Limits, deadline: Deadline) -> Result<Picture, Error> {
    match composite(data, limits, deadline, false, false)? {
        Composite::Colours(picture) => Ok(picture),
        Composite::Inks(_) => Err(broken("inks were kept")),
    }
}

/// The composite, inks kept as inks if `keep_inks` and the profile they
/// print by can be written anew exactly; colours and shades of grey kept in
/// a profile other than sRGB's if `keep_profile` and it can be.
pub(super) fn composite(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_inks: bool,
    keep_profile: bool,
) -> Result<Composite, Error> {
    if !data.starts_with(b"8BPS") {
        return Err(broken("signature is missing"));
    }
    let wide = match be16(data, 4)? {
        1 => false,
        2 => true,
        _ => return Err(broken("version is unknown")),
    };
    let channels = be16(data, 12)? as usize;
    let (height, width) = (be32(data, 14)?, be32(data, 18)?);
    let (depth, mode) = (be16(data, 22)?, be16(data, 24)?);
    if width == 0 || height == 0 || !(1..=56).contains(&channels) {
        return Err(broken("header is out of range"));
    }
    let pixels = width as u64 * height as u64;
    if pixels > limits.max_pixels {
        return Err(Error::TooLarge);
    }
    let (colour_mode, after_colours) = section(data, 26, false)?;
    let (resource_data, after_resources) = section(data, after_colours, false)?;
    let found = resources(resource_data);
    let (layers, image_start) = section(data, after_resources, wide)?;
    if found.merged == Some(false) {
        return Err(Error::Unsupported {
            file_type: crate::detect::FileType::Psd,
            reason: "it was saved without a composite image",
        });
    }

    // Channels of colour, and whether one more is transparency.
    let colours = match (mode, depth) {
        (0, 1) | (1, 8 | 16 | 32) | (2, 8) | (8, 8 | 16 | 32) => 1,
        (3 | 9, 8 | 16 | 32) => 3,
        (4, 8 | 16) => 4,
        // Every channel an ink.
        (7, 8 | 16) => channels,
        _ => {
            return Err(Error::Unsupported {
                file_type: crate::detect::FileType::Psd,
                reason: "its colour mode or depth is not one this reads",
            });
        }
    };
    if channels < colours {
        return Err(broken("has too few channels"));
    }
    let alpha = channels > colours && !matches!(mode, 0 | 2 | 7) && transparent(layers, wide);
    let kept = colours + usize::from(alpha);

    let row = (width as usize * depth as usize).div_ceil(8);
    let plane = row * height as usize;
    if (plane as u64).saturating_mul(kept as u64 + 1) > limits.max_decompressed {
        return Err(Error::TooLarge);
    }
    let compression = be16(data, image_start)?;
    let at = image_start + 2;
    let mut planes = vec![0u8; plane * kept];
    match compression {
        0 => {
            let raw = data
                .get(at..at + plane * kept)
                .ok_or_else(|| broken("planes are short"))?;
            planes.copy_from_slice(raw);
        }
        1 => {
            // The length of every row of every channel comes first.
            let size = if wide { 4 } else { 2 };
            let rows = height as usize * channels;
            let counts_end = at + rows * size;
            if counts_end > data.len() {
                return Err(broken("row lengths are out of bounds"));
            }
            let mut start = counts_end;
            for index in 0..height as usize * kept {
                let count = match wide {
                    true => be32(data, at + index * size)? as usize,
                    false => be16(data, at + index * size)? as usize,
                };
                let packed = data
                    .get(start..start + count)
                    .ok_or_else(|| broken("row is out of bounds"))?;
                unpack(packed, &mut planes[index * row..(index + 1) * row])?;
                start += count;
                if index % height as usize == 0 {
                    deadline.check()?;
                }
            }
        }
        2 | 3 => {
            // One zlib stream of every channel, one plane after another.
            let all = plane * channels;
            let budget = usize::try_from(limits.max_decompressed).unwrap_or(usize::MAX);
            let inflated = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
                data.get(at..).unwrap_or_default(),
                all.min(budget),
            )
            .map_err(|_| broken("composite does not inflate"))?;
            if inflated.len() < plane * kept {
                return Err(broken("planes are short"));
            }
            planes.copy_from_slice(&inflated[..plane * kept]);
            if compression == 3 {
                unpredict(&mut planes, row, width as usize, depth)?;
            }
        }
        _ => {
            return Err(Error::Unsupported {
                file_type: crate::detect::FileType::Psd,
                reason: "its composite image is compressed in a way this does not read",
            });
        }
    }
    deadline.check()?;
    let count = pixels as usize;
    // Photoshop keeps the composite of a document with transparency
    // matted against white: the colours of a pixel half covered are half
    // white. Taken back out, they are the colours of what covers it.
    if alpha && matches!(mode, 1 | 3 | 4 | 8) {
        unmatte(&mut planes, plane, colours, depth, count);
    }

    let sample8 = |channel: usize, i: usize| planes[channel * plane + i];
    let sample16 = |channel: usize, i: usize| {
        let at = channel * plane + i * 2;
        u16::from_be_bytes([planes[at], planes[at + 1]])
    };
    let sample32 = |channel: usize, i: usize| {
        let at = channel * plane + i * 4;
        f32::from_be_bytes([planes[at], planes[at + 1], planes[at + 2], planes[at + 3]])
    };
    let interleave8 = |channels: usize| -> Vec<u8> {
        (0..count)
            .flat_map(|i| (0..channels).map(move |c| sample8(c, i)))
            .collect()
    };
    let interleave16 = |channels: usize| -> Vec<u16> {
        (0..count)
            .flat_map(|i| (0..channels).map(move |c| sample16(c, i)))
            .collect()
    };
    // Linear light, as Photoshop keeps 32-bit documents, onto the sRGB
    // curve; the alpha channel stays linear.
    let interleave32 = |channels: usize, colours: usize| -> Vec<u16> {
        (0..count)
            .flat_map(|i| {
                (0..channels).map(move |c| {
                    let value = sample32(c, i);
                    let value = if c < colours {
                        encode_srgb(value)
                    } else {
                        value.clamp(0.0, 1.0)
                    };
                    (value * 65535.0).round() as u16
                })
            })
            .collect()
    };

    // Inks as inks, 0 for none, which Photoshop stores as the most.
    let profile = match (keep_inks && mode == 4, found.icc) {
        (false, _) => None,
        (true, None) => Some(None),
        (true, Some(icc)) => colour::rewritten_cmyk(icc).map(Some),
    };
    if let Some(icc) = profile {
        let channels = kept;
        let samples = match depth {
            8 => InkSamples::Eight(
                (0..count)
                    .flat_map(|i| {
                        (0..channels).map(move |c| match c {
                            4 => sample8(c, i),
                            _ => 255 - sample8(c, i),
                        })
                    })
                    .collect(),
            ),
            _ => InkSamples::Sixteen(
                (0..count)
                    .flat_map(|i| {
                        (0..channels).map(move |c| match c {
                            4 => sample16(c, i),
                            _ => 65535 - sample16(c, i),
                        })
                    })
                    .collect(),
            ),
        };
        return Ok(Composite::Inks(Kept {
            width,
            height,
            samples,
            alpha: alpha.then_some(false),
            icc,
            density: found.density,
        }));
    }

    let mut image = match (mode, depth, alpha) {
        // Bitmap: a set bit is black.
        (0, _, _) => {
            let grey = (0..count)
                .map(|i| {
                    let (x, y) = (i % width as usize, i / width as usize);
                    let byte = planes[y * row + x / 8];
                    if byte >> (7 - x % 8) & 1 == 1 { 0 } else { 255 }
                })
                .collect();
            DynamicImage::from(sized::<Luma<u8>>(width, height, grey)?)
        }
        (2, _, _) => {
            if colour_mode.len() < 768 {
                return Err(broken("colour table is missing"));
            }
            let transparent = found.transparent_index;
            let rgba = (0..count).flat_map(|i| {
                let index = sample8(0, i) as usize;
                let opaque = if transparent == Some(index as u16) {
                    0
                } else {
                    255
                };
                [
                    colour_mode[index],
                    colour_mode[256 + index],
                    colour_mode[512 + index],
                    opaque,
                ]
            });
            let rgba: Vec<u8> = rgba.collect();
            if transparent.is_some() {
                DynamicImage::from(sized::<Rgba<u8>>(width, height, rgba)?)
            } else {
                let rgb = rgba
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .flat_map(|p| [p[0], p[1], p[2]])
                    .collect();
                DynamicImage::from(sized::<Rgb<u8>>(width, height, rgb)?)
            }
        }
        // Grey, and the grey a duotone's inks are printed from.
        (1 | 8, 8, false) => DynamicImage::from(sized::<Luma<u8>>(width, height, interleave8(1))?),
        (1 | 8, 8, true) => DynamicImage::from(sized::<LumaA<u8>>(width, height, interleave8(2))?),
        (1 | 8, 16, false) => {
            DynamicImage::from(sized::<Luma<u16>>(width, height, interleave16(1))?)
        }
        (1 | 8, 16, true) => {
            DynamicImage::from(sized::<LumaA<u16>>(width, height, interleave16(2))?)
        }
        (1 | 8, _, false) => {
            DynamicImage::from(sized::<Luma<u16>>(width, height, interleave32(1, 1))?)
        }
        (1 | 8, _, true) => {
            DynamicImage::from(sized::<LumaA<u16>>(width, height, interleave32(2, 1))?)
        }
        (3, 8, false) => DynamicImage::from(sized::<Rgb<u8>>(width, height, interleave8(3))?),
        (3, 8, true) => DynamicImage::from(sized::<Rgba<u8>>(width, height, interleave8(4))?),
        (3, 16, false) => DynamicImage::from(sized::<Rgb<u16>>(width, height, interleave16(3))?),
        (3, 16, true) => DynamicImage::from(sized::<Rgba<u16>>(width, height, interleave16(4))?),
        (3, _, false) => DynamicImage::from(sized::<Rgb<u16>>(width, height, interleave32(3, 3))?),
        (3, _, true) => DynamicImage::from(sized::<Rgba<u16>>(width, height, interleave32(4, 3))?),
        // Inks, stored as 255 for none.
        (4, 8, _) => {
            let inks: Vec<u8> = (0..count)
                .flat_map(|i| (0..4).map(move |c| 255 - sample8(c, i)))
                .collect();
            let rgb = colour::inks(&inks, found.icc);
            if alpha {
                let rgba = rgb
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .enumerate()
                    .flat_map(|(i, c)| [c[0], c[1], c[2], sample8(4, i)])
                    .collect();
                DynamicImage::from(sized::<Rgba<u8>>(width, height, rgba)?)
            } else {
                DynamicImage::from(sized::<Rgb<u8>>(width, height, rgb)?)
            }
        }
        (4, _, _) => {
            let inks: Vec<u16> = (0..count)
                .flat_map(|i| (0..4).map(move |c| 65535 - sample16(c, i)))
                .collect();
            let rgb = colour::inks16(&inks, found.icc);
            if alpha {
                let rgba = rgb
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .enumerate()
                    .flat_map(|(i, c)| [c[0], c[1], c[2], sample16(4, i)])
                    .collect();
                DynamicImage::from(sized::<Rgba<u16>>(width, height, rgba)?)
            } else {
                DynamicImage::from(sized::<Rgb<u16>>(width, height, rgb)?)
            }
        }
        // L*a*b*, a* and b* stored with 128 for none, relative to D50.
        (9, _, _) => {
            let lab = colour::Lab::new(colour::Lab::D50);
            let (l, a, b): (Vec<f32>, Vec<f32>, Vec<f32>) = match depth {
                8 => (
                    (0..count)
                        .map(|i| sample8(0, i) as f32 * 100.0 / 255.0)
                        .collect(),
                    (0..count).map(|i| sample8(1, i) as f32 - 128.0).collect(),
                    (0..count).map(|i| sample8(2, i) as f32 - 128.0).collect(),
                ),
                16 => (
                    (0..count)
                        .map(|i| sample16(0, i) as f32 * 100.0 / 65535.0)
                        .collect(),
                    (0..count)
                        .map(|i| sample16(1, i) as f32 / 257.0 - 128.0)
                        .collect(),
                    (0..count)
                        .map(|i| sample16(2, i) as f32 / 257.0 - 128.0)
                        .collect(),
                ),
                _ => (
                    (0..count).map(|i| sample32(0, i) * 100.0).collect(),
                    (0..count).map(|i| sample32(1, i) * 255.0 - 128.0).collect(),
                    (0..count).map(|i| sample32(2, i) * 255.0 - 128.0).collect(),
                ),
            };
            let alpha_of = |i: usize| match depth {
                8 => sample8(3, i) as u16 * 257,
                16 => sample16(3, i),
                _ => (sample32(3, i).clamp(0.0, 1.0) * 65535.0).round() as u16,
            };
            let colours = (0..count).map(|i| {
                lab.srgb(l[i], a[i], b[i])
                    .map(|c| (c * 65535.0).round() as u16)
            });
            if alpha {
                let rgba = colours
                    .enumerate()
                    .flat_map(|(i, [r, g, b])| [r, g, b, alpha_of(i)])
                    .collect();
                DynamicImage::from(sized::<Rgba<u16>>(width, height, rgba)?)
            } else {
                let rgb = colours.flatten().collect();
                DynamicImage::from(sized::<Rgb<u16>>(width, height, rgb)?)
            }
        }
        // Multichannel: each channel an ink, all of it at 0, shown in its
        // colour over the ones before it.
        (7, _, _) => {
            let inks = match found.display.get(..channels) {
                Some(inks) => inks.to_vec(),
                None => Ink::assumed(channels),
            };
            let value = |c: usize, i: usize| match depth {
                8 => sample8(c, i) as f32 / 255.0,
                _ => sample16(c, i) as f32 / 65535.0,
            };
            let rgb = (0..count)
                .flat_map(|i| {
                    let mut out = [1.0f32; 3];
                    for (c, ink) in inks.iter().enumerate() {
                        let cover = (1.0 - value(c, i)) * ink.solidity;
                        for (o, &k) in out.iter_mut().zip(&ink.colour) {
                            *o *= 1.0 - cover * (1.0 - k);
                        }
                    }
                    out.map(|o| (o.clamp(0.0, 1.0) * 65535.0).round() as u16)
                })
                .collect();
            let image = DynamicImage::from(sized::<Rgb<u16>>(width, height, rgb)?);
            match depth {
                8 => image.into_rgb8().into(),
                _ => image,
            }
        }
        _ => return Err(broken("mode is not handled")),
    };
    deadline.check()?;
    // An 8-bit L*a*b* document comes out as 16 bits a channel; it held no
    // more than 8.
    if mode == 9 && depth == 8 {
        image = if alpha {
            image.into_rgba8().into()
        } else {
            image.into_rgb8().into()
        };
    }
    let mut kept = None;
    if matches!(mode, 1 | 3 | 8)
        && let Some(colors) = ToSrgb::new(found.icc.map(<[u8]>::to_vec))
    {
        // Grey shown in inks is in their colours, not the profile's.
        let channels = if mode == 3 { 3 } else { 1 };
        kept = found
            .icc
            .filter(|_| keep_profile && mode != 8)
            .and_then(|icc| colour::rewritten_screen(icc, channels));
        if kept.is_none() {
            colors.image(&mut image);
        }
    }
    // A duotone is grey printed in up to four inks, each through its own
    // curve; it is shown in the colours they make.
    if mode == 8
        && let Some(inks) = Duotone::of(colour_mode)
    {
        image = inks.apply(&image);
    }
    Ok(Composite::Colours(Picture {
        image,
        density: found.density,
        icc: kept,
    }))
}

/// The inks of a duotone, from its colour mode data: as Photoshop writes
/// it (and a duotone options file), a version, how many inks, four colours
/// of ten bytes, four names of 64, four curves of 13 points and an override
/// flag, a dot gain and the colours of the overprints.
struct Duotone {
    /// The colour of each ink, and how much of it each amount of the grey
    /// prints, at 1024 steps.
    inks: Vec<([f32; 3], Vec<f32>)>,
    /// The colour each mix of inks prints where all of them cover the
    /// paper, by the mask of the inks in it: white for none, an ink's own
    /// colour for one, the overprint colour the file gives for more.
    mixes: Vec<[f32; 3]>,
}

impl Duotone {
    const STEPS: usize = 1024;

    fn of(data: &[u8]) -> Option<Self> {
        let be16 = |at: usize| Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]));
        if be16(0)? != 1 {
            return None;
        }
        let count = be16(2)? as usize;
        if !(1..=4).contains(&count) {
            return None;
        }
        // The amount of grey each point of a curve stands for, in percent.
        const AT: [f32; 13] = [
            0.0, 5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 95.0, 100.0,
        ];
        let mut inks = Vec::new();
        for ink in 0..count {
            let spec = 4 + ink * 10;
            let c = [
                be16(spec + 2)?,
                be16(spec + 4)?,
                be16(spec + 6)?,
                be16(spec + 8)?,
            ];
            let colour = Ink::of(be16(spec)?, c, 100).colour;
            let curve = 4 + 40 + 256 + ink * 28;
            // The points that are set, in tenths of a percent of ink.
            let mut points: Vec<(f32, f32)> = (0..13)
                .filter_map(|i| {
                    let value = be16(curve + i * 2)? as i16;
                    // A point that is not set is -1.
                    (0..=1000)
                        .contains(&value)
                        .then(|| (AT[i] / 100.0, value as f32 / 1000.0))
                })
                .collect();
            if points.is_empty() {
                points = vec![(0.0, 0.0), (1.0, 1.0)];
            }
            if points[0].0 > 0.0 {
                points.insert(0, (0.0, 0.0));
            }
            if points[points.len() - 1].0 < 1.0 {
                points.push((1.0, 1.0));
            }
            let amounts = (0..Self::STEPS)
                .map(|step| {
                    let x = step as f32 / (Self::STEPS - 1) as f32;
                    let after = points
                        .iter()
                        .position(|p| p.0 >= x)
                        .unwrap_or(points.len() - 1);
                    if after == 0 {
                        return points[0].1;
                    }
                    let (a, b) = (points[after - 1], points[after]);
                    let t = if b.0 > a.0 {
                        (x - a.0) / (b.0 - a.0)
                    } else {
                        1.0
                    };
                    a.1 + (b.1 - a.1) * t
                })
                .collect();
            inks.push((colour, amounts));
        }
        // Mixes of two inks or more, fewest first and then in the order of
        // their inks (1+2, 1+3, 2+3, 1+2+3 for three), each a colour of 10
        // bytes after the dot gain. A mix the file does not give is the
        // product of its inks.
        let mut mixes: Vec<[f32; 3]> = (0..1usize << count)
            .map(|mask| {
                let mut out = [1.0f32; 3];
                for (i, (colour, _)) in inks.iter().enumerate() {
                    if mask >> i & 1 == 1 {
                        for (o, c) in out.iter_mut().zip(colour) {
                            *o *= c;
                        }
                    }
                }
                out
            })
            .collect();
        let mut overprints: Vec<usize> = (0..1usize << count)
            .filter(|mask| mask.count_ones() >= 2)
            .collect();
        let indexes = |mask: usize| {
            (0..count)
                .filter(|i| mask >> i & 1 == 1)
                .collect::<Vec<_>>()
        };
        overprints.sort_by_key(|&mask| (mask.count_ones(), indexes(mask)));
        let overprint_at = 4 + 40 + 256 + 4 * 28 + 2;
        for (index, mask) in overprints.into_iter().enumerate() {
            let spec = overprint_at + index * 10;
            let Some(c) = (|| {
                Some([
                    be16(spec + 2)?,
                    be16(spec + 4)?,
                    be16(spec + 6)?,
                    be16(spec + 8)?,
                ])
            })() else {
                break;
            };
            mixes[mask] = Ink::of(be16(spec)?, c, 100).colour;
        }
        Some(Self { inks, mixes })
    }

    /// The colour of grey `level`, 0 for black (all ink) to 1 for white.
    ///
    /// Each mix of inks covers as much of the paper as its inks cover
    /// together and the others leave bare, and shows its colour there.
    fn colour(&self, level: f32) -> [f32; 3] {
        let step = ((1.0 - level.clamp(0.0, 1.0)) * (Self::STEPS - 1) as f32).round() as usize;
        let mut out = [0.0f32; 3];
        for (mask, mix) in self.mixes.iter().enumerate() {
            let share: f32 = self
                .inks
                .iter()
                .enumerate()
                .map(|(i, (_, amounts))| match mask >> i & 1 {
                    1 => amounts[step],
                    _ => 1.0 - amounts[step],
                })
                .product();
            for (o, c) in out.iter_mut().zip(mix) {
                *o += share * c;
            }
        }
        out.map(|o| o.clamp(0.0, 1.0))
    }

    /// Grey, with or without transparency, in the colours of the inks, at
    /// the depth it was.
    fn apply(&self, image: &DynamicImage) -> DynamicImage {
        let (width, height) = (image.width(), image.height());
        let unit = |v: f32| (v * 65535.0).round() as u16;
        let out = if image.color().has_alpha() {
            let rgba = image
                .to_luma_alpha16()
                .pixels()
                .flat_map(|p| {
                    let [r, g, b] = self.colour(p[0] as f32 / 65535.0);
                    [unit(r), unit(g), unit(b), p[1]]
                })
                .collect();
            ImageBuffer::<Rgba<u16>, _>::from_raw(width, height, rgba).map(DynamicImage::from)
        } else {
            let rgb = image
                .to_luma16()
                .pixels()
                .flat_map(|p| self.colour(p[0] as f32 / 65535.0).map(unit))
                .collect();
            ImageBuffer::<Rgb<u16>, _>::from_raw(width, height, rgb).map(DynamicImage::from)
        };
        let Some(out) = out else {
            return image.clone();
        };
        match image {
            DynamicImage::ImageLuma8(_) => out.into_rgb8().into(),
            DynamicImage::ImageLumaA8(_) => out.into_rgba8().into(),
            _ => out,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PSD of `channels` planes, `compression` 0, 2 or 3, with `resources`.
    fn psd(
        (width, height): (u32, u32),
        (mode, depth): (u16, u16),
        planes: &[Vec<u8>],
        compression: u16,
        resources: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = b"8BPS\0\x01\0\0\0\0\0\0".to_vec();
        out.extend_from_slice(&(planes.len() as u16).to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&depth.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        let mut block = Vec::new();
        for (id, body) in resources {
            block.extend_from_slice(b"8BIM");
            block.extend_from_slice(&id.to_be_bytes());
            block.extend_from_slice(&[0, 0]);
            block.extend_from_slice(&(body.len() as u32).to_be_bytes());
            block.extend_from_slice(body);
            if body.len() % 2 == 1 {
                block.push(0);
            }
        }
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        out.extend_from_slice(&block);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&compression.to_be_bytes());
        let all = planes.concat();
        match compression {
            0 => out.extend_from_slice(&all),
            _ => out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec_zlib(&all, 6)),
        }
        out
    }

    /// A duotone of black and red: no ink is white, all of both is black,
    /// half of each is half of each.
    #[test]
    fn duotone_is_shown_in_its_inks() {
        let mut spec = vec![0, 1, 0, 2];
        // Black and red, as RGB of 16 bits.
        for colour in [[0u16, 0, 0], [65535, 0, 0]] {
            spec.extend_from_slice(&0u16.to_be_bytes());
            for c in colour {
                spec.extend_from_slice(&c.to_be_bytes());
            }
            spec.extend_from_slice(&[0, 0]);
        }
        spec.resize(4 + 40 + 256, 0);
        for _ in 0..4 {
            // A straight curve: 0 and 100 percent, the rest not set.
            for i in 0..13 {
                let value: i16 = match i {
                    0 => 0,
                    12 => 1000,
                    _ => -1,
                };
                spec.extend_from_slice(&value.to_be_bytes());
            }
            spec.extend_from_slice(&[0, 0]);
        }
        spec.resize(524, 0);
        let plain = psd((3, 1), (8, 8), &[vec![255, 0, 128]], 0, &[]);
        let mut data = plain[..26].to_vec();
        data.extend_from_slice(&(spec.len() as u32).to_be_bytes());
        data.extend_from_slice(&spec);
        data.extend_from_slice(&plain[30..]);
        let Composite::Colours(picture) =
            composite(&data, &Limits::default(), Deadline(None), false, false).unwrap()
        else {
            panic!("not colours");
        };
        let rgb = picture.image.to_rgb8();
        assert_eq!(rgb.get_pixel(0, 0).0, [255, 255, 255]);
        assert_eq!(rgb.get_pixel(1, 0).0, [0, 0, 0]);
        let [r, g, b] = rgb.get_pixel(2, 0).0;
        assert!(
            r.abs_diff(128) <= 2 && g.abs_diff(64) <= 2 && b.abs_diff(64) <= 2,
            "{r} {g} {b}"
        );
        // Where both cover the paper, the overprint colour shows: here
        // blue, nothing like black.
        let mut blue = spec.clone();
        let at = 4 + 40 + 256 + 4 * 28 + 2;
        blue[at..at + 10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 255, 255, 0, 0]);
        let mut data = plain[..26].to_vec();
        data.extend_from_slice(&(blue.len() as u32).to_be_bytes());
        data.extend_from_slice(&blue);
        data.extend_from_slice(&plain[30..]);
        let Composite::Colours(picture) =
            composite(&data, &Limits::default(), Deadline(None), false, false).unwrap()
        else {
            panic!("not colours");
        };
        let rgb = picture.image.to_rgb8();
        assert_eq!(rgb.get_pixel(0, 0).0, [255, 255, 255]);
        assert_eq!(rgb.get_pixel(1, 0).0, [0, 0, 255]);
        // A quarter each of paper, black, red and blue.
        let [r, g, b] = rgb.get_pixel(2, 0).0;
        assert!(
            r.abs_diff(128) <= 2 && g.abs_diff(64) <= 2 && b.abs_diff(128) <= 2,
            "{r} {g} {b}"
        );
        // Without the specification it is grey.
        let Composite::Colours(grey) =
            composite(&plain, &Limits::default(), Deadline(None), false, false).unwrap()
        else {
            panic!("not colours");
        };
        assert!(!grey.image.color().has_color());
    }

    #[test]
    fn inks_are_kept_as_inks_when_asked() {
        // Four inks of 3 by 2, stored as 255 for none; no layers, so no
        // alpha even with a fifth channel.
        let planes: Vec<Vec<u8>> = (0..4u8)
            .map(|c| (0..6u8).map(|i| 255 - c * 40 - i * 7).collect())
            .collect();
        let data = psd((3, 2), (4, 8), &planes, 0, &[]);
        let Composite::Inks(kept) =
            composite(&data, &Limits::default(), Deadline(None), true, false).unwrap()
        else {
            panic!("inks were not kept");
        };
        let InkSamples::Eight(samples) = &kept.samples else {
            panic!("not 8 bits");
        };
        let expected: Vec<u8> = (0..6u8)
            .flat_map(|i| (0..4u8).map(move |c| c * 40 + i * 7))
            .collect();
        assert_eq!(samples, &expected);
        assert_eq!((kept.width, kept.height, kept.alpha), (3, 2, None));
        assert!(kept.icc.is_none());

        let wide: Vec<Vec<u8>> = planes
            .iter()
            .map(|p| p.iter().flat_map(|&v| [v, 0x12]).collect())
            .collect();
        let data = psd((3, 2), (4, 16), &wide, 0, &[]);
        let Composite::Inks(kept) =
            composite(&data, &Limits::default(), Deadline(None), true, false).unwrap()
        else {
            panic!("inks were not kept");
        };
        let InkSamples::Sixteen(samples) = &kept.samples else {
            panic!("not 16 bits");
        };
        assert_eq!(samples[1], 65535 - u16::from_be_bytes([215, 0x12]));
        assert!(matches!(
            composite(&data, &Limits::default(), Deadline(None), false, false).unwrap(),
            Composite::Colours(_)
        ));
    }

    /// Rows of `planes` as ZIP with prediction stores them.
    fn predicted(plane: &[u8], width: usize, depth: u16) -> Vec<u8> {
        let row = width * depth as usize / 8;
        plane
            .chunks(row)
            .flat_map(|line| match depth {
                8 => (0..line.len())
                    .map(|x| line[x].wrapping_sub(if x > 0 { line[x - 1] } else { 0 }))
                    .collect::<Vec<u8>>(),
                16 => {
                    let values: Vec<u16> = line
                        .chunks(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                    (0..values.len())
                        .flat_map(|x| {
                            let before = if x > 0 { values[x - 1] } else { 0 };
                            values[x].wrapping_sub(before).to_be_bytes()
                        })
                        .collect()
                }
                _ => {
                    let shuffled: Vec<u8> = (0..4)
                        .flat_map(|byte| (0..width).map(move |x| line[x * 4 + byte]))
                        .collect();
                    (0..shuffled.len())
                        .map(|x| shuffled[x].wrapping_sub(if x > 0 { shuffled[x - 1] } else { 0 }))
                        .collect()
                }
            })
            .collect()
    }

    #[test]
    fn a_zip_compressed_composite_is_read() {
        let (width, height) = (7usize, 5usize);
        for depth in [8u16, 16, 32] {
            let value = |c: usize, i: usize| ((i * 37 + c * 50) % 256) as f32 / 255.0;
            let plane = |c: usize| -> Vec<u8> {
                (0..width * height)
                    .flat_map(|i| match depth {
                        8 => vec![(value(c, i) * 255.0).round() as u8],
                        16 => ((value(c, i) * 65535.0).round() as u16)
                            .to_be_bytes()
                            .to_vec(),
                        // Linear light, as 32-bit documents hold it.
                        _ => {
                            let v = value(c, i);
                            let linear = if v <= 0.04045 {
                                v / 12.92
                            } else {
                                ((v + 0.055) / 1.055).powf(2.4)
                            };
                            linear.to_be_bytes().to_vec()
                        }
                    })
                    .collect()
            };
            let planes: Vec<Vec<u8>> = (0..3).map(plane).collect();
            let raw = psd((width as u32, height as u32), (3, depth), &planes, 0, &[]);
            let expected = read(&raw, &Limits::default(), Deadline(None))
                .unwrap()
                .image;
            for compression in [2u16, 3] {
                let stored: Vec<Vec<u8>> = match compression {
                    3 => planes.iter().map(|p| predicted(p, width, depth)).collect(),
                    _ => planes.clone(),
                };
                let data = psd(
                    (width as u32, height as u32),
                    (3, depth),
                    &stored,
                    compression,
                    &[],
                );
                let found = read(&data, &Limits::default(), Deadline(None))
                    .unwrap()
                    .image;
                assert_eq!(found, expected, "{depth} bits, compression {compression}");
            }
        }
    }

    #[test]
    fn multichannel_inks_are_shown_in_their_colours() {
        // Two inks, red and 50% solid blue, at full, half and no coverage.
        let first = vec![0u8, 128, 255, 255];
        let second = vec![255u8, 255, 0, 255];
        let entry = |space: u16, c: [u16; 4], opacity: u16| {
            let mut e = space.to_be_bytes().to_vec();
            c.iter().for_each(|v| e.extend_from_slice(&v.to_be_bytes()));
            e.extend_from_slice(&opacity.to_be_bytes());
            e.push(2);
            e
        };
        let mut info = 1u32.to_be_bytes().to_vec();
        info.extend(entry(0, [65535, 0, 0, 0], 100));
        info.extend(entry(0, [0, 0, 65535, 0], 50));
        let data = psd((4, 1), (7, 8), &[first, second], 0, &[(0x0435, info)]);
        let image = read(&data, &Limits::default(), Deadline(None))
            .unwrap()
            .image;
        let pixels = image.to_rgb8();
        let found: Vec<[u8; 3]> = pixels.pixels().map(|p| p.0).collect();
        assert_eq!(
            found,
            [
                [255, 0, 0],
                [255, 128, 128],
                [128, 128, 255],
                [255, 255, 255]
            ]
        );

        // Without display information, four channels are process inks.
        let cyan = vec![0u8, 255];
        let none = vec![255u8, 255];
        let data = psd(
            (2, 1),
            (7, 8),
            &[cyan, none.clone(), none.clone(), none],
            0,
            &[],
        );
        let image = read(&data, &Limits::default(), Deadline(None))
            .unwrap()
            .image;
        let found: Vec<[u8; 3]> = image.to_rgb8().pixels().map(|p| p.0).collect();
        assert_eq!(found, [[0, 255, 255], [255, 255, 255]]);
    }
}
