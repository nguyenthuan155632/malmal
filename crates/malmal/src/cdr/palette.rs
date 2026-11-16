//! PNG files of few colours, written as indexed images.
//!
//! A decoder hands an indexed PNG or a GIF over as full colour. Written
//! back that way, a picture of a few dozen colours takes two or three
//! times the room it did. Every pixel keeps its exact value here; only
//! the way it is stored changes back.

use std::borrow::Cow;
use std::collections::HashMap;

use image::DynamicImage;

/// The image as an indexed PNG of the smallest depth that holds its
/// colours, or `None` if it has more than 256 of them or more than 8 bits a
/// sample.
pub(super) fn indexed(
    image: &DynamicImage,
    pixel_dims: Option<png::PixelDimensions>,
) -> Option<Vec<u8>> {
    let (width, height) = (image.width(), image.height());
    let pixels: Box<dyn Iterator<Item = [u8; 4]> + '_> = match image {
        DynamicImage::ImageRgb8(rgb) => Box::new(rgb.pixels().map(|p| [p[0], p[1], p[2], 255])),
        DynamicImage::ImageRgba8(rgba) => Box::new(rgba.pixels().map(|p| p.0)),
        DynamicImage::ImageLumaA8(grey) => {
            Box::new(grey.pixels().map(|p| [p[0], p[0], p[0], p[1]]))
        }
        _ => return None,
    };
    let mut colours: HashMap<[u8; 4], u8> = HashMap::new();
    let mut order: Vec<[u8; 4]> = Vec::new();
    let mut indices = Vec::with_capacity(width as usize * height as usize);
    for pixel in pixels {
        let index = match colours.get(&pixel) {
            Some(&index) => index,
            None => {
                if order.len() == 256 {
                    return None;
                }
                let index = order.len() as u8;
                colours.insert(pixel, index);
                order.push(pixel);
                index
            }
        };
        indices.push(index);
    }

    // Colours that are not opaque first, so that their alpha values are
    // all the tRNS chunk has to list.
    let mut sorted: Vec<usize> = (0..order.len()).collect();
    sorted.sort_by_key(|&i| (order[i][3] == 255, i));
    let mut renumber = [0u8; 256];
    for (new, &old) in sorted.iter().enumerate() {
        renumber[old] = new as u8;
    }
    let palette: Vec<u8> = sorted
        .iter()
        .flat_map(|&i| &order[i][..3])
        .copied()
        .collect();
    let alphas: Vec<u8> = sorted
        .iter()
        .map(|&i| order[i][3])
        .take_while(|&alpha| alpha < 255)
        .collect();

    let depth = match order.len() {
        0..=2 => 1u8,
        3..=4 => 2,
        5..=16 => 4,
        _ => 8,
    };
    let per_byte = 8 / depth as usize;
    let row_bytes = (width as usize).div_ceil(per_byte);
    let mut packed = vec![0u8; row_bytes * height as usize];
    for (y, row) in indices.chunks(width as usize).enumerate() {
        let out = &mut packed[y * row_bytes..(y + 1) * row_bytes];
        for (x, &index) in row.iter().enumerate() {
            let shift = 8 - depth as usize * (x % per_byte + 1);
            out[x / per_byte] |= renumber[index as usize] << shift;
        }
    }

    let mut data = Vec::new();
    let mut encoder = png::Encoder::new(&mut data, width, height);
    encoder.set_color(png::ColorType::Indexed);
    encoder.set_depth(match depth {
        1 => png::BitDepth::One,
        2 => png::BitDepth::Two,
        4 => png::BitDepth::Four,
        _ => png::BitDepth::Eight,
    });
    encoder.set_palette(palette);
    if !alphas.is_empty() {
        encoder.set_trns(alphas);
    }
    encoder.set_compression(png::Compression::Balanced);
    // Indices are not quantities; predicting them from their neighbours
    // seldom helps, and adaptive filtering is what does best when it does.
    encoder.set_filter(png::Filter::Adaptive);
    encoder.set_pixel_dims(pixel_dims);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(&packed).ok()?;
    writer.finish().ok()?;
    Some(data)
}

/// The image as a PNG of its own colour type and depth.
pub(super) fn truecolor(
    image: &DynamicImage,
    pixel_dims: Option<png::PixelDimensions>,
) -> Option<Vec<u8>> {
    use png::{BitDepth, ColorType};

    let wide = |samples: &[u16]| {
        samples
            .iter()
            .flat_map(|s| s.to_be_bytes())
            .collect::<Vec<u8>>()
    };
    let (color, depth, bytes): (ColorType, BitDepth, Cow<'_, [u8]>) = match image {
        DynamicImage::ImageLuma8(i) => (
            ColorType::Grayscale,
            BitDepth::Eight,
            Cow::Borrowed(i.as_raw()),
        ),
        DynamicImage::ImageLumaA8(i) => (
            ColorType::GrayscaleAlpha,
            BitDepth::Eight,
            Cow::Borrowed(i.as_raw()),
        ),
        DynamicImage::ImageRgb8(i) => (ColorType::Rgb, BitDepth::Eight, Cow::Borrowed(i.as_raw())),
        DynamicImage::ImageRgba8(i) => {
            (ColorType::Rgba, BitDepth::Eight, Cow::Borrowed(i.as_raw()))
        }
        DynamicImage::ImageLuma16(i) => (
            ColorType::Grayscale,
            BitDepth::Sixteen,
            wide(i.as_raw()).into(),
        ),
        DynamicImage::ImageLumaA16(i) => (
            ColorType::GrayscaleAlpha,
            BitDepth::Sixteen,
            wide(i.as_raw()).into(),
        ),
        DynamicImage::ImageRgb16(i) => (ColorType::Rgb, BitDepth::Sixteen, wide(i.as_raw()).into()),
        DynamicImage::ImageRgba16(i) => {
            (ColorType::Rgba, BitDepth::Sixteen, wide(i.as_raw()).into())
        }
        // Floating-point samples have no place in a PNG.
        DynamicImage::ImageRgb32F(_) => return truecolor(&image.to_rgb16().into(), pixel_dims),
        DynamicImage::ImageRgba32F(_) => return truecolor(&image.to_rgba16().into(), pixel_dims),
        _ => return None,
    };
    let mut data = Vec::new();
    let mut encoder = png::Encoder::new(&mut data, image.width(), image.height());
    encoder.set_color(color);
    encoder.set_depth(depth);
    encoder.set_compression(png::Compression::Balanced);
    encoder.set_filter(png::Filter::Adaptive);
    encoder.set_pixel_dims(pixel_dims);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(&bytes).ok()?;
    writer.finish().ok()?;
    Some(data)
}

/// The smaller of the image as an indexed PNG, where it can be one, and
/// as one of its own colour type.
pub(super) fn smallest(
    image: &DynamicImage,
    pixel_dims: Option<png::PixelDimensions>,
) -> Option<Vec<u8>> {
    let full = truecolor(image, pixel_dims)?;
    match indexed(image, pixel_dims) {
        Some(indexed) if indexed.len() < full.len() => Some(indexed),
        _ => Some(full),
    }
}

/// Pixels per metre, from pixels per inch or per centimetre.
pub(super) fn per_metre(unit: u8, x: u32, y: u32) -> Option<png::PixelDimensions> {
    let scale = match unit {
        1 => 1.0 / 0.0254,
        2 => 100.0,
        _ => return None,
    };
    let metre = |v: u32| (v as f64 * scale).round() as u32;
    (x > 0 && y > 0).then(|| png::PixelDimensions {
        xppu: metre(x),
        yppu: metre(y),
        unit: png::Unit::Meter,
    })
}

/// The pixel density a PNG or BMP file gives, as a PNG states it.
pub(super) fn density_of(
    data: &[u8],
    file_type: crate::detect::FileType,
) -> Option<png::PixelDimensions> {
    use crate::detect::FileType;

    let be32 = |at: usize| Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?));
    let le32 = |at: usize| Some(i32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?));
    match file_type {
        FileType::Png => {
            let mut at = 8;
            while let Some(length) = be32(at) {
                let kind = data.get(at + 4..at + 8)?;
                if kind == b"IDAT" {
                    return None;
                }
                if kind == b"pHYs" && length == 9 {
                    let unit = match *data.get(at + 16)? {
                        1 => png::Unit::Meter,
                        _ => png::Unit::Unspecified,
                    };
                    let (xppu, yppu) = (be32(at + 8)?, be32(at + 12)?);
                    return (xppu > 0 && yppu > 0).then_some(png::PixelDimensions {
                        xppu,
                        yppu,
                        unit,
                    });
                }
                at = at.checked_add(12 + length as usize)?;
            }
            None
        }
        FileType::Bmp => {
            let header = u32::from_le_bytes(data.get(14..18)?.try_into().ok()?);
            if header < 40 {
                return None;
            }
            let (x, y) = (le32(38)?, le32(42)?);
            (x > 0 && y > 0).then_some(png::PixelDimensions {
                xppu: x as u32,
                yppu: y as u32,
                unit: png::Unit::Meter,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use image::{Rgba, RgbaImage};

    use super::*;

    #[test]
    fn few_colours_come_back_indexed_and_exact() {
        for colours in [2u32, 3, 9, 200] {
            let picture = RgbaImage::from_fn(13, 7, |x, y| {
                let i = (x * 7 + y * 3) % colours;
                Rgba([
                    i as u8,
                    255 - i as u8,
                    9,
                    if i % 3 == 0 { 255 } else { i as u8 },
                ])
            });
            let image = DynamicImage::from(picture.clone());
            let data = indexed(&image, None).unwrap();
            let decoded = image::load_from_memory(&data).unwrap().to_rgba8();
            assert_eq!(decoded, picture, "{colours} colours");
            // Colour type 3 in the header.
            assert_eq!(data[25], 3);
        }
        let many = RgbaImage::from_fn(20, 20, |x, y| Rgba([x as u8, y as u8, 0, 255]));
        assert!(indexed(&many.into(), None).is_none());
    }
}
