//! Colours that are not RGB, turned into sRGB: inks under the profile that
//! says what they look like, and CIE L*a*b*.

use moxcms::{ColorProfile, DataColorSpace, Layout, TransformOptions};

/// Pixels converted at a time.
const BATCH: usize = 1 << 16;

/// The CMYK profile `icc` is, if it is one.
fn cmyk_profile(icc: Option<&[u8]>) -> Option<ColorProfile> {
    let profile = ColorProfile::new_from_slice(icc?).ok()?;
    (profile.color_space == DataColorSpace::Cmyk).then_some(profile)
}

/// Four inks a pixel, 0 for none, as 8-bit sRGB: through the profile when
/// there is one that applies, by arithmetic otherwise.
pub(super) fn inks(inks: &[u8], icc: Option<&[u8]>) -> Vec<u8> {
    let mut colours = vec![0u8; inks.len() / 4 * 3];
    if let Some(profile) = cmyk_profile(icc) {
        let transform = profile.create_transform_8bit(
            Layout::Rgba,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        );
        if let Ok(transform) = transform {
            let batches = inks.chunks(BATCH * 4).zip(colours.chunks_mut(BATCH * 3));
            if batches
                .into_iter()
                .all(|(inks, colours)| transform.transform(inks, colours).is_ok())
            {
                return colours;
            }
        }
    }
    for (ink, colour) in inks
        .as_chunks::<4>()
        .0
        .iter()
        .zip(colours.as_chunks_mut::<3>().0.iter_mut())
    {
        let white = 255 - ink[3] as u32;
        for (c, &i) in colour.iter_mut().zip(&ink[..3]) {
            *c = ((255 - i as u32) * white / 255) as u8;
        }
    }
    colours
}

/// [`inks`] for 16-bit samples.
pub(super) fn inks16(inks: &[u16], icc: Option<&[u8]>) -> Vec<u16> {
    let mut colours = vec![0u16; inks.len() / 4 * 3];
    if let Some(profile) = cmyk_profile(icc) {
        let transform = profile.create_transform_16bit(
            Layout::Rgba,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        );
        if let Ok(transform) = transform {
            let batches = inks.chunks(BATCH * 4).zip(colours.chunks_mut(BATCH * 3));
            if batches
                .into_iter()
                .all(|(inks, colours)| transform.transform(inks, colours).is_ok())
            {
                return colours;
            }
        }
    }
    for (ink, colour) in inks
        .as_chunks::<4>()
        .0
        .iter()
        .zip(colours.as_chunks_mut::<3>().0.iter_mut())
    {
        let white = 65535 - ink[3] as u64;
        for (c, &i) in colour.iter_mut().zip(&ink[..3]) {
            *c = ((65535 - i as u64) * white / 65535) as u16;
        }
    }
    colours
}

/// Colours of CIE L*a*b* relative to a white, turned into sRGB.
pub(super) struct Lab {
    white: [f32; 3],
    /// From XYZ relative to that white to linear sRGB.
    matrix: [[f32; 3]; 3],
}

fn product(a: &[[f32; 3]; 3], b: &[[f32; 3]; 3]) -> [[f32; 3]; 3] {
    let mut out = [[0f32; 3]; 3];
    for (i, row) in out.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            *entry = (0..3).map(|k| a[i][k] * b[k][j]).sum();
        }
    }
    out
}

fn apply(m: &[[f32; 3]; 3], v: [f32; 3]) -> [f32; 3] {
    [0, 1, 2].map(|i| m[i][0] * v[0] + m[i][1] * v[1] + m[i][2] * v[2])
}

impl Lab {
    /// D50, the white of ICC profiles and of most files that do not say.
    pub(super) const D50: (f32, f32) = (0.3457, 0.3585);

    /// Relative to the white of chromaticity `(x, y)`.
    pub(super) fn new((x, y): (f32, f32)) -> Self {
        let white = [x / y, 1.0, (1.0 - x - y) / y];
        const BRADFORD: [[f32; 3]; 3] = [
            [0.8951, 0.2664, -0.1614],
            [-0.7502, 1.7135, 0.0367],
            [0.0389, -0.0685, 1.0296],
        ];
        const BRADFORD_INVERSE: [[f32; 3]; 3] = [
            [0.986_993, -0.147_054, 0.159_963],
            [0.432_305, 0.518_360, 0.049_291],
            [-0.008_529, 0.040_043, 0.968_487],
        ];
        const D65: [f32; 3] = [0.950_47, 1.0, 1.088_83];
        const SRGB: [[f32; 3]; 3] = [
            [3.240_454, -1.537_139, -0.498_531],
            [-0.969_266, 1.876_011, 0.041_556],
            [0.055_643, -0.204_026, 1.057_225],
        ];
        let (source, target) = (apply(&BRADFORD, white), apply(&BRADFORD, D65));
        let scale = [0, 1, 2].map(|i| {
            let mut row = [0f32; 3];
            row[i] = target[i] / source[i];
            row
        });
        let adapt = product(&BRADFORD_INVERSE, &product(&scale, &BRADFORD));
        Self {
            white,
            matrix: product(&SRGB, &adapt),
        }
    }

    /// L* from 0 to 100, as sRGB from 0 to 1.
    pub(super) fn srgb(&self, l: f32, a: f32, b: f32) -> [f32; 3] {
        let fy = (l + 16.0) / 116.0;
        let (fx, fz) = (fy + a / 500.0, fy - b / 200.0);
        let inverse = |t: f32| {
            const DELTA: f32 = 6.0 / 29.0;
            if t > DELTA {
                t * t * t
            } else {
                3.0 * DELTA * DELTA * (t - 4.0 / 29.0)
            }
        };
        let xyz = [
            self.white[0] * inverse(fx),
            self.white[1] * inverse(fy),
            self.white[2] * inverse(fz),
        ];
        apply(&self.matrix, xyz).map(|c| {
            let c = c.clamp(0.0, 1.0);
            if c <= 0.003_130_8 {
                12.92 * c
            } else {
                1.055 * c.powf(1.0 / 2.4) - 0.055
            }
        })
    }
}

/// Tags of a profile that say what colours its inks make, kept as they
/// are; every other tag is left out.
const COLOUR_TAGS: [&[u8; 4]; 10] = [
    b"A2B0", b"A2B1", b"A2B2", b"B2A0", b"B2A1", b"B2A2", b"wtpt", b"bkpt", b"chad", b"gamt",
];

/// Tags of a profile of a screen's colours that say what they are.
const RGB_TAGS: [&[u8; 4]; 16] = [
    b"rXYZ", b"gXYZ", b"bXYZ", b"rTRC", b"gTRC", b"bTRC", b"A2B0", b"A2B1", b"A2B2", b"B2A0",
    b"B2A1", b"B2A2", b"wtpt", b"bkpt", b"chad", b"cicp",
];

/// A grid of every mix of 17 amounts of each of `channels` samples, 16
/// bits each.
fn grid(channels: u32) -> Vec<u16> {
    (0..17u32.pow(channels))
        .flat_map(|i| {
            (0..channels)
                .rev()
                .map(move |c| (i / 17u32.pow(c) % 17 * 65535 / 16) as u16)
        })
        .collect()
}

/// The colours `profile` gives each pixel of `grid`, in sRGB.
fn through(profile: &ColorProfile, grid: &[u16], layout: Layout) -> Option<Vec<u16>> {
    let transform = profile
        .create_transform_16bit(
            layout,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        )
        .ok()?;
    let mut colours = vec![0u16; grid.len() / layout.channels() * 3];
    transform.transform(grid, &mut colours).ok()?;
    Some(colours)
}

/// A CMYK profile written anew: its header, the tags that describe its
/// colours byte for byte, and a description and copyright of its own.
/// Nothing else of the file is kept: no text, no private tags, nothing
/// between or after the tags. `None` unless the new profile makes the
/// same colours as the old of every mix of a grid of ink amounts.
pub(super) fn rewritten_cmyk(icc: &[u8]) -> Option<Vec<u8>> {
    let original = cmyk_profile(Some(icc))?;
    let out = rewritten(icc, &COLOUR_TAGS, "CMYK")?;
    let again = cmyk_profile(Some(&out))?;
    let grid = grid(4);
    (through(&original, &grid, Layout::Rgba)? == through(&again, &grid, Layout::Rgba)?)
        .then_some(out)
}

/// An RGB profile written anew as [`rewritten_cmyk`] writes one of inks,
/// from the tags that say what its colours are. `None` unless the new
/// profile makes the same colours as the old of every mix of a grid of
/// amounts of red, green and blue.
pub(super) fn rewritten_rgb(icc: &[u8]) -> Option<Vec<u8>> {
    let rgb = |icc: &[u8]| {
        ColorProfile::new_from_slice(icc)
            .ok()
            .filter(|p| p.color_space == DataColorSpace::Rgb)
    };
    let original = rgb(icc)?;
    let out = rewritten(icc, &RGB_TAGS, "RGB")?;
    let again = rgb(&out)?;
    let grid = grid(3);
    (through(&original, &grid, Layout::Rgb)? == through(&again, &grid, Layout::Rgb)?).then_some(out)
}

/// Tags of a profile of shades of grey that say what they are.
const GREY_TAGS: [&[u8; 4]; 5] = [b"kTRC", b"wtpt", b"bkpt", b"chad", b"cicp"];

/// A grey profile written anew as [`rewritten_rgb`] writes one of colours.
/// `None` unless the new profile makes the same colour as the old of every
/// one of 257 shades.
pub(super) fn rewritten_grey(icc: &[u8]) -> Option<Vec<u8>> {
    let grey = |icc: &[u8]| {
        ColorProfile::new_from_slice(icc)
            .ok()
            .filter(|p| p.color_space == DataColorSpace::Gray)
    };
    let original = grey(icc)?;
    let out = rewritten(icc, &GREY_TAGS, "Grey")?;
    let again = grey(&out)?;
    let shades: Vec<u16> = (0..=256u32).map(|i| (i * 65535 / 256) as u16).collect();
    (through(&original, &shades, Layout::Gray)? == through(&again, &shades, Layout::Gray)?)
        .then_some(out)
}

/// A profile of colours or of grey written anew, for pixels of `channels`
/// samples (1 or 3, alpha aside) that it is the right kind for.
pub(super) fn rewritten_screen(icc: &[u8], channels: usize) -> Option<Vec<u8>> {
    match channels {
        1 => rewritten_grey(icc),
        3 => rewritten_rgb(icc),
        _ => None,
    }
}

/// Whether `icc` says it is a profile of grey.
pub(super) fn is_grey(icc: &[u8]) -> bool {
    icc.get(16..20) == Some(b"GRAY")
}

/// The header of profile `icc`, the tags of it named in `tags` byte for
/// byte, and a description `name` and a copyright of its own.
fn rewritten(icc: &[u8], tags_kept: &[&[u8; 4]], name: &str) -> Option<Vec<u8>> {
    let be32 = |at: usize| Some(u32::from_be_bytes(icc.get(at..at + 4)?.try_into().ok()?));
    let count = be32(128)? as usize;
    if count > 256 {
        return None;
    }
    // The data of each tag kept, once however many tags share it.
    let mut kept: Vec<([u8; 4], usize, usize)> = Vec::new();
    for index in 0..count {
        let at = 132 + index * 12;
        let signature: [u8; 4] = icc.get(at..at + 4)?.try_into().ok()?;
        if !tags_kept.contains(&&signature) {
            continue;
        }
        let (offset, size) = (be32(at + 4)? as usize, be32(at + 8)? as usize);
        icc.get(offset..offset.checked_add(size)?)?;
        kept.push((signature, offset, size));
    }
    let text = |kind: &[u8; 4], words: &str| -> Vec<u8> {
        let mut tag = kind.to_vec();
        tag.extend_from_slice(&[0; 4]);
        match kind {
            // Version 2: ASCII, then empty Unicode and ScriptCode parts.
            b"desc" => {
                tag.extend_from_slice(&(words.len() as u32 + 1).to_be_bytes());
                tag.extend_from_slice(words.as_bytes());
                tag.push(0);
                tag.extend_from_slice(&[0; 4 + 4 + 2 + 1 + 67]);
            }
            _ => {
                tag.extend_from_slice(words.as_bytes());
                tag.push(0);
            }
        }
        tag
    };
    let version = icc.get(8).copied()?;
    let (description, copyright) = if version >= 4 {
        // Version 4 has one kind of text, in records of UTF-16.
        let unicode = |words: &str| {
            let mut tag = b"mluc\0\0\0\0".to_vec();
            tag.extend_from_slice(&1u32.to_be_bytes());
            tag.extend_from_slice(&12u32.to_be_bytes());
            tag.extend_from_slice(b"enUS");
            let utf16: Vec<u8> = words.encode_utf16().flat_map(u16::to_be_bytes).collect();
            tag.extend_from_slice(&(utf16.len() as u32).to_be_bytes());
            tag.extend_from_slice(&28u32.to_be_bytes());
            tag.extend_from_slice(&utf16);
            tag
        };
        (unicode(name), unicode("No copyright"))
    } else {
        (text(b"desc", name), text(b"text", "No copyright"))
    };

    let mut blocks: Vec<(Vec<[u8; 4]>, Vec<u8>)> = Vec::new();
    for (signature, offset, size) in &kept {
        let data = &icc[*offset..offset + size];
        match blocks.iter_mut().find(|(_, d)| d == data) {
            Some((signatures, _)) => signatures.push(*signature),
            None => blocks.push((vec![*signature], data.to_vec())),
        }
    }
    blocks.push((vec![*b"desc"], description));
    blocks.push((vec![*b"cprt"], copyright));
    let tags: usize = blocks.iter().map(|(s, _)| s.len()).sum();
    let mut out = icc.get(..128)?.to_vec();
    // Who made the profile, for what device, and its checksum, which
    // would no longer hold, are not kept.
    for range in [4..8, 40..44, 48..56, 56..64, 80..84, 84..100, 100..128] {
        out[range].fill(0);
    }
    out.extend_from_slice(&(tags as u32).to_be_bytes());
    let mut offset = 128 + 4 + tags * 12;
    let mut table = Vec::new();
    let mut body = Vec::new();
    for (signatures, data) in &blocks {
        for signature in signatures {
            table.extend_from_slice(signature);
            table.extend_from_slice(&(offset as u32).to_be_bytes());
            table.extend_from_slice(&(data.len() as u32).to_be_bytes());
        }
        body.extend_from_slice(data);
        // Each tag starts on four bytes.
        while body.len() % 4 != 0 {
            body.push(0);
        }
        offset = 128 + 4 + tags * 12 + body.len();
    }
    out.extend_from_slice(&table);
    out.extend_from_slice(&body);
    let size = out.len() as u32;
    out[..4].copy_from_slice(&size.to_be_bytes());

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_white_black_and_red() {
        let close = |a: [f32; 3], b: [f32; 3]| a.iter().zip(b).all(|(x, y)| (x - y).abs() < 0.01);
        let d50 = Lab::new(Lab::D50);
        assert!(close(d50.srgb(100.0, 0.0, 0.0), [1.0, 1.0, 1.0]));
        assert!(close(d50.srgb(0.0, 0.0, 0.0), [0.0, 0.0, 0.0]));
        // sRGB red is L* 54.29, a* 80.80, b* 69.89 under D50, and
        // 53.24, 80.09, 67.20 under D65.
        assert!(close(d50.srgb(54.29, 80.80, 69.89), [1.0, 0.0, 0.0]));
        let d65 = Lab::new((0.3127, 0.3290));
        assert!(close(d65.srgb(53.24, 80.09, 67.20), [1.0, 0.0, 0.0]));
    }

    #[test]
    fn inks_without_a_profile_are_mixed_by_arithmetic() {
        assert_eq!(
            inks(&[0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255], None),
            [255, 255, 255, 0, 255, 255, 0, 0, 0]
        );
    }
}
