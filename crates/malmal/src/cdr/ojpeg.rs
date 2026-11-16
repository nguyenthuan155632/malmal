//! JPEG in a TIFF of the first kind (compression 6), which later TIFF
//! readers dropped: the page is made into the JPEG it stands for, which is
//! then rebuilt as any JPEG is.
//!
//! Such a page holds a whole JPEG where `JPEGInterchangeFormat` points, or
//! its tables there and its scan in the strips, or the tables in tags of
//! their own and the scan in the strips. Only a TIFF of one page, in
//! strips of one scan of 8-bit grey, YCbCr or RGB coded as baseline, is
//! made into a JPEG.

use std::io::Cursor;

use tiff::decoder::Decoder;
use tiff::tags::Tag;

use crate::limits::Limits;

fn segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) -> Option<()> {
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&u16::try_from(body.len() + 2).ok()?.to_be_bytes());
    out.extend_from_slice(body);
    Some(())
}

/// Whether a stream has a frame and a scan in it, so it is a whole JPEG.
fn whole(stream: &[u8]) -> bool {
    stream.starts_with(&[0xFF, 0xD8]) && stream.windows(2).any(|w| w == [0xFF, 0xDA])
}

/// The JPEG the first page of the TIFF in `data` stands for, if it is
/// compressed as JPEG of the first kind.
pub(super) fn jpeg(data: &[u8], limits: &Limits) -> Option<Vec<u8>> {
    let mut decoder = Decoder::new(Cursor::new(data)).ok()?;
    let tag = |decoder: &mut Decoder<_>, tag| decoder.find_tag_unsigned::<u32>(tag).ok().flatten();
    if tag(&mut decoder, Tag::Compression)? != 6 {
        return None;
    }
    let (width, height) = decoder.dimensions().ok()?;
    if u64::from(width) * u64::from(height) > limits.max_pixels {
        return None;
    }
    let photometric = tag(&mut decoder, Tag::PhotometricInterpretation).unwrap_or(6);
    let spp = tag(&mut decoder, Tag::SamplesPerPixel).unwrap_or(1);
    if !matches!((photometric, spp), (1, 1) | (2 | 6, 3)) {
        return None;
    }
    let bytes = |at: u64, length: u64| {
        let at = usize::try_from(at).ok()?;
        data.get(at..at.checked_add(usize::try_from(length).ok()?)?)
    };
    // Pages but the first would be lost.
    if decoder.more_images() {
        return None;
    }
    let offsets = decoder.get_tag_u64_vec(Tag::StripOffsets).ok()?;
    let counts = decoder.get_tag_u64_vec(Tag::StripByteCounts).ok()?;
    if offsets.len() != counts.len() || offsets.len() > 1 << 16 {
        return None;
    }
    let mut scan = Vec::new();
    for (&at, &length) in offsets.iter().zip(&counts) {
        scan.extend_from_slice(bytes(at, length)?);
        if scan.len() as u64 > limits.max_decompressed {
            return None;
        }
    }

    // A whole JPEG where the tag points, or tables there and the scan in
    // the strips, or a whole JPEG in the strips.
    let format = tag(&mut decoder, Tag::Unknown(513));
    let format_length = tag(&mut decoder, Tag::Unknown(514));
    if let Some(at) = format {
        let rest = data.get(usize::try_from(at).ok()?..)?;
        let interchange = match format_length {
            Some(length) => rest.get(..usize::try_from(length).ok()?)?,
            None => rest,
        };
        if whole(interchange) {
            let end = interchange
                .windows(2)
                .rposition(|w| w == [0xFF, 0xD9])
                .map_or(interchange.len(), |at| at + 2);
            return Some(interchange[..end].to_vec());
        }
        if interchange.starts_with(&[0xFF, 0xD8]) {
            let tables = interchange
                .strip_suffix(&[0xFF, 0xD9])
                .unwrap_or(interchange);
            let scan = scan.strip_prefix(&[0xFF, 0xD8]).unwrap_or(&scan);
            let mut out = [tables, scan].concat();
            if !out.ends_with(&[0xFF, 0xD9]) {
                out.extend_from_slice(&[0xFF, 0xD9]);
            }
            return whole(&out).then_some(out);
        }
    }
    if whole(&scan) {
        return Some(scan);
    }

    // The tables in tags of their own: one of each kind for each component.
    if tag(&mut decoder, Tag::Unknown(512)).unwrap_or(1) != 1 {
        return None;
    }
    let mut offsets_of = |number| {
        decoder
            .get_tag_u64_vec(Tag::Unknown(number))
            .ok()
            .filter(|o| o.len() == spp as usize)
    };
    let (quant, dc, ac) = (offsets_of(519)?, offsets_of(520)?, offsets_of(521)?);
    let restart = tag(&mut decoder, Tag::Unknown(515)).unwrap_or(0);
    let sampling = match photometric {
        6 => {
            let factors = decoder
                .find_tag_unsigned_vec::<u16>(Tag::Unknown(530))
                .ok()
                .flatten()
                .unwrap_or_else(|| vec![2, 2]);
            let [h, v] = factors[..] else {
                return None;
            };
            if !matches!(h, 1 | 2 | 4) || !matches!(v, 1 | 2 | 4) {
                return None;
            }
            (h as u8, v as u8)
        }
        _ => (1, 1),
    };
    let huffman = |at: u64| -> Option<Vec<u8>> {
        let counts = bytes(at, 16)?;
        let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
        if total > 256 {
            return None;
        }
        bytes(at, 16 + total).map(<[u8]>::to_vec)
    };

    let mut out = vec![0xFF, 0xD8];
    if photometric == 2 {
        // Red, green and blue, not to be converted from YCbCr.
        segment(&mut out, 0xEE, b"Adobe\0\x64\0\0\0\0\0")?;
    }
    for (index, &at) in quant.iter().enumerate() {
        let mut body = vec![index as u8];
        body.extend_from_slice(bytes(at, 64)?);
        segment(&mut out, 0xDB, &body)?;
    }
    // Four tables of each class at most, as an extended frame allows; a
    // baseline one allows two.
    let extended = spp > 2;
    for (class, tables) in [(0u8, &dc), (1, &ac)] {
        for (index, &at) in tables.iter().enumerate() {
            let mut body = vec![class << 4 | index as u8];
            body.extend_from_slice(&huffman(at)?);
            segment(&mut out, 0xC4, &body)?;
        }
    }
    let mut frame = vec![8];
    frame.extend_from_slice(&u16::try_from(height).ok()?.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(width).ok()?.to_be_bytes());
    frame.push(spp as u8);
    for index in 0..spp as u8 {
        let (h, v) = if index == 0 { sampling } else { (1, 1) };
        frame.extend_from_slice(&[index + 1, h << 4 | v, index]);
    }
    segment(&mut out, if extended { 0xC1 } else { 0xC0 }, &frame)?;
    if restart > 0 {
        segment(&mut out, 0xDD, &u16::try_from(restart).ok()?.to_be_bytes())?;
    }
    let mut header = vec![spp as u8];
    for index in 0..spp as u8 {
        header.extend_from_slice(&[index + 1, index << 4 | index]);
    }
    header.extend_from_slice(&[0, 63, 0]);
    segment(&mut out, 0xDA, &header)?;
    out.extend_from_slice(&scan);
    if !out.ends_with(&[0xFF, 0xD9]) {
        out.extend_from_slice(&[0xFF, 0xD9]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::{Options, rebuild};
    use super::*;
    use crate::detect::FileType;

    /// A JPEG's segments before its scan, and the scan after its header.
    fn segments(jpeg: &[u8]) -> (Vec<(u8, Vec<u8>)>, Vec<u8>) {
        let mut at = 2;
        let mut found = Vec::new();
        loop {
            let marker = jpeg[at + 1];
            let length = u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]) as usize;
            let body = jpeg[at + 4..at + 2 + length].to_vec();
            at += 2 + length;
            if marker == 0xDA {
                return (found, jpeg[at..].to_vec());
            }
            found.push((marker, body));
        }
    }

    /// A little-endian TIFF of one page: `entries` of tag, type and
    /// values (shorts or longs), and `blobs` of tag and bytes, whose
    /// offsets are the values of the tag; a tag of several blobs has an
    /// offset for each.
    fn tiff(entries: &[(u16, u16, Vec<u32>)], blobs: &[(u16, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut out = b"II*\0\0\0\0\0".to_vec();
        let mut all: Vec<(u16, u16, Vec<u32>)> = entries.to_vec();
        for (tag, pieces) in blobs {
            let mut offsets = Vec::new();
            for piece in pieces {
                offsets.push(out.len() as u32);
                out.extend_from_slice(piece);
            }
            all.push((*tag, 4, offsets));
        }
        all.sort_by_key(|e| e.0);
        let mut values = Vec::new();
        for (_, kind, list) in &all {
            let bytes: Vec<u8> = list
                .iter()
                .flat_map(|&v| match kind {
                    3 => (v as u16).to_le_bytes().to_vec(),
                    _ => v.to_le_bytes().to_vec(),
                })
                .collect();
            if bytes.len() > 4 {
                values.push(out.len() as u32);
                out.extend_from_slice(&bytes);
            } else {
                let mut value = [0u8; 4];
                value[..bytes.len()].copy_from_slice(&bytes);
                values.push(u32::from_le_bytes(value));
            }
        }
        let directory = out.len() as u32;
        out[4..8].copy_from_slice(&directory.to_le_bytes());
        out.extend_from_slice(&(all.len() as u16).to_le_bytes());
        for ((tag, kind, list), value) in all.iter().zip(values) {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(list.len() as u32).to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&[0; 4]);
        out
    }

    /// The same JPEG in each of the three ways such a page can hold it.
    #[test]
    fn each_way_of_holding_the_jpeg_gives_it() {
        let picture = image::RgbImage::from_fn(40, 24, |x, y| {
            image::Rgb([(x * 6) as u8, (y * 10) as u8, ((x + y) * 3) as u8])
        });
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 80)
            .encode_image(&picture)
            .unwrap();
        let shown = image::load_from_memory(&jpeg).unwrap().to_rgb8();
        let (segments, scan) = segments(&jpeg);
        let frame = &segments.iter().find(|(m, _)| *m == 0xC0).unwrap().1;
        let (h, v) = (frame[7] >> 4, frame[7] & 15);
        let base = |extra: Vec<(u16, u16, Vec<u32>)>| {
            let mut entries = vec![
                (256, 4, vec![40]),
                (257, 4, vec![24]),
                (258, 3, vec![8, 8, 8]),
                (259, 3, vec![6]),
                (262, 3, vec![6]),
                (277, 3, vec![3]),
                (278, 4, vec![24]),
                (530, 3, vec![u32::from(h), u32::from(v)]),
            ];
            entries.extend(extra);
            entries
        };
        // Where the header of the scan begins: 14 bytes, for three
        // components.
        let tables_end = jpeg.len() - scan.len() - 14;

        // The tables, by component, in the order the frame uses them.
        let mut quant: Vec<Vec<u8>> = Vec::new();
        let mut huffman: [Vec<(u8, Vec<u8>)>; 2] = [Vec::new(), Vec::new()];
        for (marker, body) in &segments {
            let mut rest = &body[..];
            match marker {
                0xDB => {
                    while !rest.is_empty() {
                        quant.push(rest[1..65].to_vec());
                        rest = &rest[65..];
                    }
                }
                0xC4 => {
                    while !rest.is_empty() {
                        let total: usize = rest[1..17].iter().map(|&c| c as usize).sum();
                        huffman[(rest[0] >> 4) as usize]
                            .push((rest[0] & 15, rest[1..17 + total].to_vec()));
                        rest = &rest[17 + total..];
                    }
                }
                _ => {}
            }
        }
        let table =
            |class: usize, id: u8| huffman[class].iter().find(|t| t.0 == id).unwrap().1.clone();
        let components: Vec<(u8, u8)> = (0..3).map(|i| (frame[6 + i * 3 + 2], i as u8)).collect();
        // The image crate gives the chroma components the second tables.
        let tables_of = |i: u8| if i == 0 { 0 } else { 1 };

        let ways = [
            // A whole JPEG where the tag points, the strip the same.
            tiff(
                &base(vec![
                    (279, 4, vec![jpeg.len() as u32]),
                    (514, 4, vec![jpeg.len() as u32]),
                ]),
                &[(273, vec![jpeg.clone()])],
            ),
            // Its tables where the tag points, its scan in the strip.
            tiff(
                &base(vec![(279, 4, vec![(jpeg.len() - tables_end) as u32])]),
                &[
                    (513, vec![jpeg[..tables_end].to_vec()]),
                    (273, vec![jpeg[tables_end..].to_vec()]),
                ],
            ),
            // The tables in tags of their own.
            tiff(
                &base(vec![(279, 4, vec![scan.len() as u32]), (512, 3, vec![1])]),
                &[
                    (
                        519,
                        components
                            .iter()
                            .map(|&(q, _)| quant[q as usize].clone())
                            .collect(),
                    ),
                    (
                        520,
                        components
                            .iter()
                            .map(|&(_, i)| table(0, tables_of(i)))
                            .collect(),
                    ),
                    (
                        521,
                        components
                            .iter()
                            .map(|&(_, i)| table(1, tables_of(i)))
                            .collect(),
                    ),
                    (273, vec![scan.clone()]),
                ],
            ),
        ];
        for (index, data) in ways.iter().enumerate() {
            let made = jpeg_of(data).unwrap_or_else(|| panic!("way {index}"));
            let decoded = image::load_from_memory(&made).unwrap().to_rgb8();
            assert_eq!(decoded, shown, "way {index}");
            let rebuilt = rebuild(data, &Limits::default(), &Options::default()).unwrap();
            assert_eq!(rebuilt.file_type, FileType::Jpeg, "way {index}");
            assert_eq!(
                image::load_from_memory(&rebuilt.data).unwrap().to_rgb8(),
                shown,
                "way {index}"
            );
        }
    }

    fn jpeg_of(data: &[u8]) -> Option<Vec<u8>> {
        jpeg(data, &Limits::default())
    }
}
