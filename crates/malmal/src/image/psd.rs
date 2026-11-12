use super::{Layout, Malformed, be16, be32};

const HEADER_LEN: usize = 26;
/// Signatures Photoshop has used for image resource blocks.
const RESOURCE_SIGNATURES: [&[u8; 4]; 5] = [b"8BIM", b"MeSa", b"AgHg", b"PHUT", b"DCSR"];

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let truncated = Malformed::truncated(data.len());
    let (Some(version), Some(channels), Some(height), Some(width), Some(depth)) = (
        be16(data, 4),
        be16(data, 12),
        be32(data, 14),
        be32(data, 18),
        be16(data, 22),
    ) else {
        return Err(truncated);
    };
    // Version 2 is PSB, which widens some length fields.
    let large = match version {
        1 => false,
        2 => true,
        _ => return Err(Malformed::new(4, "unknown PSD version")),
    };
    if !(1..=56).contains(&channels) {
        return Err(Malformed::new(12, "PSD channel count out of range"));
    }
    if !matches!(depth, 1 | 8 | 16 | 32) {
        return Err(Malformed::new(22, "PSD bit depth is not 1, 8, 16 or 32"));
    }

    // Colour mode data, then image resources, then layers and masks.
    let mut pos = section_end(data, HEADER_LEN, false)?;
    let resources_end = section_end(data, pos, false)?;
    check_resources(data, pos + 4, resources_end)?;
    pos = section_end(data, resources_end, large)?;
    let layers_start = resources_end + if large { 8 } else { 4 };
    let largest_layer = check_layers(data, layers_start, pos, large)?;

    let compression = be16(data, pos).ok_or(Malformed::truncated(data.len()))?;
    pos += 2;
    let (channels, height, width) = (channels as u64, height as u64, width as u64);
    let rows = channels * height;
    let length = match compression {
        // Saturates for sizes no file can hold; the bounds check below rejects those.
        0 => Some(rows.saturating_mul((width * depth as u64).div_ceil(8))),
        // A byte count per row and channel, then the rows.
        1 => {
            let count_len = if large { 4 } else { 2 };
            let table_len = rows * count_len as u64;
            let table = usize::try_from(table_len)
                .ok()
                .and_then(|length| data.get(pos..pos.checked_add(length)?))
                .ok_or(Malformed::truncated(data.len()))?;
            let total: u64 = if large {
                table
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_be_bytes(*c) as u64)
                    .sum()
            } else {
                table
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c) as u64)
                    .sum()
            };
            Some(table_len + total)
        }
        // Deflate streams carry no length; the image runs to the end.
        2 | 3 => None,
        _ => return Err(Malformed::new(pos - 2, "unknown PSD compression method")),
    };
    let end = match length {
        Some(length) => {
            let end = (pos as u64)
                .checked_add(length)
                .filter(|&end| end <= data.len() as u64);
            Some(end.ok_or(Malformed::truncated(data.len()))? as usize)
        }
        None => None,
    };
    // A layer may be larger than the canvas, and is decoded all the same.
    let canvas = (width, height);
    let area = |(width, height): (u64, u64)| width.saturating_mul(height);
    Ok(Layout {
        end,
        dimensions: Some(match largest_layer {
            Some(layer) if area(layer) > area(canvas) => layer,
            _ => canvas,
        }),
    })
}

/// End of the length-prefixed section at `start`.
fn section_end(data: &[u8], start: usize, wide: bool) -> Result<usize, Malformed> {
    let truncated = Malformed::truncated(data.len());
    let (length, body) = if wide {
        let high = be32(data, start).ok_or(Malformed::truncated(data.len()))? as u64;
        let low = be32(data, start + 4).ok_or(Malformed::truncated(data.len()))? as u64;
        (high << 32 | low, start + 8)
    } else {
        (
            be32(data, start).ok_or(Malformed::truncated(data.len()))? as u64,
            start + 4,
        )
    };
    (body as u64)
        .checked_add(length)
        .filter(|&end| end <= data.len() as u64)
        .map(|end| end as usize)
        .ok_or(truncated)
}

/// Walk the image resource blocks, which must tile the section exactly.
fn check_resources(data: &[u8], start: usize, end: usize) -> Result<(), Malformed> {
    let mut pos = start;
    while pos < end {
        let bad = Malformed::new(pos, "PSD image resource block is malformed");
        let signature = data
            .get(pos..pos + 4)
            .ok_or(Malformed::truncated(data.len()))?;
        if !RESOURCE_SIGNATURES.iter().any(|known| signature == *known) {
            return Err(bad);
        }
        // Signature, id, then a Pascal string padded to an even length.
        let name_len = *data.get(pos + 6).ok_or(Malformed::truncated(data.len()))? as usize;
        let size_at = pos + 6 + (name_len + 2) / 2 * 2;
        let size = be32(data, size_at).ok_or(Malformed::truncated(data.len()))? as usize;
        let next = (size_at + 4).checked_add(size.div_ceil(2) * 2);
        // The last block may omit its padding byte.
        pos = match next {
            Some(next) if next <= end || next == end + 1 => next.min(end),
            _ => return Err(bad),
        };
    }
    Ok(())
}

/// Additional layer information blocks that hold a layer list, as 16- and
/// 32-bit documents store theirs.
const LAYER_LIST_KEYS: [&[u8; 4]; 3] = [b"Layr", b"Lr16", b"Lr32"];
/// Blocks whose length field is 8 bytes wide in a PSB.
const WIDE_KEYS: [&[u8; 4]; 13] = [
    b"LMsk", b"Lr16", b"Lr32", b"Layr", b"Mt16", b"Mt32", b"Mtrn", b"Alph", b"FMsk", b"lnk2",
    b"FEid", b"FXid", b"PxSD",
];

/// A length field at `pos` and the offset of what it measures, which must
/// end by `end`.
fn length(data: &[u8], pos: usize, end: usize, wide: bool) -> Result<(usize, usize), Malformed> {
    let out_of_bounds = Malformed::new(pos, "PSD layer section is out of bounds");
    let (length, body) = if wide {
        let high = be32(data, pos).ok_or(Malformed::truncated(data.len()))? as u64;
        let low = be32(data, pos + 4).ok_or(Malformed::truncated(data.len()))? as u64;
        (high << 32 | low, pos + 8)
    } else {
        let length = be32(data, pos).ok_or(Malformed::truncated(data.len()))?;
        (length as u64, pos + 4)
    };
    match usize::try_from(length) {
        Ok(length) if body <= end && length <= end - body => Ok((length, body)),
        _ => Err(out_of_bounds),
    }
}

/// Walk the layer and mask information in `start..end`: the layer list, the
/// global mask and the blocks after it. Returns the size of the largest
/// layer.
fn check_layers(
    data: &[u8],
    start: usize,
    end: usize,
    large: bool,
) -> Result<Option<(u64, u64)>, Malformed> {
    if start >= end {
        return Ok(None);
    }
    let (info_len, info) = length(data, start, end, large)?;
    let mut pos = info + info_len;
    let mut largest = layer_list(data, info, pos, large)?;

    if end - pos >= 4 {
        let (mask_len, mask) = length(data, pos, end, false)?;
        pos = mask + mask_len;
    }
    // Writers disagree on whether these blocks are padded to 2 or 4 bytes,
    // so the walk ends quietly where no block follows.
    while end - pos >= 12 && matches!(&data[pos..pos + 4], b"8BIM" | b"8B64") {
        let key = &data[pos + 4..pos + 8];
        let wide = large && WIDE_KEYS.iter().any(|known| key == *known);
        let (block_len, block) = length(data, pos + 8, end, wide)?;
        if LAYER_LIST_KEYS.iter().any(|known| key == *known) {
            let layer = layer_list(data, block, block + block_len, large)?;
            largest = larger(largest, layer);
        }
        let next = block + block_len;
        let aligned = [next, next.next_multiple_of(2), next.next_multiple_of(4)]
            .into_iter()
            .find(|&at| at >= end || data.get(at..at + 2) == Some(b"8B"));
        pos = aligned.unwrap_or(end).min(end);
    }
    Ok(largest)
}

fn larger(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let area = |size: Option<(u64, u64)>| size.map_or(0, |(width, height)| width * height);
    if area(b) > area(a) { b } else { a }
}

/// Walk the layer records in `start..end` and check that the channel data
/// they announce fits behind them. Returns the size of the largest layer.
fn layer_list(
    data: &[u8],
    start: usize,
    end: usize,
    large: bool,
) -> Result<Option<(u64, u64)>, Malformed> {
    let Some(count) = be16(&data[..end], start) else {
        return Ok(None);
    };
    // A negative count marks the first alpha channel as transparency.
    let count = (count as i16).unsigned_abs();
    let field = |pos: usize| be32(&data[..end], pos);
    let mut pos = start + 2;
    let mut channel_data = 0u64;
    let mut largest = None;
    for _ in 0..count {
        let bad = Malformed::new(pos, "PSD layer record is malformed");
        let (Some(top), Some(left), Some(bottom), Some(right), Some(channels)) = (
            field(pos),
            field(pos + 4),
            field(pos + 8),
            field(pos + 12),
            be16(&data[..end], pos + 16),
        ) else {
            return Err(bad);
        };
        // Coordinates are signed; a layer may start off the canvas.
        let height = (bottom as i32 as i64 - top as i32 as i64).max(0) as u64;
        let width = (right as i32 as i64 - left as i32 as i64).max(0) as u64;
        largest = larger(largest, Some((width, height)));

        pos += 18;
        for _ in 0..channels {
            // A channel id, then the length of its image data.
            let Ok((length, body)) = length(data, pos + 2, end, large) else {
                return Err(bad);
            };
            channel_data = channel_data.saturating_add(length as u64);
            pos = body;
        }
        // Blend mode signature and key, four flag bytes, then extra data.
        if data.get(pos..pos + 4) != Some(b"8BIM") {
            return Err(bad);
        }
        let Ok((extra_len, extra)) = length(data, pos + 12, end, false) else {
            return Err(bad);
        };
        pos = extra + extra_len;
    }
    if channel_data > (end - pos) as u64 {
        return Err(Malformed::new(pos, "PSD layer data is out of bounds"));
    }
    Ok(largest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2x2 single-channel 8-bit image with one resource block.
    fn psd(compression: u16) -> Vec<u8> {
        let mut data = b"8BPS\x00\x01".to_vec();
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&8u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let resource = b"8BIM\x04\x04\x00\x00\x00\x00\x00\x03abc\x00";
        data.extend_from_slice(&(resource.len() as u32).to_be_bytes());
        data.extend_from_slice(resource);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&compression.to_be_bytes());
        match compression {
            0 => data.extend_from_slice(&[1, 2, 3, 4]),
            _ => data.extend_from_slice(&[0, 2, 0, 3, 0xFF, 7, 1, 8, 9]),
        }
        data
    }

    #[test]
    fn finds_the_end_of_raw_and_rle_data() {
        for compression in [0, 1] {
            let mut data = psd(compression);
            let end = data.len();
            data.extend_from_slice(b"appended");
            assert_eq!(
                parse(&data),
                Ok(Layout {
                    end: Some(end),
                    dimensions: Some((2, 2)),
                })
            );
        }
    }

    /// The image from [`psd`] with one layer of the given size, whose single
    /// channel announces `announced` bytes of data and has 2.
    fn layered(width: u32, height: u32, announced: u32) -> Vec<u8> {
        let mut info = 1u16.to_be_bytes().to_vec();
        for edge in [0, 0, height, width] {
            info.extend_from_slice(&edge.to_be_bytes());
        }
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&announced.to_be_bytes());
        info.extend_from_slice(b"8BIMnorm\xFF\0\0\0");
        // Extra data: an empty mask.
        info.extend_from_slice(&4u32.to_be_bytes());
        info.extend_from_slice(&[0; 4]);
        info.extend_from_slice(&[0, 0]);

        let mut section = (info.len() as u32).to_be_bytes().to_vec();
        section.extend(info);
        // No global mask, then a block that is not a layer list.
        section.extend_from_slice(&0u32.to_be_bytes());
        section.extend_from_slice(b"8BIMPatt\0\0\0\x03abc\0");

        let flat = psd(0);
        let layers_at = flat.len() - 10;
        let mut data = flat[..layers_at].to_vec();
        data.extend_from_slice(&(section.len() as u32).to_be_bytes());
        data.extend(section);
        data.extend_from_slice(&flat[layers_at + 4..]);
        data
    }

    #[test]
    fn walks_layer_records() {
        let data = layered(3, 5, 2);
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(data.len()),
                dimensions: Some((3, 5)),
            })
        );
        // The canvas is reported unless a layer is larger.
        assert_eq!(parse(&layered(1, 1, 2)).unwrap().dimensions, Some((2, 2)));
        assert_eq!(
            parse(&layered(70_000, 70_000, 2)).unwrap().dimensions,
            Some((70_000, 70_000))
        );
    }

    #[test]
    fn rejects_broken_layers() {
        assert_eq!(
            parse(&layered(3, 5, 900)).unwrap_err().reason,
            "PSD layer record is malformed"
        );
        assert_eq!(
            parse(&layered(3, 5, 20)).unwrap_err().reason,
            "PSD layer data is out of bounds"
        );
        let data = layered(3, 5, 2);
        let record = data.windows(8).position(|w| w == b"8BIMnorm").unwrap();
        let mut bad_signature = data.clone();
        bad_signature[record] = b'X';
        assert_eq!(
            parse(&bad_signature).unwrap_err().reason,
            "PSD layer record is malformed"
        );
        // Two layers announced, one present.
        let mut missing = data.clone();
        missing[record - 25] = 2;
        assert_eq!(
            parse(&missing).unwrap_err().reason,
            "PSD layer record is malformed"
        );
        let mut long_block = data;
        let block = long_block
            .windows(8)
            .position(|w| w == b"8BIMPatt")
            .unwrap();
        long_block[block + 8] = 1;
        assert_eq!(
            parse(&long_block).unwrap_err().reason,
            "PSD layer section is out of bounds"
        );
    }

    #[test]
    fn rejects_broken_structure() {
        let data = psd(0);
        assert!(parse(&data[..data.len() - 1]).is_err());
        assert!(parse(&data[..30]).is_err());
        let mut bad_resource = data.clone();
        bad_resource[34] = b'X';
        assert!(parse(&bad_resource).is_err());
        let mut bad_version = data.clone();
        bad_version[5] = 3;
        assert!(parse(&bad_version).is_err());
        // Dimensions whose raw size overflows.
        let mut huge = data.clone();
        huge[12..22].copy_from_slice(&[0, 56, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        huge[23] = 32;
        assert!(parse(&huge).is_err());
        let mut bad_compression = data;
        let at = bad_compression.len() - 5;
        bad_compression[at] = 9;
        assert!(parse(&bad_compression).is_err());
    }
}
