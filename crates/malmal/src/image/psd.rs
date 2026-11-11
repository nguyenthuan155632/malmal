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
    Ok(Layout {
        end,
        dimensions: Some((width, height)),
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
