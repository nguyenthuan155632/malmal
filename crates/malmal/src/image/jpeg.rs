use super::{Layout, Malformed, be16};

/// Phones store depth maps and previews as further JPEGs after the first
/// (Multi-Picture Format); those are part of the image, not trailing data.
const MAX_IMAGES: usize = 32;

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let (mut end, dimensions) = parse_one(data, 0)?;
    for _ in 1..MAX_IMAGES {
        let next = end + data[end..].iter().take_while(|&&b| b == 0).count();
        if !data[next..].starts_with(b"\xFF\xD8\xFF") {
            break;
        }
        match parse_one(data, next) {
            Ok((next_end, _)) => end = next_end,
            Err(_) => break,
        }
    }
    Ok(Layout {
        end: Some(end),
        dimensions,
    })
}

/// Walk one JPEG from its SOI at `start`; returns the offset after its EOI.
fn parse_one(data: &[u8], start: usize) -> Result<(usize, Option<(u64, u64)>), Malformed> {
    let mut pos = start + 2;
    let mut dimensions = None;
    loop {
        match data.get(pos) {
            Some(0xFF) => {}
            Some(_) => return Err(Malformed::new(pos, "expected a JPEG marker")),
            None => return Err(Malformed::truncated(pos)),
        }
        // Any number of 0xFF fill bytes may precede the marker code.
        while data.get(pos + 1) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&marker) = data.get(pos + 1) else {
            return Err(Malformed::truncated(pos));
        };
        pos += 2;
        match marker {
            0xD9 => return Ok((pos, dimensions)),
            // TEM and RSTn stand alone, without a length.
            0x01 | 0xD0..=0xD7 => continue,
            0x00 | 0xD8 => return Err(Malformed::new(pos - 2, "unexpected JPEG marker")),
            _ => {}
        }

        let length = be16(data, pos).ok_or(Malformed::truncated(pos))? as usize;
        if length < 2 || pos + length > data.len() {
            return Err(Malformed::new(pos, "JPEG segment length is out of bounds"));
        }
        if is_start_of_frame(marker) {
            let body = &data[pos + 2..pos + length];
            let (Some(height), Some(width)) = (be16(body, 1), be16(body, 3)) else {
                return Err(Malformed::new(pos, "JPEG frame header is too short"));
            };
            dimensions.get_or_insert((width as u64, height as u64));
        }
        pos += length;
        if marker == 0xDA {
            pos = skip_entropy_coded(data, pos).ok_or(Malformed::truncated(data.len()))?;
        }
    }
}

fn is_start_of_frame(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC)
}

/// Offset of the next real marker after scan data starting at `pos`.
fn skip_entropy_coded(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        pos += data.get(pos..)?.iter().position(|&b| b == 0xFF)?;
        match *data.get(pos + 1)? {
            // Stuffed zero and restart markers belong to the scan.
            0x00 | 0xD0..=0xD7 => pos += 2,
            0xFF => pos += 1,
            _ => return Some(pos),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg() -> Vec<u8> {
        let mut data = b"\xFF\xD8".to_vec();
        data.extend_from_slice(b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        data.extend_from_slice(b"\xFF\xC0\x00\x0B\x08\x00\x02\x00\x03\x01\x01\x11\x00");
        data.extend_from_slice(b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00");
        // Scan data with a stuffed 0xFF and a restart marker.
        data.extend_from_slice(b"\xD2\xFF\x00\xCF\xFF\xD0\x20");
        data.extend_from_slice(b"\xFF\xD9");
        data
    }

    #[test]
    fn finds_end_and_dimensions() {
        let data = jpeg();
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(data.len()),
                dimensions: Some((3, 2)),
            })
        );
    }

    #[test]
    fn end_excludes_appended_bytes() {
        let mut data = jpeg();
        let end = data.len();
        data.extend_from_slice(b"appended");
        assert_eq!(parse(&data).unwrap().end, Some(end));
    }

    #[test]
    fn concatenated_jpegs_are_one_image() {
        let mut data = jpeg();
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(&jpeg());
        assert_eq!(parse(&data).unwrap().end, Some(data.len()));
    }

    #[test]
    fn rejects_truncation_and_bad_lengths() {
        let data = jpeg();
        assert!(parse(&data[..data.len() - 2]).is_err());
        assert!(parse(&data[..10]).is_err());
        assert!(parse(b"\xFF\xD8\xFF\xE0\x00\x01").is_err());
        assert!(parse(b"\xFF\xD8\x00\x00").is_err());
    }
}
