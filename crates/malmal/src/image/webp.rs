use super::{Layout, Malformed, le16, le24, le32};

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let riff_size = le32(data, 4).ok_or(Malformed::truncated(data.len()))? as usize;
    let end = 8 + riff_size;
    if end > data.len() {
        return Err(Malformed::truncated(data.len()));
    }
    let mut pos = 12;
    let mut dimensions = None;
    while pos < end {
        let Some(size) = le32(&data[..end], pos + 4) else {
            return Err(Malformed::new(pos, "stray bytes inside the WebP container"));
        };
        let body_start = pos + 8;
        let body_end = body_start + size as usize;
        if body_end > end {
            return Err(Malformed::new(pos, "WebP chunk is out of bounds"));
        }
        let body = &data[body_start..body_end];
        if let Some(found) = chunk_dimensions(&data[pos..body_start - 4], body) {
            dimensions.get_or_insert(found);
        }
        // Chunks are padded to an even length.
        pos = body_end + (size as usize & 1);
    }
    if dimensions.is_none() {
        return Err(Malformed::new(12, "WebP has no image data chunk"));
    }
    Ok(Layout {
        end: Some(end),
        dimensions,
    })
}

fn chunk_dimensions(fourcc: &[u8], body: &[u8]) -> Option<(u64, u64)> {
    let (width, height) = match fourcc {
        b"VP8X" => (le24(body, 4)? + 1, le24(body, 7)? + 1),
        b"VP8 " if body.get(3..6) == Some(b"\x9D\x01\x2A") => (
            (le16(body, 6)? & 0x3FFF) as u32,
            (le16(body, 8)? & 0x3FFF) as u32,
        ),
        b"VP8L" if body.first() == Some(&0x2F) => {
            let bits = le32(body, 1)?;
            ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
        }
        _ => return None,
    };
    Some((width as u64, height as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webp(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = b"WEBP".to_vec();
        for (fourcc, payload) in chunks {
            body.extend_from_slice(*fourcc);
            body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            body.extend_from_slice(payload);
            if payload.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend(body);
        data
    }

    const VP8: &[u8] = b"\x00\x00\x00\x9D\x01\x2A\x10\x00\x08\x00\xAA";

    #[test]
    fn reads_lossy_dimensions_and_end() {
        let mut data = webp(&[(b"VP8 ", VP8)]);
        let end = data.len();
        data.extend_from_slice(b"appended");
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(end),
                dimensions: Some((16, 8)),
            })
        );
    }

    #[test]
    fn reads_extended_and_lossless_dimensions() {
        let vp8x = b"\x00\x00\x00\x00\xFF\x00\x00\x7F\x00\x00";
        let data = webp(&[(b"VP8X", vp8x), (b"VP8 ", VP8)]);
        assert_eq!(parse(&data).unwrap().dimensions, Some((256, 128)));

        // 14-bit width-1 = 9, height-1 = 4.
        let bits: u32 = 9 | (4 << 14);
        let mut vp8l = vec![0x2F];
        vp8l.extend_from_slice(&bits.to_le_bytes());
        let data = webp(&[(b"VP8L", &vp8l)]);
        assert_eq!(parse(&data).unwrap().dimensions, Some((10, 5)));
    }

    #[test]
    fn rejects_broken_containers() {
        let data = webp(&[(b"VP8 ", VP8)]);
        assert!(parse(&data[..data.len() - 1]).is_err());

        let mut oversized_chunk = data.clone();
        oversized_chunk[16] = 0xFF;
        assert_eq!(
            parse(&oversized_chunk).unwrap_err().reason,
            "WebP chunk is out of bounds"
        );

        let no_image = webp(&[(b"EXIF", b"II*\0")]);
        assert!(parse(&no_image).is_err());
    }
}
