use super::{Layout, Malformed, le16, le32};

const FILE_HEADER_LEN: usize = 14;

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let truncated = Malformed::truncated(data.len());
    let (Some(file_size), Some(dib_size)) = (le32(data, 2), le32(data, 14)) else {
        return Err(truncated);
    };
    let dimensions = if dib_size == 12 {
        (le16(data, 18).map(u64::from), le16(data, 20).map(u64::from))
    } else {
        // Signed; a negative height means the rows are stored top-down.
        let abs = |offset| le32(data, offset).map(|v| (v as i32).unsigned_abs() as u64);
        (abs(18), abs(22))
    };
    let (Some(width), Some(height)) = dimensions else {
        return Err(truncated);
    };

    // The colour depth must be one the format defines. Zero is left alone: it
    // is the sentinel for an embedded JPEG/PNG and turns up in merely sloppy
    // files, which this scanner tolerates rather than flag.
    let (bpp, compression) = if dib_size == 12 {
        (le16(data, 24).map(u64::from), Some(0))
    } else {
        (le16(data, 28).map(u64::from), le32(data, 30))
    };
    let (Some(bpp), Some(compression)) = (bpp, compression) else {
        return Err(truncated);
    };
    if bpp != 0 && !matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32) {
        return Err(Malformed::new(28, "BMP has an impossible colour depth"));
    }

    // For uncompressed pixels the rows cannot need more bytes than the file
    // holds; a tiny file that claims a huge image is malformed.
    if compression == 0 && bpp != 0 && file_size != 0 && file_size <= data.len() as u32 {
        let stride = width.checked_mul(bpp).map(|bits| bits.div_ceil(32) * 4);
        let needed = stride.and_then(|s| s.checked_mul(height));
        let fits = needed.is_some_and(|n| n <= file_size as u64);
        if !fits {
            return Err(Malformed::new(22, "BMP pixel data does not fit the file"));
        }
    }

    let file_size = file_size as usize;
    let end = if file_size == 0 {
        // Some writers leave the size field empty; the end is then unknown.
        None
    } else if file_size > data.len() {
        return Err(truncated);
    } else if file_size < FILE_HEADER_LEN + dib_size as usize {
        return Err(Malformed::new(
            2,
            "BMP size field is smaller than its headers",
        ));
    } else {
        Some(file_size)
    };
    Ok(Layout {
        end,
        dimensions: Some((width, height)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bmp(file_size: u32, height: i32) -> Vec<u8> {
        let mut data = b"BM".to_vec();
        data.extend_from_slice(&file_size.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&40u32.to_le_bytes());
        data.extend_from_slice(&5i32.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // planes
        data.extend_from_slice(&8u16.to_le_bytes()); // bits per pixel
        data.resize(58, 0); // compression 0, then padding
        data
    }

    #[test]
    fn reads_size_field_and_dimensions() {
        let mut data = bmp(58, -7);
        data.extend_from_slice(b"appended");
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(58),
                dimensions: Some((5, 7)),
            })
        );
        assert_eq!(parse(&bmp(0, 7)).unwrap().end, None);
    }

    #[test]
    fn rejects_inconsistent_sizes() {
        assert!(parse(&bmp(1000, 7)).is_err());
        assert!(parse(&bmp(20, 7)).is_err());
        assert!(parse(&bmp(58, 7)[..20]).is_err());
    }

    #[test]
    fn rejects_impossible_depth_and_oversized_images() {
        let mut bad_depth = bmp(58, 7);
        bad_depth[28..30].copy_from_slice(&255u16.to_le_bytes());
        assert_eq!(parse(&bad_depth).unwrap_err().offset, 28);

        let mut huge = bmp(58, 1_000_000);
        huge.resize(70, 0);
        huge[2..6].copy_from_slice(&70u32.to_le_bytes());
        assert_eq!(parse(&huge).unwrap_err().offset, 22);
    }
}
