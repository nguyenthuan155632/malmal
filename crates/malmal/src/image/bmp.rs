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
        data.resize(58, 0);
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
}
