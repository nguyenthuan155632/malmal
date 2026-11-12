//! Windows icons: a directory of images, each a PNG or a headerless bitmap.

use super::{Ctx, Layout, Malformed, le16, le32, png};

const HEADER_LEN: usize = 6;
const ENTRY_LEN: usize = 16;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

pub(crate) fn parse(data: &[u8], ctx: &mut Ctx<'_>) -> Result<Layout, Malformed> {
    let count = le16(data, 4).ok_or(Malformed::truncated(data.len()))? as usize;
    let directory_end = HEADER_LEN + count * ENTRY_LEN;
    if count == 0 || directory_end > data.len() {
        return Err(Malformed::new(4, "icon directory is out of bounds"));
    }

    let mut end = directory_end;
    let mut largest = (0, 0);
    for index in 0..count {
        let entry = HEADER_LEN + index * ENTRY_LEN;
        // The directory was bounds-checked above.
        let size = le32(data, entry + 8).unwrap_or(0) as usize;
        let offset = le32(data, entry + 12).unwrap_or(0) as usize;
        let image = offset
            .checked_add(size)
            .filter(|_| offset >= directory_end && size > 0)
            .and_then(|image_end| data.get(offset..image_end))
            .ok_or(Malformed::new(entry, "icon image is out of bounds"))?;
        end = end.max(offset + size);

        let dimensions = if image.starts_with(PNG_SIGNATURE) {
            let layout = png::parse(image, ctx).map_err(|inner| Malformed {
                offset: offset + inner.offset,
                reason: inner.reason,
            })?;
            layout.dimensions
        } else {
            // A bitmap without its file header; the height covers the
            // colour rows and the mask rows.
            if !matches!(le32(image, 0), Some(40 | 52 | 56 | 108 | 124)) {
                return Err(Malformed::new(
                    offset,
                    "icon image is neither a PNG nor a bitmap",
                ));
            }
            let abs = |at| le32(image, at).map(|v| (v as i32).unsigned_abs() as u64);
            abs(4)
                .zip(abs(8))
                .map(|(width, height)| (width, height / 2))
        };
        if let Some((width, height)) = dimensions
            && width * height >= largest.0 * largest.1
        {
            largest = (width, height);
        }
    }
    Ok(Layout {
        end: Some(end),
        dimensions: Some(largest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Budget, Limits};

    fn run(data: &[u8]) -> Result<Layout, Malformed> {
        let mut budget = Budget::new(&Limits::default());
        let mut findings = Vec::new();
        parse(
            data,
            &mut Ctx {
                budget: &mut budget,
                findings: &mut findings,
            },
        )
    }

    /// A bitmap image of the given size, with no pixels behind its header.
    fn bitmap(width: u32, height: u32) -> Vec<u8> {
        let mut image = 40u32.to_le_bytes().to_vec();
        image.extend_from_slice(&width.to_le_bytes());
        image.extend_from_slice(&(height * 2).to_le_bytes());
        image.extend_from_slice(&[0; 28]);
        image
    }

    fn ico(images: &[Vec<u8>]) -> Vec<u8> {
        let mut data = b"\0\0\x01\0".to_vec();
        data.extend_from_slice(&(images.len() as u16).to_le_bytes());
        let mut offset = HEADER_LEN + images.len() * ENTRY_LEN;
        for image in images {
            data.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
            data.extend_from_slice(&(image.len() as u32).to_le_bytes());
            data.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += image.len();
        }
        for image in images {
            data.extend_from_slice(image);
        }
        data
    }

    #[test]
    fn reads_the_largest_image_and_the_end() {
        let mut data = ico(&[bitmap(16, 16), bitmap(48, 32)]);
        let end = data.len();
        data.extend_from_slice(b"appended");
        assert_eq!(
            run(&data),
            Ok(Layout {
                end: Some(end),
                dimensions: Some((48, 32)),
            })
        );
    }

    #[test]
    fn rejects_broken_directories_and_images() {
        let data = ico(&[bitmap(16, 16)]);
        assert!(run(&data[..data.len() - 1]).is_err());
        assert!(run(&data[..10]).is_err());
        assert!(run(b"\0\0\x01\0\0\0").is_err());

        // An image that starts inside the directory.
        let mut overlapping = data.clone();
        overlapping[18] = 4;
        assert_eq!(
            run(&overlapping).unwrap_err().reason,
            "icon image is out of bounds"
        );
        let mut unknown = data.clone();
        unknown[22] = 41;
        assert_eq!(
            run(&unknown).unwrap_err().reason,
            "icon image is neither a PNG nor a bitmap"
        );
        // A PNG image is held to the PNG rules.
        let png = ico(&[b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec()]);
        assert!(run(&png).is_err());
    }
}
