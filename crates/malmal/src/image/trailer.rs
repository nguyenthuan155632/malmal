//! Data that phone cameras append after the end of an image. A trailer is
//! only recognized when its own structure accounts for every byte up to the
//! end of the file.

use super::{be32, le32};

/// What a recognized trailer holds, for the finding message.
pub(super) fn recognize(trailing: &[u8]) -> Option<&'static str> {
    if is_samsung_trailer(trailing) {
        Some("Samsung camera metadata")
    } else if is_iso_media(trailing) {
        Some("a motion photo video")
    } else {
        None
    }
}

const SEF_ENTRY_LEN: usize = 12;

/// Samsung's trailer is a run of data blocks, a `SEFH` directory listing
/// each block by its distance back from the directory, the directory
/// length, and `SEFT`.
fn is_samsung_trailer(trailing: &[u8]) -> bool {
    let Some(tail_at) = trailing.len().checked_sub(8) else {
        return false;
    };
    if &trailing[tail_at + 4..] != b"SEFT" {
        return false;
    }
    let directory_len = le32(trailing, tail_at).unwrap_or(0) as usize;
    let Some(directory_at) = tail_at.checked_sub(directory_len) else {
        return false;
    };
    let directory = &trailing[directory_at..tail_at];
    let count = le32(directory, 8).unwrap_or(0) as usize;
    if !directory.starts_with(b"SEFH")
        || count.checked_mul(SEF_ENTRY_LEN) != Some(directory_len - 12)
    {
        return false;
    }
    // The blocks must tile everything before the directory.
    let mut blocks: Vec<(usize, usize)> = (0..count)
        .filter_map(|index| {
            let entry = 12 + index * SEF_ENTRY_LEN;
            let back = le32(directory, entry + 4)? as usize;
            let size = le32(directory, entry + 8)? as usize;
            Some((directory_at.checked_sub(back)?, size))
        })
        .collect();
    blocks.sort_unstable();
    let mut expected = 0;
    for &(start, size) in &blocks {
        if start != expected {
            return false;
        }
        expected = start + size;
    }
    blocks.len() == count && expected == directory_at
}

/// An MP4 or QuickTime file: boxes from `ftyp` that end exactly at the end
/// of the data.
fn is_iso_media(trailing: &[u8]) -> bool {
    if trailing.get(4..8) != Some(b"ftyp") {
        return false;
    }
    let mut pos = 0;
    while pos < trailing.len() {
        let Some(size) = be32(trailing, pos) else {
            return false;
        };
        let size = match size {
            // The box runs to the end.
            0 => return true,
            // A 64-bit size follows the type.
            1 => match (be32(trailing, pos + 8), be32(trailing, pos + 12)) {
                (Some(high), Some(low)) => (high as u64) << 32 | low as u64,
                _ => return false,
            },
            size => size as u64,
        };
        let next = (pos as u64).checked_add(size).filter(|_| size >= 8);
        pos = match next {
            Some(next) if next <= trailing.len() as u64 => next as usize,
            _ => return false,
        };
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samsung_trailer() -> Vec<u8> {
        let blocks: [&[u8]; 2] = [b"\0\0\x51\x0cfirst block", b"\0\0\xa1\x0dsecond"];
        let mut data = blocks.concat();
        let directory_at = data.len();
        data.extend_from_slice(b"SEFH\x6b\0\0\0\x02\0\0\0");
        let mut start = 0;
        for block in blocks {
            data.extend_from_slice(&[0, 0, block[2], block[3]]);
            data.extend_from_slice(&((directory_at - start) as u32).to_le_bytes());
            data.extend_from_slice(&(block.len() as u32).to_le_bytes());
            start += block.len();
        }
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(b"SEFT");
        data
    }

    #[test]
    fn recognizes_a_complete_samsung_trailer() {
        let trailer = samsung_trailer();
        assert_eq!(recognize(&trailer), Some("Samsung camera metadata"));
        // Bytes the directory does not account for.
        let mut prefixed = b"extra".to_vec();
        prefixed.extend_from_slice(&trailer);
        assert_eq!(recognize(&prefixed), None);
        let mut suffixed = trailer.clone();
        suffixed.push(0);
        assert_eq!(recognize(&suffixed), None);
        assert_eq!(recognize(b"SEFT"), None);
        assert_eq!(recognize(b"\0\0\0\0SEFT"), None);
    }

    #[test]
    fn recognizes_video_boxes_that_reach_the_end() {
        let mut video = b"\0\0\0\x10ftypisom\0\0\0\0".to_vec();
        video.extend_from_slice(b"\0\0\0\x01mdat\0\0\0\0\0\0\0\x14abcd");
        assert_eq!(recognize(&video), Some("a motion photo video"));
        video.extend_from_slice(b"PK\x03\x04");
        assert_eq!(recognize(&video), None);
        assert_eq!(recognize(b"\0\0\0\x04ftyp"), None);
    }
}
