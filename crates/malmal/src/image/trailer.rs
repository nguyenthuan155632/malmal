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
    } else if is_oppo_trailer(trailing) {
        Some("OPPO camera metadata")
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

/// OPPO's camera writes data blocks, then a JSON list that names each
/// block by its distance back from the list and its length, then a zero
/// byte, a tag of four letters and the length from the list to the end
/// (little-endian). The blocks must tile everything before the list.
fn is_oppo_trailer(trailing: &[u8]) -> bool {
    let Some(tail_at) = trailing.len().checked_sub(9) else {
        return false;
    };
    let (zero, tag) = (trailing[tail_at], &trailing[tail_at + 1..tail_at + 5]);
    let length = le32(trailing, tail_at + 5).unwrap_or(0) as usize;
    let Some(list_at) = trailing.len().checked_sub(length) else {
        return false;
    };
    if zero != 0 || !tag.iter().all(u8::is_ascii_lowercase) || list_at >= tail_at {
        return false;
    }
    let Some(blocks) = oppo_blocks(&trailing[list_at..tail_at]) else {
        return false;
    };
    let Some(mut blocks) = blocks
        .into_iter()
        .map(|(back, size)| Some((list_at.checked_sub(back)?, size)))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    blocks.sort_unstable();
    let mut expected = 0;
    for (start, size) in blocks {
        if start != expected {
            return false;
        }
        expected += size;
    }
    expected == list_at
}

/// The blocks of the list, as distance back and length: objects of
/// `"length"`, `"name"`, `"offset"` and `"version"`, with numbers and plain
/// names, and nothing else.
fn oppo_blocks(list: &[u8]) -> Option<Vec<(usize, usize)>> {
    let inner = list.strip_prefix(b"[{")?.strip_suffix(b"}]")?;
    let mut blocks = Vec::new();
    for entry in inner.split(|&byte| byte == b'}').map(|entry| {
        // Every object but the first starts with `,{`.
        entry.strip_prefix(b",{").unwrap_or(entry)
    }) {
        let (mut back, mut size, mut named) = (None, None, false);
        for field in entry.split(|&byte| byte == b',') {
            let (key, value) = field.split_at(field.iter().position(|&byte| byte == b':')?);
            let value = &value[1..];
            let number = || -> Option<usize> {
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                std::str::from_utf8(value).ok()?.parse().ok()
            };
            match key {
                b"\"length\"" => size = Some(number()?),
                b"\"offset\"" => back = Some(number()?),
                b"\"version\"" => _ = number()?,
                b"\"name\"" => {
                    let name = value.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
                    let plain = |byte: &u8| byte.is_ascii_alphanumeric() || b"._-".contains(byte);
                    named = !name.is_empty() && name.iter().all(plain);
                }
                _ => return None,
            }
        }
        if !named {
            return None;
        }
        blocks.push((back?, size?));
    }
    Some(blocks)
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

    /// Two blocks and the list that names them, as OPPO's camera writes it.
    fn oppo_trailer(tag: &[u8; 4]) -> Vec<u8> {
        let mut data = b"\0OPPO A5 5G\0\0\0\0\0".to_vec();
        let list = br#"[{"length":4,"name":"private.emptyspace","offset":16,"version":1},{"length":12,"name":"watermark.device","offset":12,"version":1}]"#;
        data.extend_from_slice(list);
        data.push(0);
        data.extend_from_slice(tag);
        data.extend_from_slice(&((list.len() + 9) as u32).to_le_bytes());
        data
    }

    #[test]
    fn recognizes_a_complete_oppo_trailer() {
        assert_eq!(
            recognize(&oppo_trailer(b"wtmk")),
            Some("OPPO camera metadata")
        );
        assert_eq!(
            recognize(&oppo_trailer(b"jxrs")),
            Some("OPPO camera metadata")
        );
        assert_eq!(recognize(&oppo_trailer(b"WTMK")), None);
        // Bytes the list does not account for, before or after.
        let mut prefixed = b"PK\x03\x04".to_vec();
        prefixed.extend_from_slice(&oppo_trailer(b"wtmk"));
        assert_eq!(recognize(&prefixed), None);
        let mut suffixed = oppo_trailer(b"wtmk");
        suffixed.push(0);
        assert_eq!(recognize(&suffixed), None);
        // Blocks that overlap, or a list that is not only blocks. Both
        // replacements keep the length.
        let replaced = |from: &[u8], to: &[u8]| {
            let data = oppo_trailer(b"wtmk");
            let at = data
                .windows(from.len())
                .position(|window| window == from)
                .unwrap();
            [&data[..at], to, &data[at + from.len()..]].concat()
        };
        let overlapping = replaced(br#""offset":12"#, br#""offset":13"#);
        assert_eq!(recognize(&overlapping), None);
        let scripted = replaced(br#""watermark.device""#, br#""<script>xxxxxxx""#);
        assert_eq!(recognize(&scripted), None);
        assert_eq!(recognize(b"\0wtmk\x09\0\0\0"), None);
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
