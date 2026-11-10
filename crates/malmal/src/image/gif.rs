use super::{Layout, Malformed, le16};

const HEADER_LEN: usize = 13;

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let (Some(width), Some(height), Some(&flags)) = (le16(data, 6), le16(data, 8), data.get(10))
    else {
        return Err(Malformed::truncated(data.len()));
    };
    let mut pos = HEADER_LEN + color_table_len(flags);
    loop {
        let block = pos;
        let next = match data.get(pos) {
            Some(0x3B) => {
                return Ok(Layout {
                    end: Some(pos + 1),
                    dimensions: Some((width as u64, height as u64)),
                });
            }
            // Extension: introducer, label, sub-blocks.
            Some(0x21) => skip_sub_blocks(data, pos + 2),
            // Image: 10-byte descriptor, optional colour table, LZW code size, sub-blocks.
            Some(0x2C) => data
                .get(pos + 9)
                .and_then(|&flags| skip_sub_blocks(data, pos + 10 + color_table_len(flags) + 1)),
            Some(_) => return Err(Malformed::new(pos, "unknown GIF block")),
            None => None,
        };
        pos = next.ok_or(Malformed::truncated(block))?;
    }
}

fn color_table_len(flags: u8) -> usize {
    if flags & 0x80 != 0 {
        3 << ((flags & 7) + 1)
    } else {
        0
    }
}

/// Offset after the zero-length block that terminates a sub-block chain.
fn skip_sub_blocks(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *data.get(pos)? as usize;
        pos += 1 + len;
        if len == 0 {
            return Some(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gif() -> Vec<u8> {
        let mut data = b"GIF89a\x02\x00\x03\x00\x80\x00\x00".to_vec();
        data.extend_from_slice(&[0; 6]); // 2-entry global colour table
        data.extend_from_slice(b"\x21\xF9\x04\x00\x00\x00\x00\x00"); // graphic control
        data.extend_from_slice(b"\x2C\x00\x00\x00\x00\x02\x00\x03\x00\x00");
        data.extend_from_slice(b"\x02\x02\x4C\x01\x00");
        data.push(0x3B);
        data
    }

    #[test]
    fn finds_end_and_dimensions() {
        let mut data = gif();
        let end = data.len();
        data.extend_from_slice(b"appended");
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(end),
                dimensions: Some((2, 3)),
            })
        );
    }

    #[test]
    fn rejects_truncation_and_unknown_blocks() {
        let data = gif();
        for len in [8, 15, 25, data.len() - 1] {
            assert!(parse(&data[..len]).is_err(), "length {len}");
        }
        let mut unknown = data.clone();
        unknown[19] = 0x99;
        assert_eq!(parse(&unknown).unwrap_err().reason, "unknown GIF block");
    }
}
