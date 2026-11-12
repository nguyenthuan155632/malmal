//! HEIF and AVIF: still images in the ISO base media file format, a tree of
//! length-prefixed boxes. The codec inside (HEVC or AV1) is not decoded; the
//! boxes, the declared image sizes and the item locations are checked.

use super::{Layout, Malformed, be32};

/// Nesting of the boxes this module descends into: `meta`, `iprp`, `ipco`.
const MAX_BOXES: usize = 1 << 16;

pub(crate) struct BoxAt<'a> {
    pub kind: &'a [u8],
    /// First byte after the box header.
    pub body: usize,
    pub end: usize,
}

pub(crate) enum Next<'a> {
    Box(BoxAt<'a>),
    /// What is at this offset does not start a box.
    NotABox,
    /// A box header whose size is impossible or reaches past `end`.
    Broken,
}

fn is_fourcc(kind: &[u8]) -> bool {
    kind.iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | 0xA9))
}

/// Read the box header at `pos` inside `..end`.
pub(crate) fn next_box(data: &[u8], pos: usize, end: usize) -> Next<'_> {
    let data = &data[..end];
    let (Some(size), Some(kind)) = (be32(data, pos), data.get(pos + 4..pos + 8)) else {
        return Next::NotABox;
    };
    if !is_fourcc(kind) {
        return Next::NotABox;
    }
    let (size, header) = match size {
        // The box runs to the end of its container.
        0 => ((end - pos) as u64, 8),
        1 => match (be32(data, pos + 8), be32(data, pos + 12)) {
            (Some(high), Some(low)) => ((high as u64) << 32 | low as u64, 16),
            _ => return Next::Broken,
        },
        size => (size as u64, 8),
    };
    match usize::try_from(size) {
        Ok(size) if size >= header && size <= end - pos => Next::Box(BoxAt {
            kind,
            body: pos + header,
            end: pos + size,
        }),
        _ => Next::Broken,
    }
}

/// Walk the boxes at the top level of a file. Returns where they stop and
/// calls `visit` for each; bytes after the last box are trailing data.
pub(crate) fn top_level<'a>(
    data: &'a [u8],
    mut visit: impl FnMut(&BoxAt<'a>) -> Result<(), Malformed>,
) -> Result<usize, Malformed> {
    let mut pos = 0;
    for _ in 0..MAX_BOXES {
        if pos == data.len() {
            return Ok(pos);
        }
        match next_box(data, pos, data.len()) {
            Next::Box(found) => {
                visit(&found)?;
                pos = found.end;
            }
            Next::NotABox => return Ok(pos),
            Next::Broken => return Err(Malformed::truncated(data.len())),
        }
    }
    Err(Malformed::new(pos, "file has too many boxes to analyze"))
}

/// Boxes that tile `start..end` exactly.
fn children(data: &[u8], start: usize, end: usize) -> Result<Vec<BoxAt<'_>>, Malformed> {
    let bad = Malformed::new(start, "box contents are malformed");
    let mut boxes = Vec::new();
    let mut pos = start;
    while pos < end {
        match next_box(data, pos, end) {
            Next::Box(found) if boxes.len() < MAX_BOXES => {
                pos = found.end;
                boxes.push(found);
            }
            _ => return Err(bad),
        }
    }
    Ok(boxes)
}

pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let mut meta = None;
    let end = top_level(data, |found| {
        if found.kind == b"meta" {
            meta.get_or_insert((found.body, found.end));
        }
        Ok(())
    })?;
    let Some((body, meta_end)) = meta else {
        return Err(Malformed::new(0, "image has no meta box"));
    };

    // A version and flags word precedes the children of `meta`.
    let mut dimensions: Option<(u64, u64)> = None;
    for child in children(data, (body + 4).min(meta_end), meta_end)? {
        match child.kind {
            b"iloc" => check_locations(data, &child)?,
            b"iprp" => {
                for group in children(data, child.body, child.end)? {
                    if group.kind != b"ipco" {
                        continue;
                    }
                    for property in children(data, group.body, group.end)? {
                        // Image spatial extents: flags, width, height.
                        if property.kind == b"ispe"
                            && let (Some(width), Some(height)) = (
                                be32(&data[..property.end], property.body + 4),
                                be32(&data[..property.end], property.body + 8),
                            )
                        {
                            let size = (width as u64, height as u64);
                            // A grid image declares its tiles too; the
                            // largest extent is the one a decoder allocates.
                            if dimensions.is_none_or(|(w, h)| size.0 * size.1 > w * h) {
                                dimensions = Some(size);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if dimensions.is_none() {
        return Err(Malformed::new(body, "image declares no dimensions"));
    }
    Ok(Layout {
        end: Some(end),
        dimensions,
    })
}

/// Check that every item stored in the file itself lies inside it.
fn check_locations(data: &[u8], iloc: &BoxAt<'_>) -> Result<(), Malformed> {
    let bad = || Malformed::new(iloc.body, "item location box is malformed");
    let body = &data[..iloc.end];
    let mut pos = iloc.body;
    // An unsigned big-endian field of 0 to 8 bytes.
    let mut field = |width: usize| -> Option<u64> {
        let bytes = body.get(pos..pos + width)?;
        pos += width;
        (width <= 8).then(|| bytes.iter().fold(0, |value, &b| value << 8 | b as u64))
    };

    let (Some(version), Some(_flags), Some(sizes), Some(more_sizes)) =
        (field(1), field(3), field(1), field(1))
    else {
        return Err(bad());
    };
    if version > 2 {
        return Err(bad());
    }
    let (offset_size, length_size) = ((sizes >> 4) as usize, (sizes & 15) as usize);
    let base_size = (more_sizes >> 4) as usize;
    let index_size = if version >= 1 {
        (more_sizes & 15) as usize
    } else {
        0
    };
    let id_size = if version == 2 { 4 } else { 2 };
    let item_count = field(id_size).ok_or_else(bad)?;

    for _ in 0..item_count {
        let _id = field(id_size);
        let method = if version >= 1 {
            field(2).map(|word| word & 15)
        } else {
            Some(0)
        };
        let (Some(method), Some(_reference), Some(base), Some(extents)) =
            (method, field(2), field(base_size), field(2))
        else {
            return Err(bad());
        };
        // Extents without any field are all the same one.
        let extents = if index_size + offset_size + length_size == 0 {
            extents.min(1)
        } else {
            extents
        };
        for _ in 0..extents {
            let (Some(_index), Some(offset), Some(length)) =
                (field(index_size), field(offset_size), field(length_size))
            else {
                return Err(bad());
            };
            // Method 0 is an offset into this file; the others point into
            // boxes that were bounds-checked as boxes.
            let end = base
                .checked_add(offset)
                .and_then(|start| start.checked_add(length));
            if method == 0 && end.is_none_or(|end| end > data.len() as u64) {
                return Err(Malformed::new(iloc.body, "image data is out of bounds"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32 + 8).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    }

    fn ispe(width: u32, height: u32) -> Vec<u8> {
        let mut body = vec![0; 4];
        body.extend_from_slice(&width.to_be_bytes());
        body.extend_from_slice(&height.to_be_bytes());
        boxed(b"ispe", &body)
    }

    /// Version 0 `iloc` with one item of one extent.
    fn iloc(offset: u32, length: u32) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0, 0x44, 0x00];
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0, 1, 0, 0]);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&offset.to_be_bytes());
        body.extend_from_slice(&length.to_be_bytes());
        boxed(b"iloc", &body)
    }

    /// A HEIC with a 4-byte payload; `location` is the item's offset and length.
    pub(crate) fn heic(sizes: &[(u32, u32)], location: Option<(u32, u32)>) -> Vec<u8> {
        let properties: Vec<u8> = sizes.iter().flat_map(|&(w, h)| ispe(w, h)).collect();
        let build = |offset: u32, length: u32| {
            let mut meta = vec![0; 4];
            meta.extend(boxed(b"hdlr", &[0; 12]));
            meta.extend(iloc(offset, length));
            meta.extend(boxed(b"iprp", &boxed(b"ipco", &properties)));
            let mut data = boxed(b"ftyp", b"heic\0\0\0\0mif1heic");
            data.extend(boxed(b"meta", &meta));
            data.extend(boxed(b"mdat", b"\x01\x02\x03\x04"));
            data
        };
        let payload = build(0, 0).len() as u32 - 4;
        let (offset, length) = location.unwrap_or((payload, 4));
        build(offset, length)
    }

    #[test]
    fn reads_the_largest_extent_and_the_end() {
        let mut data = heic(&[(512, 512), (4032, 3024), (160, 120)], None);
        let end = data.len();
        data.extend_from_slice(b"\0\0\0\0<appended>");
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(end),
                dimensions: Some((4032, 3024)),
            })
        );
    }

    #[test]
    fn large_and_open_ended_boxes() {
        let mut data = heic(&[(8, 8)], None);
        // A box with a 64-bit size, then one that runs to the end of the file.
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(b"free");
        data.extend_from_slice(&20u64.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(b"mdat rest of the file");
        assert_eq!(parse(&data).unwrap().end, Some(data.len()));
    }

    #[test]
    fn rejects_broken_files() {
        let data = heic(&[(8, 8)], None);
        assert!(parse(&data[..data.len() - 1]).is_err());
        assert_eq!(
            parse(&boxed(b"ftyp", b"heic\0\0\0\0")).unwrap_err().reason,
            "image has no meta box"
        );
        assert_eq!(
            parse(&heic(&[], None)).unwrap_err().reason,
            "image declares no dimensions"
        );
        let end = data.len() as u32;
        assert_eq!(
            parse(&heic(&[(8, 8)], Some((end - 2, 4))))
                .unwrap_err()
                .reason,
            "image data is out of bounds"
        );
        assert_eq!(
            parse(&heic(&[(8, 8)], Some((u32::MAX, u32::MAX))))
                .unwrap_err()
                .reason,
            "image data is out of bounds"
        );
        // A child box that overruns its parent.
        let mut overrun = data.clone();
        let hdlr = overrun.windows(4).position(|w| w == b"hdlr").unwrap();
        overrun[hdlr - 1] = 0xFF;
        assert_eq!(
            parse(&overrun).unwrap_err().reason,
            "box contents are malformed"
        );
    }
}
