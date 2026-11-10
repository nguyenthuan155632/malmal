use std::collections::HashSet;

use super::{Layout, Malformed};

const MAX_IFDS: usize = 4096;
/// Cap on IFD entries plus array values read, so overlapping directories
/// cannot make a small file expensive to walk.
const MAX_WORK: u64 = 1 << 22;

const TAG_WIDTH: u16 = 256;
const TAG_HEIGHT: u16 = 257;
/// (offsets tag, byte counts tag) pairs that locate image data.
const DATA_TAGS: [(u16, u16); 3] = [(273, 279), (324, 325), (513, 514)];
/// SubIFDs, Exif, GPS and Interoperability directories.
const IFD_POINTER_TAGS: [u16; 4] = [330, 34665, 34853, 40965];

struct Tiff<'a> {
    data: &'a [u8],
    little_endian: bool,
    work: u64,
}

impl Tiff<'_> {
    fn bytes<const N: usize>(&self, offset: u64) -> Option<[u8; N]> {
        let offset = usize::try_from(offset).ok()?;
        self.data
            .get(offset..offset.checked_add(N)?)?
            .try_into()
            .ok()
    }

    fn u16(&self, offset: u64) -> Option<u16> {
        let bytes = self.bytes(offset)?;
        Some(if self.little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    fn u32(&self, offset: u64) -> Option<u32> {
        let bytes = self.bytes(offset)?;
        Some(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn spend(&mut self, amount: u64, offset: u64) -> Result<(), Malformed> {
        self.work += amount;
        if self.work > MAX_WORK {
            return Err(Malformed::new(
                offset as usize,
                "TIFF structure is too large to analyze",
            ));
        }
        Ok(())
    }

    /// Values of a SHORT, LONG or IFD entry; empty for any other type.
    fn values(&mut self, kind: u16, count: u64, at: u64) -> Result<Vec<u32>, Malformed> {
        let read: fn(&Self, u64) -> Option<u32> = match kind {
            3 => |tiff, offset| tiff.u16(offset).map(u32::from),
            4 | 13 => Self::u32,
            _ => return Ok(Vec::new()),
        };
        self.spend(count, at)?;
        let width = type_size(kind).unwrap_or(0);
        (0..count)
            .map(|i| read(self, at + i * width))
            .collect::<Option<Vec<u32>>>()
            .ok_or(Malformed::truncated(at as usize))
    }
}

fn type_size(kind: u16) -> Option<u64> {
    match kind {
        1 | 2 | 6 | 7 => Some(1),
        3 | 8 => Some(2),
        4 | 9 | 11 | 13 => Some(4),
        5 | 10 | 12 => Some(8),
        _ => None,
    }
}

/// TIFF has no end marker, so the end is the furthest byte any directory,
/// entry value or image strip refers to.
pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let mut tiff = Tiff {
        data,
        little_endian: data.starts_with(b"II"),
        work: 0,
    };
    let file_len = data.len() as u64;
    if tiff.u16(2) != Some(42) {
        return Err(Malformed::new(2, "BigTIFF is not supported"));
    }
    let first = tiff.u32(4).ok_or(Malformed::truncated(data.len()))?;

    let mut extent = 8u64;
    let (mut width, mut height) = (None, None);
    let mut visited = HashSet::new();
    let mut queue = vec![first];
    while let Some(offset) = queue.pop() {
        let ifd = offset as u64;
        if !visited.insert(offset) {
            return Err(Malformed::new(
                offset as usize,
                "TIFF directories form a loop",
            ));
        }
        if visited.len() > MAX_IFDS {
            return Err(Malformed::new(
                offset as usize,
                "TIFF has too many directories",
            ));
        }
        let is_first = visited.len() == 1;

        let out_of_bounds = Malformed::new(offset as usize, "TIFF directory is out of bounds");
        let Some(count) = tiff.u16(ifd).map(u64::from) else {
            return Err(out_of_bounds);
        };
        let entries_end = ifd + 2 + count * 12;
        let Some(next) = tiff.u32(entries_end) else {
            return Err(out_of_bounds);
        };
        extent = extent.max(entries_end + 4);
        tiff.spend(count, ifd)?;

        let mut data_offsets: [Vec<u32>; 3] = Default::default();
        let mut data_lengths: [Vec<u32>; 3] = Default::default();
        for index in 0..count {
            // Entry fields are in bounds: the directory's end was read above.
            let entry = ifd + 2 + index * 12;
            let tag = tiff.u16(entry).unwrap_or(0);
            let kind = tiff.u16(entry + 2).unwrap_or(0);
            let value_count = tiff.u32(entry + 4).unwrap_or(0) as u64;
            // Readers skip entries of unknown type.
            let Some(size) = type_size(kind) else {
                continue;
            };
            let total = size * value_count;
            let at = if total <= 4 {
                entry + 8
            } else {
                let at = tiff.u32(entry + 8).unwrap_or(0) as u64;
                if at + total > file_len {
                    return Err(Malformed::new(
                        entry as usize,
                        "TIFF entry data is out of bounds",
                    ));
                }
                extent = extent.max(at + total);
                at
            };

            if is_first && (tag == TAG_WIDTH || tag == TAG_HEIGHT) {
                let value = tiff.values(kind, value_count.min(1), at)?.first().copied();
                if tag == TAG_WIDTH {
                    width = value;
                } else {
                    height = value;
                }
            } else if let Some(slot) = DATA_TAGS.iter().position(|pair| pair.0 == tag) {
                data_offsets[slot] = tiff.values(kind, value_count, at)?;
            } else if let Some(slot) = DATA_TAGS.iter().position(|pair| pair.1 == tag) {
                data_lengths[slot] = tiff.values(kind, value_count, at)?;
            } else if IFD_POINTER_TAGS.contains(&tag) {
                let pointers = tiff.values(kind, value_count, at)?;
                queue.extend(pointers.into_iter().filter(|&pointer| pointer != 0));
            }
        }

        for (offsets, lengths) in data_offsets.iter().zip(&data_lengths) {
            for (&start, &length) in offsets.iter().zip(lengths) {
                let end = start as u64 + length as u64;
                if end > file_len {
                    return Err(Malformed::new(
                        offset as usize,
                        "TIFF image data is out of bounds",
                    ));
                }
                extent = extent.max(end);
            }
        }
        if next != 0 {
            queue.push(next);
        }
    }

    Ok(Layout {
        end: Some(extent as usize),
        dimensions: width
            .zip(height)
            .map(|(width, height)| (width as u64, height as u64)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u16, kind: u16, count: u32, value: u32) -> Vec<u8> {
        let mut out = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    /// One directory at offset 8 followed by a 4-byte strip.
    fn tiff(next_ifd: u32, strip_len: u32) -> Vec<u8> {
        let strip_offset = 8 + 2 + 4 * 12 + 4;
        let mut data = b"II*\0\x08\0\0\0".to_vec();
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend(entry(256, 3, 1, 6));
        data.extend(entry(257, 4, 1, 9));
        data.extend(entry(273, 4, 1, strip_offset));
        data.extend(entry(279, 4, 1, strip_len));
        data.extend_from_slice(&next_ifd.to_le_bytes());
        data.extend_from_slice(b"\x01\x02\x03\x04");
        data
    }

    #[test]
    fn end_is_the_furthest_referenced_byte() {
        let mut data = tiff(0, 4);
        let end = data.len();
        data.extend_from_slice(b"appended");
        assert_eq!(
            parse(&data),
            Ok(Layout {
                end: Some(end),
                dimensions: Some((6, 9)),
            })
        );
    }

    #[test]
    fn reads_big_endian() {
        let mut data = b"MM\0*\0\0\0\x08".to_vec();
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(b"\x01\x00\x00\x03\0\0\0\x01\x00\x07\0\0");
        data.extend_from_slice(&[0; 4]);
        assert_eq!(parse(&data).unwrap().end, Some(data.len()));
    }

    #[test]
    fn rejects_loops_and_out_of_bounds_references() {
        assert_eq!(
            parse(&tiff(8, 4)).unwrap_err().reason,
            "TIFF directories form a loop"
        );
        assert_eq!(
            parse(&tiff(0, 400)).unwrap_err().reason,
            "TIFF image data is out of bounds"
        );
        assert_eq!(
            parse(&tiff(9000, 4)).unwrap_err().reason,
            "TIFF directory is out of bounds"
        );
        assert!(parse(b"II+\0\x08\0\0\0").is_err());
    }
}
