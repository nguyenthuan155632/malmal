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
    /// BigTIFF: 64-bit offsets and counts, 20-byte directory entries.
    big: bool,
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

    fn u64(&self, offset: u64) -> Option<u64> {
        let bytes = self.bytes(offset)?;
        Some(if self.little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    /// An offset or count field, whose width depends on the flavour.
    fn word(&self, offset: u64) -> Option<u64> {
        if self.big {
            self.u64(offset)
        } else {
            self.u32(offset).map(u64::from)
        }
    }

    fn word_size(&self) -> u64 {
        if self.big { 8 } else { 4 }
    }

    fn spend(&mut self, amount: u64, offset: u64) -> Result<(), Malformed> {
        self.work = self.work.saturating_add(amount);
        if self.work > MAX_WORK {
            return Err(Malformed::new(
                offset as usize,
                "TIFF structure is too large to analyze",
            ));
        }
        Ok(())
    }

    /// Values of a SHORT, LONG, LONG8 or IFD entry; empty for any other type.
    fn values(&mut self, kind: u16, count: u64, at: u64) -> Result<Vec<u64>, Malformed> {
        let read: fn(&Self, u64) -> Option<u64> = match kind {
            3 => |tiff, offset| tiff.u16(offset).map(u64::from),
            4 | 13 => |tiff, offset| tiff.u32(offset).map(u64::from),
            16 | 18 => Self::u64,
            _ => return Ok(Vec::new()),
        };
        self.spend(count, at)?;
        let width = type_size(kind).unwrap_or(0);
        (0..count)
            .map(|i| read(self, at + i * width))
            .collect::<Option<Vec<u64>>>()
            .ok_or(Malformed::truncated(at as usize))
    }
}

fn type_size(kind: u16) -> Option<u64> {
    match kind {
        1 | 2 | 6 | 7 => Some(1),
        3 | 8 => Some(2),
        4 | 9 | 11 | 13 => Some(4),
        // 16 to 18 are the 64-bit types BigTIFF adds.
        5 | 10 | 12 | 16 | 17 | 18 => Some(8),
        _ => None,
    }
}

/// TIFF has no end marker, so the end is the furthest byte any directory,
/// entry value or image strip refers to.
pub(crate) fn parse(data: &[u8]) -> Result<Layout, Malformed> {
    let mut tiff = Tiff {
        data,
        little_endian: data.starts_with(b"II"),
        big: false,
        work: 0,
    };
    let file_len = data.len() as u64;
    let truncated = Malformed::truncated(data.len());
    let (first, mut extent) = match tiff.u16(2) {
        Some(42) => (tiff.word(4).ok_or(truncated)?, 8u64),
        Some(43) => {
            tiff.big = true;
            // Offsets are declared as 8 bytes wide, followed by a reserved zero.
            if tiff.u16(4) != Some(8) || tiff.u16(6) != Some(0) {
                return Err(Malformed::new(4, "BigTIFF header is malformed"));
            }
            (tiff.word(8).ok_or(truncated)?, 16u64)
        }
        _ => return Err(Malformed::new(2, "unknown TIFF version")),
    };
    // Count, tag entries, then the offset of the next directory.
    let word = tiff.word_size();
    let (count_size, entry_size) = if tiff.big { (8, 20) } else { (2, 12) };

    let (mut width, mut height) = (None, None);
    let mut visited = HashSet::new();
    let mut queue = vec![first];
    while let Some(ifd) = queue.pop() {
        if !visited.insert(ifd) {
            return Err(Malformed::new(ifd as usize, "TIFF directories form a loop"));
        }
        if visited.len() > MAX_IFDS {
            return Err(Malformed::new(
                ifd as usize,
                "TIFF has too many directories",
            ));
        }
        let is_first = visited.len() == 1;

        let out_of_bounds = Malformed::new(ifd as usize, "TIFF directory is out of bounds");
        let count = if tiff.big {
            tiff.u64(ifd)
        } else {
            tiff.u16(ifd).map(u64::from)
        };
        // A count the file cannot hold would overflow the arithmetic below.
        let Some(count) = count.filter(|&count| count <= file_len / entry_size) else {
            return Err(out_of_bounds);
        };
        let Some(entries) = ifd.checked_add(count_size) else {
            return Err(out_of_bounds);
        };
        let Some(entries_end) = entries.checked_add(count * entry_size) else {
            return Err(out_of_bounds);
        };
        let Some(next) = tiff.word(entries_end) else {
            return Err(out_of_bounds);
        };
        extent = extent.max(entries_end + word);
        tiff.spend(count, ifd)?;

        let mut data_offsets: [Vec<u64>; 3] = Default::default();
        let mut data_lengths: [Vec<u64>; 3] = Default::default();
        for index in 0..count {
            // Entry fields are in bounds: the directory's end was read above.
            let entry = entries + index * entry_size;
            let tag = tiff.u16(entry).unwrap_or(0);
            let kind = tiff.u16(entry + 2).unwrap_or(0);
            let value_count = tiff.word(entry + 4).unwrap_or(0);
            // Readers skip entries of unknown type.
            let Some(size) = type_size(kind) else {
                continue;
            };
            let out_of_bounds = Malformed::new(entry as usize, "TIFF entry data is out of bounds");
            let Some(total) = size.checked_mul(value_count) else {
                return Err(out_of_bounds);
            };
            // Values that fit in the offset field are stored there.
            let value_field = entry + 4 + word;
            let at = if total <= word {
                value_field
            } else {
                let at = tiff.word(value_field).unwrap_or(0);
                match at.checked_add(total) {
                    Some(end) if end <= file_len => extent = extent.max(end),
                    _ => return Err(out_of_bounds),
                }
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
                match start.checked_add(length) {
                    Some(end) if end <= file_len => extent = extent.max(end),
                    _ => {
                        return Err(Malformed::new(
                            ifd as usize,
                            "TIFF image data is out of bounds",
                        ));
                    }
                }
            }
        }
        if next != 0 {
            queue.push(next);
        }
    }

    Ok(Layout {
        end: Some(extent as usize),
        dimensions: width.zip(height),
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
        assert!(parse(b"II\x2C\0\x08\0\0\0").is_err());
    }

    fn big_entry(tag: u16, kind: u16, count: u64, value: u64) -> Vec<u8> {
        let mut out = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    /// The same image as [`tiff`] in the 64-bit flavour.
    fn big_tiff(entry_count: u64, next_ifd: u64, strip_len: u64) -> Vec<u8> {
        let strip_offset = 16 + 8 + 4 * 20 + 8;
        let mut data = b"II+\0\x08\0\0\0".to_vec();
        data.extend_from_slice(&16u64.to_le_bytes());
        data.extend_from_slice(&entry_count.to_le_bytes());
        data.extend(big_entry(256, 3, 1, 6));
        data.extend(big_entry(257, 16, 1, 9));
        data.extend(big_entry(273, 16, 1, strip_offset));
        data.extend(big_entry(279, 16, 1, strip_len));
        data.extend_from_slice(&next_ifd.to_le_bytes());
        data.extend_from_slice(b"\x01\x02\x03\x04");
        data
    }

    #[test]
    fn reads_bigtiff() {
        let mut data = big_tiff(4, 0, 4);
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
    fn rejects_broken_bigtiff() {
        assert_eq!(
            parse(&big_tiff(4, 16, 4)).unwrap_err().reason,
            "TIFF directories form a loop"
        );
        assert_eq!(
            parse(&big_tiff(4, 0, u64::MAX)).unwrap_err().reason,
            "TIFF image data is out of bounds"
        );
        assert_eq!(
            parse(&big_tiff(u64::MAX / 20, 0, 4)).unwrap_err().reason,
            "TIFF directory is out of bounds"
        );
        // Offsets that are not 8 bytes wide.
        let mut odd = big_tiff(4, 0, 4);
        odd[4] = 4;
        assert_eq!(
            parse(&odd).unwrap_err().reason,
            "BigTIFF header is malformed"
        );
        assert!(parse(&big_tiff(4, 0, 4)[..40]).is_err());
    }
}
