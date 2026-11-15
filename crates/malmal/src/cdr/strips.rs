//! Strips and tiles compressed in ways the `tiff` crate does not read,
//! stored uncompressed in the copy of the file it is given: CCITT
//! Modified Huffman and T.4, Zstandard and LZMA.

use std::io::{Cursor, Read, Write};

use super::Error;
use super::fax::{self, Coding};
use super::ifd::{Entry, Form, LONG, SHORT};
use crate::limits::Limits;

/// Bytes kept in the copy, and those that would pass `most`.
struct Capped<'a> {
    out: &'a mut Vec<u8>,
    most: u64,
}

impl Write for Capped<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (self.out.len() + bytes.len()) as u64 > self.most {
            return Err(std::io::Error::other("too large"));
        }
        self.out.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Rewrite the page whose `entries` these are, in `work`, as uncompressed
/// strips or tiles, if they are compressed in a way that calls for it.
pub(super) fn unpack(
    work: &mut Vec<u8>,
    form: Form,
    data: &[u8],
    entries: &[Entry],
    compression: u64,
    limits: &Limits,
) -> Result<(), Error> {
    if !matches!(compression, 2 | 3 | 34_925 | 50_000) {
        return Ok(());
    }
    let find = |tag: u16| entries.iter().find(|e| e.tag == tag).copied();
    let number = |tag: u16| find(tag).and_then(|e| form.value(data, &e));
    let broken = || Error::Decode("TIFF strips are not where the file says".into());
    let width = number(256).ok_or_else(broken)? as u32;
    let height = number(257).ok_or_else(broken)? as u32;
    let tiled = find(324).is_some();
    let (offsets, counts) = if tiled {
        (find(324), find(325))
    } else {
        (find(273), find(279))
    };
    let (offsets, counts) = (offsets.ok_or_else(broken)?, counts.ok_or_else(broken)?);
    let most = 1 << 20;
    let starts = form.values(data, &offsets, most).ok_or_else(broken)?;
    let lengths = form.values(data, &counts, most).ok_or_else(broken)?;
    if starts.len() != lengths.len() {
        return Err(broken());
    }
    // The size of each chunk, which CCITT coding does not record.
    let (chunk_width, chunk_height) = if tiled {
        (
            number(322).ok_or_else(broken)? as u32,
            number(323).ok_or_else(broken)? as u32,
        )
    } else {
        (
            width,
            number(278).map_or(height, |r| r.min(height.into()) as u32),
        )
    };
    let options = number(292).unwrap_or(0);
    let reversed = number(266) == Some(2);

    let mut new_starts = Vec::with_capacity(starts.len());
    let mut new_lengths = Vec::with_capacity(starts.len());
    let mut held = 0u64;
    for (index, (&start, &length)) in starts.iter().zip(&lengths).enumerate() {
        let start = usize::try_from(start).map_err(|_| broken())?;
        let end = usize::try_from(length)
            .ok()
            .and_then(|l| start.checked_add(l))
            .ok_or_else(broken)?;
        let packed = data.get(start..end).ok_or_else(broken)?;
        let budget = limits.max_decompressed.saturating_sub(held);
        let mut out = Vec::new();
        match compression {
            2 | 3 => {
                // The last strip, or a tile at the edge, holds only the rows
                // that are left; a tile is always whole.
                let rows = if tiled {
                    chunk_height
                } else {
                    let first = (index as u32).saturating_mul(chunk_height);
                    chunk_height.min(height.saturating_sub(first))
                };
                if (chunk_width as u64).div_ceil(8) * rows as u64 > budget {
                    return Err(Error::TooLarge);
                }
                let packed: Vec<u8> = if reversed {
                    packed.iter().map(|b| b.reverse_bits()).collect()
                } else {
                    packed.to_vec()
                };
                let coding = match compression {
                    2 => Coding::ModifiedHuffman,
                    _ => Coding::T4 {
                        two_d: options & 1 != 0,
                    },
                };
                if options & 2 != 0 && compression == 3 {
                    return Err(Error::Decode("TIFF with uncompressed fax mode".into()));
                }
                out = fax::decode(&packed, chunk_width, rows, coding)
                    .ok_or_else(|| Error::Decode("fax coding is broken".into()))?;
            }
            34_925 => {
                let mut capped = Capped {
                    out: &mut out,
                    most: budget,
                };
                xz(packed, &mut capped)?;
            }
            _ => {
                let decoder = ruzstd::decoding::StreamingDecoder::new(packed)
                    .map_err(|error| Error::Decode(format!("Zstandard: {error}")))?;
                decoder
                    .take(budget.saturating_add(1))
                    .read_to_end(&mut out)
                    .map_err(|error| Error::Decode(format!("Zstandard: {error}")))?;
                if out.len() as u64 > budget {
                    return Err(Error::TooLarge);
                }
            }
        }
        held += out.len() as u64;
        // Each chunk after the end of the copy.
        new_starts.push(work.len() as u64);
        new_lengths.push(out.len() as u64);
        work.extend_from_slice(&out);
    }
    let kind = form.offset_kind(work.len()).ok_or(Error::TooLarge)?;
    form.set(work, &offsets, kind, &new_starts);
    form.set(
        work,
        &counts,
        if kind == LONG { LONG } else { kind },
        &new_lengths,
    );
    if let Some(entry) = find(259) {
        form.set(work, &entry, SHORT, &[1]);
    }
    // Fax rows come out with the first pixel the highest bit.
    if let (2 | 3, Some(entry)) = (compression, find(266)) {
        form.set(work, &entry, SHORT, &[1]);
    }
    Ok(())
}

/// An xz stream, as libtiff writes one: blocks of LZMA2, after a delta
/// filter or not. `lzma-rs` reads LZMA2 but not the delta filter.
fn xz(data: &[u8], out: &mut Capped<'_>) -> Result<(), Error> {
    let broken = || Error::Decode("LZMA stream is broken".into());
    if data.get(..6) != Some(b"\xFD7zXZ\0") {
        return Err(broken());
    }
    // The size of the check after each block.
    let check = match data.get(7).ok_or_else(broken)? & 0x0F {
        0 => 0,
        1 => 4,
        4 => 8,
        10 => 32,
        _ => return Err(broken()),
    };
    let varint = |at: &mut usize| -> Result<u64, Error> {
        let mut value = 0u64;
        for shift in (0..63).step_by(7) {
            let byte = *data.get(*at).ok_or_else(broken)?;
            *at += 1;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(broken())
    };
    let mut at = 12;
    // A header size of 0 starts the index, which ends the blocks.
    while let Some(&size) = data.get(at).filter(|&&size| size != 0) {
        let header_end = at + (usize::from(size) + 1) * 4;
        let flags = *data.get(at + 1).ok_or_else(broken)?;
        let mut cursor = at + 2;
        if flags & 0x40 != 0 {
            varint(&mut cursor)?;
        }
        if flags & 0x80 != 0 {
            varint(&mut cursor)?;
        }
        let mut delta = None;
        for _ in 0..=(flags & 3) {
            let id = varint(&mut cursor)?;
            let length = varint(&mut cursor)? as usize;
            let properties = data.get(cursor..cursor + length).ok_or_else(broken)?;
            cursor += length;
            match (id, properties) {
                (3, [distance]) => delta = Some(usize::from(*distance) + 1),
                (0x21, [_]) => {}
                _ => return Err(Error::Decode("LZMA filter is not supported".into())),
            }
        }
        let start = out.out.len();
        let mut input = Cursor::new(data.get(header_end..).ok_or_else(broken)?);
        lzma_rs::lzma2_decompress(&mut input, out).map_err(|error| match error {
            lzma_rs::error::Error::IoError(_) => Error::TooLarge,
            other => Error::Decode(format!("LZMA: {other}")),
        })?;
        if let Some(distance) = delta {
            let block = &mut out.out[start..];
            for i in distance..block.len() {
                block[i] = block[i].wrapping_add(block[i - distance]);
            }
        }
        // Compressed data is padded to four bytes, then checked.
        at = (header_end + input.position() as usize).div_ceil(4) * 4 + check;
    }
    Ok(())
}
