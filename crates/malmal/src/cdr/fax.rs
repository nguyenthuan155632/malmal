//! CCITT bilevel coding as TIFF stores it with compression 2 (Modified
//! Huffman) and 3 (T.4, one or two-dimensional). Group 4 the `tiff` crate
//! reads itself.
//!
//! The codes are those of ITU-T T.4, tables 1 to 3 and 4.

use std::sync::OnceLock;

/// How the rows are coded.
#[derive(Clone, Copy)]
pub(super) enum Coding {
    /// Runs only, each row starting on a byte, no end-of-line codes.
    ModifiedHuffman,
    /// Rows after end-of-line codes; with `two_d`, each says whether it is
    /// coded from the row above.
    T4 { two_d: bool },
}

/// Runs of white: terminating codes 0 to 63, then make-up codes from 64.
const WHITE: &[(&str, u16)] = &[
    ("00110101", 0),
    ("000111", 1),
    ("0111", 2),
    ("1000", 3),
    ("1011", 4),
    ("1100", 5),
    ("1110", 6),
    ("1111", 7),
    ("10011", 8),
    ("10100", 9),
    ("00111", 10),
    ("01000", 11),
    ("001000", 12),
    ("000011", 13),
    ("110100", 14),
    ("110101", 15),
    ("101010", 16),
    ("101011", 17),
    ("0100111", 18),
    ("0001100", 19),
    ("0001000", 20),
    ("0010111", 21),
    ("0000011", 22),
    ("0000100", 23),
    ("0101000", 24),
    ("0101011", 25),
    ("0010011", 26),
    ("0100100", 27),
    ("0011000", 28),
    ("00000010", 29),
    ("00000011", 30),
    ("00011010", 31),
    ("00011011", 32),
    ("00010010", 33),
    ("00010011", 34),
    ("00010100", 35),
    ("00010101", 36),
    ("00010110", 37),
    ("00010111", 38),
    ("00101000", 39),
    ("00101001", 40),
    ("00101010", 41),
    ("00101011", 42),
    ("00101100", 43),
    ("00101101", 44),
    ("00000100", 45),
    ("00000101", 46),
    ("00001010", 47),
    ("00001011", 48),
    ("01010010", 49),
    ("01010011", 50),
    ("01010100", 51),
    ("01010101", 52),
    ("00100100", 53),
    ("00100101", 54),
    ("01011000", 55),
    ("01011001", 56),
    ("01011010", 57),
    ("01011011", 58),
    ("01001010", 59),
    ("01001011", 60),
    ("00110010", 61),
    ("00110011", 62),
    ("00110100", 63),
    ("11011", 64),
    ("10010", 128),
    ("010111", 192),
    ("0110111", 256),
    ("00110110", 320),
    ("00110111", 384),
    ("01100100", 448),
    ("01100101", 512),
    ("01101000", 576),
    ("01100111", 640),
    ("011001100", 704),
    ("011001101", 768),
    ("011010010", 832),
    ("011010011", 896),
    ("011010100", 960),
    ("011010101", 1024),
    ("011010110", 1088),
    ("011010111", 1152),
    ("011011000", 1216),
    ("011011001", 1280),
    ("011011010", 1344),
    ("011011011", 1408),
    ("010011000", 1472),
    ("010011001", 1536),
    ("010011010", 1600),
    ("011000", 1664),
    ("010011011", 1728),
];

/// Runs of black, likewise.
const BLACK: &[(&str, u16)] = &[
    ("0000110111", 0),
    ("010", 1),
    ("11", 2),
    ("10", 3),
    ("011", 4),
    ("0011", 5),
    ("0010", 6),
    ("00011", 7),
    ("000101", 8),
    ("000100", 9),
    ("0000100", 10),
    ("0000101", 11),
    ("0000111", 12),
    ("00000100", 13),
    ("00000111", 14),
    ("000011000", 15),
    ("0000010111", 16),
    ("0000011000", 17),
    ("0000001000", 18),
    ("00001100111", 19),
    ("00001101000", 20),
    ("00001101100", 21),
    ("00000110111", 22),
    ("00000101000", 23),
    ("00000010111", 24),
    ("00000011000", 25),
    ("000011001010", 26),
    ("000011001011", 27),
    ("000011001100", 28),
    ("000011001101", 29),
    ("000001101000", 30),
    ("000001101001", 31),
    ("000001101010", 32),
    ("000001101011", 33),
    ("000011010010", 34),
    ("000011010011", 35),
    ("000011010100", 36),
    ("000011010101", 37),
    ("000011010110", 38),
    ("000011010111", 39),
    ("000001101100", 40),
    ("000001101101", 41),
    ("000011011010", 42),
    ("000011011011", 43),
    ("000001010100", 44),
    ("000001010101", 45),
    ("000001010110", 46),
    ("000001010111", 47),
    ("000001100100", 48),
    ("000001100101", 49),
    ("000001010010", 50),
    ("000001010011", 51),
    ("000000100100", 52),
    ("000000110111", 53),
    ("000000111000", 54),
    ("000000100111", 55),
    ("000000101000", 56),
    ("000001011000", 57),
    ("000001011001", 58),
    ("000000101011", 59),
    ("000000101100", 60),
    ("000001011010", 61),
    ("000001100110", 62),
    ("000001100111", 63),
    ("0000001111", 64),
    ("000011001000", 128),
    ("000011001001", 192),
    ("000001011011", 256),
    ("000000110011", 320),
    ("000000110100", 384),
    ("000000110101", 448),
    ("0000001101100", 512),
    ("0000001101101", 576),
    ("0000001001010", 640),
    ("0000001001011", 704),
    ("0000001001100", 768),
    ("0000001001101", 832),
    ("0000001110010", 896),
    ("0000001110011", 960),
    ("0000001110100", 1024),
    ("0000001110101", 1088),
    ("0000001110110", 1152),
    ("0000001110111", 1216),
    ("0000001010010", 1280),
    ("0000001010011", 1344),
    ("0000001010100", 1408),
    ("0000001010101", 1472),
    ("0000001011010", 1536),
    ("0000001011011", 1600),
    ("0000001100100", 1664),
    ("0000001100101", 1728),
];

/// Make-up codes both colours share.
const LONG: &[(&str, u16)] = &[
    ("00000001000", 1792),
    ("00000001100", 1856),
    ("00000001101", 1920),
    ("000000010010", 1984),
    ("000000010011", 2048),
    ("000000010100", 2112),
    ("000000010101", 2176),
    ("000000010110", 2240),
    ("000000010111", 2304),
    ("000000011100", 2368),
    ("000000011101", 2432),
    ("000000011110", 2496),
    ("000000011111", 2560),
];

#[derive(Clone, Copy)]
enum Mode {
    Pass,
    Horizontal,
    Vertical(i8),
}

const MODES: &[(&str, Mode)] = &[
    ("0001", Mode::Pass),
    ("001", Mode::Horizontal),
    ("1", Mode::Vertical(0)),
    ("011", Mode::Vertical(1)),
    ("000011", Mode::Vertical(2)),
    ("0000011", Mode::Vertical(3)),
    ("010", Mode::Vertical(-1)),
    ("000010", Mode::Vertical(-2)),
    ("0000010", Mode::Vertical(-3)),
];

/// Longest code, in bits.
const WIDEST: u32 = 13;

/// A table looked up by the next `WIDEST` bits: the value and the length
/// of the code they start with, or none.
struct Table<T: Copy>(Vec<Option<(T, u8)>>);

impl<T: Copy> Table<T> {
    fn new(codes: &[&[(&str, T)]]) -> Self {
        let mut table = vec![None; 1 << WIDEST];
        for &(code, value) in codes.iter().flat_map(|c| c.iter()) {
            let length = code.len() as u32;
            let bits = u32::from_str_radix(code, 2).unwrap_or(0);
            let first = (bits << (WIDEST - length)) as usize;
            for entry in &mut table[first..first + (1 << (WIDEST - length))] {
                *entry = Some((value, length as u8));
            }
        }
        Self(table)
    }
}

fn white() -> &'static Table<u16> {
    static TABLE: OnceLock<Table<u16>> = OnceLock::new();
    TABLE.get_or_init(|| Table::new(&[WHITE, LONG]))
}

fn black() -> &'static Table<u16> {
    static TABLE: OnceLock<Table<u16>> = OnceLock::new();
    TABLE.get_or_init(|| Table::new(&[BLACK, LONG]))
}

fn modes() -> &'static Table<Mode> {
    static TABLE: OnceLock<Table<Mode>> = OnceLock::new();
    TABLE.get_or_init(|| Table::new(&[MODES]))
}

struct Bits<'a> {
    data: &'a [u8],
    /// The next bit to read.
    at: usize,
}

impl Bits<'_> {
    /// The next `count` bits, zeros past the end.
    fn peek(&self, count: u32) -> u32 {
        let mut value = 0;
        for bit in self.at..self.at + count as usize {
            let byte = self.data.get(bit / 8).copied().unwrap_or(0);
            value = (value << 1) | u32::from((byte >> (7 - bit % 8)) & 1);
        }
        value
    }

    fn ended(&self) -> bool {
        self.at >= self.data.len() * 8
    }

    fn take<T: Copy>(&mut self, table: &Table<T>) -> Option<T> {
        let (value, length) = table.0[self.peek(WIDEST) as usize]?;
        self.at += length as usize;
        Some(value)
    }

    /// A run: make-up codes and the terminating code that ends them.
    fn run(&mut self, table: &Table<u16>) -> Option<u32> {
        let mut total = 0u32;
        loop {
            let length = self.take(table)?;
            total = total.checked_add(length.into())?;
            if length < 64 {
                return Some(total);
            }
        }
    }

    /// Skip an end-of-line code, and the fill zeros before it, if one is
    /// next.
    fn end_of_line(&mut self) -> bool {
        let mut zeros = 0;
        while !self.ended() && self.peek(1) == 0 {
            zeros += 1;
            self.at += 1;
        }
        if zeros >= 11 && !self.ended() {
            self.at += 1;
            true
        } else {
            self.at -= zeros;
            false
        }
    }

    fn align(&mut self) {
        self.at = self.at.div_ceil(8) * 8;
    }
}

/// Where the colour changes along a row, as T.4 counts: positions of the
/// first pixel of each run after the first, which is white.
type Changes = Vec<u32>;

fn one_dimensional(bits: &mut Bits<'_>, width: u32) -> Option<Changes> {
    let mut changes = Vec::new();
    let (mut at, mut is_white) = (0u32, true);
    while at < width {
        let run = bits.run(if is_white { white() } else { black() })?;
        at = at.checked_add(run)?.min(width);
        changes.push(at);
        is_white = !is_white;
    }
    Some(changes)
}

fn two_dimensional(bits: &mut Bits<'_>, width: u32, above: &[u32]) -> Option<Changes> {
    let mut changes = Vec::new();
    // Before the first pixel, white.
    let (mut a0, mut is_white, mut start) = (0u32, true, true);
    while a0 < width {
        // The first change above, right of a0, to the colour a0 is not;
        // changes to black are at even places.
        let mut index = above.partition_point(|&b| if start { false } else { b <= a0 });
        if index % 2 != usize::from(!is_white) {
            index += 1;
        }
        let b1 = above.get(index).copied().unwrap_or(width);
        let b2 = above.get(index + 1).copied().unwrap_or(width);
        match bits.take(modes())? {
            Mode::Pass => a0 = b2,
            Mode::Horizontal => {
                let (first, second) = if is_white {
                    (white(), black())
                } else {
                    (black(), white())
                };
                let a1 = a0.checked_add(bits.run(first)?)?.min(width);
                let a2 = a1.checked_add(bits.run(second)?)?.min(width);
                changes.extend([a1, a2]);
                a0 = a2;
            }
            Mode::Vertical(offset) => {
                let a1 = (i64::from(b1) + i64::from(offset)).clamp(0, width.into()) as u32;
                if !start && a1 < a0 {
                    return None;
                }
                changes.push(a1);
                a0 = a1;
                is_white = !is_white;
            }
        }
        start = false;
    }
    Some(changes)
}

/// `rows` rows of `width` pixels, packed eight a byte with the first the
/// highest, each row starting on a byte: 1 for black.
pub(super) fn decode(data: &[u8], width: u32, rows: u32, coding: Coding) -> Option<Vec<u8>> {
    let row_bytes = (width as usize).div_ceil(8);
    let mut out = vec![0u8; row_bytes * rows as usize];
    let mut bits = Bits { data, at: 0 };
    let mut above: Changes = Vec::new();
    for row in out.chunks_mut(row_bytes) {
        let changes = match coding {
            Coding::ModifiedHuffman => {
                bits.align();
                one_dimensional(&mut bits, width)?
            }
            Coding::T4 { two_d } => {
                bits.end_of_line();
                if two_d {
                    let tag = bits.peek(1);
                    bits.at += 1;
                    if tag == 1 {
                        one_dimensional(&mut bits, width)?
                    } else {
                        two_dimensional(&mut bits, width, &above)?
                    }
                } else {
                    one_dimensional(&mut bits, width)?
                }
            }
        };
        // Odd runs are black.
        for pair in changes.chunks(2) {
            let start = pair[0];
            let end = pair.get(1).copied().unwrap_or(width);
            for x in start..end.min(width) {
                row[x as usize / 8] |= 0x80 >> (x % 8);
            }
        }
        above = changes;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_prefix_free() {
        for codes in [&[WHITE, LONG][..], &[BLACK, LONG][..]] {
            let all: Vec<&str> = codes.iter().flat_map(|c| c.iter().map(|e| e.0)).collect();
            for a in &all {
                for b in &all {
                    assert!(a == b || !b.starts_with(a), "{a} {b}");
                }
            }
        }
    }

    #[test]
    fn one_row_of_runs() {
        // White 2 (0111), black 3 (10), white 3 (1000): 8 pixels.
        let data = [0b0111_1010, 0b0000_0000];
        let rows = decode(&data, 8, 1, Coding::ModifiedHuffman).unwrap();
        assert_eq!(rows, [0b0011_1000]);
    }
}
