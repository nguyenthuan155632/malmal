//! A lossy WebP picture written anew without being decoded to pixels.
//!
//! A VP8 key frame is a run of symbols, each coded with a boolean
//! arithmetic coder at a probability that the symbols before it decide:
//! the frame's settings, then each macroblock's prediction modes and the
//! quantised coefficients of its blocks. Each symbol is read here and at
//! once written again at the same probability, so the new frame holds the
//! same symbols and decodes to the same pixels. What the coder would never
//! read is not carried over: bytes after the end of a partition, and the
//! padding of the last one.
//!
//! The syntax is that of RFC 6386, sections 9 to 13; frames that are not
//! key frames, which WebP does not use, are refused.

mod tables;

use super::{Deadline, Error};
use tables::{COEFF_PROBS, COEFF_UPDATE_PROBS, KEYFRAME_BPRED_MODE_PROBS, Tokens};

fn broken() -> Error {
    Error::Decode("VP8 frame is broken".into())
}

/// RFC 6386, section 7.3: the decoder, reading zeros past the end as the
/// reference decoder does.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    value: u32,
    range: u32,
    bits: i32,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut reader = Self {
            data,
            at: 0,
            value: 0,
            range: 255,
            bits: 0,
        };
        reader.value = (u32::from(reader.byte()) << 8) | u32::from(reader.byte());
        reader
    }

    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        byte
    }

    fn bool(&mut self, probability: u8) -> bool {
        let split = 1 + (((self.range - 1) * u32::from(probability)) >> 8);
        let high = split << 8;
        let bit = self.value >= high;
        if bit {
            self.range -= split;
            self.value -= high;
        } else {
            self.range = split;
        }
        while self.range < 128 {
            self.value <<= 1;
            self.range <<= 1;
            self.bits += 1;
            if self.bits == 8 {
                self.bits = 0;
                self.value |= u32::from(self.byte());
            }
        }
        bit
    }

    /// Whether it has read more than the two bytes past the end that a
    /// complete partition can make it read.
    fn overran(&self) -> bool {
        self.at > self.data.len() + 2
    }
}

/// RFC 6386, section 7.3: the encoder.
struct Writer {
    out: Vec<u8>,
    range: u32,
    bottom: u32,
    bits: i32,
}

impl Writer {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            range: 255,
            bottom: 0,
            bits: 24,
        }
    }

    /// Carry into the bytes already written.
    fn carry(out: &mut [u8]) {
        for byte in out.iter_mut().rev() {
            if *byte == 255 {
                *byte = 0;
            } else {
                *byte += 1;
                return;
            }
        }
    }

    fn bool(&mut self, probability: u8, bit: bool) {
        let split = 1 + (((self.range - 1) * u32::from(probability)) >> 8);
        if bit {
            self.bottom = self.bottom.wrapping_add(split);
            self.range -= split;
        } else {
            self.range = split;
        }
        while self.range < 128 {
            self.range <<= 1;
            if self.bottom & (1 << 31) != 0 {
                Self::carry(&mut self.out);
            }
            self.bottom <<= 1;
            self.bits -= 1;
            if self.bits == 0 {
                self.out.push((self.bottom >> 24) as u8);
                self.bottom &= (1 << 24) - 1;
                self.bits = 8;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        let mut count = self.bits;
        let mut value = self.bottom;
        if value & (1 << (32 - count)) != 0 {
            Self::carry(&mut self.out);
        }
        value <<= count & 7;
        count >>= 3;
        while count > 0 {
            value <<= 8;
            count -= 1;
        }
        for _ in 0..4 {
            self.out.push((value >> 24) as u8);
            value <<= 8;
        }
        self.out
    }
}

/// Each symbol read, written again.
struct Copy<'a> {
    reader: Reader<'a>,
    writer: Writer,
}

impl<'a> Copy<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(data),
            writer: Writer::new(),
        }
    }

    fn bool(&mut self, probability: u8) -> bool {
        let bit = self.reader.bool(probability);
        self.writer.bool(probability, bit);
        bit
    }

    fn flag(&mut self) -> bool {
        self.bool(128)
    }

    fn literal(&mut self, bits: u32) -> u32 {
        (0..bits).fold(0, |value, _| (value << 1) | u32::from(self.flag()))
    }

    /// A value of `bits` and a sign, if the flag before it is set.
    fn optional_signed(&mut self, bits: u32) -> i32 {
        if !self.flag() {
            return 0;
        }
        let magnitude = self.literal(bits) as i32;
        if self.flag() { -magnitude } else { magnitude }
    }

    /// A tree laid out as RFC 6386 lays them out, from node `start`.
    fn tree(&mut self, tree: &[i8], probabilities: &[u8], start: usize) -> i8 {
        let mut index = start;
        loop {
            let next = tree[index + usize::from(self.bool(probabilities[index >> 1]))];
            if next <= 0 {
                return -next;
            }
            index = next as usize;
        }
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        if self.reader.overran() {
            return Err(broken());
        }
        Ok(self.writer.finish())
    }
}

const SEGMENT_TREE: [i8; 6] = [2, 4, 0, -1, -2, -3];
const B_PRED: i8 = 4;
const YMODE_TREE: [i8; 8] = [-B_PRED, 2, 4, 6, 0, -1, -2, -3];
const YMODE_PROBS: [u8; 4] = [145, 156, 163, 128];
const UV_MODE_TREE: [i8; 6] = [0, 2, -1, 4, -2, -3];
const UV_MODE_PROBS: [u8; 3] = [142, 114, 183];
/// Modes of a 4x4 block: DC, TM, VE, HE, LD, RD, VR, VL, HD, HU.
const BMODE_TREE: [i8; 18] = [
    0, 2, -1, 4, -2, 6, 8, 12, -3, 10, -5, -6, -4, 14, -7, 16, -8, -9,
];
/// The 4x4 mode a whole-block luma mode counts as: DC, V, H, TM.
const BMODE_OF_YMODE: [u8; 4] = [0, 2, 3, 1];

const EOB: i8 = 11;
const ZERO: i8 = 0;
const TOKEN_TREE: [i8; 22] = [
    -EOB, 2, ZERO, 4, -1, 6, 8, 12, -2, 10, -3, -4, 14, 16, -5, -6, 18, 20, -7, -8, -9, -10,
];
/// Extra bits of the categories of large coefficients.
const CATEGORY_PROBS: [&[u8]; 6] = [
    &[159],
    &[165, 145],
    &[173, 148, 140],
    &[176, 155, 140, 135],
    &[180, 157, 141, 134, 130],
    &[254, 254, 243, 230, 196, 177, 153, 140, 133, 130, 129],
];
const BANDS: [usize; 16] = [0, 1, 2, 3, 6, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7];

/// What the macroblocks above and to the left decide of the next one: the
/// modes of their 4x4 blocks along the edge, and whether each block along
/// it had coefficients (the second-order block first, then four luma, two
/// of each chroma).
#[derive(Clone, Copy, Default)]
struct Edge {
    modes: [u8; 4],
    coded: [bool; 9],
}

/// The coefficients of one block; whether any token but the end was read.
fn block(
    copy: &mut Copy<'_>,
    probabilities: &[[[u8; 11]; 3]; 8],
    first: usize,
    context: usize,
) -> bool {
    let mut context = context;
    let mut after_zero = false;
    let mut coded = false;
    for index in first..16 {
        let node = &probabilities[BANDS[index]][context];
        let token = copy.tree(&TOKEN_TREE, node, if after_zero { 2 } else { 0 });
        if token == EOB {
            break;
        }
        coded = true;
        if token == ZERO {
            after_zero = true;
            context = 0;
            continue;
        }
        if let Some(extra) = (token as usize).checked_sub(5).map(|c| CATEGORY_PROBS[c]) {
            for &probability in extra {
                copy.bool(probability);
            }
        }
        after_zero = false;
        context = if token == 1 { 1 } else { 2 };
        // The sign.
        copy.flag();
    }
    coded
}

/// The VP8 frame in `frame`, written anew from the symbols it codes.
pub(super) fn rewrite(frame: &[u8], deadline: Deadline) -> Result<Vec<u8>, Error> {
    let header = frame.get(..10).ok_or_else(broken)?;
    let tag = u32::from(header[0]) | u32::from(header[1]) << 8 | u32::from(header[2]) << 16;
    if tag & 1 != 0 || header[3..6] != [0x9D, 0x01, 0x2A] {
        return Err(Error::Decode("VP8 frame is not a key frame".into()));
    }
    let (version, shown) = ((tag >> 1) & 7, (tag >> 4) & 1);
    let first_size = (tag >> 5) as usize;
    let width = u16::from_le_bytes([header[6], header[7]]) & 0x3FFF;
    let height = u16::from_le_bytes([header[8], header[9]]) & 0x3FFF;
    let first = frame.get(10..10 + first_size).ok_or_else(broken)?;
    let mut head = Copy::new(first);

    // Section 9.2 to 9.6: colour space and clamping, segments, the loop
    // filter, partitions and quantisers.
    if head.literal(1) != 0 {
        return Err(Error::Decode("VP8 colour space is reserved".into()));
    }
    head.literal(1);
    let segments = head.flag();
    let mut update_map = false;
    let mut segment_probs = [255u8; 3];
    if segments {
        update_map = head.flag();
        if head.flag() {
            head.flag();
            for _ in 0..4 {
                head.optional_signed(7);
            }
            for _ in 0..4 {
                head.optional_signed(6);
            }
        }
        if update_map {
            for probability in &mut segment_probs {
                *probability = if head.flag() {
                    head.literal(8) as u8
                } else {
                    255
                };
            }
        }
    }
    head.flag();
    head.literal(6);
    head.literal(3);
    if head.flag() && head.flag() {
        for _ in 0..8 {
            head.optional_signed(6);
        }
    }
    let partitions = 1usize << head.literal(2);

    // The sizes of all partitions but the last, then the partitions.
    let after = 10 + first_size;
    let sizes_end = after + 3 * (partitions - 1);
    let sizes = frame.get(after..sizes_end).ok_or_else(broken)?;
    let mut parts = Vec::with_capacity(partitions);
    let mut at = sizes_end;
    for index in 0..partitions {
        let size = match sizes.get(index * 3..index * 3 + 3) {
            Some(s) => usize::from(s[0]) | usize::from(s[1]) << 8 | usize::from(s[2]) << 16,
            None => frame.len().saturating_sub(at),
        };
        let part = frame.get(at..at + size).ok_or_else(broken)?;
        parts.push(Copy::new(part));
        at += size;
    }

    head.literal(7);
    for _ in 0..5 {
        head.optional_signed(4);
    }
    // Whether to keep the probabilities, which a still picture does not use.
    head.literal(1);
    let mut probabilities: Tokens = COEFF_PROBS;
    for (plane, bands) in COEFF_UPDATE_PROBS.iter().enumerate() {
        for (band, contexts) in bands.iter().enumerate() {
            for (context, nodes) in contexts.iter().enumerate() {
                for (node, &update) in nodes.iter().enumerate() {
                    if head.bool(update) {
                        probabilities[plane][band][context][node] = head.literal(8) as u8;
                    }
                }
            }
        }
    }
    let skip_probability = (head.literal(1) == 1).then(|| head.literal(8) as u8);

    // Section 19.3: the macroblocks, row by row.
    let across = usize::from(width).div_ceil(16);
    let down = usize::from(height).div_ceil(16);
    let mut above = vec![Edge::default(); across];
    for row in 0..down {
        deadline.check()?;
        let part = &mut parts[row % partitions];
        let mut left = Edge::default();
        for top in &mut above {
            if update_map {
                head.tree(&SEGMENT_TREE, &segment_probs, 0);
            }
            let skipped = skip_probability.is_some_and(|p| head.bool(p));
            let ymode = head.tree(&YMODE_TREE, &YMODE_PROBS, 0);
            if ymode == B_PRED {
                for y in 0..4 {
                    for x in 0..4 {
                        let context = &KEYFRAME_BPRED_MODE_PROBS[usize::from(top.modes[x])]
                            [usize::from(left.modes[y])];
                        let mode = head.tree(&BMODE_TREE, context, 0) as u8;
                        top.modes[x] = mode;
                        left.modes[y] = mode;
                    }
                }
            } else {
                let mode = BMODE_OF_YMODE[ymode as usize];
                top.modes = [mode; 4];
                left.modes = [mode; 4];
            }
            head.tree(&UV_MODE_TREE, &UV_MODE_PROBS, 0);

            let whole = ymode != B_PRED;
            if skipped {
                // A macroblock without coefficients leaves none along its
                // edges; the second-order block only if it has one.
                let from = if whole { 0 } else { 1 };
                top.coded[from..].fill(false);
                left.coded[from..].fill(false);
                continue;
            }
            // The second-order block of luma DC, then the luma blocks
            // without it or with it, then the chroma blocks.
            let luma_plane = if whole {
                let context = usize::from(top.coded[0]) + usize::from(left.coded[0]);
                let coded = block(part, &probabilities[1], 0, context);
                top.coded[0] = coded;
                left.coded[0] = coded;
                0
            } else {
                3
            };
            let first_coefficient = usize::from(whole);
            for y in 0..4 {
                for x in 0..4 {
                    let context = usize::from(top.coded[1 + x]) + usize::from(left.coded[1 + y]);
                    let coded = block(part, &probabilities[luma_plane], first_coefficient, context);
                    top.coded[1 + x] = coded;
                    left.coded[1 + y] = coded;
                }
            }
            for chroma in [5, 7] {
                for y in 0..2 {
                    for x in 0..2 {
                        let context = usize::from(top.coded[chroma + x])
                            + usize::from(left.coded[chroma + y]);
                        let coded = block(part, &probabilities[2], 0, context);
                        top.coded[chroma + x] = coded;
                        left.coded[chroma + y] = coded;
                    }
                }
            }
        }
    }

    let first = head.finish()?;
    let parts = parts
        .into_iter()
        .map(Copy::finish)
        .collect::<Result<Vec<_>, _>>()?;
    if first.len() >= 1 << 19 || parts.iter().any(|p| p.len() >= 1 << 24) {
        return Err(Error::TooLarge);
    }
    let tag = (first.len() as u32) << 5 | shown << 4 | version << 1;
    let mut out = Vec::with_capacity(frame.len());
    out.extend_from_slice(&tag.to_le_bytes()[..3]);
    out.extend_from_slice(&header[3..10]);
    out.extend_from_slice(&first);
    for part in &parts[..partitions - 1] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes()[..3]);
    }
    for part in &parts {
        out.extend_from_slice(part);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_written_reads_back() {
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        let symbols: Vec<(u8, bool)> = (0..20_000)
            .map(|_| {
                let value = next();
                let probability = (value % 255 + 1) as u8;
                (probability, (value >> 8) % 256 >= u32::from(probability))
            })
            .collect();
        let mut writer = Writer::new();
        for &(probability, bit) in &symbols {
            writer.bool(probability, bit);
        }
        let data = writer.finish();
        let mut reader = Reader::new(&data);
        for (index, &(probability, bit)) in symbols.iter().enumerate() {
            assert_eq!(reader.bool(probability), bit, "symbol {index}");
        }
        assert!(!reader.overran());
    }
}
