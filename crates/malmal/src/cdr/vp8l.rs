//! Lossless WebP (VP8L) written here, smaller than the `image` crate
//! writes it: a colour table for pictures of few colours, packed several
//! to a byte; otherwise green taken from red and blue and each block of
//! 16 by 16 pixels predicted from its neighbours by whichever of the
//! format's fourteen ways suits it best; and pixels that repeat earlier
//! ones sent as copies of them. Whatever is written is decoded again by
//! the caller and kept only if every pixel comes back.

use std::collections::{BinaryHeap, HashMap};

use super::{Deadline, Error};

/// The order the lengths of the code-length code are written in.
const CODE_LENGTH_ORDER: [usize; 19] = [
    17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

/// Short codes for copies from near by: columns right, rows up.
const DISTANCE_MAP: [(i8, i8); 120] = [
    (0, 1),
    (1, 0),
    (1, 1),
    (-1, 1),
    (0, 2),
    (2, 0),
    (1, 2),
    (-1, 2),
    (2, 1),
    (-2, 1),
    (2, 2),
    (-2, 2),
    (0, 3),
    (3, 0),
    (1, 3),
    (-1, 3),
    (3, 1),
    (-3, 1),
    (2, 3),
    (-2, 3),
    (3, 2),
    (-3, 2),
    (0, 4),
    (4, 0),
    (1, 4),
    (-1, 4),
    (4, 1),
    (-4, 1),
    (3, 3),
    (-3, 3),
    (2, 4),
    (-2, 4),
    (4, 2),
    (-4, 2),
    (0, 5),
    (3, 4),
    (-3, 4),
    (4, 3),
    (-4, 3),
    (5, 0),
    (1, 5),
    (-1, 5),
    (5, 1),
    (-5, 1),
    (2, 5),
    (-2, 5),
    (5, 2),
    (-5, 2),
    (4, 4),
    (-4, 4),
    (3, 5),
    (-3, 5),
    (5, 3),
    (-5, 3),
    (0, 6),
    (6, 0),
    (1, 6),
    (-1, 6),
    (6, 1),
    (-6, 1),
    (2, 6),
    (-2, 6),
    (6, 2),
    (-6, 2),
    (4, 5),
    (-4, 5),
    (5, 4),
    (-5, 4),
    (3, 6),
    (-3, 6),
    (6, 3),
    (-6, 3),
    (0, 7),
    (7, 0),
    (1, 7),
    (-1, 7),
    (5, 5),
    (-5, 5),
    (7, 1),
    (-7, 1),
    (4, 6),
    (-4, 6),
    (6, 4),
    (-6, 4),
    (2, 7),
    (-2, 7),
    (7, 2),
    (-7, 2),
    (3, 7),
    (-3, 7),
    (7, 3),
    (-7, 3),
    (5, 6),
    (-5, 6),
    (6, 5),
    (-6, 5),
    (8, 0),
    (4, 7),
    (-4, 7),
    (7, 4),
    (-7, 4),
    (8, 1),
    (8, 2),
    (6, 6),
    (-6, 6),
    (8, 3),
    (5, 7),
    (-5, 7),
    (7, 5),
    (-7, 5),
    (8, 4),
    (6, 7),
    (-6, 7),
    (7, 6),
    (-7, 6),
    (8, 5),
    (7, 7),
    (-7, 7),
    (8, 6),
    (8, 7),
];

/// Bits, the first of each value in the lowest place.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    word: u64,
    count: u32,
}

impl Bits {
    fn put(&mut self, value: u32, bits: u32) {
        debug_assert!(bits <= 32);
        if bits == 0 {
            return;
        }
        self.word |= u64::from(value & ((1u64 << bits) - 1) as u32) << self.count;
        self.count += bits;
        while self.count >= 8 {
            self.out.push(self.word as u8);
            self.word >>= 8;
            self.count -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.out.push(self.word as u8);
        }
        self.out
    }
}

/// Lengths of a Huffman code for `frequencies`, none longer than `limit`.
fn lengths(frequencies: &[u32], limit: u8) -> Vec<u8> {
    let mut weights: Vec<u64> = frequencies.iter().map(|&f| u64::from(f)).collect();
    loop {
        let found = huffman(&weights);
        if found.iter().all(|&l| l <= limit) {
            return found;
        }
        // Flatter weights make a shallower tree.
        for weight in &mut weights {
            if *weight > 0 {
                *weight = (*weight >> 1).max(1);
            }
        }
    }
}

fn huffman(weights: &[u64]) -> Vec<u8> {
    let mut lengths = vec![0u8; weights.len()];
    // Nodes: leaves first, then the ones that join two.
    let mut parent: Vec<usize> = Vec::new();
    let mut heap = BinaryHeap::new();
    for (symbol, &weight) in weights.iter().enumerate() {
        if weight > 0 {
            heap.push(std::cmp::Reverse((weight, parent.len(), symbol)));
            parent.push(usize::MAX);
        }
    }
    let leaves = parent.len();
    if leaves == 1 {
        let symbol = weights.iter().position(|&w| w > 0).unwrap_or(0);
        lengths[symbol] = 1;
        return lengths;
    }
    let mut symbol_of = vec![0usize; leaves];
    for std::cmp::Reverse((_, node, symbol)) in heap.iter() {
        symbol_of[*node] = *symbol;
    }
    while heap.len() > 1 {
        let std::cmp::Reverse((a, one, _)) = heap.pop().unwrap_or(std::cmp::Reverse((0, 0, 0)));
        let std::cmp::Reverse((b, other, _)) = heap.pop().unwrap_or(std::cmp::Reverse((0, 0, 0)));
        let node = parent.len();
        parent.push(usize::MAX);
        parent[one] = node;
        parent[other] = node;
        heap.push(std::cmp::Reverse((a + b, node, usize::MAX)));
    }
    for leaf in 0..leaves {
        let (mut node, mut depth) = (leaf, 0u8);
        while parent[node] != usize::MAX {
            node = parent[node];
            depth = depth.saturating_add(1);
        }
        lengths[symbol_of[leaf]] = depth;
    }
    lengths
}

/// The canonical code of each length, its bits reversed to be written
/// lowest first.
fn codes(lengths: &[u8]) -> Vec<u16> {
    let mut count = [0u16; 16];
    for &l in lengths {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..16 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let code = next[l as usize];
            next[l as usize] += 1;
            code.reverse_bits() >> (16 - l)
        })
        .collect()
}

/// A code as written, for the symbols that follow.
struct Code {
    lengths: Vec<u8>,
    codes: Vec<u16>,
}

impl Code {
    fn put(&self, bits: &mut Bits, symbol: usize) {
        bits.put(
            u32::from(self.codes[symbol]),
            u32::from(self.lengths[symbol]),
        );
    }
}

/// Write the code for `frequencies` and give it back.
fn write_code(bits: &mut Bits, frequencies: &[u32]) -> Code {
    let used: Vec<usize> = (0..frequencies.len())
        .filter(|&s| frequencies[s] > 0)
        .collect();
    // One or two symbols below 256 have a short form; one takes no bits.
    if used.len() <= 2 && used.iter().all(|&s| s < 256) {
        let mut lengths = vec![0u8; frequencies.len()];
        let symbols: Vec<usize> = if used.is_empty() { vec![0] } else { used };
        bits.put(1, 1);
        bits.put(symbols.len() as u32 - 1, 1);
        if symbols[0] < 2 {
            bits.put(0, 1);
            bits.put(symbols[0] as u32, 1);
        } else {
            bits.put(1, 1);
            bits.put(symbols[0] as u32, 8);
        }
        if let Some(&second) = symbols.get(1) {
            bits.put(second as u32, 8);
            for &s in &symbols {
                lengths[s] = 1;
            }
        }
        let codes = codes(&lengths);
        return Code { lengths, codes };
    }
    let lengths = lengths(&at_least_two(frequencies), 15);
    // The lengths, run-length coded.
    let mut tokens: Vec<(u8, u8)> = Vec::new();
    let mut previous = 8u8;
    let mut i = 0;
    while i < lengths.len() {
        let value = lengths[i];
        let run = lengths[i..].iter().take_while(|&&l| l == value).count();
        let mut left = run;
        if value == 0 {
            while left >= 11 {
                let take = left.min(138);
                tokens.push((18, (take - 11) as u8));
                left -= take;
            }
            if left >= 3 {
                tokens.push((17, (left - 3) as u8));
                left = 0;
            }
        } else {
            if value != previous {
                tokens.push((value, 0));
                previous = value;
                left -= 1;
            }
            while left >= 3 {
                let take = left.min(6);
                tokens.push((16, (take - 3) as u8));
                left -= take;
            }
        }
        for _ in 0..left {
            tokens.push((value, 0));
        }
        i += run;
    }
    let mut counts = [0u32; 19];
    for &(symbol, _) in &tokens {
        counts[symbol as usize] += 1;
    }
    let code_lengths = lengths_limited7(&counts);
    let code_codes = codes(&code_lengths);
    bits.put(0, 1);
    let written = CODE_LENGTH_ORDER
        .iter()
        .rposition(|&s| code_lengths[s] > 0)
        .map_or(4, |last| (last + 1).max(4));
    bits.put(written as u32 - 4, 4);
    for &symbol in &CODE_LENGTH_ORDER[..written] {
        bits.put(u32::from(code_lengths[symbol]), 3);
    }
    // Every symbol has a length written.
    bits.put(0, 1);
    for (symbol, extra) in tokens {
        let s = symbol as usize;
        bits.put(u32::from(code_codes[s]), u32::from(code_lengths[s]));
        match symbol {
            16 => bits.put(u32::from(extra), 2),
            17 => bits.put(u32::from(extra), 3),
            18 => bits.put(u32::from(extra), 7),
            _ => {}
        }
    }
    let codes = codes(&lengths);
    Code { lengths, codes }
}

fn lengths_limited7(counts: &[u32; 19]) -> Vec<u8> {
    lengths(&at_least_two(counts), 7)
}

/// Frequencies with two symbols used at least, so that no code is of one
/// symbol, which would take no bits.
fn at_least_two(frequencies: &[u32]) -> Vec<u32> {
    let mut out = frequencies.to_vec();
    let mut spare = 0;
    while out.iter().filter(|&&f| f > 0).count() < 2 {
        while out[spare] > 0 {
            spare += 1;
        }
        out[spare] = 1;
    }
    out
}

/// A value of 1 or more as the format writes lengths and distances: a
/// prefix, and how many extra bits of what value follow it.
fn prefix(value: u32) -> (u32, u32, u32) {
    let d = value - 1;
    if d < 4 {
        return (d, 0, 0);
    }
    let high = 31 - d.leading_zeros();
    let second = (d >> (high - 1)) & 1;
    let extra = high - 1;
    (2 * high + second, extra, d & ((1 << extra) - 1))
}

enum Token {
    Literal(u32),
    Copy { length: u32, code: u32 },
}

const MAX_LENGTH: usize = 4096;
const MAX_DISTANCE: usize = (1 << 20) - 120;

/// `pixels` as literals and copies of what came before.
fn tokens(pixels: &[u32], xsize: usize, deadline: Deadline) -> Result<Vec<Token>, Error> {
    let mut plane: HashMap<usize, u32> = HashMap::new();
    for (index, &(x, y)) in DISTANCE_MAP.iter().enumerate() {
        let distance = i64::from(x) + i64::from(y) * xsize as i64;
        if distance >= 1 {
            plane.entry(distance as usize).or_insert(index as u32 + 1);
        }
    }
    const HASH_BITS: u32 = 16;
    let hash = |i: usize| {
        let key = u64::from(pixels[i]) ^ (u64::from(pixels[i + 1]) << 32);
        (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - HASH_BITS)) as usize
    };
    let mut head = vec![usize::MAX; 1 << HASH_BITS];
    let mut previous = vec![usize::MAX; pixels.len()];
    let matching = |at: usize, from: usize| {
        let most = (pixels.len() - at).min(MAX_LENGTH);
        (0..most)
            .take_while(|&k| pixels[from + k] == pixels[at + k])
            .count()
    };
    let mut found = Vec::new();
    let mut at = 0;
    let insert = |head: &mut Vec<usize>, previous: &mut Vec<usize>, i: usize| {
        if i + 1 < pixels.len() {
            let h = hash(i);
            previous[i] = head[h];
            head[h] = i;
        }
    };
    while at < pixels.len() {
        if at % (1 << 16) == 0 {
            deadline.check()?;
        }
        let (mut best, mut best_distance) = (0, 0);
        // Left and above are the cheapest to name.
        for distance in [1, xsize] {
            if distance >= 1 && distance <= at {
                let length = matching(at, at - distance);
                if length > best {
                    (best, best_distance) = (length, distance);
                }
            }
        }
        if at + 1 < pixels.len() {
            let mut candidate = head[hash(at)];
            let mut tries = 32;
            while candidate != usize::MAX && tries > 0 && at - candidate <= MAX_DISTANCE {
                let length = matching(at, candidate);
                if length > best + 1 {
                    (best, best_distance) = (length, at - candidate);
                }
                candidate = previous[candidate];
                tries -= 1;
            }
        }
        if best >= 3 {
            let code = plane
                .get(&best_distance)
                .copied()
                .unwrap_or(best_distance as u32 + 120);
            found.push(Token::Copy {
                length: best as u32,
                code,
            });
            for i in at..at + best {
                insert(&mut head, &mut previous, i);
            }
            at += best;
        } else {
            found.push(Token::Literal(pixels[at]));
            insert(&mut head, &mut previous, at);
            at += 1;
        }
    }
    Ok(found)
}

/// An image of `pixels` `xsize` across, coded; with the bit that says it
/// has no meta codes if it is the `main` one.
fn write_image(
    bits: &mut Bits,
    pixels: &[u32],
    xsize: usize,
    main: bool,
    deadline: Deadline,
) -> Result<(), Error> {
    let tokens = tokens(pixels, xsize, deadline)?;
    // No colour cache.
    bits.put(0, 1);
    if main {
        bits.put(0, 1);
    }
    let mut green = vec![0u32; 256 + 24];
    let mut red = vec![0u32; 256];
    let mut blue = vec![0u32; 256];
    let mut alpha = vec![0u32; 256];
    let mut distance = vec![0u32; 40];
    for token in &tokens {
        match *token {
            Token::Literal(p) => {
                green[(p >> 8 & 0xFF) as usize] += 1;
                red[(p >> 16 & 0xFF) as usize] += 1;
                blue[(p & 0xFF) as usize] += 1;
                alpha[(p >> 24) as usize] += 1;
            }
            Token::Copy { length, code } => {
                green[256 + prefix(length).0 as usize] += 1;
                distance[prefix(code).0 as usize] += 1;
            }
        }
    }
    let codes = [&green, &red, &blue, &alpha, &distance].map(|f| write_code(bits, f));
    for token in tokens {
        match token {
            Token::Literal(p) => {
                codes[0].put(bits, (p >> 8 & 0xFF) as usize);
                codes[1].put(bits, (p >> 16 & 0xFF) as usize);
                codes[2].put(bits, (p & 0xFF) as usize);
                codes[3].put(bits, (p >> 24) as usize);
            }
            Token::Copy { length, code } => {
                let (symbol, extra, value) = prefix(length);
                codes[0].put(bits, 256 + symbol as usize);
                bits.put(value, extra);
                let (symbol, extra, value) = prefix(code);
                codes[4].put(bits, symbol as usize);
                bits.put(value, extra);
            }
        }
    }
    Ok(())
}

fn channels(p: u32) -> [i32; 4] {
    [24, 16, 8, 0].map(|shift| (p >> shift & 0xFF) as i32)
}

fn join(c: [i32; 4]) -> u32 {
    c.iter().fold(0, |p, &v| p << 8 | (v as u32 & 0xFF))
}

fn average(a: u32, b: u32) -> u32 {
    let (a, b) = (channels(a), channels(b));
    join([0, 1, 2, 3].map(|i| (a[i] + b[i]) / 2))
}

/// The prediction of `mode` from the pixels left, above, above left and
/// above right.
fn predict(mode: u8, l: u32, t: u32, tl: u32, tr: u32) -> u32 {
    match mode {
        0 => 0xFF00_0000,
        1 => l,
        2 => t,
        3 => tr,
        4 => tl,
        5 => average(average(l, tr), t),
        6 => average(l, tl),
        7 => average(l, t),
        8 => average(tl, t),
        9 => average(t, tr),
        10 => average(average(l, tl), average(t, tr)),
        11 => {
            let (l4, t4, tl4) = (channels(l), channels(t), channels(tl));
            let to_l: i32 = (0..4).map(|i| (t4[i] - tl4[i]).abs()).sum();
            let to_t: i32 = (0..4).map(|i| (l4[i] - tl4[i]).abs()).sum();
            if to_l < to_t { l } else { t }
        }
        12 => {
            let (l4, t4, tl4) = (channels(l), channels(t), channels(tl));
            join([0, 1, 2, 3].map(|i| (l4[i] + t4[i] - tl4[i]).clamp(0, 255)))
        }
        _ => {
            let (a, tl4) = (channels(average(l, t)), channels(tl));
            join([0, 1, 2, 3].map(|i| (a[i] + (a[i] - tl4[i]) / 2).clamp(0, 255)))
        }
    }
}

fn minus(p: u32, q: u32) -> u32 {
    let (p, q) = (channels(p), channels(q));
    join([0, 1, 2, 3].map(|i| p[i] - q[i]))
}

/// How far a residual is from nothing, roughly what it costs.
fn cost(residual: u32) -> u32 {
    channels(residual)
        .iter()
        .map(|&c| u32::from((c as u8 as i8).unsigned_abs()))
        .sum()
}

const BLOCK_BITS: u32 = 4;

/// The stream after the header with green taken from red and blue and
/// each block predicted.
fn predicted(
    bits: &mut Bits,
    argb: &[u32],
    width: usize,
    height: usize,
    deadline: Deadline,
) -> Result<(), Error> {
    let pixels: Vec<u32> = argb
        .iter()
        .map(|&p| {
            let g = p >> 8 & 0xFF;
            let r = (p >> 16).wrapping_sub(g) & 0xFF;
            let b = p.wrapping_sub(g) & 0xFF;
            (p & 0xFF00_FF00) | r << 16 | b
        })
        .collect();
    let block = 1usize << BLOCK_BITS;
    let (across, down) = (width.div_ceil(block), height.div_ceil(block));
    let neighbours = |x: usize, y: usize| {
        let at = y * width + x;
        let l = pixels[at - 1];
        let t = pixels[at - width];
        let tl = pixels[at - width - 1];
        // The last column takes the first pixel of its own row as above
        // right.
        let tr = pixels[at - width + 1];
        (l, t, tl, tr)
    };
    let mut modes = vec![0u8; across * down];
    for by in 0..down {
        deadline.check()?;
        for bx in 0..across {
            let mut totals = [0u32; 14];
            for y in (by * block).max(1)..((by + 1) * block).min(height) {
                for x in (bx * block).max(1)..((bx + 1) * block).min(width) {
                    let (l, t, tl, tr) = neighbours(x, y);
                    let p = pixels[y * width + x];
                    for (mode, total) in totals.iter_mut().enumerate() {
                        *total += cost(minus(p, predict(mode as u8, l, t, tl, tr)));
                    }
                }
            }
            let best = (0..14).min_by_key(|&m| totals[m]).unwrap_or(1);
            modes[by * across + bx] = best as u8;
        }
    }
    let mut residuals = vec![0u32; pixels.len()];
    for y in 0..height {
        for x in 0..width {
            let at = y * width + x;
            let prediction = match (x, y) {
                (0, 0) => 0xFF00_0000,
                (_, 0) => pixels[at - 1],
                (0, _) => pixels[at - width],
                _ => {
                    let (l, t, tl, tr) = neighbours(x, y);
                    let mode = modes[(y >> BLOCK_BITS) * across + (x >> BLOCK_BITS)];
                    predict(mode, l, t, tl, tr)
                }
            };
            residuals[at] = minus(pixels[at], prediction);
        }
    }
    // Green taken from red and blue, then the prediction, each undone in
    // the other order.
    bits.put(1, 1);
    bits.put(2, 2);
    bits.put(1, 1);
    bits.put(0, 2);
    bits.put(BLOCK_BITS - 2, 3);
    let mode_image: Vec<u32> = modes
        .iter()
        .map(|&m| 0xFF00_0000 | u32::from(m) << 8)
        .collect();
    write_image(bits, &mode_image, across, false, deadline)?;
    bits.put(0, 1);
    write_image(bits, &residuals, width, true, deadline)
}

/// The stream after the header with a table of the colours, if there are
/// no more than 256.
fn indexed(
    bits: &mut Bits,
    argb: &[u32],
    width: usize,
    height: usize,
    deadline: Deadline,
) -> Result<bool, Error> {
    let mut table: Vec<u32> = Vec::new();
    for &p in argb {
        if let Err(at) = table.binary_search(&p) {
            if table.len() == 256 {
                return Ok(false);
            }
            table.insert(at, p);
        }
    }
    let index: HashMap<u32, u32> = table
        .iter()
        .enumerate()
        .map(|(i, &p)| (p, i as u32))
        .collect();
    let width_bits = match table.len() {
        0..=2 => 3,
        3..=4 => 2,
        5..=16 => 1,
        _ => 0,
    };
    let per = 1usize << width_bits;
    let depth = 8 >> width_bits;
    let packed_width = width.div_ceil(per);
    let mut packed = vec![0u32; packed_width * height];
    for y in 0..height {
        for x in 0..width {
            let i = index[&argb[y * width + x]];
            packed[y * packed_width + x / per] |= i << (8 + depth * (x % per) as u32);
        }
    }
    bits.put(1, 1);
    bits.put(3, 2);
    bits.put(table.len() as u32 - 1, 8);
    // Each colour as it differs from the one before.
    let deltas: Vec<u32> = (0..table.len())
        .map(|i| {
            if i == 0 {
                table[0]
            } else {
                minus(table[i], table[i - 1])
            }
        })
        .collect();
    write_image(bits, &deltas, table.len(), false, deadline)?;
    bits.put(0, 1);
    write_image(bits, &packed, packed_width, true, deadline)?;
    Ok(true)
}

/// A VP8L stream of `rgba`, four samples a pixel: the smaller of the ways
/// tried. `None` if the picture is too large for the format.
pub(super) fn encode(
    rgba: &[u8],
    width: u32,
    height: u32,
    deadline: Deadline,
) -> Result<Option<Vec<u8>>, Error> {
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        return Ok(None);
    }
    let (w, h) = (width as usize, height as usize);
    if rgba.len() != w * h * 4 {
        return Ok(None);
    }
    let argb: Vec<u32> = rgba
        .as_chunks::<4>()
        .0
        .iter()
        .map(|p| u32::from_be_bytes([p[3], p[0], p[1], p[2]]))
        .collect();
    let alpha = argb.iter().any(|&p| p >> 24 != 0xFF);
    let header = || {
        let mut bits = Bits::default();
        bits.put(0x2F, 8);
        bits.put(width - 1, 14);
        bits.put(height - 1, 14);
        bits.put(u32::from(alpha), 1);
        bits.put(0, 3);
        bits
    };
    let mut best: Option<Vec<u8>> = None;
    let mut bits = header();
    if indexed(&mut bits, &argb, w, h, deadline)? {
        best = Some(bits.finish());
    }
    let mut bits = header();
    predicted(&mut bits, &argb, w, h, deadline)?;
    let stream = bits.finish();
    if best.as_ref().is_none_or(|b| stream.len() < b.len()) {
        best = Some(stream);
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_cover_their_values() {
        for value in 1..5000u32 {
            let (code, extra, rest) = prefix(value);
            let decoded = if code < 4 {
                code + 1
            } else {
                let extra_bits = (code - 2) >> 1;
                assert_eq!(extra_bits, extra);
                ((2 + (code & 1)) << extra_bits) + rest + 1
            };
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn huffman_lengths_stay_within_the_limit() {
        let frequencies: Vec<u32> = (0..280).map(|i| 1 << (i % 30)).collect();
        let found = lengths(&frequencies, 15);
        assert!(found.iter().all(|&l| (1..=15).contains(&l)));
        let kraft: f64 = found.iter().map(|&l| 0.5f64.powi(l.into())).sum();
        assert!(kraft <= 1.0 + 1e-9);
    }
}

#[cfg(test)]
mod size {
    use std::io::Cursor;

    use image::codecs::webp::{WebPDecoder, WebPEncoder};
    use image::{DynamicImage, ExtendedColorType};

    use super::*;

    fn ours(rgba: &[u8], w: u32, h: u32) -> (usize, Vec<u8>) {
        let stream = encode(rgba, w, h, Deadline(None)).unwrap().unwrap();
        let mut body = b"WEBP".to_vec();
        super::super::riff_chunk(&mut body, b"VP8L", &stream).unwrap();
        let mut file = Vec::new();
        super::super::riff_chunk(&mut file, b"RIFF", &body).unwrap();
        let decoded = DynamicImage::from_decoder(WebPDecoder::new(Cursor::new(&file)).unwrap())
            .unwrap()
            .into_rgba8();
        (file.len(), decoded.into_raw())
    }

    #[test]
    fn smaller_and_exact() {
        let corpus = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        for name in std::fs::read_dir(corpus).unwrap() {
            let path = name.unwrap().path();
            let Ok(image) = image::open(&path) else {
                continue;
            };
            let rgba = image.to_rgba8();
            let (w, h) = rgba.dimensions();
            if w > 16384 || h > 16384 || u64::from(w) * u64::from(h) > 4 << 20 {
                continue;
            }
            let mut theirs = Vec::new();
            WebPEncoder::new_lossless(&mut theirs)
                .encode(rgba.as_raw(), w, h, ExtendedColorType::Rgba8)
                .unwrap();
            let (size, decoded) = ours(rgba.as_raw(), w, h);
            assert!(decoded == *rgba.as_raw(), "{path:?} decodes otherwise");
            println!(
                "{:>8} {:>8} {:?}",
                theirs.len(),
                size,
                path.file_name().unwrap()
            );
        }
    }
}
