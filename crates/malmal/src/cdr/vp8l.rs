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
#[derive(Default, Clone)]
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

    /// How many bits have been put.
    fn len(&self) -> usize {
        self.out.len() * 8 + self.count as usize
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

#[derive(Clone, Copy)]
enum Token {
    Literal(u32),
    /// A pixel at this place in the colour cache.
    Cache(u32),
    Copy {
        length: u32,
        code: u32,
    },
}

impl Token {
    /// How many pixels it stands for.
    fn pixels(&self) -> usize {
        match *self {
            Token::Copy { length, .. } => length as usize,
            _ => 1,
        }
    }
}

const MAX_LENGTH: usize = 4096;
/// The shortest copy from further than the distances of the plane codes
/// that is taken: one shorter costs more than its pixels as literals do,
/// in a photograph, and is not much cheaper in a drawing.
const FAR_MIN: usize = 6;
/// How many earlier places of the same two pixels are tried for a copy.
const TRIES: usize = 16;
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
    // Places, as u32 (a picture has 2^28 pixels at most), u32::MAX for
    // none.
    const NONE: u32 = u32::MAX;
    let mut head = vec![NONE; 1 << HASH_BITS];
    let mut previous = vec![NONE; pixels.len()];
    let matching = |at: usize, from: usize| {
        let most = (pixels.len() - at).min(MAX_LENGTH);
        (0..most)
            .take_while(|&k| pixels[from + k] == pixels[at + k])
            .count()
    };
    let mut found = Vec::new();
    let mut at = 0;
    let insert = |head: &mut Vec<u32>, previous: &mut Vec<u32>, i: usize| {
        if i + 1 < pixels.len() {
            let h = hash(i);
            previous[i] = head[h];
            head[h] = i as u32;
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
            let mut tries = TRIES;
            while candidate != NONE && tries > 0 && at - candidate as usize <= MAX_DISTANCE {
                let place = candidate as usize;
                // Only one that goes on past the best so far can beat it.
                let past = best + 1;
                if at + past < pixels.len() && pixels[place + past] == pixels[at + past] {
                    let length = matching(at, place);
                    if length > past {
                        (best, best_distance) = (length, at - place);
                    }
                }
                candidate = previous[place];
                tries -= 1;
            }
        }
        let code = plane
            .get(&best_distance)
            .copied()
            .unwrap_or(best_distance as u32 + 120);
        if best >= if code <= 120 { 3 } else { FAR_MIN } {
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

/// Literals that are in a colour cache of `cache_bits` when they come, as
/// their place in it; every pixel goes into it as it comes.
fn cached(tokens: &[Token], pixels: &[u32], cache_bits: u32) -> Vec<Token> {
    if cache_bits == 0 {
        return tokens.to_vec();
    }
    let key = |p: u32| (p.wrapping_mul(0x1E35_A7BD) >> (32 - cache_bits)) as usize;
    let mut cache: Vec<Option<u32>> = vec![None; 1 << cache_bits];
    let mut at = 0;
    let mut out = Vec::with_capacity(tokens.len());
    for &token in tokens {
        match token {
            Token::Literal(p) => {
                let k = key(p);
                out.push(match cache[k] == Some(p) {
                    true => Token::Cache(k as u32),
                    false => token,
                });
                cache[k] = Some(p);
            }
            _ => {
                for &p in &pixels[at..at + token.pixels()] {
                    cache[key(p)] = Some(p);
                }
                out.push(token);
            }
        }
        at += token.pixels();
    }
    out
}

/// How often each symbol of each of the five codes is used: green with
/// lengths and cache places, red, blue, alpha, distances.
#[derive(Clone)]
struct Histogram([Vec<u32>; 5]);

impl Histogram {
    fn new(cache_bits: u32) -> Self {
        let cache = if cache_bits > 0 { 1 << cache_bits } else { 0 };
        Self([
            vec![0; 256 + 24 + cache],
            vec![0; 256],
            vec![0; 256],
            vec![0; 256],
            vec![0; 40],
        ])
    }

    fn add(&mut self, token: Token) {
        let h = &mut self.0;
        match token {
            Token::Literal(p) => {
                h[0][(p >> 8 & 0xFF) as usize] += 1;
                h[1][(p >> 16 & 0xFF) as usize] += 1;
                h[2][(p & 0xFF) as usize] += 1;
                h[3][(p >> 24) as usize] += 1;
            }
            Token::Cache(k) => h[0][280 + k as usize] += 1,
            Token::Copy { length, code } => {
                h[0][256 + prefix(length).0 as usize] += 1;
                h[4][prefix(code).0 as usize] += 1;
            }
        }
    }

    fn merge(&mut self, other: &Histogram) {
        for (to, from) in self.0.iter_mut().zip(&other.0) {
            for (a, b) in to.iter_mut().zip(from) {
                *a += b;
            }
        }
    }
}

fn put(codes: &[Code], bits: &mut Bits, token: Token) {
    match token {
        Token::Literal(p) => {
            codes[0].put(bits, (p >> 8 & 0xFF) as usize);
            codes[1].put(bits, (p >> 16 & 0xFF) as usize);
            codes[2].put(bits, (p & 0xFF) as usize);
            codes[3].put(bits, (p >> 24) as usize);
        }
        Token::Cache(k) => codes[0].put(bits, 280 + k as usize),
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

/// An image of a transform, `pixels` `xsize` across, coded with one code
/// of each kind and no colour cache.
fn write_image(
    bits: &mut Bits,
    pixels: &[u32],
    xsize: usize,
    deadline: Deadline,
) -> Result<(), Error> {
    let tokens = tokens(pixels, xsize, deadline)?;
    bits.put(0, 1);
    let mut histogram = Histogram::new(0);
    tokens.iter().for_each(|&t| histogram.add(t));
    let codes = histogram.0.map(|f| write_code(bits, &f));
    for token in tokens {
        put(&codes, bits, token);
    }
    Ok(())
}

/// The block of each token, of `1 << block_bits` pixels a side.
fn blocks_of(tokens: &[Token], xsize: usize, block_bits: u32) -> Vec<usize> {
    let across = xsize.div_ceil(1 << block_bits);
    let mut at = 0;
    tokens
        .iter()
        .map(|t| {
            let (x, y) = (at % xsize, at / xsize);
            at += t.pixels();
            (y >> block_bits) * across + (x >> block_bits)
        })
        .collect()
}

/// Blocks put in groups that code alike: the group of each block, and how
/// many groups there are.
fn grouped(
    tokens: &[Token],
    blocks: &[usize],
    count: usize,
    cache_bits: u32,
    deadline: Deadline,
) -> Result<(Vec<u32>, usize), Error> {
    // The symbols of each block, by code.
    let mut used: Vec<Histogram> = vec![Histogram::new(cache_bits); count];
    for (&token, &block) in tokens.iter().zip(blocks) {
        used[block].add(token);
    }
    let sparse: Vec<Vec<(u8, u16, u32)>> = used
        .iter()
        .map(|h| {
            h.0.iter()
                .enumerate()
                .flat_map(|(code, f)| {
                    f.iter()
                        .enumerate()
                        .filter(|&(_, &c)| c > 0)
                        .map(move |(s, &c)| (code as u8, s as u16, c))
                })
                .collect()
        })
        .collect();
    let wanted = count.min(16);
    // Begin from blocks spread over the picture.
    let mut group: Vec<u32> = (0..count).map(|b| (b * wanted / count) as u32).collect();
    for _ in 0..6 {
        deadline.check()?;
        let mut totals = vec![Histogram::new(cache_bits); wanted];
        for (block, &g) in group.iter().enumerate() {
            totals[g as usize].merge(&used[block]);
        }
        // What each symbol costs in each group, a symbol never seen there
        // as if it were seen once.
        let costs: Vec<[Vec<f32>; 5]> = totals
            .iter()
            .map(|h| {
                h.0.clone().map(|f| {
                    let total = f.iter().map(|&c| u64::from(c) + 1).sum::<u64>() as f32;
                    f.iter().map(|&c| (total / (c + 1) as f32).log2()).collect()
                })
            })
            .collect();
        let mut changed = false;
        for (block, symbols) in sparse.iter().enumerate() {
            if symbols.is_empty() {
                continue;
            }
            let cost = |g: usize| -> f32 {
                symbols
                    .iter()
                    .map(|&(code, s, c)| costs[g][code as usize][s as usize] * c as f32)
                    .sum()
            };
            let best = (0..wanted)
                .filter(|&g| totals[g].0[0].iter().any(|&c| c > 0) || g == group[block] as usize)
                .min_by(|&a, &b| cost(a).total_cmp(&cost(b)))
                .unwrap_or(0) as u32;
            if best != group[block] {
                group[block] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Groups numbered from 0 as they are used.
    let mut number = vec![u32::MAX; wanted];
    let mut next = 0;
    for g in &mut group {
        if number[*g as usize] == u32::MAX {
            number[*g as usize] = next;
            next += 1;
        }
        *g = number[*g as usize];
    }
    Ok((group, next as usize))
}

/// The main image of `pixels` `xsize` across, coded in whichever of the
/// ways tried takes the fewest bits: with a colour cache of some size or
/// none, with one code of each kind or with codes for groups of blocks.
fn write_main(
    bits: &mut Bits,
    pixels: &[u32],
    xsize: usize,
    deadline: Deadline,
) -> Result<(), Error> {
    let plain = tokens(pixels, xsize, deadline)?;
    let ysize = pixels.len() / xsize;

    let write = |bits: &mut Bits,
                 tokens: &[Token],
                 cache_bits: u32,
                 grouping: Option<(u32, Vec<u32>, usize, Vec<usize>)>| {
        bits.put(u32::from(cache_bits > 0), 1);
        if cache_bits > 0 {
            bits.put(cache_bits, 4);
        }
        let (groups, of_token) = match grouping {
            None => {
                bits.put(0, 1);
                (1, None)
            }
            Some((block_bits, group, count, blocks)) => {
                bits.put(1, 1);
                bits.put(block_bits - 2, 3);
                let image: Vec<u32> = group.iter().map(|&g| 0xFF00_0000 | g << 8).collect();
                write_image(bits, &image, xsize.div_ceil(1 << block_bits), deadline)?;
                (count, Some((group, blocks)))
            }
        };
        let mut histograms = vec![Histogram::new(cache_bits); groups];
        for (index, &token) in tokens.iter().enumerate() {
            let g = of_token
                .as_ref()
                .map_or(0, |(group, blocks)| group[blocks[index]] as usize);
            histograms[g].add(token);
        }
        let codes: Vec<Vec<Code>> = histograms
            .iter()
            .map(|h| h.0.iter().map(|f| write_code(bits, f)).collect())
            .collect();
        for (index, &token) in tokens.iter().enumerate() {
            let g = of_token
                .as_ref()
                .map_or(0, |(group, blocks)| group[blocks[index]] as usize);
            put(&codes[g], bits, token);
        }
        Ok::<(), Error>(())
    };

    // The size of colour cache, or none, that comes out smallest.
    let mut best: Option<(Bits, u32, Vec<Token>)> = None;
    for cache_bits in [0, 2, 4, 6, 8, 10] {
        deadline.check()?;
        let tokens = cached(&plain, pixels, cache_bits);
        let mut written = bits.clone();
        write(&mut written, &tokens, cache_bits, None)?;
        if best
            .as_ref()
            .is_none_or(|(b, _, _)| written.len() < b.len())
        {
            best = Some((written, cache_bits, tokens));
        }
    }
    drop(plain);
    let Some((single, cache_bits, tokens)) = best else {
        return Ok(());
    };
    // Blocks of a size that makes a few thousand of them at most.
    if pixels.len() >= 1 << 14 {
        let block_bits = (3..=9)
            .find(|&b| xsize.div_ceil(1 << b) * ysize.div_ceil(1 << b) <= 2048)
            .unwrap_or(9);
        let count = xsize.div_ceil(1 << block_bits) * ysize.div_ceil(1 << block_bits);
        let blocks = blocks_of(&tokens, xsize, block_bits);
        let (group, groups) = grouped(&tokens, &blocks, count, cache_bits, deadline)?;
        if groups > 1 {
            let mut split = bits.clone();
            write(
                &mut split,
                &tokens,
                cache_bits,
                Some((block_bits, group, groups, blocks)),
            )?;
            if split.len() < single.len() {
                *bits = split;
                return Ok(());
            }
        }
    }
    *bits = single;
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
    cross: bool,
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
    write_image(bits, &mode_image, across, deadline)?;
    // Then, if asked, red and blue taken in part from the others.
    if cross {
        let multipliers = crossed(&mut residuals, width, height, deadline)?;
        bits.put(1, 1);
        bits.put(1, 2);
        bits.put(CROSS_BITS - 2, 3);
        write_image(
            bits,
            &multipliers,
            width.div_ceil(1 << CROSS_BITS),
            deadline,
        )?;
    }
    bits.put(0, 1);
    write_main(bits, &residuals, width, deadline)
}

const CROSS_BITS: u32 = 5;

/// What the colour transform takes away: `t` times `c`, both as signed
/// bytes, over 32.
fn delta(t: i32, c: u32) -> i32 {
    (t * i32::from(c as u8 as i8)) >> 5
}

/// The residuals with red taken in part from green and blue in part from
/// green and red, block by block, by the multipliers that leave them
/// smallest; the image of those multipliers.
fn crossed(
    residuals: &mut [u32],
    width: usize,
    height: usize,
    deadline: Deadline,
) -> Result<Vec<u32>, Error> {
    let block = 1usize << CROSS_BITS;
    let (across, down) = (width.div_ceil(block), height.div_ceil(block));
    let mut image = Vec::with_capacity(across * down);
    let signed = |v: u32| i64::from(v as u8 as i8);
    for by in 0..down {
        deadline.check()?;
        for bx in 0..across {
            let at: Vec<usize> = (by * block..((by + 1) * block).min(height))
                .flat_map(|y| {
                    (bx * block..((bx + 1) * block).min(width)).map(move |x| y * width + x)
                })
                .collect();
            let part = |p: u32, shift: u32| p >> shift & 0xFF;
            // The multiplier of `from` that best takes it out of `to`,
            // as the least squares give it and those next to it.
            let best = |to: &dyn Fn(u32) -> u32, from: &dyn Fn(u32) -> u32| -> i32 {
                let (mut cross, mut square) = (0i64, 0i64);
                for &i in &at {
                    let (t, f) = (signed(to(residuals[i])), signed(from(residuals[i])));
                    cross += t * f;
                    square += f * f;
                }
                if square == 0 {
                    return 0;
                }
                let guess = ((cross * 32) as f64 / square as f64)
                    .round()
                    .clamp(-128.0, 127.0) as i32;
                let cost = |m: i32| -> u64 {
                    at.iter()
                        .map(|&i| {
                            let left = to(residuals[i]) as i32 - delta(m, from(residuals[i]));
                            u64::from((left as u8 as i8).unsigned_abs())
                        })
                        .sum()
                };
                [0, guess - 1, guess, guess + 1]
                    .into_iter()
                    .filter(|m| (-128..=127).contains(m))
                    .min_by_key(|&m| (cost(m), m.unsigned_abs()))
                    .unwrap_or(0)
            };
            let green_to_red = best(&|p| part(p, 16), &|p| part(p, 8));
            let green_to_blue = best(&|p| part(p, 0), &|p| part(p, 8));
            // Blue with green taken out, against red.
            let red_to_blue = best(
                &|p| (part(p, 0) as i32 - delta(green_to_blue, part(p, 8))) as u32 & 0xFF,
                &|p| part(p, 16),
            );
            for &i in &at {
                let p = residuals[i];
                let (r, g, b) = (part(p, 16), part(p, 8), part(p, 0));
                let red = (r as i32 - delta(green_to_red, g)) as u32 & 0xFF;
                let blue =
                    (b as i32 - delta(green_to_blue, g) - delta(red_to_blue, r)) as u32 & 0xFF;
                residuals[i] = (p & 0xFF00_FF00) | red << 16 | blue;
            }
            let byte = |m: i32| m as u8 as u32;
            image.push(
                0xFF00_0000
                    | byte(red_to_blue) << 16
                    | byte(green_to_blue) << 8
                    | byte(green_to_red),
            );
        }
    }
    Ok(image)
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
    write_image(bits, &deltas, table.len(), deadline)?;
    bits.put(0, 1);
    write_main(bits, &packed, packed_width, deadline)?;
    Ok(true)
}

/// A VP8L stream of `rgba`, four samples a pixel: the smaller of the ways
/// tried. `None` if the picture is too large for the format.
/// The most pixels the two ways of coding a picture are tried at once for:
/// each holds some 40 bytes a pixel.
const PARALLEL_PIXELS: usize = 1 << 22;

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
    // Grey has nothing for the colour transform to take out.
    let colours = argb.iter().any(|&p| {
        let (r, g, b) = (p >> 16 & 0xFF, p >> 8 & 0xFF, p & 0xFF);
        r != g || g != b
    });
    let way = |cross: bool| {
        let mut bits = header();
        predicted(&mut bits, &argb, w, h, cross, deadline)?;
        Ok::<_, Error>(bits.finish())
    };
    let ways: Vec<bool> = [false, true]
        .into_iter()
        .filter(|&cross| !cross || colours)
        .collect();
    // With the colour transform and without, at once, unless holding both
    // at once takes much memory.
    let streams: Vec<Result<Vec<u8>, Error>> = if w * h <= PARALLEL_PIXELS {
        std::thread::scope(|scope| {
            let running: Vec<_> = ways
                .iter()
                .map(|&cross| scope.spawn(move || way(cross)))
                .collect();
            running
                .into_iter()
                .map(|way| {
                    way.join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect()
        })
    } else {
        ways.into_iter().map(way).collect()
    };
    for stream in streams {
        let stream = stream?;
        if best.as_ref().is_none_or(|b| stream.len() < b.len()) {
            best = Some(stream);
        }
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

    /// A picture large enough for codes of groups of blocks, with parts
    /// that code differently, comes back exact.
    #[test]
    fn large_pictures_with_parts_unlike_each_other_are_exact() {
        let (w, h) = (300u32, 200u32);
        let rgba: Vec<u8> = (0..w * h)
            .flat_map(|i| {
                let (x, y) = (i % w, i / w);
                let noise = (x.wrapping_mul(2_654_435_761) ^ y.wrapping_mul(40_503)) >> 27;
                if x < w / 2 {
                    [(x + noise) as u8, (y * 2) as u8, (x ^ y) as u8, 255]
                } else {
                    let stripe = [[200, 30, 30, 255], [30, 200, 30, 128], [10, 10, 250, 255]];
                    stripe[((x / 7 + y / 5) % 3) as usize]
                }
            })
            .collect();
        let (size, decoded) = ours(&rgba, w, h);
        assert!(decoded == rgba);
        println!("{size}");
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
