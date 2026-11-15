//! JPEG files written anew from their DCT coefficients, and from pixels.
//!
//! A JPEG holds its picture as quantised DCT coefficients. Decoding them to
//! pixels and compressing the pixels again loses a little more of the
//! picture every time, and the new file is larger for it. Here the
//! coefficients themselves are read and written out again, under new
//! Huffman tables computed for them: every pixel of the new file decodes to
//! what it did in the old one. Nothing else of the old file is kept: the
//! markers are written from what was read, and only the quantisation
//! tables, the layout of the components, the colour transform and the
//! pixel density come across.
//!
//! An Exif orientation is applied to the coefficients, as `jpegtran
//! -perfect` does: by moving blocks and changing signs, which loses
//! nothing. That is only possible where the image ends on a whole block
//! along each edge that has to move; elsewhere the caller decodes the
//! pixels and turns them, and [`encode`] compresses them again, with
//! quantisation tables no coarser than those of the original.

use image::DynamicImage;

use super::{Deadline, Error};
use crate::limits::Limits;

/// The natural (row-major) position of each coefficient, in the zigzag
/// order the file stores them in.
const NATURAL: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// The luminance quantisation table of the JPEG standard (Annex K), in
/// natural order; libjpeg scales it by quality.
const LUMA: [u16; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

/// The chrominance table of the standard, in natural order.
const CHROMA: [u16; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// Coefficients in zigzag order.
type Block = [i16; 64];

/// Why a JPEG is not transcoded. The first two are answers; the last sends
/// the file to be decoded to pixels, which may yet work.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    TooLarge,
    TimedOut,
    /// Not a kind of JPEG this reads (arithmetic coding, lossless,
    /// hierarchical, 12-bit, four components), or one it cannot read whole.
    Other,
}

impl Refusal {
    /// The answer for the caller, if this is one.
    pub(super) fn answer(self) -> Option<Error> {
        match self {
            Self::TooLarge => Some(Error::TooLarge),
            Self::TimedOut => Some(Error::TimedOut),
            Self::Other => None,
        }
    }
}

type Read<T> = Result<T, Refusal>;

/// How many pixels make an inch or a centimetre, as JFIF says it. Unit 0
/// gives only the shape of a pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Density {
    pub(super) unit: u8,
    pub(super) x: u16,
    pub(super) y: u16,
}

impl Default for Density {
    fn default() -> Self {
        Self {
            unit: 0,
            x: 1,
            y: 1,
        }
    }
}

#[derive(Clone)]
struct Component {
    id: u8,
    /// Sampling factors.
    h: u8,
    v: u8,
    /// Which quantisation table the frame names for it.
    table: u8,
    /// That table, as it stood when the first scan of the component began.
    quant: Option<[u16; 64]>,
    /// Blocks across and down, as many as the frame's MCUs lay out.
    across: usize,
    down: usize,
    blocks: Vec<Block>,
}

/// A JPEG as its coefficients.
pub(super) struct Coefficients {
    width: u32,
    height: u32,
    components: Vec<Component>,
    /// Three components that are red, green and blue rather than luma and
    /// chroma.
    rgb: bool,
    /// The colour transform of an Adobe segment, if the file has one.
    adobe: Option<u8>,
    pub(super) density: Density,
    /// Exif orientation, 1 to 8.
    pub(super) orientation: u8,
    /// The colour profile, put together from its pieces.
    pub(super) icc: Option<Vec<u8>>,
}

/// What a JPEG says about how it was compressed, for compressing its pixels
/// again no worse.
#[derive(Debug, Clone)]
pub(super) struct Source {
    /// Tables in zigzag order: luma, and chroma where there is any.
    luma: [u16; 64],
    chroma: Option<[u16; 64]>,
    pub(super) density: Density,
}

/// How a still image is compressed.
#[derive(Debug, Clone)]
pub(super) struct Settings {
    pub(super) quality: u8,
    pub(super) source: Option<Source>,
}

impl Settings {
    pub(super) fn new(quality: u8) -> Self {
        Self {
            quality: quality.clamp(1, 100),
            source: None,
        }
    }
}

// --- reading -------------------------------------------------------------

fn be16(data: &[u8], at: usize) -> Read<u16> {
    match data.get(at..at + 2) {
        Some(&[a, b]) => Ok(u16::from_be_bytes([a, b])),
        _ => Err(Refusal::Other),
    }
}

/// A Huffman table for decoding.
struct Decoding {
    /// For each 8-bit prefix, the code length and the symbol of the code it
    /// starts with, if that code is 8 bits or fewer; 0 otherwise.
    fast: [u16; 256],
    /// The largest code of each length, or -1.
    max_code: [i32; 17],
    /// What to add to a code of each length to index `values`.
    offset: [i32; 17],
    values: Vec<u8>,
}

impl Decoding {
    fn new(counts: &[u8; 16], values: &[u8]) -> Read<Self> {
        let mut table = Self {
            fast: [0; 256],
            max_code: [-1; 17],
            offset: [0; 17],
            values: values.to_vec(),
        };
        let mut code = 0u32;
        let mut index = 0usize;
        for length in 1..=16usize {
            let count = counts[length - 1] as usize;
            if count > 0 {
                table.offset[length] = index as i32 - code as i32;
                for _ in 0..count {
                    if length <= 8 {
                        let shift = 8 - length;
                        let first = (code << shift) as usize;
                        let entry = ((length as u16) << 8) | values[index] as u16;
                        table.fast[first..first + (1 << shift)].fill(entry);
                    }
                    code += 1;
                    index += 1;
                }
                // More codes than the length holds, or one of all ones.
                if code >= 1 << length {
                    return Err(Refusal::Other);
                }
                table.max_code[length] = code as i32 - 1;
            }
            code <<= 1;
        }
        Ok(table)
    }
}

/// The bits of a scan, with the bytes stuffed after 0xFF taken out.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    word: u64,
    count: u32,
    /// Zero bytes put in past the end of the data, which nothing may use.
    padded: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self {
            data,
            pos,
            word: 0,
            count: 0,
            padded: 0,
        }
    }

    fn fill(&mut self) {
        while self.count <= 56 {
            let mut byte = 0;
            if self.padded == 0 {
                match self.data.get(self.pos..) {
                    Some([0xFF, 0x00, ..]) => {
                        byte = 0xFF;
                        self.pos += 2;
                    }
                    Some([0xFF, ..]) | Some([]) | None => self.padded = 1,
                    Some([value, ..]) => {
                        byte = *value;
                        self.pos += 1;
                    }
                }
            } else {
                self.padded += 1;
            }
            self.word |= (byte as u64) << (56 - self.count);
            self.count += 8;
        }
    }

    /// Whether bits from past the end of the data have been used.
    fn overran(&self) -> bool {
        self.padded * 8 > self.count
    }

    fn take(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill();
        let value = (self.word >> (64 - n)) as u32;
        self.word <<= n;
        self.count -= n;
        value
    }

    fn decode(&mut self, table: &Decoding) -> Read<u8> {
        self.fill();
        let entry = table.fast[(self.word >> 56) as usize];
        if entry != 0 {
            let length = (entry >> 8) as u32;
            self.word <<= length;
            self.count -= length;
            return Ok(entry as u8);
        }
        for length in 9..=16usize {
            let code = (self.word >> (64 - length)) as i32;
            if code <= table.max_code[length] {
                self.word <<= length;
                self.count -= length as u32;
                let index = code + table.offset[length];
                return table
                    .values
                    .get(index as usize)
                    .copied()
                    .ok_or(Refusal::Other);
            }
        }
        Err(Refusal::Other)
    }

    /// The value of a coefficient of `size` bits.
    fn extend(&mut self, size: u8) -> i32 {
        if size == 0 {
            return 0;
        }
        let value = self.take(size as u32) as i32;
        if value < 1 << (size - 1) {
            value - (1 << size) + 1
        } else {
            value
        }
    }

    /// Past a restart marker, which has to be next.
    fn restart(&mut self) -> Read<()> {
        if self.overran() {
            return Err(Refusal::Other);
        }
        self.word = 0;
        self.count = 0;
        self.padded = 0;
        let mut pos = self.pos;
        while self.data.get(pos) == Some(&0xFF) && self.data.get(pos + 1) == Some(&0xFF) {
            pos += 1;
        }
        match self.data.get(pos..pos + 2) {
            Some([0xFF, 0xD0..=0xD7]) => {
                self.pos = pos + 2;
                Ok(())
            }
            _ => Err(Refusal::Other),
        }
    }
}

struct Frame {
    width: u32,
    height: u32,
    progressive: bool,
    components: Vec<Component>,
    h_max: u8,
    v_max: u8,
    mcus_across: usize,
    mcus_down: usize,
}

impl Frame {
    /// Blocks across and down that hold the component's own samples, which
    /// is what a scan of it alone goes over.
    fn exact(&self, component: &Component) -> (usize, usize) {
        let width = (self.width as usize * component.h as usize).div_ceil(self.h_max as usize);
        let height = (self.height as usize * component.v as usize).div_ceil(self.v_max as usize);
        (width.div_ceil(8), height.div_ceil(8))
    }
}

struct Scan {
    /// Component index, DC table, AC table.
    components: Vec<(usize, usize, usize)>,
    start: u8,
    end: u8,
    high: u8,
    low: u8,
}

/// Where the next marker starts, from `pos` on.
fn next_marker(data: &[u8], mut pos: usize) -> usize {
    while pos + 1 < data.len() {
        if data[pos] == 0xFF {
            let byte = data[pos + 1];
            if byte != 0 && byte != 0xFF && !(0xD0..=0xD7).contains(&byte) {
                return pos;
            }
        }
        pos += 1;
    }
    data.len()
}

/// The orientation and pixel density an Exif segment gives, as far as it
/// gives them.
fn exif(segment: &[u8]) -> (Option<u8>, Option<Density>) {
    let none = (None, None);
    let Some(tiff) = segment.strip_prefix(b"Exif\0\0") else {
        return none;
    };
    let little = match tiff.get(..4) {
        Some(b"II*\0") => true,
        Some(b"MM\0*") => false,
        _ => return none,
    };
    let u16_at = |at: usize| {
        let bytes: [u8; 2] = tiff.get(at..at + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };
    let u32_at = |at: usize| {
        let bytes: [u8; 4] = tiff.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    };
    let Some(ifd) = u32_at(4) else {
        return none;
    };
    let ifd = ifd as usize;
    let Some(entries) = u16_at(ifd) else {
        return none;
    };
    let mut orientation = None;
    let (mut x, mut y, mut unit) = (None, None, 2);
    let rational = |entry: usize| {
        let at = u32_at(entry + 8)? as usize;
        let (numerator, denominator) = (u32_at(at)?, u32_at(at + 4)?);
        let value = (numerator as f64 / denominator as f64).round();
        (1.0..=65535.0).contains(&value).then_some(value as u16)
    };
    for index in 0..entries as usize {
        let entry = ifd + 2 + index * 12;
        let (Some(tag), Some(kind)) = (u16_at(entry), u16_at(entry + 2)) else {
            break;
        };
        match (tag, kind) {
            (0x0112, 3) => orientation = u16_at(entry + 8).filter(|o| (1..=8).contains(o)),
            (0x011A, 5) => x = rational(entry),
            (0x011B, 5) => y = rational(entry),
            (0x0128, 3) => unit = u16_at(entry + 8).unwrap_or(2),
            _ => {}
        }
    }
    // Exif counts inches as 2 and centimetres as 3; JFIF as 1 and 2.
    let density = match (x, y, unit) {
        (Some(x), Some(y), 2 | 3) => Some(Density {
            unit: unit as u8 - 1,
            x,
            y,
        }),
        _ => None,
    };
    (orientation.map(|o| o as u8), density)
}

/// Read the coefficients of a JPEG.
pub(super) fn read(data: &[u8], limits: &Limits, deadline: Deadline) -> Read<Coefficients> {
    if !data.starts_with(&[0xFF, 0xD8]) {
        return Err(Refusal::Other);
    }
    let mut pos = 2;
    let mut quant: [Option<[u16; 64]>; 4] = [None; 4];
    let mut dc: [Option<Decoding>; 4] = [None, None, None, None];
    let mut ac: [Option<Decoding>; 4] = [None, None, None, None];
    let mut frame: Option<Frame> = None;
    let mut restart = 0u16;
    let mut jfif: Option<Density> = None;
    let mut exif_density = None;
    let mut orientation = None;
    let mut adobe: Option<u8> = None;
    let mut icc: Vec<(u8, u8, &[u8])> = Vec::new();
    let mut scans = 0;

    loop {
        if pos >= data.len() {
            // A file that stops after a scan without saying so is common
            // enough, and what was read of it is whole.
            if scans > 0 {
                break;
            }
            return Err(Refusal::Other);
        }
        if data[pos] != 0xFF {
            return Err(Refusal::Other);
        }
        while data.get(pos) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&marker) = data.get(pos) else {
            return Err(Refusal::Other);
        };
        pos += 1;
        match marker {
            0xD9 => break,
            0x01 | 0xD0..=0xD7 => continue,
            0xD8 => return Err(Refusal::Other),
            _ => {}
        }
        let length = be16(data, pos)? as usize;
        if length < 2 || pos + length > data.len() {
            return Err(Refusal::Other);
        }
        let segment = &data[pos + 2..pos + length];
        let next = pos + length;
        match marker {
            0xC0..=0xC2 => {
                if frame.is_some() {
                    return Err(Refusal::Other);
                }
                frame = Some(read_frame(segment, marker == 0xC2, limits)?);
            }
            // Lossless, hierarchical and arithmetic-coded frames, and the
            // tables of arithmetic coding.
            0xC3 | 0xC5..=0xCF => return Err(Refusal::Other),
            0xC4 => read_huffman(segment, &mut dc, &mut ac)?,
            0xDB => read_quant(segment, &mut quant)?,
            0xDD => restart = be16(segment, 0)?,
            // A height given after the first scan.
            0xDC => return Err(Refusal::Other),
            0xDA => {
                let frame = frame.as_mut().ok_or(Refusal::Other)?;
                let scan = read_scan_header(segment, frame)?;
                for &(index, _, _) in &scan.components {
                    let component = &mut frame.components[index];
                    if component.quant.is_none() {
                        component.quant = quant[component.table as usize];
                    }
                }
                let end = decode_scan(data, next, frame, &scan, &dc, &ac, restart, deadline)?;
                scans += 1;
                pos = next_marker(data, end);
                continue;
            }
            0xE0 if segment.starts_with(b"JFIF\0") && segment.len() >= 12 => {
                let unit = segment[7];
                let (x, y) = (be16(segment, 8)?, be16(segment, 10)?);
                if unit <= 2 && x > 0 && y > 0 {
                    jfif = Some(Density { unit, x, y });
                }
            }
            0xE1 if orientation.is_none() && segment.starts_with(b"Exif\0\0") => {
                let (found, density) = exif(segment);
                orientation = Some(found.unwrap_or(1));
                exif_density = density;
            }
            0xE2 if segment.starts_with(b"ICC_PROFILE\0") && segment.len() >= 14 => {
                icc.push((segment[12], segment[13], &segment[14..]));
            }
            0xEE if segment.starts_with(b"Adobe") && segment.len() >= 12 => {
                adobe = Some(segment[11]);
            }
            _ => {}
        }
        pos = next;
    }

    let frame = frame.ok_or(Refusal::Other)?;
    if scans == 0 {
        return Err(Refusal::Other);
    }
    let mut components = frame.components;
    for component in &mut components {
        if component.quant.is_none() {
            component.quant = quant[component.table as usize];
        }
        if component.quant.is_none() {
            return Err(Refusal::Other);
        }
    }
    let rgb = components.len() == 3
        && jfif.is_none()
        && match adobe {
            Some(transform) => transform == 0,
            None => components.iter().map(|c| c.id).eq(*b"RGB"),
        };
    // A density in a unit says more than one that only gives the shape.
    let density = match jfif {
        Some(density) if density.unit != 0 => density,
        _ => exif_density.or(jfif).unwrap_or_default(),
    };
    Ok(Coefficients {
        width: frame.width,
        height: frame.height,
        components,
        rgb,
        adobe,
        density,
        orientation: orientation.unwrap_or(1),
        icc: assemble_icc(icc),
    })
}

/// A profile split over APP2 segments, in the order of their numbers, if
/// every piece is there once.
fn assemble_icc(mut pieces: Vec<(u8, u8, &[u8])>) -> Option<Vec<u8>> {
    let count = pieces.first()?.1;
    pieces.sort_by_key(|piece| piece.0);
    let whole = pieces.len() == count as usize
        && pieces
            .iter()
            .enumerate()
            .all(|(index, piece)| piece.0 as usize == index + 1 && piece.1 == count);
    whole.then(|| pieces.iter().flat_map(|piece| piece.2).copied().collect())
}

fn read_frame(segment: &[u8], progressive: bool, limits: &Limits) -> Read<Frame> {
    let (Some(&precision), Some(&count)) = (segment.first(), segment.get(5)) else {
        return Err(Refusal::Other);
    };
    let (height, width) = (be16(segment, 1)? as u32, be16(segment, 3)? as u32);
    if precision != 8 || height == 0 || width == 0 || !matches!(count, 1 | 3 | 4) {
        return Err(Refusal::Other);
    }
    if width as u64 * height as u64 > limits.max_pixels {
        return Err(Refusal::TooLarge);
    }
    let mut components = Vec::new();
    for index in 0..count as usize {
        let at = 6 + index * 3;
        let Some(&[id, sampling, table]) = segment.get(at..at + 3) else {
            return Err(Refusal::Other);
        };
        let (h, v) = (sampling >> 4, sampling & 15);
        if !(1..=4).contains(&h) || !(1..=4).contains(&v) || table > 3 {
            return Err(Refusal::Other);
        }
        if components.iter().any(|c: &Component| c.id == id) {
            return Err(Refusal::Other);
        }
        components.push(Component {
            id,
            h,
            v,
            table,
            quant: None,
            across: 0,
            down: 0,
            blocks: Vec::new(),
        });
    }
    // One component is one block to an MCU, whatever its factors say.
    if count == 1 {
        components[0].h = 1;
        components[0].v = 1;
    }
    let h_max = components.iter().map(|c| c.h).max().unwrap_or(1);
    let v_max = components.iter().map(|c| c.v).max().unwrap_or(1);
    let mcus_across = (width as usize).div_ceil(8 * h_max as usize);
    let mcus_down = (height as usize).div_ceil(8 * v_max as usize);
    let blocks: u64 = components
        .iter()
        .map(|c| (mcus_across * c.h as usize * mcus_down * c.v as usize) as u64)
        .sum();
    if blocks.saturating_mul(size_of::<Block>() as u64) > limits.max_decompressed {
        return Err(Refusal::TooLarge);
    }
    for component in &mut components {
        component.across = mcus_across * component.h as usize;
        component.down = mcus_down * component.v as usize;
        component.blocks = vec![[0; 64]; component.across * component.down];
    }
    Ok(Frame {
        width,
        height,
        progressive,
        components,
        h_max,
        v_max,
        mcus_across,
        mcus_down,
    })
}

fn read_huffman(
    mut segment: &[u8],
    dc: &mut [Option<Decoding>; 4],
    ac: &mut [Option<Decoding>; 4],
) -> Read<()> {
    while !segment.is_empty() {
        let Some((&class_id, rest)) = segment.split_first() else {
            return Err(Refusal::Other);
        };
        let (class, id) = (class_id >> 4, (class_id & 15) as usize);
        let counts: [u8; 16] = rest
            .get(..16)
            .and_then(|c| c.try_into().ok())
            .ok_or(Refusal::Other)?;
        let total: usize = counts.iter().map(|&c| c as usize).sum();
        let values = rest.get(16..16 + total).ok_or(Refusal::Other)?;
        if class > 1 || id > 3 || total > 256 {
            return Err(Refusal::Other);
        }
        let table = Decoding::new(&counts, values)?;
        let slot = if class == 0 { &mut dc[id] } else { &mut ac[id] };
        *slot = Some(table);
        segment = &rest[16 + total..];
    }
    Ok(())
}

fn read_quant(mut segment: &[u8], quant: &mut [Option<[u16; 64]>; 4]) -> Read<()> {
    while let Some((&precision_id, rest)) = segment.split_first() {
        let (precision, id) = (precision_id >> 4, (precision_id & 15) as usize);
        if precision > 1 || id > 3 {
            return Err(Refusal::Other);
        }
        let size = 64 << precision;
        let values = rest.get(..size).ok_or(Refusal::Other)?;
        let mut table = [0u16; 64];
        for (index, entry) in table.iter_mut().enumerate() {
            *entry = match precision {
                0 => values[index] as u16,
                _ => u16::from_be_bytes([values[index * 2], values[index * 2 + 1]]),
            };
        }
        if table.contains(&0) {
            return Err(Refusal::Other);
        }
        quant[id] = Some(table);
        segment = &rest[size..];
    }
    Ok(())
}

fn read_scan_header(segment: &[u8], frame: &Frame) -> Read<Scan> {
    let count = *segment.first().ok_or(Refusal::Other)? as usize;
    if count == 0 || count > frame.components.len() {
        return Err(Refusal::Other);
    }
    let mut components = Vec::new();
    for index in 0..count {
        let at = 1 + index * 2;
        let Some(&[id, tables]) = segment.get(at..at + 2) else {
            return Err(Refusal::Other);
        };
        let component = frame
            .components
            .iter()
            .position(|c| c.id == id)
            .ok_or(Refusal::Other)?;
        let (dc, ac) = ((tables >> 4) as usize, (tables & 15) as usize);
        if dc > 3 || ac > 3 || components.iter().any(|c: &(usize, _, _)| c.0 == component) {
            return Err(Refusal::Other);
        }
        components.push((component, dc, ac));
    }
    let at = 1 + count * 2;
    let Some(&[start, end, approximation]) = segment.get(at..at + 3) else {
        return Err(Refusal::Other);
    };
    let (high, low) = (approximation >> 4, approximation & 15);
    let valid = if frame.progressive {
        let dc = start == 0 && end == 0;
        let ac = start >= 1 && start <= end && end <= 63 && count == 1;
        (dc || ac) && high <= 13 && low <= 13
    } else {
        start == 0 && end == 63 && high == 0 && low == 0
    };
    if !valid {
        return Err(Refusal::Other);
    }
    // An MCU of more than ten blocks is not allowed.
    let blocks: usize = components
        .iter()
        .map(|&(index, _, _)| {
            let c = &frame.components[index];
            c.h as usize * c.v as usize
        })
        .sum();
    if count > 1 && blocks > 10 {
        return Err(Refusal::Other);
    }
    Ok(Scan {
        components,
        start,
        end,
        high,
        low,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_scan(
    data: &[u8],
    start: usize,
    frame: &mut Frame,
    scan: &Scan,
    dc: &[Option<Decoding>; 4],
    ac: &[Option<Decoding>; 4],
    restart: u16,
    deadline: Deadline,
) -> Read<usize> {
    let kind = match (frame.progressive, scan.start, scan.high) {
        (false, _, _) => Kind::Sequential,
        (true, 0, 0) => Kind::DcFirst,
        (true, 0, _) => Kind::DcRefine,
        (true, _, 0) => Kind::AcFirst,
        (true, _, _) => Kind::AcRefine,
    };
    // The tables each component of the scan needs.
    let mut tables = Vec::new();
    for &(index, dc_id, ac_id) in &scan.components {
        let dc_table = match kind {
            Kind::Sequential | Kind::DcFirst => Some(dc[dc_id].as_ref().ok_or(Refusal::Other)?),
            _ => None,
        };
        let ac_table = match kind {
            Kind::Sequential | Kind::AcFirst | Kind::AcRefine => {
                Some(ac[ac_id].as_ref().ok_or(Refusal::Other)?)
            }
            _ => None,
        };
        tables.push((index, dc_table, ac_table));
    }

    let single = scan.components.len() == 1;
    let (across, down) = if single {
        frame.exact(&frame.components[scan.components[0].0])
    } else {
        (frame.mcus_across, frame.mcus_down)
    };
    let mut bits = Bits::new(data, start);
    let mut predictions = [0i32; 4];
    let mut eob_run = 0u32;
    let mut left = restart;
    for mcu in 0..across * down {
        if restart > 0 {
            if left == 0 {
                bits.restart()?;
                predictions = [0; 4];
                eob_run = 0;
                left = restart;
            }
            left -= 1;
        }
        let (x, y) = (mcu % across, mcu / across);
        if x == 0 {
            if deadline.check().is_err() {
                return Err(Refusal::TimedOut);
            }
            if bits.overran() {
                return Err(Refusal::Other);
            }
        }
        for (slot, &(index, dc_table, ac_table)) in tables.iter().enumerate() {
            let component = &mut frame.components[index];
            let (h, v) = if single {
                (1, 1)
            } else {
                (component.h as usize, component.v as usize)
            };
            for by in 0..v {
                for bx in 0..h {
                    let at = (y * v + by) * component.across + x * h + bx;
                    let block = &mut component.blocks[at];
                    let prediction = &mut predictions[slot];
                    match kind {
                        Kind::Sequential => {
                            sequential(&mut bits, block, prediction, dc_table, ac_table)?
                        }
                        Kind::DcFirst => {
                            let size = bits.decode(dc_table.ok_or(Refusal::Other)?)?;
                            if size > 11 {
                                return Err(Refusal::Other);
                            }
                            *prediction += bits.extend(size);
                            block[0] = coefficient(*prediction << scan.low)?;
                        }
                        Kind::DcRefine => {
                            if bits.take(1) == 1 {
                                block[0] |= 1 << scan.low;
                            }
                        }
                        Kind::AcFirst => ac_first(&mut bits, block, &mut eob_run, ac_table, scan)?,
                        Kind::AcRefine => {
                            ac_refine(&mut bits, block, &mut eob_run, ac_table, scan)?
                        }
                    }
                }
            }
        }
    }
    if bits.overran() {
        return Err(Refusal::Other);
    }
    Ok(bits.pos)
}

#[derive(Clone, Copy)]
enum Kind {
    Sequential,
    DcFirst,
    DcRefine,
    AcFirst,
    AcRefine,
}

fn coefficient(value: i32) -> Read<i16> {
    i16::try_from(value).map_err(|_| Refusal::Other)
}

fn sequential(
    bits: &mut Bits<'_>,
    block: &mut Block,
    prediction: &mut i32,
    dc: Option<&Decoding>,
    ac: Option<&Decoding>,
) -> Read<()> {
    let (dc, ac) = (dc.ok_or(Refusal::Other)?, ac.ok_or(Refusal::Other)?);
    let size = bits.decode(dc)?;
    if size > 11 {
        return Err(Refusal::Other);
    }
    *prediction += bits.extend(size);
    block[0] = coefficient(*prediction)?;
    let mut k = 1;
    while k < 64 {
        let symbol = bits.decode(ac)?;
        let (run, size) = ((symbol >> 4) as usize, symbol & 15);
        if size == 0 {
            if run != 15 {
                break;
            }
            k += 16;
            continue;
        }
        k += run;
        if k > 63 || size > 10 {
            return Err(Refusal::Other);
        }
        block[k] = bits.extend(size) as i16;
        k += 1;
    }
    Ok(())
}

fn ac_first(
    bits: &mut Bits<'_>,
    block: &mut Block,
    eob_run: &mut u32,
    ac: Option<&Decoding>,
    scan: &Scan,
) -> Read<()> {
    if *eob_run > 0 {
        *eob_run -= 1;
        return Ok(());
    }
    let ac = ac.ok_or(Refusal::Other)?;
    let (mut k, end) = (scan.start as usize, scan.end as usize);
    while k <= end {
        let symbol = bits.decode(ac)?;
        let (run, size) = ((symbol >> 4) as u32, symbol & 15);
        if size == 0 {
            if run < 15 {
                *eob_run = (1 << run) - 1 + bits.take(run);
                break;
            }
            k += 16;
            continue;
        }
        k += run as usize;
        if k > end || size > 10 {
            return Err(Refusal::Other);
        }
        block[k] = coefficient(bits.extend(size) << scan.low)?;
        k += 1;
    }
    Ok(())
}

/// libjpeg's `decode_mcu_AC_refine`.
fn ac_refine(
    bits: &mut Bits<'_>,
    block: &mut Block,
    eob_run: &mut u32,
    ac: Option<&Decoding>,
    scan: &Scan,
) -> Read<()> {
    let ac = ac.ok_or(Refusal::Other)?;
    let plus = 1i32 << scan.low;
    let minus = -1i32 << scan.low;
    let (mut k, end) = (scan.start as usize, scan.end as usize);
    let refine = |bits: &mut Bits<'_>, coef: &mut i16| -> Read<()> {
        if bits.take(1) == 1 && (*coef as i32 & plus) == 0 {
            let step = if *coef >= 0 { plus } else { minus };
            *coef = coefficient(*coef as i32 + step)?;
        }
        Ok(())
    };
    if *eob_run == 0 {
        while k <= end {
            let symbol = bits.decode(ac)?;
            let (mut run, size) = ((symbol >> 4) as i32, symbol & 15);
            let mut value = 0;
            if size != 0 {
                if size != 1 {
                    return Err(Refusal::Other);
                }
                value = if bits.take(1) == 1 { plus } else { minus };
            } else if run != 15 {
                *eob_run = (1u32 << run) + bits.take(run as u32);
                break;
            }
            while k <= end {
                let coef = &mut block[k];
                if *coef != 0 {
                    refine(bits, coef)?;
                } else {
                    run -= 1;
                    if run < 0 {
                        break;
                    }
                }
                k += 1;
            }
            if value != 0 {
                if k > end {
                    return Err(Refusal::Other);
                }
                block[k] = coefficient(value)?;
            }
            k += 1;
        }
    }
    if *eob_run > 0 {
        while k <= end {
            let coef = &mut block[k];
            if *coef != 0 {
                refine(bits, coef)?;
            }
            k += 1;
        }
        *eob_run -= 1;
    }
    Ok(())
}

// --- turning -------------------------------------------------------------

/// The zigzag index of each coefficient's mirror across the diagonal.
fn transposed() -> [u8; 64] {
    let mut zigzag = [0u8; 64];
    for (k, &natural) in NATURAL.iter().enumerate() {
        zigzag[natural as usize] = k as u8;
    }
    let mut out = [0u8; 64];
    for (k, &natural) in NATURAL.iter().enumerate() {
        let (row, column) = (natural / 8, natural % 8);
        out[k] = zigzag[(column * 8 + row) as usize];
    }
    out
}

impl Coefficients {
    /// Turn the coefficients the way the orientation says, if that can be
    /// done without losing anything; otherwise leave them as they are.
    pub(super) fn orient(&mut self) -> bool {
        let (transpose, h_flip, v_flip) = match self.orientation {
            1 => return true,
            2 => (false, true, false),
            3 => (false, true, true),
            4 => (false, false, true),
            5 => (true, false, false),
            6 => (true, true, false),
            7 => (true, true, true),
            8 => (true, false, true),
            _ => return false,
        };
        let (width, height) = if transpose {
            (self.height, self.width)
        } else {
            (self.width, self.height)
        };
        let factors = |c: &Component| if transpose { (c.v, c.h) } else { (c.h, c.v) };
        let h_max = self
            .components
            .iter()
            .map(|c| factors(c).0)
            .max()
            .unwrap_or(1);
        let v_max = self
            .components
            .iter()
            .map(|c| factors(c).1)
            .max()
            .unwrap_or(1);
        // An edge that moves has to fall on whole MCUs, or the blocks that
        // run past it would come out on the other side.
        if (h_flip && width % (8 * h_max as u32) != 0)
            || (v_flip && height % (8 * v_max as u32) != 0)
        {
            return false;
        }
        let mirror = transposed();
        for component in &mut self.components {
            if transpose {
                let mut blocks = vec![[0i16; 64]; component.blocks.len()];
                for y in 0..component.down {
                    for x in 0..component.across {
                        let from = &component.blocks[y * component.across + x];
                        let to = &mut blocks[x * component.down + y];
                        for k in 0..64 {
                            to[mirror[k] as usize] = from[k];
                        }
                    }
                }
                component.blocks = blocks;
                std::mem::swap(&mut component.across, &mut component.down);
                std::mem::swap(&mut component.h, &mut component.v);
                if let Some(quant) = &mut component.quant {
                    let mut turned = [0u16; 64];
                    for k in 0..64 {
                        turned[mirror[k] as usize] = quant[k];
                    }
                    *quant = turned;
                }
            }
            let (across, down) = (component.across, component.down);
            // Each axis that moves needs exactly the blocks of the image
            // along it, which is what whole MCUs give.
            if h_flip {
                for row in component.blocks.chunks_mut(across) {
                    row.reverse();
                }
            }
            if v_flip {
                for y in 0..down / 2 {
                    for x in 0..across {
                        component
                            .blocks
                            .swap(y * across + x, (down - 1 - y) * across + x);
                    }
                }
            }
            if h_flip || v_flip {
                for block in &mut component.blocks {
                    for (k, coef) in block.iter_mut().enumerate() {
                        let natural = NATURAL[k];
                        let odd = (h_flip && natural % 2 == 1) ^ (v_flip && (natural / 8) % 2 == 1);
                        if odd {
                            *coef = coef.saturating_neg();
                        }
                    }
                }
            }
        }
        self.width = width;
        self.height = height;
        self.orientation = 1;
        true
    }

    /// The tables and sampling, for compressing the pixels again.
    pub(super) fn source(&self) -> Option<Source> {
        let luma = self.components.first()?.quant?;
        let chroma = self.components.get(1).and_then(|c| c.quant);
        Some(Source {
            luma,
            chroma,
            density: self.density,
        })
    }

    pub(super) fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

// --- writing -------------------------------------------------------------

/// The code of each symbol of a Huffman table: its bits and its length.
struct Encoding {
    counts: [u8; 16],
    values: Vec<u8>,
    codes: [(u16, u8); 256],
}

impl Encoding {
    /// The optimal table for the symbol frequencies, codes at most 16 bits
    /// long (JPEG Annex K.2, as libjpeg's `jpeg_gen_optimal_table`).
    fn optimal(frequencies: &[u64; 256]) -> Self {
        let mut freq = [0u64; 257];
        freq[..256].copy_from_slice(frequencies);
        if !frequencies.iter().any(|&f| f > 0) {
            freq[0] = 1;
        }
        // A symbol that never occurs keeps any code from being all ones.
        freq[256] = 1;
        let mut size = [0usize; 257];
        let mut others = [-1i32; 257];
        loop {
            let mut first: i32 = -1;
            let mut least = u64::MAX;
            for (i, &f) in freq.iter().enumerate() {
                if f != 0 && f <= least {
                    least = f;
                    first = i as i32;
                }
            }
            let mut second: i32 = -1;
            least = u64::MAX;
            for (i, &f) in freq.iter().enumerate() {
                if f != 0 && f <= least && i as i32 != first {
                    least = f;
                    second = i as i32;
                }
            }
            if second < 0 {
                break;
            }
            let (mut a, mut b) = (first as usize, second as usize);
            freq[a] += freq[b];
            freq[b] = 0;
            size[a] += 1;
            while others[a] >= 0 {
                a = others[a] as usize;
                size[a] += 1;
            }
            others[a] = b as i32;
            size[b] += 1;
            while others[b] >= 0 {
                b = others[b] as usize;
                size[b] += 1;
            }
        }
        // A tree of 257 leaves is at most 256 deep.
        let mut bits = [0u32; 258];
        for &s in &size {
            if s > 0 {
                bits[s] += 1;
            }
        }
        for i in (17..bits.len()).rev() {
            while bits[i] > 0 {
                let mut j = i - 2;
                while bits[j] == 0 {
                    j -= 1;
                }
                bits[i] -= 2;
                bits[i - 1] += 1;
                bits[j + 1] += 2;
                bits[j] -= 1;
            }
        }
        let mut longest = 16;
        while bits[longest] == 0 {
            longest -= 1;
        }
        // The symbol that never occurs gives up its code.
        bits[longest] -= 1;
        let mut values = Vec::new();
        // Ordered by the lengths the tree gave them; the counts above say
        // which lengths they get now.
        for length in 1..=256 {
            for (symbol, &s) in size.iter().enumerate().take(256) {
                if s == length {
                    values.push(symbol as u8);
                }
            }
        }
        let mut counts = [0u8; 16];
        for (i, count) in counts.iter_mut().enumerate() {
            *count = bits[i + 1] as u8;
        }
        let mut codes = [(0u16, 0u8); 256];
        let (mut code, mut index) = (0u16, 0usize);
        for (i, &count) in counts.iter().enumerate() {
            for _ in 0..count {
                codes[values[index] as usize] = (code, i as u8 + 1);
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        Self {
            counts,
            values,
            codes,
        }
    }
}

/// Bits written to a file, with a 0 stuffed after each 0xFF.
struct Writer {
    out: Vec<u8>,
    word: u64,
    count: u32,
}

impl Writer {
    fn put(&mut self, value: u32, length: u8) {
        if length == 0 {
            return;
        }
        let value = value as u64 & ((1u64 << length) - 1);
        self.word = (self.word << length) | value;
        self.count += length as u32;
        while self.count >= 8 {
            let byte = (self.word >> (self.count - 8)) as u8;
            self.out.push(byte);
            if byte == 0xFF {
                self.out.push(0);
            }
            self.count -= 8;
        }
    }

    fn finish(&mut self) {
        let pad = (8 - self.count % 8) % 8;
        self.put((1 << pad) - 1, pad as u8);
    }
}

/// The number of bits of a value's magnitude.
fn magnitude(value: i32) -> u8 {
    (32 - value.unsigned_abs().leading_zeros()) as u8
}

fn segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) {
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&(body.len() as u16 + 2).to_be_bytes());
    out.extend_from_slice(body);
}

impl Coefficients {
    /// Each block in the order a single interleaved scan goes over them,
    /// with the index of its component.
    fn each_block(&self, mut visit: impl FnMut(usize, &Block) -> Option<()>) -> Option<()> {
        let zero = [0i16; 64];
        let h_max = self.components.iter().map(|c| c.h).max()? as usize;
        let v_max = self.components.iter().map(|c| c.v).max()? as usize;
        let mcus_across = (self.width as usize).div_ceil(8 * h_max);
        let mcus_down = (self.height as usize).div_ceil(8 * v_max);
        for y in 0..mcus_down {
            for x in 0..mcus_across {
                for (index, component) in self.components.iter().enumerate() {
                    let (h, v) = (component.h as usize, component.v as usize);
                    for by in 0..v {
                        for bx in 0..h {
                            let (column, row) = (x * h + bx, y * v + by);
                            let block = if column < component.across && row < component.down {
                                &component.blocks[row * component.across + column]
                            } else {
                                &zero
                            };
                            visit(index, block)?;
                        }
                    }
                }
            }
        }
        Some(())
    }

    /// Write the coefficients as a baseline JPEG; `None` if they do not fit
    /// in one.
    /// Whether the components are four inks, or three and black.
    pub(super) fn inks(&self) -> bool {
        self.components.len() == 4
    }

    /// Write the coefficients as a baseline JPEG, with the colour profile
    /// `icc` if one is given; `None` if they do not fit in one.
    pub(super) fn write(&self, icc: Option<&[u8]>) -> Option<Vec<u8>> {
        // Luma and chroma each have their tables.
        let class = |index: usize| usize::from(index > 0);
        let mut dc_freq = [[0u64; 256]; 2];
        let mut ac_freq = [[0u64; 256]; 2];
        let mut predictions = [0i32; 4];
        self.each_block(|index, block| {
            let difference = block[0] as i32 - predictions[index];
            predictions[index] = block[0] as i32;
            let size = magnitude(difference);
            if size > 11 {
                return None;
            }
            dc_freq[class(index)][size as usize] += 1;
            let mut run = 0;
            for &coef in &block[1..] {
                if coef == 0 {
                    run += 1;
                    continue;
                }
                while run > 15 {
                    ac_freq[class(index)][0xF0] += 1;
                    run -= 16;
                }
                let size = magnitude(coef as i32);
                if size > 10 {
                    return None;
                }
                ac_freq[class(index)][(run << 4 | size) as usize] += 1;
                run = 0;
            }
            if run > 0 {
                ac_freq[class(index)][0] += 1;
            }
            Some(())
        })?;
        let classes = if self.components.len() > 1 { 2 } else { 1 };
        let dc: Vec<Encoding> = (0..classes)
            .map(|c| Encoding::optimal(&dc_freq[c]))
            .collect();
        let ac: Vec<Encoding> = (0..classes)
            .map(|c| Encoding::optimal(&ac_freq[c]))
            .collect();

        // The quantisation tables, each once.
        let mut tables: Vec<[u16; 64]> = Vec::new();
        let mut table_of = Vec::new();
        for component in &self.components {
            let quant = component.quant?;
            let index = match tables.iter().position(|t| *t == quant) {
                Some(index) => index,
                None => {
                    tables.push(quant);
                    tables.len() - 1
                }
            };
            table_of.push(index as u8);
        }
        let wide = tables.iter().flatten().any(|&q| q > 255);

        let mut out = vec![0xFF, 0xD8];
        if self.inks() {
            // Inks are read as the Adobe segment says, and stored inverted
            // where there is one; it is kept as it was, or left out.
            if let Some(transform) = self.adobe {
                let mut adobe = b"Adobe\0\x64\0\0\0\0".to_vec();
                adobe.push(transform);
                segment(&mut out, 0xEE, &adobe);
            }
        } else if self.rgb {
            // Three components that are not to be converted from YCbCr.
            segment(&mut out, 0xEE, b"Adobe\0\x64\0\0\0\0\0");
        } else {
            let d = self.density;
            let mut jfif = b"JFIF\0\x01\x02".to_vec();
            jfif.push(d.unit);
            jfif.extend_from_slice(&d.x.to_be_bytes());
            jfif.extend_from_slice(&d.y.to_be_bytes());
            jfif.extend_from_slice(&[0, 0]);
            segment(&mut out, 0xE0, &jfif);
        }
        // The profile, in pieces that fit a segment each.
        if let Some(icc) = icc {
            let pieces = icc.chunks(65_519);
            let count = u8::try_from(pieces.len()).ok()?;
            for (index, piece) in pieces.enumerate() {
                let mut body = b"ICC_PROFILE\0".to_vec();
                body.extend_from_slice(&[index as u8 + 1, count]);
                body.extend_from_slice(piece);
                segment(&mut out, 0xE2, &body);
            }
        }
        for (id, table) in tables.iter().enumerate() {
            let mut body = vec![(u8::from(wide) << 4) | id as u8];
            for &q in table {
                if wide {
                    body.extend_from_slice(&q.to_be_bytes());
                } else {
                    body.push(q as u8);
                }
            }
            segment(&mut out, 0xDB, &body);
        }
        let mut frame = vec![8];
        frame.extend_from_slice(&u16::try_from(self.height).ok()?.to_be_bytes());
        frame.extend_from_slice(&u16::try_from(self.width).ok()?.to_be_bytes());
        frame.push(self.components.len() as u8);
        for (component, &table) in self.components.iter().zip(&table_of) {
            frame.extend_from_slice(&[component.id, component.h << 4 | component.v, table]);
        }
        // Tables of 16-bit entries are not allowed in a baseline file.
        segment(&mut out, if wide { 0xC1 } else { 0xC0 }, &frame);
        for (tables, class_bits) in [(&dc, 0x00u8), (&ac, 0x10)] {
            for (id, table) in tables.iter().enumerate() {
                let mut body = vec![class_bits | id as u8];
                body.extend_from_slice(&table.counts);
                body.extend_from_slice(&table.values);
                segment(&mut out, 0xC4, &body);
            }
        }
        let mut scan = vec![self.components.len() as u8];
        for (index, component) in self.components.iter().enumerate() {
            let c = class(index) as u8;
            scan.extend_from_slice(&[component.id, c << 4 | c]);
        }
        scan.extend_from_slice(&[0, 63, 0]);
        segment(&mut out, 0xDA, &scan);

        let mut writer = Writer {
            out,
            word: 0,
            count: 0,
        };
        let mut predictions = [0i32; 4];
        self.each_block(|index, block| {
            let (dc, ac) = (&dc[class(index)], &ac[class(index)]);
            let difference = block[0] as i32 - predictions[index];
            predictions[index] = block[0] as i32;
            let size = magnitude(difference);
            let (code, length) = dc.codes[size as usize];
            writer.put(code as u32, length);
            let extra = if difference < 0 {
                difference - 1
            } else {
                difference
            };
            writer.put(extra as u32, size);
            let mut run = 0;
            for &coef in &block[1..] {
                if coef == 0 {
                    run += 1;
                    continue;
                }
                while run > 15 {
                    let (code, length) = ac.codes[0xF0];
                    writer.put(code as u32, length);
                    run -= 16;
                }
                let value = coef as i32;
                let size = magnitude(value);
                let (code, length) = ac.codes[(run << 4 | size) as usize];
                writer.put(code as u32, length);
                let extra = if value < 0 { value - 1 } else { value };
                writer.put(extra as u32, size);
                run = 0;
            }
            if run > 0 {
                let (code, length) = ac.codes[0];
                writer.put(code as u32, length);
            }
            Some(())
        })?;
        writer.finish();
        let mut out = writer.out;
        out.extend_from_slice(&[0xFF, 0xD9]);
        Some(out)
    }
}

// --- compressing pixels --------------------------------------------------

/// A table of the standard scaled to `quality` as libjpeg does, in zigzag
/// order.
fn scaled(base: &[u16; 64], quality: u8) -> [u16; 64] {
    let quality = quality.clamp(1, 100) as u32;
    let scale = if quality < 50 {
        5000 / quality
    } else {
        200 - quality * 2
    };
    let mut table = [0u16; 64];
    for (k, entry) in table.iter_mut().enumerate() {
        let value = (base[NATURAL[k] as usize] as u32 * scale + 50) / 100;
        *entry = value.clamp(1, 255) as u16;
    }
    table
}

/// The finer of two tables, entry by entry.
fn finer(a: [u16; 64], b: Option<[u16; 64]>) -> [u16; 64] {
    let Some(b) = b else {
        return a;
    };
    let mut out = a;
    for (entry, other) in out.iter_mut().zip(b) {
        *entry = (*entry).min(other);
    }
    out
}

/// The DCT of a block of samples, level-shifted, as `F = M f Mᵀ`.
struct Dct {
    matrix: [[f32; 8]; 8],
}

impl Dct {
    fn new() -> Self {
        let mut matrix = [[0f32; 8]; 8];
        for (u, row) in matrix.iter_mut().enumerate() {
            let c = if u == 0 { 0.5f32.sqrt() } else { 1.0 };
            for (x, entry) in row.iter_mut().enumerate() {
                let angle = ((2 * x + 1) * u) as f32 * std::f32::consts::PI / 16.0;
                *entry = c / 2.0 * angle.cos();
            }
        }
        Self { matrix }
    }

    fn forward(&self, samples: &[[f32; 8]; 8], quant: &[u16; 64], out: &mut Block) {
        let m = &self.matrix;
        let mut rows = [[0f32; 8]; 8];
        for y in 0..8 {
            for u in 0..8 {
                rows[y][u] = (0..8).map(|x| m[u][x] * samples[y][x]).sum();
            }
        }
        let mut full = [0f32; 64];
        for v in 0..8 {
            for u in 0..8 {
                full[v * 8 + u] = (0..8).map(|y| m[v][y] * rows[y][u]).sum();
            }
        }
        for (k, coef) in out.iter_mut().enumerate() {
            let value = full[NATURAL[k] as usize] / quant[k] as f32;
            // A baseline file holds AC values of at most ten bits.
            let limit = if k == 0 { 2047.0 } else { 1023.0 };
            *coef = value.round().clamp(-limit, limit) as i16;
        }
    }
}

/// A plane of samples, as large as the blocks that cover it, the edges
/// repeated into the margin.
fn plane(
    width: usize,
    height: usize,
    across: usize,
    down: usize,
    sample: impl Fn(usize, usize) -> f32,
) -> Vec<f32> {
    let (wide, high) = (across * 8, down * 8);
    let mut out = vec![0f32; wide * high];
    for y in 0..high {
        let sy = y.min(height - 1);
        for x in 0..wide {
            out[y * wide + x] = sample(x.min(width - 1), sy);
        }
    }
    out
}

/// Compress an 8-bit grey or colour image as a baseline JPEG, with tables
/// no coarser than the quality asks for, nor than those of the file it
/// came from.
pub(super) fn encode(
    image: &DynamicImage,
    settings: &Settings,
    deadline: Deadline,
) -> Result<Vec<u8>, Error> {
    let (width, height) = (image.width() as usize, image.height() as usize);
    if width == 0 || height == 0 || width > 65535 || height > 65535 {
        return Err(Error::Encode("image is too large for a JPEG".into()));
    }
    let source = settings.source.as_ref();
    let luma = finer(scaled(&LUMA, settings.quality), source.map(|s| s.luma));
    let chroma = finer(
        scaled(&CHROMA, settings.quality),
        source.and_then(|s| s.chroma),
    );
    // Chroma at full resolution: sampling it down again, after a decoder
    // has sampled it up, loses more than the file it came from had lost.
    let (h, v) = (1u8, 1u8);
    let dct = Dct::new();

    let component =
        |id: u8, h: u8, v: u8, quant: [u16; 64], samples: Vec<f32>, across: usize, down: usize| {
            let mut blocks = vec![[0i16; 64]; across * down];
            let wide = across * 8;
            for by in 0..down {
                for bx in 0..across {
                    let mut block = [[0f32; 8]; 8];
                    for (y, row) in block.iter_mut().enumerate() {
                        let at = (by * 8 + y) * wide + bx * 8;
                        for (x, sample) in row.iter_mut().enumerate() {
                            *sample = samples[at + x] - 128.0;
                        }
                    }
                    dct.forward(&block, &quant, &mut blocks[by * across + bx]);
                }
            }
            Component {
                id,
                h,
                v,
                table: 0,
                quant: Some(quant),
                across,
                down,
                blocks,
            }
        };

    let components = match image {
        DynamicImage::ImageLuma8(grey) => {
            let (across, down) = (width.div_ceil(8), height.div_ceil(8));
            let samples = plane(width, height, across, down, |x, y| {
                grey.get_pixel(x as u32, y as u32).0[0] as f32
            });
            vec![component(1, 1, 1, luma, samples, across, down)]
        }
        DynamicImage::ImageRgb8(rgb) => {
            let (mcus_across, mcus_down) = (
                width.div_ceil(8 * h as usize),
                height.div_ceil(8 * v as usize),
            );
            let pixel = |x: usize, y: usize| {
                let [r, g, b] = rgb.get_pixel(x as u32, y as u32).0.map(|c| c as f32);
                (r, g, b)
            };
            let y_plane = plane(
                width,
                height,
                mcus_across * h as usize,
                mcus_down * v as usize,
                |x, y| {
                    let (r, g, b) = pixel(x, y);
                    0.299 * r + 0.587 * g + 0.114 * b
                },
            );
            deadline.check()?;
            // Chroma averaged over the pixels each of its samples covers.
            let (cw, ch) = (width.div_ceil(h as usize), height.div_ceil(v as usize));
            let average = |x: usize, y: usize, f: &dyn Fn(f32, f32, f32) -> f32| {
                let mut sum = 0.0;
                let mut n = 0.0;
                for dy in 0..v as usize {
                    for dx in 0..h as usize {
                        let (px, py) = (
                            (x * h as usize + dx).min(width - 1),
                            (y * v as usize + dy).min(height - 1),
                        );
                        let (r, g, b) = pixel(px, py);
                        sum += f(r, g, b);
                        n += 1.0;
                    }
                }
                sum / n
            };
            let cb = |r: f32, g: f32, b: f32| -0.168_736 * r - 0.331_264 * g + 0.5 * b + 128.0;
            let cr = |r: f32, g: f32, b: f32| 0.5 * r - 0.418_688 * g - 0.081_312 * b + 128.0;
            let cb_plane = plane(cw, ch, mcus_across, mcus_down, |x, y| average(x, y, &cb));
            let cr_plane = plane(cw, ch, mcus_across, mcus_down, |x, y| average(x, y, &cr));
            deadline.check()?;
            let (luma_across, luma_down) = (mcus_across * h as usize, mcus_down * v as usize);
            vec![
                component(1, h, v, luma, y_plane, luma_across, luma_down),
                component(2, 1, 1, chroma, cb_plane, mcus_across, mcus_down),
                component(3, 1, 1, chroma, cr_plane, mcus_across, mcus_down),
            ]
        }
        _ => return Err(Error::Encode("a JPEG holds 8-bit grey or colour".into())),
    };
    deadline.check()?;
    let coefficients = Coefficients {
        width: width as u32,
        height: height as u32,
        components,
        rgb: false,
        adobe: None,
        density: source.map(|s| s.density).unwrap_or_default(),
        orientation: 1,
        icc: None,
    };
    coefficients
        .write(None)
        .ok_or_else(|| Error::Encode("coefficients out of range".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimal_tables_are_prefix_codes_of_at_most_sixteen_bits() {
        // Frequencies of a Fibonacci sequence make the deepest tree.
        let mut frequencies = [0u64; 256];
        let (mut a, mut b) = (1u64, 1u64);
        for f in frequencies.iter_mut().take(40) {
            *f = a;
            (a, b) = (b, a + b);
        }
        let table = Encoding::optimal(&frequencies);
        let used: Vec<_> = (0..40).map(|s| table.codes[s]).collect();
        assert!(used.iter().all(|&(_, length)| (1..=16).contains(&length)));
        // No code is a prefix of another, and none is all ones.
        for (i, &(code, length)) in used.iter().enumerate() {
            assert_ne!(code as u32, (1u32 << length) - 1);
            for &(other, other_length) in &used[i + 1..] {
                let shorter = length.min(other_length);
                let a = code >> (length - shorter);
                let b = other >> (other_length - shorter);
                assert_ne!(a, b);
            }
        }
        // And a decoder takes it.
        assert!(Decoding::new(&table.counts, &table.values).is_ok());
    }

    #[test]
    fn exif_gives_orientation_and_density() {
        // Four entries, then the two resolutions they point to.
        let mut segment = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\x04".to_vec();
        segment.extend_from_slice(b"\x01\x12\0\x03\0\0\0\x01\0\x06\0\0");
        segment.extend_from_slice(b"\x01\x1A\0\x05\0\0\0\x01\0\0\0\x3E");
        segment.extend_from_slice(b"\x01\x1B\0\x05\0\0\0\x01\0\0\0\x46");
        segment.extend_from_slice(b"\x01\x28\0\x03\0\0\0\x01\0\x02\0\0");
        segment.extend_from_slice(b"\0\0\0\0");
        for value in [300u32, 1, 600, 2] {
            segment.extend_from_slice(&value.to_be_bytes());
        }
        let (orientation, density) = exif(&segment);
        assert_eq!(orientation, Some(6));
        assert_eq!(
            density,
            Some(Density {
                unit: 1,
                x: 300,
                y: 300
            })
        );
        // Without the second resolution there is no density.
        segment[6 + 9] = 2;
        assert_eq!(exif(&segment).1, None);
    }
}
