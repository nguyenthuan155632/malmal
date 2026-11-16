//! An AVIF image, as a PNG of the picture it shows.
//!
//! The primary item is decoded with `filmcraft-av1`, an AV1 decoder in safe
//! Rust that gives the samples libdav1d gives; a grid of tiles is put
//! together first. Its samples are turned into RGB by the matrix and range
//! the file gives, at 8 bits a channel or, if it holds more, at 16, with
//! the auxiliary alpha image if there is one. The picture is then cut,
//! turned and mirrored as its properties say, and its colours brought into
//! sRGB from its ICC profile or from the primaries and transfer it names;
//! or, when they are to be kept, left as they are under the profile written
//! anew, or with the primaries and transfer named in the PNG (`cICP`).
//! Pictures in a range only a display for high dynamic range shows (PQ,
//! HLG) cannot be brought into sRGB: they are always left as they are, at
//! 16 bits a channel, with what they are named in the PNG.

use image::{DynamicImage, ImageBuffer, Luma, LumaA, Rgb, Rgba};
use moxcms::{
    CicpColorPrimaries, CicpProfile, ColorProfile, MatrixCoefficients, TransferCharacteristics,
};

use super::{Deadline, Error, ToSrgb, colour};
use crate::detect::FileType;
use crate::limits::Limits;

fn broken(what: &str) -> Error {
    Error::Decode(format!("AVIF {what}"))
}

fn refused(reason: &'static str) -> Error {
    Error::Unsupported {
        file_type: FileType::Avif,
        reason,
    }
}

/// Boxes nested deeper than this, or more of them, are refused.
const MOST_BOXES: usize = 1 << 16;
/// Tiles of a grid, and items, at most.
const MOST_ITEMS: usize = 1 << 12;

/// The boxes laid end to end in `body`.
/// Boxes by kind, each with its body.
type Boxes<'a> = Vec<([u8; 4], &'a [u8])>;

fn boxes(body: &[u8]) -> Result<Boxes<'_>, Error> {
    let mut found = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let short = || broken("box is cut short");
        let size = u32::from_be_bytes(rest.get(..4).ok_or_else(short)?.try_into().unwrap());
        let kind: [u8; 4] = rest.get(4..8).ok_or_else(short)?.try_into().unwrap();
        let (start, size) = match size {
            0 => (8, rest.len()),
            1 => {
                let large = rest.get(8..16).ok_or_else(short)?;
                (
                    16,
                    usize::try_from(u64::from_be_bytes(large.try_into().unwrap()))
                        .map_err(|_| short())?,
                )
            }
            size => (8, size as usize),
        };
        if size < start || size > rest.len() || found.len() >= MOST_BOXES {
            return Err(broken("box does not fit"));
        }
        found.push((kind, &rest[start..size]));
        rest = &rest[size..];
    }
    Ok(found)
}

/// The boxes at the top of a file, up to the first that is not one:
/// whatever follows them is not part of the image.
fn top_level(data: &[u8]) -> Boxes<'_> {
    let mut found = Vec::new();
    let mut rest = data;
    while rest.len() >= 8 {
        let size = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let size = if size == 0 { rest.len() } else { size };
        if size < 8 || size > rest.len() || found.len() >= MOST_BOXES {
            break;
        }
        found.push((rest[4..8].try_into().unwrap(), &rest[8..size]));
        rest = &rest[size..];
    }
    found
}

/// Big-endian fields read one after another.
struct Fields<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    /// An unsigned field of `width` bytes, 0 to 8.
    fn take(&mut self, width: usize) -> Result<u64, Error> {
        let bytes = self
            .data
            .get(self.at..self.at + width)
            .filter(|_| width <= 8)
            .ok_or_else(|| broken("box is cut short"))?;
        self.at += width;
        Ok(bytes.iter().fold(0, |value, &b| value << 8 | u64::from(b)))
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)? as u8)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(self.take(2)? as u16)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(self.take(4)? as u32)
    }

    fn four(&mut self) -> Result<[u8; 4], Error> {
        Ok(self.u32()?.to_be_bytes())
    }

    fn rest(&self) -> &'a [u8] {
        self.data.get(self.at..).unwrap_or_default()
    }
}

/// Where the bytes of an item are: in the file, or in the `idat` box.
struct Extent {
    in_idat: bool,
    offset: u64,
    length: u64,
}

struct Item {
    id: u32,
    kind: [u8; 4],
    extents: Vec<Extent>,
    /// Indexes into the properties, 1 for the first, and whether each is
    /// essential.
    properties: Vec<(bool, usize)>,
}

/// The items of the file and what is known of them.
struct Heif<'a> {
    data: &'a [u8],
    primary: u32,
    items: Vec<Item>,
    properties: Boxes<'a>,
    /// References: kind, from, to.
    references: Vec<([u8; 4], u32, Vec<u32>)>,
    idat: &'a [u8],
}

impl<'a> Heif<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let top = top_level(data);
        let meta = top
            .iter()
            .find(|(kind, _)| kind == b"meta")
            .map(|(_, body)| *body)
            .ok_or_else(|| refused("it holds no still image"))?;
        let mut heif = Self {
            data,
            primary: 0,
            items: Vec::new(),
            properties: Vec::new(),
            references: Vec::new(),
            idat: &[],
        };
        let mut primary = None;
        let mut associations = Vec::new();
        for (kind, body) in boxes(meta.get(4..).unwrap_or_default())? {
            let mut fields = Fields::new(body);
            match &kind {
                b"pitm" => {
                    let version = fields.u8()?;
                    fields.take(3)?;
                    primary = Some(if version == 0 {
                        u32::from(fields.u16()?)
                    } else {
                        fields.u32()?
                    });
                }
                b"iinf" => {
                    let version = fields.u8()?;
                    fields.take(3)?;
                    fields.take(if version == 0 { 2 } else { 4 })?;
                    for (entry, body) in boxes(fields.rest())? {
                        if &entry != b"infe" {
                            continue;
                        }
                        let mut fields = Fields::new(body);
                        let version = fields.u8()?;
                        fields.take(3)?;
                        if version < 2 {
                            continue;
                        }
                        let id = if version == 2 {
                            u32::from(fields.u16()?)
                        } else {
                            fields.u32()?
                        };
                        fields.u16()?;
                        let kind = fields.four()?;
                        // Placed already, if `iloc` came first.
                        if let Some(item) = heif.items.iter_mut().find(|i| i.id == id) {
                            item.kind = kind;
                            continue;
                        }
                        if heif.items.len() >= MOST_ITEMS {
                            return Err(refused("it has too many items"));
                        }
                        heif.items.push(Item {
                            id,
                            kind,
                            extents: Vec::new(),
                            properties: Vec::new(),
                        });
                    }
                }
                b"iloc" => {
                    for (id, extents) in locations(body)? {
                        if let Some(item) = heif.items.iter_mut().find(|i| i.id == id) {
                            item.extents = extents;
                        } else {
                            heif.items.push(Item {
                                id,
                                kind: *b"    ",
                                extents,
                                properties: Vec::new(),
                            });
                        }
                    }
                }
                b"iref" => {
                    let version = fields.u8()?;
                    fields.take(3)?;
                    let width = if version == 0 { 2 } else { 4 };
                    for (kind, body) in boxes(fields.rest())? {
                        let mut fields = Fields::new(body);
                        let from = fields.take(width)? as u32;
                        let count = fields.u16()?;
                        let to = (0..count)
                            .map(|_| fields.take(width).map(|v| v as u32))
                            .collect::<Result<Vec<_>, _>>()?;
                        heif.references.push((kind, from, to));
                    }
                }
                b"iprp" => {
                    for (kind, body) in boxes(body)? {
                        match &kind {
                            b"ipco" => heif.properties = boxes(body)?,
                            b"ipma" => associations.push(body),
                            _ => {}
                        }
                    }
                }
                b"idat" => heif.idat = body,
                _ => {}
            }
        }
        for body in associations {
            let mut fields = Fields::new(body);
            let version = fields.u8()?;
            let flags = fields.take(3)?;
            for _ in 0..fields.u32()? {
                let id = if version == 0 {
                    u32::from(fields.u16()?)
                } else {
                    fields.u32()?
                };
                let count = fields.u8()?;
                let mut properties = Vec::with_capacity(count.into());
                for _ in 0..count {
                    let (essential, index) = if flags & 1 == 1 {
                        let v = fields.u16()?;
                        (v & 0x8000 != 0, usize::from(v & 0x7FFF))
                    } else {
                        let v = fields.u8()?;
                        (v & 0x80 != 0, usize::from(v & 0x7F))
                    };
                    properties.push((essential, index));
                }
                if let Some(item) = heif.items.iter_mut().find(|i| i.id == id) {
                    item.properties.extend(properties);
                }
            }
        }
        heif.primary = primary.ok_or_else(|| broken("has no primary item"))?;
        Ok(heif)
    }

    fn item(&self, id: u32) -> Result<&Item, Error> {
        self.items
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| broken("names an item it does not have"))
    }

    /// The properties of an item, in the order they are given. One that is
    /// essential and not understood here refuses the item.
    fn properties(&self, item: &Item) -> Result<Boxes<'a>, Error> {
        const KNOWN: [&[u8; 4]; 9] = [
            b"av1C", b"ispe", b"pixi", b"colr", b"irot", b"imir", b"clap", b"auxC", b"a1lx",
        ];
        let mut found = Vec::new();
        for &(essential, index) in &item.properties {
            if index == 0 {
                continue;
            }
            let property = *self
                .properties
                .get(index - 1)
                .ok_or_else(|| broken("names a property it does not have"))?;
            if essential && !KNOWN.contains(&&property.0) {
                return Err(refused("one of its properties is not one this reads"));
            }
            found.push(property);
        }
        Ok(found)
    }

    fn property(&self, item: &Item, kind: &[u8; 4]) -> Result<Option<&'a [u8]>, Error> {
        Ok(self
            .properties(item)?
            .into_iter()
            .find(|(k, _)| k == kind)
            .map(|(_, body)| body))
    }

    /// The items `from` points to by references of `kind`.
    fn references(&self, kind: &[u8; 4], from: u32) -> Vec<u32> {
        self.references
            .iter()
            .filter(|(k, f, _)| k == kind && *f == from)
            .flat_map(|(_, _, to)| to.iter().copied())
            .collect()
    }

    /// The items that point to `to` by references of `kind`.
    fn referring(&self, kind: &[u8; 4], to: u32) -> Vec<u32> {
        self.references
            .iter()
            .filter(|(k, _, t)| k == kind && t.contains(&to))
            .map(|(_, from, _)| *from)
            .collect()
    }

    fn bytes(&self, item: &Item) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for extent in &item.extents {
            let source = if extent.in_idat { self.idat } else { self.data };
            let start =
                usize::try_from(extent.offset).map_err(|_| broken("item is out of bounds"))?;
            // A length of 0 is the rest of the file.
            let end = match extent.length {
                0 => source.len(),
                length => usize::try_from(length)
                    .ok()
                    .and_then(|l| start.checked_add(l))
                    .ok_or_else(|| broken("item is out of bounds"))?,
            };
            out.extend_from_slice(
                source
                    .get(start..end)
                    .ok_or_else(|| broken("item is out of bounds"))?,
            );
        }
        Ok(out)
    }
}

/// The extents of each item that `iloc` places.
fn locations(body: &[u8]) -> Result<Vec<(u32, Vec<Extent>)>, Error> {
    let mut fields = Fields::new(body);
    let version = fields.u8()?;
    fields.take(3)?;
    if version > 2 {
        return Err(broken("item locations are of a version this does not read"));
    }
    let sizes = fields.u8()?;
    let more = fields.u8()?;
    let (offset_size, length_size) = (usize::from(sizes >> 4), usize::from(sizes & 15));
    let base_size = usize::from(more >> 4);
    let index_size = if version >= 1 {
        usize::from(more & 15)
    } else {
        0
    };
    let count = if version < 2 {
        fields.take(2)?
    } else {
        fields.take(4)?
    };
    let mut found = Vec::new();
    for _ in 0..count {
        if found.len() >= MOST_ITEMS {
            return Err(refused("it has too many items"));
        }
        let id = if version < 2 {
            fields.take(2)?
        } else {
            fields.take(4)?
        } as u32;
        let method = if version >= 1 { fields.u16()? & 15 } else { 0 };
        fields.u16()?;
        let base = fields.take(base_size)?;
        let extents = fields.u16()?;
        let mut list = Vec::new();
        for _ in 0..extents {
            fields.take(index_size)?;
            let offset = fields.take(offset_size)?;
            let length = fields.take(length_size)?;
            list.push(Extent {
                in_idat: method == 1,
                offset: base.saturating_add(offset),
                length,
            });
        }
        if method > 1 {
            return Err(refused("its items are stored in a way this does not read"));
        }
        found.push((id, list));
    }
    Ok(found)
}

/// Decoded samples of an item: one plane, or three.
struct Planes {
    width: u32,
    height: u32,
    depth: u8,
    subsampling: (u8, u8),
    mono: bool,
    planes: [Vec<u16>; 3],
    /// The colour description the AV1 stream itself gives.
    matrix: u8,
    full_range: bool,
}

impl Planes {
    fn plane_size(&self, plane: usize) -> (usize, usize) {
        if plane == 0 {
            return (self.width as usize, self.height as usize);
        }
        let (x, y) = self.subsampling;
        (
            ((self.width + u32::from(x)) >> x) as usize,
            ((self.height + u32::from(y)) >> y) as usize,
        )
    }
}

/// The OBUs of a stream, with their types.
fn obus(data: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let header = data[at];
        let kind = (header >> 3) & 15;
        let extension = (header >> 2) & 1 == 1;
        let has_size = (header >> 1) & 1 == 1;
        at += 1 + usize::from(extension);
        let size = if has_size {
            let mut size = 0u64;
            let mut shift = 0;
            loop {
                let byte = *data
                    .get(at)
                    .ok_or_else(|| broken("AV1 stream is cut short"))?;
                at += 1;
                size |= u64::from(byte & 0x7F) << shift;
                if byte & 0x80 == 0 || shift >= 56 {
                    break;
                }
                shift += 7;
            }
            usize::try_from(size).map_err(|_| broken("AV1 stream is cut short"))?
        } else {
            data.len().saturating_sub(at)
        };
        let payload = data
            .get(at..at.saturating_add(size))
            .ok_or_else(|| broken("AV1 stream is cut short"))?;
        found.push((kind, payload));
        at += size;
    }
    Ok(found)
}

/// The pictures an AV1 `stream` of frames of up to `pixels` shows. A large
/// one is decoded on up to four threads, a tile to each. With a deadline
/// the decoder runs on a thread of its own, and is not waited for past it:
/// the answer is then [`Error::TimedOut`], though the thread runs on until
/// the picture is done, which the limits on its size keep short.
fn av1(
    stream: Vec<u8>,
    pixels: u64,
    deadline: Deadline,
) -> Result<Vec<filmcraft_av1::Picture>, Error> {
    let threads = if pixels >= 1 << 20 {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
    } else {
        1
    };
    // Set when the answer is no longer waited for, so that the decoder
    // stops at its next row of superblocks instead of running on.
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = cancel.clone();
    let run = move || -> Result<Vec<filmcraft_av1::Picture>, Error> {
        let failed = |e: filmcraft_av1::Error| match e {
            filmcraft_av1::Error::Cancelled => Error::TimedOut,
            e => broken(&format!("AV1 image: {e}")),
        };
        let mut decoder = filmcraft_av1::Decoder::with_threads(threads);
        decoder.set_cancel(flag);
        let mut pictures = decoder.decode(&stream).map_err(failed)?;
        pictures.extend(decoder.flush_result().map_err(failed)?);
        Ok(pictures)
    };
    let Some(at) = deadline.0 else {
        return run();
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("malmal-av1".into())
        .spawn(move || {
            let _ = sender.send(run());
        })
        .map_err(|e| broken(&format!("no thread for the AV1 decoder: {e}")))?;
    match receiver.recv_timeout(at.saturating_duration_since(std::time::Instant::now())) {
        Ok(answer) => answer,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            Err(Error::TimedOut)
        }
        // It stopped without an answer: it panicked.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(broken("AV1 decoder failed")),
    }
}

/// The item decoded: an AV1 image, or a grid of them.
fn decode(
    heif: &Heif<'_>,
    id: u32,
    limits: &Limits,
    deadline: Deadline,
    nested: bool,
) -> Result<Planes, Error> {
    deadline.check()?;
    let item = heif.item(id)?;
    match &item.kind {
        b"av01" => {
            // The sequence header the configuration holds, then the image.
            let mut stream = Vec::new();
            if let Some(config) = heif.property(item, b"av1C")? {
                stream.extend_from_slice(config.get(4..).unwrap_or_default());
            }
            stream.extend_from_slice(&heif.bytes(item)?);
            let sequence = obus(&stream)?
                .into_iter()
                .find(|(kind, _)| *kind == 1)
                .ok_or_else(|| broken("AV1 image has no sequence header"))?;
            let header = filmcraft_av1::SequenceHeader::parse(sequence.1)
                .map_err(|e| broken(&format!("sequence header: {e}")))?;
            let pixels = u64::from(header.max_frame_width) * u64::from(header.max_frame_height);
            if pixels > limits.max_pixels || pixels * 6 > limits.max_decompressed {
                return Err(Error::TooLarge);
            }
            let pictures = av1(stream, pixels, deadline)?;
            deadline.check()?;
            let picture = pictures
                .into_iter()
                .next()
                .ok_or_else(|| broken("AV1 image shows nothing"))?;
            Ok(Planes {
                width: picture.width,
                height: picture.height,
                depth: picture.bit_depth,
                subsampling: (picture.subsampling_x, picture.subsampling_y),
                mono: picture.mono_chrome,
                matrix: picture.matrix_coefficients,
                full_range: picture.full_range,
                planes: picture.planes,
            })
        }
        b"grid" if !nested => {
            let description = heif.bytes(item)?;
            let mut fields = Fields::new(&description);
            fields.u8()?;
            let wide = fields.u8()? & 1 == 1;
            let rows = usize::from(fields.u8()?) + 1;
            let columns = usize::from(fields.u8()?) + 1;
            let width = fields.take(if wide { 4 } else { 2 })? as u32;
            let height = fields.take(if wide { 4 } else { 2 })? as u32;
            if u64::from(width) * u64::from(height) > limits.max_pixels {
                return Err(Error::TooLarge);
            }
            let tiles = heif.references(b"dimg", id);
            if tiles.len() != rows * columns {
                return Err(broken("grid has the wrong number of tiles"));
            }
            let mut decoded = Vec::with_capacity(tiles.len());
            let mut held = 0u64;
            for tile in tiles {
                let planes = decode(heif, tile, limits, deadline, true)?;
                held += u64::from(planes.width) * u64::from(planes.height);
                if held > limits.max_pixels.saturating_mul(2) {
                    return Err(Error::TooLarge);
                }
                decoded.push(planes);
            }
            grid(decoded, columns, width, height)
        }
        _ => Err(refused("its image is of a kind this does not read")),
    }
}

/// Tiles of the same size and format, row by row, cut to `width` by
/// `height`.
fn grid(tiles: Vec<Planes>, columns: usize, width: u32, height: u32) -> Result<Planes, Error> {
    let first = &tiles[0];
    let (tile_width, tile_height) = (first.width, first.height);
    let same = |t: &Planes| {
        (t.width, t.height, t.depth, t.subsampling, t.mono)
            == (
                tile_width,
                tile_height,
                first.depth,
                first.subsampling,
                first.mono,
            )
    };
    if !tiles.iter().all(same) {
        return Err(broken("grid tiles differ"));
    }
    let rows = tiles.len() / columns;
    if width > tile_width * columns as u32 || height > tile_height * rows as u32 {
        return Err(broken("grid is larger than its tiles"));
    }
    let mut out = Planes {
        width,
        height,
        depth: first.depth,
        subsampling: first.subsampling,
        mono: first.mono,
        matrix: first.matrix,
        full_range: first.full_range,
        planes: Default::default(),
    };
    for plane in 0..if first.mono { 1 } else { 3 } {
        let (out_width, out_height) = out.plane_size(plane);
        let (piece_width, piece_height) = first.plane_size(plane);
        let mut samples = vec![0u16; out_width * out_height];
        for (index, tile) in tiles.iter().enumerate() {
            let (left, top) = (
                (index % columns) * piece_width,
                (index / columns) * piece_height,
            );
            for y in 0..piece_height {
                let to_y = top + y;
                if to_y >= out_height || left >= out_width {
                    continue;
                }
                let count = piece_width.min(out_width - left);
                let from = &tile.planes[plane][y * piece_width..][..count];
                samples[to_y * out_width + left..][..count].copy_from_slice(from);
            }
        }
        out.planes[plane] = samples;
    }
    Ok(out)
}

/// How colour samples become RGB.
#[derive(Clone, Copy)]
enum Matrix {
    /// Green, blue and red as they are stored.
    Identity,
    /// The weights of red and blue in luma.
    Luma(f32, f32),
}

impl Matrix {
    fn of(code: u8) -> Result<Self, Error> {
        Ok(match code {
            0 => Self::Identity,
            1 => Self::Luma(0.2126, 0.0722),
            4 => Self::Luma(0.30, 0.11),
            7 => Self::Luma(0.212, 0.087),
            9 | 10 => Self::Luma(0.2627, 0.0593),
            // BT.601, which an unspecified matrix is taken to be.
            2 | 5 | 6 => Self::Luma(0.299, 0.114),
            _ => return Err(refused("its colours are coded in a way this does not read")),
        })
    }
}

/// A sample of `planes`, a chroma plane brought up to the size of luma, as
/// a value from 0 to 1, or centred on 0 if it is `chroma`.
fn sample(
    planes: &Planes,
    plane: usize,
    (x, y): (usize, usize),
    full_range: bool,
    chroma: bool,
) -> f32 {
    let (width, height) = planes.plane_size(plane);
    let samples = &planes.planes[plane];
    let value = if plane == 0 || planes.subsampling == (0, 0) {
        f32::from(samples[y * width + x])
    } else {
        // Between the chroma samples around the pixel's centre.
        let (sx, sy) = planes.subsampling;
        let at = |p: usize, s: u8| (p as f32 + 0.5) / f32::from(1u8 << s) - 0.5;
        let (fx, fy) = (at(x, sx).max(0.0), at(y, sy).max(0.0));
        let (x0, y0) = (fx as usize, fy as usize);
        let (x1, y1) = ((x0 + 1).min(width - 1), (y0 + 1).min(height - 1));
        let (wx, wy) = (fx - x0 as f32, fy - y0 as f32);
        let get =
            |x: usize, y: usize| f32::from(samples[y.min(height - 1) * width + x.min(width - 1)]);
        let top = get(x0, y0) * (1.0 - wx) + get(x1, y0) * wx;
        let bottom = get(x0, y1) * (1.0 - wx) + get(x1, y1) * wx;
        top * (1.0 - wy) + bottom * wy
    };
    let scale = f32::from(1u16 << (planes.depth - 8));
    let most = f32::from(((1u32 << planes.depth) - 1) as u16);
    match (chroma, full_range) {
        (false, true) => value / most,
        (false, false) => (value - 16.0 * scale) / (219.0 * scale),
        (true, true) => (value - 128.0 * scale) / most,
        (true, false) => (value - 128.0 * scale) / (224.0 * scale),
    }
}

/// The picture of `planes` as RGB, or grey, with `alpha`.
fn picture(
    planes: &Planes,
    matrix: Matrix,
    full_range: bool,
    alpha: Option<&Planes>,
    deadline: Deadline,
) -> Result<DynamicImage, Error> {
    let (width, height) = (planes.width as usize, planes.height as usize);
    let deep = planes.depth > 8;
    let most = if deep { 65535.0 } else { 255.0 };
    let level = |v: f32| (v.clamp(0.0, 1.0) * most).round() as u16;
    if let Some(alpha) = alpha
        && (alpha.width, alpha.height) != (planes.width, planes.height)
    {
        return Err(broken("alpha is not the size of the image"));
    }
    let channels = if planes.mono { 1 } else { 3 } + usize::from(alpha.is_some());
    let mut samples = Vec::with_capacity(width * height * channels);
    for y in 0..height {
        if y % 64 == 0 {
            deadline.check()?;
        }
        for x in 0..width {
            let luma = sample(planes, 0, (x, y), full_range, false);
            if planes.mono {
                samples.push(level(luma));
            } else {
                let (r, g, b) = match matrix {
                    // Green, blue and red, each read as luma is.
                    Matrix::Identity => (
                        sample(planes, 2, (x, y), full_range, false),
                        luma,
                        sample(planes, 1, (x, y), full_range, false),
                    ),
                    Matrix::Luma(kr, kb) => {
                        let u = sample(planes, 1, (x, y), full_range, true);
                        let v = sample(planes, 2, (x, y), full_range, true);
                        let kg = 1.0 - kr - kb;
                        let r = luma + 2.0 * (1.0 - kr) * v;
                        let b = luma + 2.0 * (1.0 - kb) * u;
                        (r, (luma - kr * r - kb * b) / kg, b)
                    }
                };
                samples.extend([level(r), level(g), level(b)]);
            }
            if let Some(alpha) = alpha {
                samples.push(level(sample(alpha, 0, (x, y), alpha.full_range, false)));
            }
        }
    }
    let (w, h) = (planes.width, planes.height);
    let narrow = |s: Vec<u16>| s.into_iter().map(|v| v as u8).collect::<Vec<u8>>();
    let wrong = || broken("image is not what it says");
    Ok(match (deep, planes.mono, alpha.is_some()) {
        (false, true, false) => ImageBuffer::<Luma<u8>, _>::from_raw(w, h, narrow(samples))
            .ok_or_else(wrong)?
            .into(),
        (false, true, true) => ImageBuffer::<LumaA<u8>, _>::from_raw(w, h, narrow(samples))
            .ok_or_else(wrong)?
            .into(),
        (false, false, false) => ImageBuffer::<Rgb<u8>, _>::from_raw(w, h, narrow(samples))
            .ok_or_else(wrong)?
            .into(),
        (false, false, true) => ImageBuffer::<Rgba<u8>, _>::from_raw(w, h, narrow(samples))
            .ok_or_else(wrong)?
            .into(),
        (true, true, false) => ImageBuffer::<Luma<u16>, _>::from_raw(w, h, samples)
            .ok_or_else(wrong)?
            .into(),
        (true, true, true) => ImageBuffer::<LumaA<u16>, _>::from_raw(w, h, samples)
            .ok_or_else(wrong)?
            .into(),
        (true, false, false) => ImageBuffer::<Rgb<u16>, _>::from_raw(w, h, samples)
            .ok_or_else(wrong)?
            .into(),
        (true, false, true) => ImageBuffer::<Rgba<u16>, _>::from_raw(w, h, samples)
            .ok_or_else(wrong)?
            .into(),
    })
}

/// The part a clean aperture box keeps: left, top, width, height.
fn aperture(body: &[u8], width: u32, height: u32) -> Result<(u32, u32, u32, u32), Error> {
    let mut fields = Fields::new(body);
    let mut fraction = |signed: bool| -> Result<f64, Error> {
        let n = fields.u32()?;
        let d = fields.u32()?;
        if d == 0 {
            return Err(broken("clean aperture divides by 0"));
        }
        let n = if signed {
            f64::from(n as i32)
        } else {
            f64::from(n)
        };
        Ok(n / f64::from(d))
    };
    let (w, h) = (fraction(false)?, fraction(false)?);
    let (dx, dy) = (fraction(true)?, fraction(true)?);
    // The offsets are of the centre of the aperture from that of the image.
    let left = dx + (f64::from(width) - 1.0) / 2.0 - (w - 1.0) / 2.0;
    let top = dy + (f64::from(height) - 1.0) / 2.0 - (h - 1.0) / 2.0;
    let whole = |v: f64| v.fract() == 0.0 && v >= 0.0;
    if !(whole(left) && whole(top) && whole(w) && whole(h))
        || w < 1.0
        || h < 1.0
        || left + w > f64::from(width)
        || top + h > f64::from(height)
    {
        return Err(refused("its clean aperture does not fall on whole pixels"));
    }
    Ok((left as u32, top as u32, w as u32, h as u32))
}

/// What the colours of the picture are, as the file says.
enum Described {
    Srgb,
    Icc(Vec<u8>),
    /// Primaries and transfer, as ITU-T H.273 numbers them.
    Cicp(u8, u8),
}

fn described(colour: Option<&[u8]>) -> Result<Described, Error> {
    let Some(body) = colour else {
        return Ok(Described::Srgb);
    };
    let mut fields = Fields::new(body);
    match &fields.four()? {
        b"prof" | b"rICC" => Ok(Described::Icc(fields.rest().to_vec())),
        b"nclx" => {
            let primaries = fields.u16()?;
            let transfer = fields.u16()?;
            // Those of sRGB, or close enough that every viewer shows them
            // as sRGB, or not given.
            if matches!(primaries, 1 | 2) && matches!(transfer, 1 | 2 | 6 | 13 | 14 | 15) {
                return Ok(Described::Srgb);
            }
            let known = |v: u16| u8::try_from(v).map_err(|_| refused("its colours are unknown"));
            // Not given is taken to be sRGB's.
            let primaries = match primaries {
                2 => 1,
                p => known(p)?,
            };
            let transfer = match transfer {
                2 => 13,
                t => known(t)?,
            };
            CicpColorPrimaries::try_from(primaries)
                .map_err(|_| refused("its colour primaries are unknown"))?;
            TransferCharacteristics::try_from(transfer)
                .map_err(|_| refused("its transfer function is unknown"))?;
            Ok(Described::Cicp(primaries, transfer))
        }
        _ => Ok(Described::Srgb),
    }
}

/// What turns colours of `primaries` and `transfer` into sRGB.
fn cicp_to_srgb(primaries: u8, transfer: u8) -> Result<Option<ToSrgb>, Error> {
    let primaries = CicpColorPrimaries::try_from(primaries)
        .map_err(|_| refused("its colour primaries are unknown"))?;
    let transfer = TransferCharacteristics::try_from(transfer)
        .map_err(|_| refused("its transfer function is unknown"))?;
    let mut profile = ColorProfile::new_srgb();
    let cicp = CicpProfile {
        color_primaries: primaries,
        transfer_characteristics: transfer,
        matrix_coefficients: MatrixCoefficients::Identity,
        full_range: true,
    };
    // What it returns says nothing; the description is kept only when the
    // colours were set from it.
    profile.update_rgb_colorimetry_from_cicp(cicp);
    if profile.cicp.is_none() || profile.red_trc.is_none() {
        return Err(refused("its colours cannot be brought into sRGB"));
    }
    Ok(ToSrgb::of(profile))
}

/// What the colours of a picture read are in.
pub(super) enum Space {
    Srgb,
    /// A profile written anew.
    Icc(Vec<u8>),
    /// Primaries, transfer, matrix and range, as a PNG `cICP` chunk has
    /// them.
    Cicp([u8; 4]),
}

/// The picture of an AVIF, and what its colours are in.
pub(super) struct Shown {
    pub(super) image: DynamicImage,
    pub(super) space: Space,
}

/// The AVIF in `data`: its primary image, as it is shown, in sRGB.
#[cfg(test)]
pub(super) fn read(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
) -> Result<DynamicImage, Error> {
    let shown = shown(data, limits, deadline, false)?;
    match shown.space {
        Space::Srgb => Ok(shown.image),
        _ => Err(refused(
            "its colours are for a display of high dynamic range",
        )),
    }
}

/// The AVIF in `data`: its primary image, as it is shown, its colours
/// left in what they are if `keep_profile` and that can be said in a PNG,
/// in sRGB otherwise.
pub(super) fn shown(
    data: &[u8],
    limits: &Limits,
    deadline: Deadline,
    keep_profile: bool,
) -> Result<Shown, Error> {
    let heif = Heif::parse(data)?;
    let primary = heif.item(heif.primary)?;
    let planes = decode(&heif, heif.primary, limits, deadline, false)?;

    // The colour description in the file before that of the stream.
    let colours: Vec<&[u8]> = heif
        .properties(primary)?
        .into_iter()
        .filter(|(k, _)| k == b"colr")
        .map(|(_, body)| body)
        .collect();
    let nclx = colours.iter().find(|b| b.starts_with(b"nclx")).copied();
    let (matrix, full_range) = match nclx {
        Some(body) if body.len() >= 11 && body[8] == 0 => (body[9], body[10] & 0x80 != 0),
        _ => (planes.matrix, planes.full_range),
    };
    let matrix = if planes.mono {
        Matrix::Identity
    } else {
        Matrix::of(matrix)?
    };
    if matches!(matrix, Matrix::Identity) && !planes.mono && planes.subsampling != (0, 0) {
        return Err(broken("colours stored as they are cannot be subsampled"));
    }

    // An auxiliary image of alpha, which points to the primary one.
    let mut alpha = None;
    let mut premultiplied = false;
    for id in heif.referring(b"auxl", heif.primary) {
        let item = heif.item(id)?;
        let urn = heif.property(item, b"auxC")?.unwrap_or_default();
        let urn = urn.get(4..).unwrap_or_default();
        if urn.starts_with(b"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha")
            || urn.starts_with(b"urn:mpeg:hevc:2015:auxid:1")
        {
            let planes_of_alpha = decode(&heif, id, limits, deadline, false)?;
            premultiplied = heif.references(b"prem", heif.primary).contains(&id);
            alpha = Some(planes_of_alpha);
            break;
        }
    }
    let mut image = picture(&planes, matrix, full_range, alpha.as_ref(), deadline)?;
    if premultiplied {
        unpremultiply(&mut image);
    }

    let description = described(
        colours
            .iter()
            .find(|b| b.starts_with(b"prof") || b.starts_with(b"rICC"))
            .or(nclx.as_ref())
            .copied(),
    )?;
    let channels = if image.color().has_color() { 3 } else { 1 };
    let space = match description {
        Described::Srgb => Space::Srgb,
        Described::Icc(icc) => match ToSrgb::new(Some(icc.clone())) {
            None => Space::Srgb,
            Some(colors) => match keep_profile
                .then(|| colour::rewritten_screen(&icc, channels))
                .flatten()
            {
                Some(icc) => Space::Icc(icc),
                None => {
                    colors.image(&mut image);
                    Space::Srgb
                }
            },
        },
        // PQ and HLG: sRGB cannot show them, so they stay as they are, at
        // 16 bits whatever the stream has.
        Described::Cicp(primaries, transfer @ (16 | 18)) => {
            image = if image.color().has_alpha() {
                image.into_rgba16().into()
            } else {
                image.into_rgb16().into()
            };
            Space::Cicp([primaries, transfer, 0, 1])
        }
        Described::Cicp(primaries, transfer) if keep_profile => {
            Space::Cicp([primaries, transfer, 0, 1])
        }
        Described::Cicp(primaries, transfer) => {
            if let Some(colors) = cicp_to_srgb(primaries, transfer)? {
                colors.image(&mut image);
            }
            Space::Srgb
        }
    };

    // Cut, turned and mirrored in the order the file gives.
    for (kind, body) in heif.properties(primary)? {
        image = match &kind {
            b"clap" => {
                let (left, top, w, h) = aperture(body, image.width(), image.height())?;
                image.crop_imm(left, top, w, h)
            }
            // Turned anticlockwise, a quarter at a time.
            b"irot" => match body.first().map(|a| a & 3) {
                Some(1) => image.rotate270(),
                Some(2) => image.rotate180(),
                Some(3) => image.rotate90(),
                _ => image,
            },
            // About a vertical axis, or a horizontal one.
            b"imir" => match body.first().map(|a| a & 1) {
                Some(0) => image.fliph(),
                Some(_) => image.flipv(),
                None => image,
            },
            _ => image,
        };
    }
    Ok(Shown { image, space })
}

/// Colours divided by their alpha.
fn unpremultiply(image: &mut DynamicImage) {
    fn undo(value: u16, alpha: u16, most: f32) -> u16 {
        match alpha {
            0 => value,
            alpha => (f32::from(value) * most / f32::from(alpha))
                .round()
                .min(most) as u16,
        }
    }
    match image {
        DynamicImage::ImageLumaA8(i) => i.pixels_mut().for_each(|p| {
            p[0] = undo(p[0].into(), p[1].into(), 255.0) as u8;
        }),
        DynamicImage::ImageRgba8(i) => i.pixels_mut().for_each(|p| {
            for c in 0..3 {
                p[c] = undo(p[c].into(), p[3].into(), 255.0) as u8;
            }
        }),
        DynamicImage::ImageLumaA16(i) => i.pixels_mut().for_each(|p| {
            p[0] = undo(p[0], p[1], 65535.0);
        }),
        DynamicImage::ImageRgba16(i) => i.pixels_mut().for_each(|p| {
            for c in 0..3 {
                p[c] = undo(p[c], p[3], 65535.0);
            }
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decoder is not waited for past the deadline.
    #[test]
    fn av1_decoding_stops_being_waited_for_at_the_deadline() {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        let data = std::fs::read(format!("{clean}/photo.avif")).unwrap();
        let heif = Heif::parse(&data).unwrap();
        let item = heif.item(heif.primary).unwrap();
        let mut stream = heif.property(item, b"av1C").unwrap().unwrap()[4..].to_vec();
        stream.extend_from_slice(&heif.bytes(item).unwrap());
        let now = Deadline(Some(std::time::Instant::now()));
        assert!(matches!(av1(stream.clone(), 1, now), Err(Error::TimedOut)));
        let later = Deadline(Some(
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        ));
        assert_eq!(av1(stream.clone(), 1, later).unwrap().len(), 1);
        assert_eq!(av1(stream.clone(), 1, Deadline(None)).unwrap().len(), 1);
        // A decoder told to stop does, with no picture.
        let mut decoder = filmcraft_av1::Decoder::with_threads(1);
        decoder.set_cancel(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )));
        let decoded = decoder.decode(&stream).and_then(|mut pictures| {
            pictures.extend(decoder.flush_result()?);
            Ok(pictures)
        });
        assert!(matches!(decoded, Err(filmcraft_av1::Error::Cancelled)));
    }

    fn boxed(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        [&(body.len() as u32 + 8).to_be_bytes()[..], kind, body].concat()
    }

    fn full(kind: &[u8; 4], version: u8, body: &[u8]) -> Vec<u8> {
        boxed(kind, &[&[version, 0, 0, 0][..], body].concat())
    }

    /// An item: its id, type, bytes and properties, 1 for the first.
    struct Part {
        id: u16,
        kind: &'static [u8; 4],
        bytes: Vec<u8>,
        properties: Vec<u8>,
    }

    /// An AVIF of `parts`, the first of them primary, each stored in
    /// `idat`.
    fn file(
        parts: &[Part],
        properties: &[Vec<u8>],
        references: &[(&[u8; 4], u16, &[u16])],
    ) -> Vec<u8> {
        let mut infe = Vec::new();
        let mut iloc = vec![0x44, 0x00];
        iloc.extend_from_slice(&(parts.len() as u16).to_be_bytes());
        let mut idat = Vec::new();
        let mut ipma = (parts.len() as u32).to_be_bytes().to_vec();
        for part in parts {
            infe.extend(full(
                b"infe",
                2,
                &[&part.id.to_be_bytes()[..], &[0, 0], part.kind].concat(),
            ));
            iloc.extend_from_slice(&part.id.to_be_bytes());
            iloc.extend_from_slice(&[0, 1, 0, 0, 0, 1]);
            iloc.extend_from_slice(&(idat.len() as u32).to_be_bytes());
            iloc.extend_from_slice(&(part.bytes.len() as u32).to_be_bytes());
            idat.extend_from_slice(&part.bytes);
            ipma.extend_from_slice(&part.id.to_be_bytes());
            ipma.push(part.properties.len() as u8);
            ipma.extend_from_slice(&part.properties);
        }
        let mut iref = Vec::new();
        for (kind, from, to) in references {
            let to: Vec<u8> = to.iter().flat_map(|t| t.to_be_bytes()).collect();
            let count = (to.len() as u16 / 2).to_be_bytes();
            iref.extend(boxed(
                kind,
                &[&from.to_be_bytes()[..], &count, &to].concat(),
            ));
        }
        let meta = [
            full(b"hdlr", 0, &[&[0; 4][..], b"pict", &[0; 13]].concat()),
            full(b"pitm", 0, &parts[0].id.to_be_bytes()),
            full(
                b"iinf",
                0,
                &[&(parts.len() as u16).to_be_bytes()[..], &infe].concat(),
            ),
            full(b"iloc", 1, &iloc),
            full(b"iref", 0, &iref),
            boxed(
                b"iprp",
                &[
                    boxed(b"ipco", &properties.concat()),
                    full(b"ipma", 0, &ipma),
                ]
                .concat(),
            ),
            boxed(b"idat", &idat),
        ];
        [
            boxed(b"ftyp", b"avifmif1miafavif"),
            full(b"meta", 0, &meta.concat()),
        ]
        .concat()
    }

    /// The AV1 image of the corpus photo and its configuration.
    fn photo() -> (Vec<u8>, Vec<u8>) {
        av1_of("photo.avif")
    }

    /// The AV1 image of a corpus file and its configuration.
    fn av1_of(name: &str) -> (Vec<u8>, Vec<u8>) {
        let clean = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus/clean");
        let data = std::fs::read(format!("{clean}/{name}")).unwrap();
        let heif = Heif::parse(&data).unwrap();
        let item = heif.item(heif.primary).unwrap();
        let config = heif.property(item, b"av1C").unwrap().unwrap();
        (heif.bytes(item).unwrap(), boxed(b"av1C", config))
    }

    fn read(data: &[u8]) -> Result<DynamicImage, Error> {
        super::read(data, &Limits::default(), Deadline(None))
    }

    /// The photo with `extra` properties after its configuration.
    fn photo_with(extra: &[Vec<u8>]) -> Vec<u8> {
        with("photo.avif", extra)
    }

    /// The image of a corpus file with `extra` properties after its
    /// configuration.
    fn with(name: &str, extra: &[Vec<u8>]) -> Vec<u8> {
        let (bytes, config) = av1_of(name);
        let properties = [vec![config], extra.to_vec()].concat();
        let indexes = (1..=properties.len() as u8).collect();
        file(
            &[Part {
                id: 1,
                kind: b"av01",
                bytes,
                properties: indexes,
            }],
            &properties,
            &[],
        )
    }

    #[test]
    fn the_picture_is_turned_mirrored_and_cut_as_it_says() {
        let plain = read(&photo_with(&[])).unwrap();
        assert_eq!((plain.width(), plain.height()), (64, 48));
        let turned = read(&photo_with(&[boxed(b"irot", &[1])])).unwrap();
        assert_eq!(turned, plain.rotate270());
        let mirrored = read(&photo_with(&[boxed(b"imir", &[0])])).unwrap();
        assert_eq!(mirrored, plain.fliph());
        // Half of each side, about the centre.
        let fraction = |n: i32, d: u32| [n.to_be_bytes(), d.to_be_bytes()].concat();
        let clap = [
            fraction(32, 1),
            fraction(24, 1),
            fraction(0, 1),
            fraction(0, 1),
        ]
        .concat();
        let cut = read(&photo_with(&[boxed(b"clap", &clap)])).unwrap();
        assert_eq!(cut, plain.crop_imm(16, 12, 32, 24));
        // Cut, then turned: in the order given.
        let both = read(&photo_with(&[boxed(b"clap", &clap), boxed(b"irot", &[3])])).unwrap();
        assert_eq!(both, plain.crop_imm(16, 12, 32, 24).rotate90());
    }

    #[test]
    fn tiles_of_a_grid_are_put_together() {
        let plain = read(&photo_with(&[])).unwrap().to_rgb8();
        let (bytes, config) = photo();
        // Two tiles across, cut to 100 wide.
        let grid = [0, 0, 0, 1, 0, 100, 0, 48].to_vec();
        let parts = [
            Part {
                id: 1,
                kind: b"grid",
                bytes: grid,
                properties: vec![],
            },
            Part {
                id: 2,
                kind: b"av01",
                bytes: bytes.clone(),
                properties: vec![1],
            },
            Part {
                id: 3,
                kind: b"av01",
                bytes,
                properties: vec![1],
            },
        ];
        let data = file(&parts, &[config], &[(b"dimg", 1, &[2, 3])]);
        let image = read(&data).unwrap().to_rgb8();
        assert_eq!(image.dimensions(), (100, 48));
        for (x, y, pixel) in image.enumerate_pixels() {
            assert_eq!(pixel, plain.get_pixel(x % 64, y), "at {x},{y}");
        }
    }

    #[test]
    fn alpha_comes_from_its_auxiliary_image() {
        let plain = read(&photo_with(&[])).unwrap().to_rgb8();
        let (bytes, config) = photo();
        let urn = full(b"auxC", 0, b"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha\0");
        let parts = [
            Part {
                id: 1,
                kind: b"av01",
                bytes: bytes.clone(),
                properties: vec![1],
            },
            Part {
                id: 2,
                kind: b"av01",
                bytes,
                properties: vec![1, 2],
            },
        ];
        let image = read(&file(&parts, &[config, urn], &[(b"auxl", 2, &[1])])).unwrap();
        let DynamicImage::ImageRgba8(image) = image else {
            panic!("no alpha");
        };
        for (x, y, Rgba([r, g, b, a])) in image.enumerate_pixels() {
            assert_eq!(Rgb([*r, *g, *b]), *plain.get_pixel(x, y));
            // The alpha image is the photo itself, whose luma it takes.
            let Rgb([pr, pg, pb]) = *plain.get_pixel(x, y);
            let luma = 0.299 * f32::from(pr) + 0.587 * f32::from(pg) + 0.114 * f32::from(pb);
            assert!(
                (f32::from(*a) - luma).abs() < 3.0,
                "at {x},{y}: {a} for {luma}"
            );
        }
    }

    #[test]
    fn colours_are_brought_into_srgb() {
        let plain = read(&with("colours.avif", &[])).unwrap().to_rgb8();
        // Display P3 with the sRGB curve: the same numbers are more
        // saturated colours, which sRGB shows with more of the others.
        // With the matrix and range of `colours.avif`, or of the photo.
        let described = |primaries: u16, transfer: u16, coding: [u8; 3]| {
            boxed(
                b"colr",
                &[
                    &b"nclx"[..],
                    &primaries.to_be_bytes(),
                    &transfer.to_be_bytes(),
                    &coding,
                ]
                .concat(),
            )
        };
        let nclx = |primaries, transfer| described(primaries, transfer, [0, 2, 0]);
        let photo_nclx = |primaries, transfer| described(primaries, transfer, [0, 6, 0x80]);
        let p3 = read(&with("colours.avif", &[nclx(12, 13)]))
            .unwrap()
            .to_rgb8();
        let apart = |one: &image::RgbImage, other: &image::RgbImage| {
            one.as_raw()
                .iter()
                .zip(other.as_raw())
                .map(|(a, b)| a.abs_diff(*b))
                .max()
                .unwrap()
        };
        assert!(apart(&p3, &plain) > 20, "{}", apart(&p3, &plain));
        // Neither more nor less saturated in grey.
        let grey = read(&photo_with(&[photo_nclx(1, 13)])).unwrap().to_rgb8();
        assert_eq!(grey, read(&photo_with(&[])).unwrap().to_rgb8());
        let p3_grey = read(&photo_with(&[photo_nclx(12, 13)])).unwrap().to_rgb8();
        assert!(apart(&grey, &p3_grey) <= 1);
        let same = read(&with("colours.avif", &[nclx(1, 13)]))
            .unwrap()
            .to_rgb8();
        assert_eq!(same, plain);
        assert!(matches!(
            read(&with("colours.avif", &[nclx(9, 16)])),
            Err(Error::Unsupported { .. })
        ));
    }

    /// Colours to be kept stay as they are, under what the file says they
    /// are in; those of high dynamic range always do, at 16 bits.
    #[test]
    fn colours_are_kept_in_what_they_are_in() {
        let nclx = |primaries: u16, transfer: u16| {
            boxed(
                b"colr",
                &[
                    &b"nclx"[..],
                    &primaries.to_be_bytes(),
                    &transfer.to_be_bytes(),
                    &[0, 2, 0],
                ]
                .concat(),
            )
        };
        let shown =
            |data: &[u8], keep| shown(data, &Limits::default(), Deadline(None), keep).unwrap();
        let plain = read(&with("colours.avif", &[])).unwrap();
        let p3 = shown(&with("colours.avif", &[nclx(12, 13)]), true);
        assert!(matches!(p3.space, Space::Cicp([12, 13, 0, 1])));
        assert_eq!(p3.image, plain);
        let pq = shown(&with("colours.avif", &[nclx(9, 16)]), false);
        assert!(matches!(pq.space, Space::Cicp([9, 16, 0, 1])));
        assert_eq!(pq.image.to_rgb8(), plain.to_rgb8());
        assert!(matches!(pq.image, DynamicImage::ImageRgb16(_)));

        let jpeg = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/corpus/clean/p3.jpg"
        ))
        .unwrap();
        let mut decoder =
            image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(&jpeg)).unwrap();
        let icc = image::ImageDecoder::icc_profile(&mut decoder)
            .unwrap()
            .unwrap();
        let profiled = with(
            "colours.avif",
            &[boxed(b"colr", &[&b"prof"[..], &icc].concat())],
        );
        let kept = shown(&profiled, true);
        assert!(
            matches!(&kept.space, Space::Icc(new) if *new == colour::rewritten_rgb(&icc).unwrap())
        );
        assert_eq!(kept.image, plain);
        let converted = shown(&profiled, false);
        assert!(matches!(converted.space, Space::Srgb));
        assert_ne!(converted.image, plain);
    }

    #[test]
    fn a_property_it_must_understand_and_does_not_is_refused() {
        let (bytes, config) = photo();
        let properties = [config, boxed(b"zzzz", &[])];
        let part = Part {
            id: 1,
            kind: b"av01",
            bytes,
            properties: vec![1, 0x82],
        };
        assert!(matches!(
            read(&file(&[part], &properties, &[])),
            Err(Error::Unsupported { .. })
        ));
    }
}
