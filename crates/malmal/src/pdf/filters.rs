//! Stream filters. Only the lossless general-purpose ones are implemented:
//! those are what object streams and embedded files are stored with.
//!
//! A chain of filters runs a block at a time, each filter drawing on the one
//! before it, so that what a stream costs in memory is a few blocks and not
//! what it expands to. The outcome is the one of running each filter to its
//! end before the next begins: an earlier filter's failure comes first, and
//! each one may produce what the ones before it have left of the limit.

use std::cell::Cell;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use super::parser::is_whitespace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// A filter or predictor this module does not implement.
    Unsupported,
    Corrupt,
    /// Output would exceed the caller's limit.
    Limit,
}

/// The `/DecodeParms` entries the supported filters use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params {
    pub predictor: usize,
    pub columns: usize,
    pub colors: usize,
    pub bits_per_component: usize,
    pub early_change: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            predictor: 1,
            columns: 1,
            colors: 1,
            bits_per_component: 8,
            early_change: true,
        }
    }
}

/// About how much a filter hands on at a time. The tests take it small, so
/// that everything they decode crosses many blocks.
#[cfg(not(test))]
const BLOCK: usize = 64 << 10;
#[cfg(test)]
const BLOCK: usize = 61;
/// How far back a deflate stream may reach.
const WINDOW: usize = 32 << 10;

/// One filter of a chain, with its parameters.
pub(crate) struct Step<'f> {
    pub filter: &'f [u8],
    pub params: Params,
}

/// Run one filter, producing at most `limit` bytes.
pub(crate) fn apply(
    filter: &[u8],
    input: &[u8],
    params: &Params,
    limit: usize,
) -> Result<Vec<u8>, DecodeError> {
    let step = Step {
        filter,
        params: *params,
    };
    let mut output = Vec::new();
    let (_, outcome) = run(&[step], input, limit as u64, &mut |block| {
        output.extend_from_slice(block)
    });
    outcome.map(|()| output)
}

/// Run `input` through `steps`, handing what comes out of the last one to
/// `sink` a block at a time. No filter may produce more than what the ones
/// before it have left of `limit`.
///
/// Returns the bytes to count against the caller's budget, which is what
/// the filters that ran to their ends produced, and how the chain ended.
/// What `sink` was given before a failure is not the stream's content: the
/// caller that acts on it waits for the end.
pub(crate) fn run(
    steps: &[Step<'_>],
    input: &[u8],
    limit: u64,
    sink: &mut dyn FnMut(&[u8]),
) -> (u64, Result<(), DecodeError>) {
    // A predictor is a stage of its own, behind the filter it belongs to.
    let mut stages: Vec<(Box<dyn Decoder>, Kind)> = Vec::new();
    for step in steps {
        let compressed = matches!(step.filter, b"FlateDecode" | b"Fl" | b"LZWDecode" | b"LZW");
        let predicted = compressed && step.params.predictor >= 2;
        let kind = if predicted {
            Kind::Predicted
        } else {
            Kind::Plain
        };
        match step.filter {
            b"FlateDecode" | b"Fl" => stages.push((Box::new(Flate::new()), kind)),
            b"LZWDecode" | b"LZW" => {
                stages.push((Box::new(Lzw::new(step.params.early_change)), kind))
            }
            b"ASCIIHexDecode" | b"AHx" => stages.push((Box::new(AsciiHex::default()), kind)),
            b"ASCII85Decode" | b"A85" => {
                stages.push((Box::new(Ascii85::default()), Kind::CheckedLast))
            }
            b"RunLengthDecode" | b"RL" => stages.push((Box::new(RunLength::default()), kind)),
            _ => stages.push((Box::new(Unknown), kind)),
        }
        if predicted {
            stages.push((Box::new(Predictor::new(&step.params)), Kind::Plain));
        }
    }

    let meter = Meter {
        limit,
        produced: stages.iter().map(|_| Cell::new(0)).collect(),
        counted: stages
            .iter()
            .map(|(_, kind)| *kind != Kind::Predicted)
            .collect(),
        failed: Cell::new(None),
    };
    let mut source = Input::Slice(input);
    for (index, (decoder, kind)) in stages.into_iter().enumerate() {
        source = Input::Stage {
            stage: Box::new(Stage {
                index,
                decoder,
                input: source,
                meter: &meter,
                kind,
                state: Ok(true),
            }),
            block: Vec::new(),
            pos: 0,
        };
    }
    let outcome = loop {
        match source.fill() {
            Ok([]) => break Ok(()),
            Ok(block) => {
                sink(block);
                let length = block.len();
                source.consume(length);
            }
            Err(error) => break Err(error),
        }
    };
    (
        meter.before(meter.failed.get().unwrap_or(usize::MAX)),
        outcome,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    /// Its output goes through a predictor, whose output is what counts.
    Predicted,
    /// The limit is looked at once the filter has read all of its input:
    /// a character that is not ASCII85 anywhere in it comes first.
    CheckedLast,
}

/// What the stages of one chain have produced, against the limit they share.
struct Meter {
    limit: u64,
    produced: Vec<Cell<u64>>,
    counted: Vec<bool>,
    /// The stage whose failure ended the chain.
    failed: Cell<Option<usize>>,
}

impl Meter {
    /// What the stages before `stage` have used of the limit.
    fn before(&self, stage: usize) -> u64 {
        let counted = self.produced.iter().zip(&self.counted).take(stage);
        counted
            .filter(|(_, counted)| **counted)
            .map(|(produced, _)| produced.get())
            .sum()
    }

    fn over(&self, stage: usize) -> bool {
        self.before(stage)
            .saturating_add(self.produced[stage].get())
            > self.limit
    }
}

/// Where a stage reads from: the stream as stored, or the stage before it.
enum Input<'a> {
    Slice(&'a [u8]),
    Stage {
        stage: Box<Stage<'a>>,
        block: Vec<u8>,
        pos: usize,
    },
}

impl Input<'_> {
    /// All of the input is at hand, and not only a block of it.
    fn whole(&self) -> bool {
        matches!(self, Self::Slice(_))
    }

    /// What has not been consumed yet; empty at the end of the input only.
    fn fill(&mut self) -> Result<&[u8], DecodeError> {
        match self {
            Self::Slice(rest) => Ok(rest),
            Self::Stage { stage, block, pos } => {
                while *pos == block.len() {
                    block.clear();
                    *pos = 0;
                    if !stage.read(block)? && block.is_empty() {
                        break;
                    }
                }
                Ok(&block[*pos..])
            }
        }
    }

    fn consume(&mut self, count: usize) {
        match self {
            Self::Slice(rest) => *rest = &rest[count..],
            Self::Stage { pos, .. } => *pos += count,
        }
    }

    /// Run whatever feeds this input to its end, unread.
    fn drain(&mut self) -> Result<(), DecodeError> {
        match self {
            Self::Slice(rest) => *rest = &[],
            Self::Stage { stage, block, pos } => {
                *pos = 0;
                block.clear();
                while stage.read(block)? {
                    block.clear();
                }
                block.clear();
            }
        }
        Ok(())
    }
}

trait Decoder {
    /// Append the next piece of output to `out`, reading as much of
    /// `input` as that takes. Returns whether more may follow.
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError>;
}

struct Stage<'a> {
    index: usize,
    decoder: Box<dyn Decoder>,
    input: Input<'a>,
    meter: &'a Meter,
    kind: Kind,
    /// Whether more may follow, or how the stage failed.
    state: Result<bool, DecodeError>,
}

impl Stage<'_> {
    fn read(&mut self, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        if self.state == Ok(true) {
            self.state = self.step(out);
        }
        self.state
    }

    fn step(&mut self, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let start = out.len();
        let outcome = self.decoder.read(&mut self.input, out);
        let produced = &self.meter.produced[self.index];
        produced.set(produced.get() + (out.len() - start) as u64);
        let over = self.meter.over(self.index);
        let ended = match outcome {
            Ok(true) if !over => return Ok(true),
            Ok(true) if self.kind == Kind::CheckedLast => {
                out.truncate(start);
                return Ok(true);
            }
            Ok(true) => Err(DecodeError::Limit),
            Ok(false) => Ok(false),
            Err(error) => Err(error),
        };
        // This filter is done. The ones before it would have run to their
        // ends before it began: a failure of theirs is the stream's, and
        // what they produce on the way counts against this one's limit.
        self.input.drain()?;
        let ended = match ended {
            Err(error) if self.kind == Kind::CheckedLast => Err(error),
            _ if self.meter.over(self.index) => Err(DecodeError::Limit),
            ended => ended,
        };
        if ended.is_err() {
            self.meter.failed.set(Some(self.index));
        }
        ended
    }
}

/// A filter this module does not implement.
struct Unknown;

impl Decoder for Unknown {
    fn read(&mut self, _: &mut Input<'_>, _: &mut Vec<u8>) -> Result<bool, DecodeError> {
        Err(DecodeError::Unsupported)
    }
}

/// Inflate a zlib stream. Readers use whatever inflated before a truncated
/// or damaged stream gave out, so that prefix is the output here too; only a
/// stream that yields nothing at all is an error.
struct Flate {
    state: Box<DecompressorOxide>,
    /// The last of the output, which the stream reaches back into, and room
    /// for a block more.
    buffer: Box<[u8]>,
    filled: usize,
    wrote: bool,
}

impl Flate {
    fn new() -> Self {
        Self {
            state: Box::default(),
            buffer: vec![0; WINDOW + BLOCK].into(),
            filled: 0,
            wrote: false,
        }
    }
}

impl Decoder for Flate {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let whole = input.whole();
        let chunk = input.fill()?;
        let more_input = !whole && !chunk.is_empty();
        let mut flags = TINFL_FLAG_PARSE_ZLIB_HEADER
            | TINFL_FLAG_IGNORE_ADLER32
            | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        if more_input {
            flags |= TINFL_FLAG_HAS_MORE_INPUT;
        }
        let (status, consumed, produced) =
            decompress(&mut self.state, chunk, &mut self.buffer, self.filled, flags);
        out.extend_from_slice(&self.buffer[self.filled..self.filled + produced]);
        self.filled += produced;
        self.wrote |= produced > 0;
        input.consume(consumed);
        match status {
            // Full: what the stream may still reach back into moves to the
            // front, and the rest of the room is free again.
            TINFLStatus::HasMoreOutput if self.filled > WINDOW => {
                self.buffer
                    .copy_within(self.filled - WINDOW..self.filled, 0);
                self.filled = WINDOW;
                Ok(true)
            }
            TINFLStatus::NeedsMoreInput if more_input => Ok(true),
            TINFLStatus::Done => Ok(false),
            _ if !self.wrote => Err(DecodeError::Corrupt),
            _ => Ok(false),
        }
    }
}

#[derive(Default)]
struct AsciiHex {
    high: Option<u8>,
    ended: bool,
}

impl Decoder for AsciiHex {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let chunk = input.fill()?;
        let length = chunk.len().min(BLOCK);
        for &byte in &chunk[..length] {
            if byte == b'>' {
                self.ended = true;
                break;
            }
            let Some(digit) = (byte as char).to_digit(16) else {
                continue;
            };
            match self.high.take() {
                Some(high) => out.push(high << 4 | digit as u8),
                None => self.high = Some(digit as u8),
            }
        }
        input.consume(length);
        if length > 0 && !self.ended {
            return Ok(true);
        }
        // A missing final digit counts as zero.
        out.extend(self.high.take().map(|high| high << 4));
        Ok(false)
    }
}

#[derive(Default)]
struct Ascii85 {
    /// Bytes seen of the `<~` that may open the data.
    opening: u8,
    group: [u8; 5],
    filled: usize,
}

impl Ascii85 {
    fn flush(&self, keep: usize, out: &mut Vec<u8>) {
        let value = self.group.iter().fold(0u32, |acc, &digit| {
            acc.wrapping_mul(85).wrapping_add(digit as u32)
        });
        out.extend_from_slice(&value.to_be_bytes()[..keep]);
    }

    /// Take one byte in; false at the `~` that ends the data.
    fn byte(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        match byte {
            b'~' => return Ok(false),
            b'z' if self.filled == 0 => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                self.group[self.filled] = byte - b'!';
                self.filled += 1;
                if self.filled == 5 {
                    self.flush(4, out);
                    self.filled = 0;
                }
            }
            byte if is_whitespace(byte) => {}
            _ => return Err(DecodeError::Corrupt),
        }
        Ok(true)
    }

    fn end(&mut self, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        // A `<` that nothing followed was data.
        if self.opening == 1 {
            self.opening = 2;
            self.byte(b'<', out)?;
        }
        match self.filled {
            0 => {}
            1 => return Err(DecodeError::Corrupt),
            filled => {
                // A short final group is padded with the highest digit.
                self.group[filled..].fill(84);
                self.flush(filled - 1, out);
            }
        }
        Ok(false)
    }
}

impl Decoder for Ascii85 {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let chunk = input.fill()?;
        let length = chunk.len().min(BLOCK);
        if length == 0 {
            return self.end(out);
        }
        for &byte in &chunk[..length] {
            let more = match (self.opening, byte) {
                (0, b'<') => {
                    self.opening = 1;
                    true
                }
                (1, b'~') => {
                    self.opening = 2;
                    true
                }
                (1, _) => {
                    self.opening = 2;
                    self.byte(b'<', out)? && self.byte(byte, out)?
                }
                _ => {
                    self.opening = 2;
                    self.byte(byte, out)?
                }
            };
            if !more {
                return self.end(out);
            }
        }
        input.consume(length);
        Ok(true)
    }
}

#[derive(Default)]
struct RunLength {
    /// A literal run, held until all of it has arrived.
    literal: Vec<u8>,
    wanted: usize,
    /// How often the next byte is repeated.
    repeat: Option<usize>,
}

impl Decoder for RunLength {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let start = out.len();
        while out.len() - start < BLOCK {
            let chunk = input.fill()?;
            let Some(&first) = chunk.first() else {
                let cut_short = self.wanted > 0 || self.repeat.is_some();
                return if cut_short {
                    Err(DecodeError::Corrupt)
                } else {
                    Ok(false)
                };
            };
            if self.wanted > 0 {
                let taken = chunk.len().min(self.wanted - self.literal.len());
                self.literal.extend_from_slice(&chunk[..taken]);
                input.consume(taken);
                if self.literal.len() == self.wanted {
                    out.append(&mut self.literal);
                    self.wanted = 0;
                }
                continue;
            }
            input.consume(1);
            match (self.repeat.take(), first) {
                (Some(count), byte) => out.resize(out.len() + count, byte),
                (None, 128) => return Ok(false),
                (None, length @ 0..=127) => self.wanted = length as usize + 1,
                (None, length) => self.repeat = Some(257 - length as usize),
            }
        }
        Ok(true)
    }
}

const LZW_CLEAR: usize = 256;
const LZW_END: usize = 257;
const LZW_MAX_CODES: usize = 4096;

/// Variable-width LZW as PDF and TIFF use it: codes are packed most
/// significant bit first and grow from 9 to 12 bits.
struct Lzw {
    early_change: bool,
    // Each table entry is the previous entry's string plus one byte.
    prefix: Vec<usize>,
    suffix: Vec<u8>,
    previous: Option<usize>,
    width: u32,
    bits: u32,
    bit_count: u32,
}

impl Lzw {
    fn new(early_change: bool) -> Self {
        Self {
            early_change,
            prefix: Vec::new(),
            suffix: Vec::new(),
            previous: None,
            width: 9,
            bits: 0,
            bit_count: 0,
        }
    }

    /// Append the string for `code` to `out`; returns its first byte.
    fn emit(&self, code: usize, out: &mut Vec<u8>) -> u8 {
        let start = out.len();
        let mut code = code;
        while code > LZW_END {
            out.push(self.suffix[code - LZW_END - 1]);
            code = self.prefix[code - LZW_END - 1];
        }
        out.push(code as u8);
        out[start..].reverse();
        out[start]
    }
}

impl Decoder for Lzw {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        let start = out.len();
        while out.len() - start < BLOCK {
            while self.bit_count < self.width {
                let Some(&byte) = input.fill()?.first() else {
                    return Ok(false);
                };
                input.consume(1);
                self.bits = self.bits << 8 | byte as u32;
                self.bit_count += 8;
            }
            self.bit_count -= self.width;
            let code = (self.bits >> self.bit_count) as usize & ((1 << self.width) - 1);

            if code == LZW_END {
                return Ok(false);
            }
            if code == LZW_CLEAR {
                self.prefix.clear();
                self.suffix.clear();
                self.previous = None;
                self.width = 9;
                continue;
            }
            let next_code = LZW_END + 1 + self.prefix.len();
            match self.previous {
                None if code < LZW_CLEAR => out.push(code as u8),
                None => return Err(DecodeError::Corrupt),
                Some(last) => {
                    let first = if code < next_code {
                        self.emit(code, out)
                    } else if code == next_code {
                        // The code being defined right now: last string plus its own first byte.
                        let first = self.emit(last, out);
                        out.push(first);
                        first
                    } else {
                        return Err(DecodeError::Corrupt);
                    };
                    if next_code < LZW_MAX_CODES {
                        self.prefix.push(last);
                        self.suffix.push(first);
                    }
                }
            }
            self.previous = Some(code);
            let defined = LZW_END + 1 + self.prefix.len() + usize::from(self.early_change);
            if defined >= 1 << self.width && self.width < 12 {
                self.width += 1;
            }
        }
        Ok(true)
    }
}

/// Undo PNG row filtering (predictors 10-15): each row is a filter-type byte
/// followed by the filtered samples.
struct Predictor {
    /// Bytes to a row and to a pixel, or why there is nothing to undo.
    layout: Result<(usize, usize), DecodeError>,
    previous: Vec<u8>,
    /// The start of a row whose end has not arrived.
    pending: Vec<u8>,
}

impl Predictor {
    fn new(params: &Params) -> Self {
        let layout = if params.predictor < 10 {
            Err(DecodeError::Unsupported)
        } else {
            let sample_bits = params.colors.checked_mul(params.bits_per_component);
            let row_len = sample_bits
                .and_then(|bits| params.columns.checked_mul(bits))
                .map(|bits| bits.div_ceil(8))
                .filter(|&len| len > 0 && len <= 1 << 24);
            sample_bits
                .zip(row_len)
                .map(|(bits, row_len)| (row_len, bits.div_ceil(8).max(1)))
                .ok_or(DecodeError::Corrupt)
        };
        Self {
            layout,
            previous: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// One row, or the part of one that the data ends with.
    fn row(
        &mut self,
        encoded: &[u8],
        pixel_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        let Some((&filter, encoded)) = encoded.split_first() else {
            return Ok(());
        };
        let start = out.len();
        out.extend_from_slice(encoded);
        let row = &mut out[start..];
        for index in 0..row.len() {
            let left = if index >= pixel_len {
                row[index - pixel_len]
            } else {
                0
            };
            let up = self.previous[index];
            let up_left = if index >= pixel_len {
                self.previous[index - pixel_len]
            } else {
                0
            };
            let predicted = match filter {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((left as u16 + up as u16) / 2) as u8,
                4 => paeth(left, up, up_left),
                _ => return Err(DecodeError::Corrupt),
            };
            row[index] = row[index].wrapping_add(predicted);
        }
        self.previous[..row.len()].copy_from_slice(row);
        Ok(())
    }
}

impl Decoder for Predictor {
    fn read(&mut self, input: &mut Input<'_>, out: &mut Vec<u8>) -> Result<bool, DecodeError> {
        // The filter before this one runs to its end first, whatever is
        // wrong here.
        let (row_len, pixel_len) = self.layout?;
        if self.previous.is_empty() {
            self.previous = vec![0; row_len];
        }
        let chunk = input.fill()?;
        let length = chunk.len().min(BLOCK);
        if length == 0 {
            let last = std::mem::take(&mut self.pending);
            self.row(&last, pixel_len, out)?;
            return Ok(false);
        }
        self.pending.extend_from_slice(&chunk[..length]);
        input.consume(length);
        let pending = std::mem::take(&mut self.pending);
        let mut rows = pending.chunks_exact(row_len + 1);
        for encoded in rows.by_ref() {
            self.row(encoded, pixel_len, out)?;
        }
        self.pending = rows.remainder().to_vec();
        Ok(true)
    }
}

fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
    let estimate = left as i16 + up as i16 - up_left as i16;
    let distance = |value: u8| (estimate - value as i16).abs();
    if distance(left) <= distance(up) && distance(left) <= distance(up_left) {
        left
    } else if distance(up) <= distance(up_left) {
        up
    } else {
        up_left
    }
}

/// The filters as they were before they ran in blocks: each one decodes all
/// of its input into one buffer. What the chain above produces is checked
/// against them.
#[cfg(test)]
mod reference {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::inflate_flags::{
        TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    };
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

    use super::{DecodeError, LZW_CLEAR, LZW_END, LZW_MAX_CODES, Params, is_whitespace};

    /// Run one filter, producing at most `limit` bytes.
    pub fn apply(
        filter: &[u8],
        input: &[u8],
        params: &Params,
        limit: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let decoded = match filter {
            b"FlateDecode" | b"Fl" => flate(input, limit)?,
            b"LZWDecode" | b"LZW" => lzw(input, params.early_change, limit)?,
            b"ASCIIHexDecode" | b"AHx" => ascii_hex(input),
            b"ASCII85Decode" | b"A85" => ascii85(input)?,
            b"RunLengthDecode" | b"RL" => run_length(input, limit)?,
            _ => return Err(DecodeError::Unsupported),
        };
        if decoded.len() > limit {
            return Err(DecodeError::Limit);
        }
        match (filter, params.predictor) {
            (b"FlateDecode" | b"Fl" | b"LZWDecode" | b"LZW", 10..) => {
                png_predictor(&decoded, params)
            }
            (b"FlateDecode" | b"Fl" | b"LZWDecode" | b"LZW", 2..) => Err(DecodeError::Unsupported),
            _ => Ok(decoded),
        }
    }

    /// Inflate a zlib stream. Readers use whatever inflated before a truncated
    /// or damaged stream gave out, so that prefix is returned here too; only a
    /// stream that yields nothing at all is an error.
    fn flate(mut input: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
        let flags = TINFL_FLAG_PARSE_ZLIB_HEADER
            | TINFL_FLAG_IGNORE_ADLER32
            | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let mut decompressor = Box::<DecompressorOxide>::default();
        let mut output = vec![0; input.len().saturating_mul(2).clamp(64, limit.max(64))];
        let mut written = 0;
        loop {
            let (status, consumed, produced) =
                decompress(&mut decompressor, input, &mut output, written, flags);
            written += produced;
            match status {
                TINFLStatus::HasMoreOutput if output.len() > limit => {
                    return Err(DecodeError::Limit);
                }
                TINFLStatus::HasMoreOutput => {
                    input = input.get(consumed..).unwrap_or(&[]);
                    // One byte past the limit is enough to tell "fits" from "too big".
                    let grown = output.len().saturating_mul(2).min(limit.saturating_add(1));
                    output.resize(grown, 0);
                }
                TINFLStatus::Done => break,
                _ if written == 0 => return Err(DecodeError::Corrupt),
                _ => break,
            }
        }
        output.truncate(written);
        Ok(output)
    }

    fn ascii_hex(input: &[u8]) -> Vec<u8> {
        let mut digits = input
            .iter()
            .take_while(|&&b| b != b'>')
            .filter_map(|&b| (b as char).to_digit(16));
        let mut output = Vec::with_capacity(input.len() / 2);
        while let Some(high) = digits.next() {
            // A missing final digit counts as zero.
            let low = digits.next().unwrap_or(0);
            output.push((high << 4 | low) as u8);
        }
        output
    }

    fn ascii85(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let input = input.strip_prefix(b"<~").unwrap_or(input);
        let mut output = Vec::with_capacity(input.len() * 4 / 5);
        let mut group = [0u8; 5];
        let mut filled = 0;
        let flush = |group: &[u8; 5], keep: usize, output: &mut Vec<u8>| {
            let value = group.iter().fold(0u32, |acc, &digit| {
                acc.wrapping_mul(85).wrapping_add(digit as u32)
            });
            output.extend_from_slice(&value.to_be_bytes()[..keep]);
        };
        for &byte in input {
            match byte {
                b'~' => break,
                b'z' if filled == 0 => output.extend_from_slice(&[0; 4]),
                b'!'..=b'u' => {
                    group[filled] = byte - b'!';
                    filled += 1;
                    if filled == 5 {
                        flush(&group, 4, &mut output);
                        filled = 0;
                    }
                }
                byte if is_whitespace(byte) => {}
                _ => return Err(DecodeError::Corrupt),
            }
        }
        match filled {
            0 => {}
            1 => return Err(DecodeError::Corrupt),
            _ => {
                // A short final group is padded with the highest digit.
                group[filled..].fill(84);
                flush(&group, filled - 1, &mut output);
            }
        }
        Ok(output)
    }

    fn run_length(input: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
        let mut output = Vec::new();
        let mut pos = 0;
        while let Some(&length) = input.get(pos) {
            pos += 1;
            match length {
                128 => break,
                0..=127 => {
                    let count = length as usize + 1;
                    let literal = input.get(pos..pos + count).ok_or(DecodeError::Corrupt)?;
                    output.extend_from_slice(literal);
                    pos += count;
                }
                129..=255 => {
                    let byte = *input.get(pos).ok_or(DecodeError::Corrupt)?;
                    output.resize(output.len() + 257 - length as usize, byte);
                    pos += 1;
                }
            }
            if output.len() > limit {
                return Err(DecodeError::Limit);
            }
        }
        Ok(output)
    }

    /// Variable-width LZW as PDF and TIFF use it: codes are packed most
    /// significant bit first and grow from 9 to 12 bits.
    fn lzw(input: &[u8], early_change: bool, limit: usize) -> Result<Vec<u8>, DecodeError> {
        // Each table entry is the previous entry's string plus one byte.
        let mut prefix: Vec<usize> = Vec::new();
        let mut suffix: Vec<u8> = Vec::new();
        let mut output = Vec::new();
        let mut previous: Option<usize> = None;
        let mut width = 9;
        let (mut bits, mut bit_count) = (0u32, 0);
        let mut bytes = input.iter();

        // Append the string for `code` to `output`; returns its first byte.
        let emit = |code: usize, prefix: &[usize], suffix: &[u8], output: &mut Vec<u8>| {
            let start = output.len();
            let mut code = code;
            while code > LZW_END {
                output.push(suffix[code - LZW_END - 1]);
                code = prefix[code - LZW_END - 1];
            }
            output.push(code as u8);
            output[start..].reverse();
            output[start]
        };

        loop {
            while bit_count < width {
                let Some(&byte) = bytes.next() else {
                    return Ok(output);
                };
                bits = bits << 8 | byte as u32;
                bit_count += 8;
            }
            bit_count -= width;
            let code = (bits >> bit_count) as usize & ((1 << width) - 1);

            if code == LZW_END {
                return Ok(output);
            }
            if code == LZW_CLEAR {
                prefix.clear();
                suffix.clear();
                previous = None;
                width = 9;
                continue;
            }
            let next_code = LZW_END + 1 + prefix.len();
            match previous {
                None if code < LZW_CLEAR => output.push(code as u8),
                None => return Err(DecodeError::Corrupt),
                Some(last) => {
                    let first = if code < next_code {
                        emit(code, &prefix, &suffix, &mut output)
                    } else if code == next_code {
                        // The code being defined right now: last string plus its own first byte.
                        let first = emit(last, &prefix, &suffix, &mut output);
                        output.push(first);
                        first
                    } else {
                        return Err(DecodeError::Corrupt);
                    };
                    if next_code < LZW_MAX_CODES {
                        prefix.push(last);
                        suffix.push(first);
                    }
                }
            }
            previous = Some(code);
            if output.len() > limit {
                return Err(DecodeError::Limit);
            }
            let defined = LZW_END + 1 + prefix.len() + usize::from(early_change);
            if defined >= 1 << width && width < 12 {
                width += 1;
            }
        }
    }

    /// Undo PNG row filtering (predictors 10-15): each row is a filter-type byte
    /// followed by the filtered samples.
    fn png_predictor(data: &[u8], params: &Params) -> Result<Vec<u8>, DecodeError> {
        let sample_bits = params
            .colors
            .checked_mul(params.bits_per_component)
            .ok_or(DecodeError::Corrupt)?;
        let row_len = params
            .columns
            .checked_mul(sample_bits)
            .map(|bits| bits.div_ceil(8))
            .filter(|&len| len > 0 && len <= 1 << 24)
            .ok_or(DecodeError::Corrupt)?;
        let pixel_len = sample_bits.div_ceil(8).max(1);

        let mut output = Vec::with_capacity(data.len());
        let mut previous = vec![0u8; row_len];
        for encoded in data.chunks(row_len + 1) {
            let (&filter, encoded) = encoded.split_first().ok_or(DecodeError::Corrupt)?;
            let mut row = encoded.to_vec();
            for index in 0..row.len() {
                let left = if index >= pixel_len {
                    row[index - pixel_len]
                } else {
                    0
                };
                let up = previous[index];
                let up_left = if index >= pixel_len {
                    previous[index - pixel_len]
                } else {
                    0
                };
                let predicted = match filter {
                    0 => 0,
                    1 => left,
                    2 => up,
                    3 => ((left as u16 + up as u16) / 2) as u8,
                    4 => paeth(left, up, up_left),
                    _ => return Err(DecodeError::Corrupt),
                };
                row[index] = row[index].wrapping_add(predicted);
            }
            output.extend_from_slice(&row);
            previous[..row.len()].copy_from_slice(&row);
        }
        Ok(output)
    }

    fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
        let estimate = left as i16 + up as i16 - up_left as i16;
        let distance = |value: u8| (estimate - value as i16).abs();
        if distance(left) <= distance(up) && distance(left) <= distance(up_left) {
            left
        } else if distance(up) <= distance(up_left) {
            up
        } else {
            up_left
        }
    }
}

#[cfg(test)]
mod tests {
    use miniz_oxide::deflate::compress_to_vec_zlib;

    use super::*;

    fn decode(filter: &str, input: &[u8]) -> Result<Vec<u8>, DecodeError> {
        apply(filter.as_bytes(), input, &Params::default(), 1 << 20)
    }

    #[test]
    fn flate_roundtrip_limit_and_damage() {
        let text = b"stream content ".repeat(50);
        let compressed = compress_to_vec_zlib(&text, 6);
        assert_eq!(decode("FlateDecode", &compressed).as_deref(), Ok(&text[..]));
        assert_eq!(
            apply(b"Fl", &compressed, &Params::default(), 100),
            Err(DecodeError::Limit)
        );
        // A truncated stream still yields its readable prefix.
        let partial = decode("FlateDecode", &compressed[..compressed.len() - 6]).unwrap();
        assert!(!partial.is_empty() && text.starts_with(&partial));
        assert_eq!(
            decode("FlateDecode", b"\xFF\xFF\xFF"),
            Err(DecodeError::Corrupt)
        );
    }

    #[test]
    fn ascii_filters() {
        assert_eq!(
            decode("ASCIIHexDecode", b"48 65 6C6c 6F7>").as_deref(),
            Ok(&b"Hellop"[..])
        );
        assert_eq!(
            decode("ASCII85Decode", b"<~87cURD]i,\"Ebo80~>").as_deref(),
            Ok(&b"Hello World!"[..])
        );
        assert_eq!(decode("A85", b"z!!~>").as_deref(), Ok(&[0, 0, 0, 0, 0][..]));
        assert_eq!(decode("ASCII85Decode", b"{bad}"), Err(DecodeError::Corrupt));
    }

    #[test]
    fn run_length() {
        let encoded = [2, b'a', b'b', b'c', 254, b'x', 128, b'!'];
        assert_eq!(
            decode("RunLengthDecode", &encoded).as_deref(),
            Ok(&b"abcxxx"[..])
        );
        assert_eq!(decode("RL", &[5, b'a']), Err(DecodeError::Corrupt));
        assert_eq!(
            apply(b"RL", &[129, b'x'], &Params::default(), 10),
            Err(DecodeError::Limit)
        );
    }

    #[test]
    fn lzw_matches_the_specification_example() {
        let encoded = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        let expected = [45, 45, 45, 45, 45, 65, 45, 45, 45, 66];
        assert_eq!(decode("LZWDecode", &encoded).as_deref(), Ok(&expected[..]));
    }

    #[test]
    fn png_predictor_rows() {
        let params = Params {
            predictor: 12,
            columns: 3,
            ..Params::default()
        };
        // Row 1 uses Sub, row 2 uses Up.
        let rows = [1, 10, 1, 1, 2, 5, 5, 5];
        let compressed = compress_to_vec_zlib(&rows, 6);
        assert_eq!(
            apply(b"FlateDecode", &compressed, &params, 1 << 20).as_deref(),
            Ok(&[10, 11, 12, 15, 16, 17][..])
        );
        let tiff = Params {
            predictor: 2,
            ..Params::default()
        };
        assert_eq!(
            apply(b"FlateDecode", &compressed, &tiff, 1 << 20),
            Err(DecodeError::Unsupported)
        );
    }

    #[test]
    fn unknown_filters_are_unsupported() {
        assert_eq!(decode("JBIG2Decode", b""), Err(DecodeError::Unsupported));
        assert_eq!(decode("Crypt", b""), Err(DecodeError::Unsupported));
    }

    /// Numbers in a fixed order, so that a failure can be run again.
    struct Random(u64);

    impl Random {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }

        fn bytes(&mut self, length: usize) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(length);
            while bytes.len() < length {
                match self.below(3) {
                    0 => bytes.push(self.below(256) as u8),
                    1 => bytes.extend_from_slice(b"BT /F1 12 Tf (text) Tj ET\n"),
                    _ => bytes.extend(vec![self.below(256) as u8; self.below(300)]),
                }
            }
            bytes.truncate(length);
            bytes
        }
    }

    const FILTERS: [&str; 6] = [
        "FlateDecode",
        "LZWDecode",
        "ASCIIHexDecode",
        "ASCII85Decode",
        "RunLengthDecode",
        "DCTDecode",
    ];

    /// `data` as `filter` stores it.
    fn encode(filter: &str, data: &[u8], random: &mut Random) -> Vec<u8> {
        let mut out = Vec::new();
        match filter {
            "FlateDecode" => out = compress_to_vec_zlib(data, 6),
            "ASCIIHexDecode" => {
                for byte in data {
                    out.extend_from_slice(format!("{byte:02x}").as_bytes());
                    if random.below(20) == 0 {
                        out.push(b'\n');
                    }
                }
                out.push(b'>');
            }
            "ASCII85Decode" => {
                if random.below(2) == 0 {
                    out.extend_from_slice(b"<~");
                }
                for group in data.chunks(4) {
                    let mut word = [0; 4];
                    word[..group.len()].copy_from_slice(group);
                    let mut value = u32::from_be_bytes(word);
                    if value == 0 && group.len() == 4 {
                        out.push(b'z');
                        continue;
                    }
                    let mut digits = [0; 5];
                    for digit in digits.iter_mut().rev() {
                        *digit = (value % 85) as u8 + b'!';
                        value /= 85;
                    }
                    out.extend_from_slice(&digits[..group.len() + 1]);
                }
                out.extend_from_slice(b"~>");
            }
            "RunLengthDecode" => {
                let mut rest = data;
                while let Some(&first) = rest.first() {
                    let run = rest.iter().take_while(|&&b| b == first).count().min(128);
                    if run > 1 {
                        out.extend_from_slice(&[(257 - run) as u8, first]);
                        rest = &rest[run..];
                    } else {
                        let literal = rest.len().min(1 + random.below(128));
                        out.push(literal as u8 - 1);
                        out.extend_from_slice(&rest[..literal]);
                        rest = &rest[literal..];
                    }
                }
                out.push(128);
            }
            // Every byte as a code of its own, the table cleared before
            // the codes grow wider.
            "LZWDecode" => {
                let (mut bits, mut count) = (0u32, 0);
                let codes = data.chunks(200).flat_map(|chunk| {
                    let literal = chunk.iter().map(|&byte| byte as u32);
                    std::iter::once(LZW_CLEAR as u32).chain(literal)
                });
                for code in codes.chain([LZW_END as u32]) {
                    bits = bits << 9 | code;
                    count += 9;
                    while count >= 8 {
                        count -= 8;
                        out.push((bits >> count) as u8);
                    }
                }
                out.push((bits << (8 - count)) as u8);
            }
            _ => out = data.to_vec(),
        }
        out
    }

    /// A chain run the way it was before: each filter over all that the
    /// one before it produced, with what is left of the limit.
    fn one_at_a_time(
        steps: &[Step<'_>],
        input: &[u8],
        limit: u64,
    ) -> (u64, Result<Vec<u8>, DecodeError>) {
        let mut data = input.to_vec();
        let mut used = 0;
        for step in steps {
            let left = (limit - used) as usize;
            match reference::apply(step.filter, &data, &step.params, left) {
                Ok(decoded) => {
                    used += decoded.len() as u64;
                    data = decoded;
                }
                Err(error) => return (used, Err(error)),
            }
        }
        (used, Ok(data))
    }

    fn in_blocks(
        steps: &[Step<'_>],
        input: &[u8],
        limit: u64,
    ) -> (u64, Result<Vec<u8>, DecodeError>) {
        let mut output = Vec::new();
        let (used, outcome) = run(steps, input, limit, &mut |block| {
            output.extend_from_slice(block)
        });
        (used, outcome.map(|()| output))
    }

    #[test]
    fn chains_in_blocks_end_as_they_did_one_filter_at_a_time() {
        let mut random = Random(0x9E37_79B9_7F4A_7C15);
        for round in 0..4000 {
            let length = random.below(3) * random.below(1500);
            let mut data = random.bytes(length);
            let names: Vec<&str> = (0..1 + random.below(3))
                .map(|_| FILTERS[random.below(FILTERS.len())])
                .collect();
            let mut steps: Vec<Step<'_>> = names
                .iter()
                .map(|name| Step {
                    filter: name.as_bytes(),
                    params: Params {
                        predictor: [1, 1, 1, 1, 2, 12, 15, 99][random.below(8)],
                        columns: random.below(9),
                        colors: 1 + random.below(3),
                        bits_per_component: [8, 8, 4, 16][random.below(4)],
                        early_change: random.below(4) != 0,
                    },
                })
                .collect();
            // Rows a predictor can undo, where it is the last to run.
            let last = steps.last_mut().unwrap();
            if random.below(2) == 0 {
                last.params.early_change = true;
                let row = last.params.columns * last.params.colors * 8;
                let row = (row * last.params.bits_per_component / 8).div_ceil(8);
                if last.params.predictor >= 10 && row > 0 {
                    let rows = data.chunks(row).flat_map(|samples| {
                        let filter = random.below(5) as u8;
                        std::iter::once(filter).chain(samples.iter().copied())
                    });
                    data = rows.collect();
                }
            } else {
                last.params.predictor = 1;
            }
            for step in steps.iter().rev() {
                let name = std::str::from_utf8(step.filter).unwrap();
                data = encode(name, &data, &mut random);
            }
            // Damage, as often as not.
            match random.below(6) {
                0 if !data.is_empty() => data.truncate(random.below(data.len())),
                1 if !data.is_empty() => {
                    let at = random.below(data.len());
                    data[at] ^= 1 << random.below(8);
                }
                2 => data.extend(random.bytes(20)),
                _ => {}
            }

            let (needed, _) = one_at_a_time(&steps, &data, u64::MAX >> 1);
            for limit in [
                u64::MAX >> 1,
                needed,
                needed.saturating_sub(1),
                needed + 1,
                needed / 2,
                random.below(200) as u64,
                0,
            ] {
                assert_eq!(
                    in_blocks(&steps, &data, limit),
                    one_at_a_time(&steps, &data, limit),
                    "round {round}: {names:?}, {} bytes, limit {limit}",
                    data.len()
                );
            }
        }
    }

    #[test]
    fn flate_reaches_back_across_blocks() {
        let mut random = Random(7);
        let page = random.bytes(30_000);
        let mut data = Vec::new();
        for _ in 0..12 {
            data.extend_from_slice(&page);
            data.extend(random.bytes(500));
        }
        let compressed = compress_to_vec_zlib(&data, 9);
        assert!(compressed.len() < data.len() / 4);
        assert_eq!(decode("FlateDecode", &compressed), Ok(data.clone()));
        // The same behind another filter, which hands it over in pieces.
        let hex = encode("ASCIIHexDecode", &compressed, &mut random);
        let steps = ["ASCIIHexDecode", "FlateDecode"].map(|name| Step {
            filter: name.as_bytes(),
            params: Params::default(),
        });
        assert_eq!(in_blocks(&steps, &hex, 1 << 20).1, Ok(data));
    }
}
