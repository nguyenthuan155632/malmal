//! Stream filters. Only the lossless general-purpose ones are implemented:
//! those are what object streams and embedded files are stored with.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use super::parser::is_whitespace;

#[derive(Debug, PartialEq, Eq)]
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

/// Run one filter, producing at most `limit` bytes.
pub(crate) fn apply(
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
        (b"FlateDecode" | b"Fl" | b"LZWDecode" | b"LZW", 10..) => png_predictor(&decoded, params),
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
            TINFLStatus::HasMoreOutput if output.len() > limit => return Err(DecodeError::Limit),
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

const LZW_CLEAR: usize = 256;
const LZW_END: usize = 257;
const LZW_MAX_CODES: usize = 4096;

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
}
