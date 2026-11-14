//! Checks that take more than a keyword: what a string says, what the numbers
//! in a dictionary add up to, and where in the file an object or a signature
//! of another format stands. They run once every object is known, object
//! streams included, and once the document has been opened if it is
//! encrypted.

use std::ops::Range;

use memchr::memmem;

use super::crypt::StreamKind;
use super::filters::DecodeError;
use super::parser::{Dict, Name, Value, is_regular, is_whitespace};
use super::{Document, Object, Output, for_each_operator, postscript};
use crate::limits::{Budget, LimitExceeded};
use crate::report::Severity;

/// A page side longer than this, in points and after `/UserUnit`, is no
/// page: 400 inches, twice what the format allows without a user unit.
const MAX_PAGE_SIDE: f64 = 28_800.0;
/// The format's own limit on the length of a name.
const MAX_NAME: usize = 255;
/// A calculator function's program is a few hundred bytes.
const MAX_FUNCTION: usize = 64 << 10;

/// Annotation flags.
const HIDDEN: usize = 1 << 1;
const PRINT: usize = 1 << 2;
const NO_VIEW: usize = 1 << 5;

const PAGE_BOXES: [&[u8]; 5] = [b"MediaBox", b"CropBox", b"BleedBox", b"TrimBox", b"ArtBox"];

/// The operators a Type 4 function may use, sorted.
const CALCULATOR: [&[u8]; 42] = [
    b"abs",
    b"add",
    b"and",
    b"atan",
    b"bitshift",
    b"ceiling",
    b"copy",
    b"cos",
    b"cvi",
    b"cvr",
    b"div",
    b"dup",
    b"eq",
    b"exch",
    b"exp",
    b"false",
    b"floor",
    b"ge",
    b"gt",
    b"idiv",
    b"if",
    b"ifelse",
    b"index",
    b"le",
    b"ln",
    b"log",
    b"lt",
    b"mod",
    b"mul",
    b"ne",
    b"neg",
    b"not",
    b"or",
    b"pop",
    b"roll",
    b"round",
    b"sin",
    b"sqrt",
    b"sub",
    b"true",
    b"truncate",
    b"xor",
];

struct Pass<'p, 'a> {
    doc: &'p Document<'a>,
    /// Strings and streams are plaintext: the document is not encrypted, or
    /// it has been opened.
    readable: bool,
    max_pixels: u64,
}

pub(super) fn inspect(
    doc: &Document<'_>,
    readable: bool,
    max_pixels: u64,
    budget: &mut Budget,
    out: &mut Output<'_>,
) {
    let pass = Pass {
        doc,
        readable,
        max_pixels,
    };
    for (count, object) in doc.objects.iter().enumerate() {
        if count % 256 == 0
            && let Err(limit) = budget.check_time()
        {
            return out.limit(limit);
        }
        let is_stream = object.stream_start.is_some();
        pass.visit(object, &object.value, is_stream, out);
        if readable
            && is_stream
            && let Err(limit) = pass.stream(object, budget, out)
        {
            return out.limit(limit);
        }
    }

    let streams = stream_ranges(doc);
    conflicting_objects(doc, &streams, out);
    foreign_signatures(doc.data, &streams, out);
}

impl Pass<'_, '_> {
    fn visit(&self, object: &Object, value: &Value, stream_dict: bool, out: &mut Output<'_>) {
        match value {
            Value::Dict(dict) => {
                self.dict(object, dict, stream_dict, out);
                for (key, item) in &dict.0 {
                    check_length(key, object.offset, out);
                    self.visit(object, item, false, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.visit(object, item, false, out);
                }
            }
            Value::Name(name) => check_length(name, object.offset, out),
            _ => {}
        }
    }

    /// A string as the document's author wrote it, where it can be read.
    fn string(&self, object: &Object, value: &Value) -> Option<Vec<u8>> {
        if !self.readable {
            return None;
        }
        let raw = self.doc.resolve(Some(value)).as_string()?;
        // Strings in an object stream are covered by the stream's encryption.
        match (&self.doc.crypt, object.packed) {
            (Some(crypt), false) => {
                crypt.decrypt(object.number, object.generation, StreamKind::Ordinary, raw)
            }
            _ => Some(raw.to_vec()),
        }
    }

    fn number(&self, dict: &Dict, key: &[u8]) -> Option<f64> {
        self.doc.resolve(dict.get(key)).as_number()
    }

    fn dict(&self, object: &Object, dict: &Dict, stream_dict: bool, out: &mut Output<'_>) {
        let doc = self.doc;
        let offset = object.offset;
        let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
        let present = |key: &[u8]| !matches!(doc.resolve(dict.get(key)), Value::Null);

        let external = if stream_dict
            && [&b"F"[..], b"FFilter", b"FDecodeParms"]
                .into_iter()
                .any(present)
        {
            Some("stream data is read from a file outside the document")
        } else if is(b"Subtype", b"Form") && present(b"Ref") {
            Some("form draws a page of another document")
        } else if is(b"FS", b"URL") {
            Some("file specification names a URL to fetch")
        } else if present(b"OPI") || is(b"Type", b"OPI") {
            Some("OPI comments name a file to put in place of the content")
        } else {
            None
        };
        if let Some(message) = external {
            out.report("pdf.external_ref", Severity::Medium, message, offset);
        }
        if is(b"S", b"Thread") && present(b"F") {
            out.report(
                "pdf.remote_goto",
                Severity::Low,
                "action opens another document",
                offset,
            );
        }

        for value in dict.all(b"URI") {
            // A link's address, or the catalog's dictionary with the base
            // that relative addresses are resolved against.
            let base = doc.resolve(Some(value)).as_dict();
            let targets = base
                .into_iter()
                .flat_map(|base| base.all(b"Base"))
                .chain([value]);
            for target in targets {
                if let Some(address) = self.string(object, target)
                    && let Some((severity, message)) = dangerous_address(&address)
                {
                    out.report("pdf.dangerous_uri", severity, message, offset);
                }
            }
        }
        for value in dict.all(b"DA") {
            if let Some(appearance) = self.string(object, value)
                && for_each_operator(&appearance, |token, _| token == b"PS")
            {
                postscript(
                    "default appearance string uses the PostScript operator",
                    offset,
                    out,
                );
            }
        }

        if is(b"Subtype", b"Image")
            && let (Some(width), Some(height)) =
                (self.number(dict, b"Width"), self.number(dict, b"Height"))
            && width * height > self.max_pixels as f64
        {
            out.report(
                "pdf.pixel_bomb",
                Severity::Medium,
                &format!("image declares {width} x {height} pixels"),
                offset,
            );
        }
        if is(b"Type", b"Page") || is(b"Type", b"Pages") {
            self.page_boxes(dict, offset, out);
        }

        let filters = match doc.resolve(dict.get(b"Filter")) {
            Value::Array(items) => items.iter().collect(),
            Value::Null => Vec::new(),
            other => vec![other],
        };
        for filter in filters {
            if is(b"Subtype", b"Image")
                && let Some(b"JBIG2Decode" | b"JPXDecode") = doc.resolve(Some(filter)).as_name()
            {
                out.report(
                    "pdf.risky_codec",
                    Severity::Info,
                    "image is compressed with JBIG2 or JPEG 2000, whose decoders have a long \
                     history of exploits",
                    offset,
                );
            }
        }
        for key in [&b"DecodeParms"[..], b"DP"] {
            let parameters = match doc.resolve(dict.get(key)) {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            let out_of_range = parameters
                .into_iter()
                .filter_map(|item| doc.resolve(Some(item)).as_dict())
                .any(|parameters| !self.decode_parameters_valid(parameters));
            if out_of_range {
                out.malformed("decode parameters outside what the format allows", offset);
            }
        }

        // An annotation, whose flags can keep it off the screen and on paper.
        if present(b"Rect")
            && present(b"Subtype")
            && let Some(flags) = doc.resolve(dict.get(b"F")).as_usize()
            && flags & PRINT != 0
            && flags & NO_VIEW != 0
            && flags & HIDDEN == 0
        {
            print_only("annotation is printed and not shown on screen", offset, out);
        }
        // The usage dictionary of a layer.
        let state = |usage: &[u8], key: &[u8], name: &[u8]| {
            let usage = doc.resolve(dict.get(usage)).as_dict();
            usage.is_some_and(|usage| doc.name_is(usage.get(key), name))
        };
        if state(b"Print", b"PrintState", b"ON") && state(b"View", b"ViewState", b"OFF") {
            print_only("layer is printed and not shown on screen", offset, out);
        }

        if let Some(ranges) = doc.resolve(dict.get(b"ByteRange")).as_array() {
            self.signed_ranges(ranges, offset, out);
        }
    }

    fn page_boxes(&self, dict: &Dict, offset: usize, out: &mut Output<'_>) {
        let unit = self.number(dict, b"UserUnit").unwrap_or(1.0).max(1.0);
        for key in PAGE_BOXES {
            let Some(corners) = self.doc.resolve(dict.get(key)).as_array() else {
                continue;
            };
            let corner = |index: usize| self.doc.resolve(corners.get(index)).as_number();
            let (Some(left), Some(bottom), Some(right), Some(top)) =
                (corner(0), corner(1), corner(2), corner(3))
            else {
                continue;
            };
            let side = (right - left).abs().max((top - bottom).abs()) * unit;
            if !side.is_finite() || side > MAX_PAGE_SIDE {
                return out.report(
                    "pdf.page_size",
                    Severity::Medium,
                    "page is larger than any real page; rendering it exhausts memory",
                    offset,
                );
            }
        }
    }

    /// Decoders size their buffers from these numbers.
    fn decode_parameters_valid(&self, parameters: &Dict) -> bool {
        let within =
            |key: &[u8], accepts: &dyn Fn(f64) -> bool| match self.doc.resolve(parameters.get(key))
            {
                Value::Null => true,
                Value::Number(value) => value.fract() == 0.0 && accepts(*value),
                _ => false,
            };
        within(b"Predictor", &|n| {
            n == 1.0 || n == 2.0 || (10.0..=15.0).contains(&n)
        }) && within(b"Colors", &|n| (1.0..=32.0).contains(&n))
            && within(b"BitsPerComponent", &|n| {
                [1.0, 2.0, 4.0, 8.0, 16.0].contains(&n)
            })
            && within(b"Columns", &|n| (1.0..=16_777_216.0).contains(&n))
    }

    /// `/ByteRange` of a signature: pairs of offset and length of what was
    /// signed, which is the whole file but the signature value.
    fn signed_ranges(&self, ranges: &[Value], offset: usize, out: &mut Output<'_>) {
        let numbers: Option<Vec<usize>> = ranges
            .iter()
            .map(|item| self.doc.resolve(Some(item)).as_usize())
            .collect();
        let Some(numbers) = numbers.filter(|n| n.len() >= 4 && n.len() % 2 == 0) else {
            return;
        };
        let end = numbers[numbers.len() - 2].saturating_add(numbers[numbers.len() - 1]);
        let length = self.doc.data.trim_ascii_end().len();
        if numbers[0] != 0 || end < length {
            out.report(
                "pdf.signature_modified",
                Severity::Info,
                "signature does not cover the whole file: bytes were added after signing, \
                 or left out of what was signed",
                offset,
            );
        }
    }

    /// Checks on what a stream holds.
    fn stream(
        &self,
        object: &Object,
        budget: &mut Budget,
        out: &mut Output<'_>,
    ) -> Result<(), LimitExceeded> {
        let doc = self.doc;
        let Some(dict) = object.value.as_dict() else {
            return Ok(());
        };
        let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
        let is_xml = is(b"Type", b"Metadata") || is(b"Subtype", b"XML");
        let is_calculator = self.number(dict, b"FunctionType") == Some(4.0);
        if !is_xml && !is_calculator {
            return Ok(());
        }
        let content = match doc.decode(object, budget) {
            Ok(content) => content,
            Err(DecodeError::Limit) => return Err(LimitExceeded::Decompression),
            // Nothing reads what cannot be decoded.
            Err(_) => return Ok(()),
        };
        if is_xml {
            xml(&content, object.offset, out);
        }
        if is_calculator && !is_calculator_program(&content) {
            postscript(
                "function holds PostScript beyond the operators of a calculator function",
                object.offset,
                out,
            );
        }
        Ok(())
    }
}

fn check_length(name: &Name, offset: usize, out: &mut Output<'_>) {
    if name.text().len() > MAX_NAME {
        out.malformed("name longer than the format allows", offset);
    }
}

fn print_only(message: &str, offset: usize, out: &mut Output<'_>) {
    out.report("pdf.print_only", Severity::Info, message, offset);
}

/// Whether a link's address runs a script or reaches for the reader's own
/// machine or a network share, read the way a browser reads it: tabs and
/// line breaks dropped, leading spaces and control characters ignored,
/// letters in either case, UTF-16 accepted.
fn dangerous_address(raw: &[u8]) -> Option<(Severity, &'static str)> {
    let text: Vec<u8> = match raw {
        [0xFE, 0xFF, rest @ ..] => rest
            .chunks(2)
            .map(|unit| match unit {
                [0, low] if low.is_ascii() => *low,
                _ => 0xFF,
            })
            .collect(),
        _ => raw.to_vec(),
    };
    let text: Vec<u8> = text
        .into_iter()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'))
        .skip_while(|&byte| byte <= b' ')
        .map(|byte| byte.to_ascii_lowercase())
        .collect();

    let local = (
        Severity::Medium,
        "link opens a file on the reader's machine or a network share",
    );
    if text.starts_with(b"\\\\") {
        return Some(local);
    }
    let length = text.iter().position(|&byte| byte == b':')?;
    let scheme = &text[..length];
    if scheme.is_empty()
        || !scheme
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    match scheme {
        b"javascript" | b"vbscript" | b"livescript" | b"data" => {
            Some((Severity::High, "link runs a script"))
        }
        b"mhtml" | b"jar" | b"search" | b"shell" | b"its" | b"mk" => Some((
            Severity::High,
            "link starts a protocol handler with a history of exploits",
        )),
        _ if scheme.starts_with(b"ms-") || scheme.starts_with(b"search-") => Some((
            Severity::High,
            "link starts a protocol handler with a history of exploits",
        )),
        b"file" | b"smb" | b"cifs" => Some(local),
        // A drive letter.
        [letter] if letter.is_ascii_alphabetic() => Some(local),
        _ => None,
    }
}

/// XML carried in the document: metadata and form packets. The parsers that
/// read it, in readers and in the tools of a server, expand what a DTD
/// declares and fetch what the text names.
pub(super) fn xml(packet: &[u8], offset: usize, out: &mut Output<'_>) {
    // UTF-16 and UTF-32 text reads as ASCII once the zero bytes are gone.
    let text: Vec<u8> = packet
        .iter()
        .filter(|&&byte| byte != 0)
        .map(u8::to_ascii_lowercase)
        .collect();
    let has = |needle: &[u8]| memmem::find(&text, needle).is_some();
    if has(b"<!entity") {
        out.report(
            "pdf.xml_entity",
            Severity::High,
            "XML in the document declares entities",
            offset,
        );
    } else if has(b"<!doctype") {
        out.report(
            "pdf.xml_entity",
            Severity::Medium,
            "XML in the document has a document type declaration",
            offset,
        );
    }
    let includes = has(b"www.w3.org/2001/xinclude") && has(b"include");
    if includes || has(b"<?xml-stylesheet") || has(b"wsdlconnection") {
        out.report(
            "pdf.xml_external_ref",
            Severity::Medium,
            "XML in the document makes its parser fetch another resource",
            offset,
        );
    }
}

/// Whether the program of a Type 4 function is what the format allows: one
/// procedure of numbers, the calculator's operators and nested procedures.
fn is_calculator_program(program: &[u8]) -> bool {
    if program.len() > MAX_FUNCTION {
        return false;
    }
    let mut depth = 0usize;
    let mut pos = 0;
    while let Some(&byte) = program.get(pos) {
        match byte {
            b'%' => pos += memchr::memchr2(b'\n', b'\r', &program[pos..]).unwrap_or(program.len()),
            b'{' => {
                depth += 1;
                pos += 1;
            }
            b'}' => {
                let Some(outer) = depth.checked_sub(1) else {
                    return false;
                };
                depth = outer;
                pos += 1;
            }
            _ if is_whitespace(byte) => pos += 1,
            _ if is_regular(byte) => {
                let length = program[pos..]
                    .iter()
                    .take_while(|&&b| is_regular(b))
                    .count();
                let token = &program[pos..pos + length];
                let number = std::str::from_utf8(token)
                    .ok()
                    .is_some_and(|text| text.parse::<f64>().is_ok());
                if depth == 0 || !(number || CALCULATOR.binary_search(&token).is_ok()) {
                    return false;
                }
                pos += length;
            }
            // Strings, names, arrays and dictionaries have no place in one.
            _ => return false,
        }
    }
    depth == 0
}

/// Where the data of each stream lies, in file order and without overlaps.
/// What stands there is the stream's, whatever it looks like.
fn stream_ranges(doc: &Document<'_>) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = doc
        .objects
        .iter()
        .filter(|object| !object.packed)
        .filter_map(|object| {
            let start = object.stream_start?;
            Some(start..start + doc.stream_data(object)?.len())
        })
        .collect();
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

fn inside(ranges: &[Range<usize>], position: usize) -> bool {
    let after = ranges.partition_point(|range| range.start <= position);
    after > 0 && position < ranges[after - 1].end
}

/// The parts of the first `end` bytes that are no stream's data, each with
/// where it starts. Most of a large document is stream data, and what is
/// looked for outside it is not looked for inside.
fn gaps<'r>(streams: &'r [Range<usize>], end: usize) -> impl Iterator<Item = Range<usize>> + 'r {
    let starts = std::iter::once(0).chain(streams.iter().map(|stream| stream.end));
    let ends = streams
        .iter()
        .map(|stream| stream.start)
        .chain(std::iter::once(end));
    starts
        .zip(ends)
        .map(move |(start, gap_end)| start..gap_end.min(end))
        .filter(|gap| gap.start < gap.end)
}

/// Where `needle` starts outside every stream, in file order. It may run
/// on into the data of the stream that follows.
fn find_outside<'d>(
    data: &'d [u8],
    streams: &'d [Range<usize>],
    needle: &'d [u8],
) -> impl Iterator<Item = usize> + 'd {
    gaps(streams, data.len()).flat_map(move |gap| {
        let reach = (gap.end + needle.len() - 1).min(data.len());
        memmem::find_iter(&data[gap.start..reach], needle).map(move |at| gap.start + at)
    })
}

/// One object number defined twice with different contents, with no end of
/// file between the two: no update did that. Which of them a reader takes
/// depends on how it reads or repairs the file, so that a scanner and a
/// reader, or two readers, are shown different documents.
fn conflicting_objects(doc: &Document<'_>, streams: &[Range<usize>], out: &mut Output<'_>) {
    let mut order: Vec<&Object> = doc
        .objects
        .iter()
        .filter(|object| !object.packed && !inside(streams, object.offset))
        .collect();
    order.sort_unstable_by_key(|object| (object.number, object.generation, object.offset));
    let mut ends: Option<Vec<usize>> = None;
    for pair in order.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if (first.number, first.generation) != (second.number, second.generation) {
            continue;
        }
        let ends = ends.get_or_insert_with(|| find_outside(doc.data, streams, b"%%EOF").collect());
        let next_end = ends.partition_point(|&end| end < first.offset);
        let same_revision = ends.get(next_end).is_none_or(|&end| end > second.offset);
        if same_revision
            && (first.value != second.value || doc.stream_data(first) != doc.stream_data(second))
        {
            return out.report(
                "pdf.conflicting_objects",
                Severity::Medium,
                &format!(
                    "object {} is defined twice with different contents; readers disagree \
                     on which one counts",
                    first.number
                ),
                second.offset,
            );
        }
    }
}

/// Signatures of other formats outside every stream, where no part of a PDF
/// has a reason to hold them: the file is laid out to open as something else
/// too.
fn foreign_signatures(data: &[u8], streams: &[Range<usize>], out: &mut Output<'_>) {
    // What follows the last end of file is judged with the end of the file.
    let data = &data[..memmem::rfind(data, b"%%EOF").unwrap_or(data.len())];
    if let Some(at) = find_outside(data, streams, b"PK\x03\x04").next() {
        out.report(
            "pdf.polyglot",
            Severity::High,
            "ZIP file header outside any stream; the file also opens as an archive",
            at,
        );
    }

    let markup = find_outside(data, streams, b"<").find(|&at| {
        let rest = &data[at + 1..];
        [&b"html"[..], b"script", b"svg"].into_iter().any(|tag| {
            rest.len() > tag.len()
                && rest[..tag.len()].eq_ignore_ascii_case(tag)
                && (rest[tag.len()].is_ascii_whitespace() || rest[tag.len()] == b'>')
        })
    });
    if let Some(at) = markup {
        out.report(
            "pdf.polyglot",
            Severity::Medium,
            "HTML or SVG markup outside any stream; the file also opens as a web page",
            at,
        );
    }

    let second_header = find_outside(data, streams, b"%PDF-")
        .filter(|&at| {
            let starts_line = at == 0 || matches!(data[at - 1], b'\n' | b'\r');
            starts_line && data.get(at + 5).is_some_and(u8::is_ascii_digit)
        })
        .nth(1);
    if let Some(at) = second_header {
        out.malformed("more than one PDF header", at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let verdict = |address: &[u8]| dangerous_address(address).map(|(severity, _)| severity);
        for harmless in [
            &b"https://example.com/a?b=c:d"[..],
            b"http://example.com",
            b"mailto:someone@example.com",
            b"page.html#top",
            b"../other.pdf",
            b"tel:+15551234",
            b"",
            b"12:30 is the time",
        ] {
            assert_eq!(verdict(harmless), None, "{harmless:?}");
        }
        for script in [
            &b"javascript:alert(1)"[..],
            b"  JavaScript:alert(1)",
            b"java\tscr\nipt:alert(1)",
            b"\xFE\xFF\0j\0a\0v\0a\0s\0c\0r\0i\0p\0t\0:\0x",
            b"data:text/html,<script>",
            b"ms-msdt:/id PCWDiagnostic",
            b"search-ms:query=x",
            b"vbscript:x",
        ] {
            assert_eq!(verdict(script), Some(Severity::High), "{script:?}");
        }
        for local in [
            &b"file:///etc/passwd"[..],
            b"\\\\host\\share\\file",
            b"smb://host/share",
            b"C:\\Windows\\system32\\calc.exe",
        ] {
            assert_eq!(verdict(local), Some(Severity::Medium), "{local:?}");
        }
    }

    #[test]
    fn calculator_programs() {
        assert!(is_calculator_program(b"{ 1 exch sub }"));
        assert!(is_calculator_program(
            b"{ dup 0.5 gt { pop 1 } { 2 mul } ifelse } % tint\n"
        ));
        assert!(CALCULATOR.is_sorted());
        for program in [
            &b"{ (%pipe%id) (r) file }"[..],
            b"{ /x 1 def }",
            b"{ currentfile }",
            b"1 add",
            b"{ 1 add",
            b"{ 1 add } }",
            b"{ [1 2] }",
        ] {
            assert!(!is_calculator_program(program), "{program:?}");
        }
    }

    #[test]
    fn ranges() {
        let ranges = [10..20, 30..40];
        for (position, expected) in [(9, false), (10, true), (19, true), (20, false), (35, true)] {
            assert_eq!(inside(&ranges, position), expected, "{position}");
        }
        assert!(!inside(&[], 5));

        let all: Vec<_> = gaps(&ranges, 50).collect();
        assert_eq!(all, [0..10, 20..30, 40..50]);
        assert_eq!(gaps(&ranges, 35).collect::<Vec<_>>(), [0..10, 20..30]);
        assert_eq!(gaps(&[Range { start: 0, end: 10 }], 10).count(), 0);
        assert_eq!(gaps(&[], 5).next(), Some(0..5));

        // A match may start in a gap and end in a stream, not the reverse.
        let data = b"..abcd....abcd......";
        let found = |streams: &[Range<usize>]| -> Vec<usize> {
            find_outside(data, streams, b"abcd").collect()
        };
        assert_eq!(found(&[]), [2, 10]);
        assert_eq!(found(&[Range { start: 4, end: 12 }]), [2]);
        assert_eq!(found(&[Range { start: 1, end: 9 }]), [10]);
    }
}
