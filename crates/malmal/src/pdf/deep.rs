//! Checks that take more than a keyword: what a string says, what the numbers
//! in a dictionary add up to, and where in the file an object or a signature
//! of another format stands. They run once every object is known, object
//! streams included, and once the document has been opened if it is
//! encrypted. An object that will read the same then as when it is walked
//! is looked at during that walk, while its value is at hand: see [`Early`].

use std::ops::Range;

use memchr::memmem;

use super::crypt::StreamKind;
use super::filters::DecodeError;
use super::parser::{Dict, Name, Value, is_regular, is_whitespace};
use super::{Document, Object, Output, content, postscript};
use crate::limits::{Budget, LimitExceeded};
use crate::report::{Finding, Severity};

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

pub(super) struct Pass<'p, 'a> {
    pub doc: &'p Document<'a>,
    /// Strings and streams are plaintext: the document is not encrypted, or
    /// it has been opened.
    pub readable: bool,
    pub max_pixels: u64,
}

/// What the objects looked at ahead of their turn hold, to be reported when
/// their turn comes: the findings in the order they were made, and the
/// object each came from.
#[derive(Default)]
pub(super) struct Early {
    findings: Vec<Finding>,
    objects: Vec<usize>,
}

impl Early {
    /// Look at the object at `index`, whose value is `value`, in a document
    /// that can be read.
    pub fn visit(&mut self, doc: &Document<'_>, index: usize, value: &Value, max_pixels: u64) {
        let pass = Pass {
            doc,
            readable: true,
            max_pixels,
        };
        let mut out = Output {
            findings: &mut self.findings,
            embedded: Vec::new(),
            contents: Vec::new(),
            xfa: Vec::new(),
            file_streams: Vec::new(),
            attachments: Vec::new(),
            attached: Vec::new(),
            foreign_attachment: false,
            links: Vec::new(),
            web_link: None,
            page_area: 0.0,
            twice: None,
            encrypt_sources: Vec::new(),
        };
        let object = &doc.objects[index];
        pass.visit(object, value, object.is_stream(), &mut out);
        self.objects.resize(self.findings.len(), index);
    }
}

/// Look at every object, or at its findings in `early` for the objects from
/// `seen_from` on, which have been looked at.
pub(super) fn inspect(
    pass: &Pass<'_, '_>,
    early: Early,
    seen_from: usize,
    budget: &mut Budget,
    out: &mut Output<'_>,
) {
    let doc = pass.doc;
    let readable = pass.readable;
    let mut early = early.objects.into_iter().zip(early.findings).peekable();
    let mut streams = Vec::new();
    for (count, object) in doc.objects.iter().enumerate() {
        if count % 256 == 0
            && let Err(limit) = budget.check_time()
        {
            return out.limit(limit);
        }
        let value = if count < seen_from {
            let value = doc.value(object);
            pass.visit(object, &value, object.is_stream(), out);
            value
        } else {
            while let Some((_, finding)) = early.next_if(|(index, _)| *index <= count) {
                out.add(finding);
            }
            if !object.is_stream() {
                continue;
            }
            doc.value(object)
        };
        let (Some(start), Some(dict)) = (object.stream_start(), value.as_dict()) else {
            continue;
        };
        streams.extend(
            doc.stream_data(object, dict)
                .map(|data| start..start + data.len()),
        );
        if readable && let Err(limit) = pass.stream(object, dict, budget, out) {
            return out.limit(limit);
        }
    }

    let streams = merged(streams);
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
        match (&self.doc.crypt, object.packed()) {
            (Some(crypt), false) => {
                crypt.decrypt(object.number, object.generation, StreamKind::Ordinary, raw)
            }
            _ => Some(raw.to_vec()),
        }
    }

    fn number(&self, dict: &Dict, key: &[u8]) -> Option<f64> {
        self.doc.resolve(dict.get(key)).as_number()
    }

    fn dict(&self, object: &Object, whole: &Dict, stream_dict: bool, out: &mut Output<'_>) {
        let doc = self.doc;
        let offset = object.offset;
        let dict = &Keys::of(whole);
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
                let Some(address) = self.string(object, target) else {
                    continue;
                };
                if let Some((severity, message)) = dangerous_address(&address) {
                    out.report("pdf.dangerous_uri", severity, message, offset);
                } else if let Some(message) = disguised_address(&address) {
                    out.report("pdf.disguised_link", Severity::Medium, message, offset);
                }
            }
        }
        for value in dict.all(b"DA") {
            if let Some(appearance) = self.string(object, value)
                && content::scan(&appearance).postscript
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
                (self.number(whole, b"Width"), self.number(whole, b"Height"))
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
            self.page_boxes(whole, offset, out);
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

        // What signatures sign is checked in the file, where their values
        // have to be: see `signatures`. One stored compressed has none there.
        let unchecked = if present(b"ByteRange") && object.packed() {
            Some("signature is stored compressed, where no range of the file can hold its value")
        } else if (is(b"Type", b"Sig") || is(b"Type", b"DocTimeStamp")) && !present(b"ByteRange") {
            Some(
                "signature has no byte range: a reader that checks only part of it shows it as valid",
            )
        } else {
            None
        };
        if let Some(message) = unchecked {
            out.report("pdf.signature_invalid", Severity::Medium, message, offset);
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

    /// Checks on what a stream holds.
    fn stream(
        &self,
        object: &Object,
        dict: &Dict,
        budget: &mut Budget,
        out: &mut Output<'_>,
    ) -> Result<(), LimitExceeded> {
        let doc = self.doc;
        let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
        let is_xml = is(b"Type", b"Metadata") || is(b"Subtype", b"XML");
        let is_calculator = self.number(dict, b"FunctionType") == Some(4.0);
        if !is_xml && !is_calculator {
            return Ok(());
        }
        let content = match doc.decode(object, dict, budget) {
            Ok(content) => content,
            Err(DecodeError::Limit) => return Err(budget.decode_limit()),
            // Nothing reads what cannot be decoded.
            Err(_) => return Ok(()),
        };
        if is_xml {
            xml(&content, object.offset, out);
        }
        if is_calculator {
            let domain: Vec<f64> = (doc.resolve(dict.get(b"Domain")).as_array())
                .unwrap_or_default()
                .iter()
                .filter_map(|bound| doc.resolve(Some(bound)).as_number())
                .collect();
            let failure = if overflows_stack(&content) {
                Some(Failure::Stack)
            } else {
                calculator_failure(&content, &domain)
            };
            match failure {
                Some(Failure::Stack) => out.malformed(
                    "calculator function asks for more values than its stack holds",
                    object.offset,
                ),
                Some(Failure::Infinite) => out.malformed(
                    "calculator function computes a number too large for any reader",
                    object.offset,
                ),
                None => {}
            }
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

/// A dictionary, and which of the keys that [`Pass::dict`] asks for it has.
/// Going through the entries for each key in turn is most of what a
/// document of many small objects costs; nearly every answer is no.
struct Keys<'d> {
    dict: &'d Dict,
    seen: u32,
}

impl<'d> Keys<'d> {
    /// One bit for each key asked for, and one for all the others.
    fn bit(key: &[u8]) -> u32 {
        let index = match key {
            b"F" => 0,
            b"FFilter" => 1,
            b"FDecodeParms" => 2,
            b"Subtype" => 3,
            b"Ref" => 4,
            b"FS" => 5,
            b"OPI" => 6,
            b"Type" => 7,
            b"S" => 8,
            b"URI" => 9,
            b"DA" => 10,
            b"Filter" => 11,
            b"DecodeParms" => 12,
            b"DP" => 13,
            b"Rect" => 14,
            b"Print" => 15,
            b"View" => 16,
            b"ByteRange" => 17,
            _ => 31,
        };
        1 << index
    }

    fn of(dict: &'d Dict) -> Self {
        let seen = dict
            .0
            .iter()
            .fold(0, |seen, (key, _)| seen | Self::bit(key.text()));
        Self { dict, seen }
    }

    fn get(&self, key: &[u8]) -> Option<&'d Value> {
        if self.seen & Self::bit(key) == 0 {
            return None;
        }
        self.dict.get(key)
    }

    fn all(&self, key: &'d [u8]) -> impl Iterator<Item = &'d Value> + use<'d> {
        let present = self.seen & Self::bit(key) != 0;
        present.then(|| self.dict.all(key)).into_iter().flatten()
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

/// What a file name ends with when opening the file runs it.
const PROGRAMS: [&[u8]; 24] = [
    b".app",
    b".bat",
    b".cmd",
    b".com",
    b".command",
    b".cpl",
    b".dll",
    b".exe",
    b".hta",
    b".jar",
    b".js",
    b".jse",
    b".lnk",
    b".msi",
    b".pif",
    b".ps1",
    b".reg",
    b".scr",
    b".sh",
    b".url",
    b".vbe",
    b".vbs",
    b".wsf",
    b".wsh",
];

/// A link's address the way a browser reads it: see [`dangerous_address`].
fn as_browsers_read(raw: &[u8]) -> Vec<u8> {
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
    text.into_iter()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'))
        .skip_while(|&byte| byte <= b' ')
        .map(|byte| byte.to_ascii_lowercase())
        .collect()
}

/// Services that send whoever follows a link on to an address the link
/// does not show.
const SHORTENERS: [&[u8]; 16] = [
    b"bit.ly",
    b"tinyurl.com",
    b"goo.gl",
    b"t.co",
    b"ow.ly",
    b"is.gd",
    b"cutt.ly",
    b"rb.gy",
    b"shorturl.at",
    b"tiny.cc",
    b"buff.ly",
    b"rebrand.ly",
    b"t.ly",
    b"v.gd",
    b"bl.ink",
    b"s.id",
];

/// Whether a web link hides where it leads, the way the links of
/// documents that are only a picture and a link to a phishing or spam site
/// do, and those of documents that mean no harm do not: through a URL
/// shortener, to a numeric address, to a host name spelled in another
/// script, or to a host or file whose name a program made up of syllables
/// (`dutitujazekap.weebly.com`, `fufenulefazagetefiv.pdf`).
fn disguised_address(raw: &[u8]) -> Option<&'static str> {
    let text = as_browsers_read(raw);
    let rest = (text.strip_prefix(b"https://")).or_else(|| text.strip_prefix(b"http://"))?;
    let end = rest
        .iter()
        .position(|&byte| matches!(byte, b'/' | b'?' | b'#'));
    let (authority, path) = rest.split_at(end.unwrap_or(rest.len()));
    let host = authority
        .rsplit(|&byte| byte == b'@')
        .next()
        .unwrap_or_default();
    let host = match host.iter().rposition(|&byte| byte == b':') {
        Some(at) if !host.starts_with(b"[") || host[..at].ends_with(b"]") => &host[..at],
        _ => host,
    };
    let host = host.strip_suffix(b".").unwrap_or(host);
    if SHORTENERS.contains(&host) {
        return Some("link goes through a URL shortener, which hides where it leads");
    }
    if host.starts_with(b"[")
        || !host.is_empty()
            && host
                .iter()
                .all(|&byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Some("link names a numeric address instead of a host");
    }
    if host
        .split(|&byte| byte == b'.')
        .any(|label| label.starts_with(b"xn--"))
    {
        return Some("link names a host spelled in another script, which can pass for a known one");
    }
    let path = &path[..path
        .iter()
        .position(|&byte| matches!(byte, b'?' | b'#'))
        .unwrap_or(path.len())];
    let file = path.rsplit(|&byte| byte == b'/').next().unwrap_or_default();
    let file = &file[..file
        .iter()
        .position(|&byte| byte == b'.')
        .unwrap_or(file.len())];
    (host.split(|&byte| byte == b'.').chain([file]))
        .any(made_up)
        .then_some("link names a host or file made up of syllables, as programs that make spam do")
}

/// Whether `name` is seven or more syllables of one consonant and one
/// vowel each, and an optional last consonant: what words of any language
/// that long rarely are.
fn made_up(name: &[u8]) -> bool {
    const SYLLABLES: usize = 7;
    let vowel = |byte: u8| matches!(byte, b'a' | b'e' | b'i' | b'o' | b'u');
    let consonant = |byte: u8| byte.is_ascii_lowercase() && !vowel(byte) && byte != b'y';
    let syllables = name.chunks(2);
    syllables.len() >= SYLLABLES
        && name.chunks(2).all(|syllable| match *syllable {
            [first, second] => consonant(first) && vowel(second),
            [last] => consonant(last),
            _ => false,
        })
}

/// Whether a link's address runs a script, reaches for a network share or
/// opens a program on the reader's own machine, read the way a browser
/// reads it: tabs and line breaks dropped, leading spaces and control
/// characters ignored, letters in either case, UTF-16 accepted.
///
/// A link to any other file on the reader's machine is what converting a
/// saved web page leaves behind (`file:///C|/book/index.html`), and is as
/// common in documents that mean no harm as in the others.
fn dangerous_address(raw: &[u8]) -> Option<(Severity, &'static str)> {
    let text = as_browsers_read(raw);

    let share = (
        Severity::Medium,
        "link opens a network share, which is sent the reader's Windows credentials",
    );
    let program = (
        Severity::Medium,
        "link opens a program or script on the reader's machine",
    );
    // Windows takes no notice of dots and spaces at the end of a name.
    let runs = |path: &[u8]| {
        let end = path.iter().position(|&byte| matches!(byte, b'?' | b'#'));
        let name = path[..end.unwrap_or(path.len())].trim_ascii_end();
        let name = name.strip_suffix(b".").unwrap_or(name).trim_ascii_end();
        PROGRAMS.iter().any(|ending| name.ends_with(ending))
    };
    if text.starts_with(b"\\\\") {
        return Some(share);
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
        b"smb" | b"cifs" => Some(share),
        b"file" => {
            // Two slashes are followed by a host, four or more by the host
            // of a share; a host that is a drive letter is none.
            let path = &text[length + 1..];
            let is_slash = |byte: &u8| matches!(byte, b'/' | b'\\');
            let slashes = path.iter().take_while(|byte| is_slash(byte)).count();
            let host = path[slashes..].split(is_slash).next().unwrap_or_default();
            let local = matches!(host, b"" | b"localhost" | [_, b':' | b'|']);
            if slashes >= 4 || (slashes == 2 && !local) {
                Some(share)
            } else {
                runs(path).then_some(program)
            }
        }
        // A drive letter.
        [letter] if letter.is_ascii_alphabetic() => runs(&text).then_some(program),
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

/// The stack of a calculator function holds 100 values.
const CALCULATOR_STACK: f64 = 100.0;

/// Whether a calculator function copies or reaches more values than its
/// stack holds: `n copy` doubles what a reader keeps for each one, and a
/// program of them takes all of its memory.
fn overflows_stack(program: &[u8]) -> bool {
    let mut tokens = program
        .split(|&byte| is_whitespace(byte) || byte == b'{' || byte == b'}')
        .filter(|token| !token.is_empty());
    let mut operand = None;
    tokens.any(|token| {
        let reaches = matches!(token, b"copy" | b"index")
            && operand.is_some_and(|count: f64| count > CALCULATOR_STACK);
        operand = std::str::from_utf8(token)
            .ok()
            .and_then(|text| text.parse().ok());
        reaches
    })
}

/// How running a calculator function fails, of the ways that a reader that
/// does not stop at them is made to spend its memory or time on.
#[derive(Debug, PartialEq)]
enum Failure {
    /// More values than the stack holds.
    Stack,
    /// A number past what floating point holds, from numbers that grow.
    Infinite,
}

/// One part of a calculator program.
enum Part<'p> {
    Number(f64),
    Operator(&'p [u8]),
    Procedure(Vec<Part<'p>>),
}

/// What a value on the calculator's stack may be.
#[derive(Clone, Copy)]
enum Item {
    Number(f64),
    Bool(bool),
}

/// Inputs tried for each function: the corners of its domain, for up to
/// this many inputs.
const MAX_CORNER_INPUTS: usize = 4;
/// Procedures nested deeper than this are not run: running one is a call
/// for each level.
const MAX_PROCEDURE_DEPTH: usize = 32;

/// How a calculator function fails when it is run on the corners of its
/// domain, `domain` being its `/Domain` as numbers. A program that cannot
/// be read, or that fails otherwise (a division by zero, a value of the
/// wrong kind), is left alone: readers stop at those, and documents made
/// carelessly have them.
fn calculator_failure(program: &[u8], domain: &[f64]) -> Option<Failure> {
    let parts = calculator_parts(program)?;
    let [Part::Procedure(body)] = parts.as_slice() else {
        return None;
    };
    let inputs = domain.len() / 2;
    if inputs == 0 || inputs > MAX_CORNER_INPUTS {
        return None;
    }
    (0..1u32 << inputs).find_map(|corner| {
        let mut stack: Vec<Item> = (0..inputs)
            .map(|input| Item::Number(domain[2 * input + usize::from(corner >> input & 1 == 1)]))
            .collect();
        run_calculator(body, &mut stack).err().flatten()
    })
}

/// The tokens of a calculator program, its procedures nested; `None` for
/// anything else.
fn calculator_parts(program: &[u8]) -> Option<Vec<Part<'_>>> {
    if program.len() > MAX_FUNCTION {
        return None;
    }
    let mut open: Vec<Vec<Part<'_>>> = vec![Vec::new()];
    let mut pos = 0;
    while let Some(&byte) = program.get(pos) {
        match byte {
            b'%' => pos += memchr::memchr2(b'\n', b'\r', &program[pos..]).unwrap_or(program.len()),
            b'{' => {
                if open.len() > MAX_PROCEDURE_DEPTH {
                    return None;
                }
                open.push(Vec::new());
                pos += 1;
            }
            b'}' => {
                let procedure = open.pop()?;
                open.last_mut()?.push(Part::Procedure(procedure));
                pos += 1;
            }
            _ if is_whitespace(byte) => pos += 1,
            _ => {
                let length = program[pos..]
                    .iter()
                    .take_while(|&&b| is_regular(b))
                    .count();
                if length == 0 {
                    return None;
                }
                let token = &program[pos..pos + length];
                let number = std::str::from_utf8(token)
                    .ok()
                    .and_then(|text| text.parse().ok());
                open.last_mut()?.push(match number {
                    Some(number) => Part::Number(number),
                    None => Part::Operator(token),
                });
                pos += length;
            }
        }
    }
    (open.len() == 1).then(|| open.pop()).flatten()
}

/// Run `body` on `stack`: `Err(Some(_))` for a failure of [`Failure`]'s,
/// `Err(None)` for any other. There are no loops, so it takes no more steps
/// than the program has parts.
fn run_calculator(body: &[Part<'_>], stack: &mut Vec<Item>) -> Result<(), Option<Failure>> {
    let limit = CALCULATOR_STACK as usize;
    let mut index = 0;
    while let Some(part) = body.get(index) {
        index += 1;
        let operator = match part {
            Part::Number(number) => {
                stack.push(Item::Number(*number));
                if stack.len() > limit {
                    return Err(Some(Failure::Stack));
                }
                continue;
            }
            // Procedures are the operands of `if` and `ifelse`.
            Part::Procedure(_) => continue,
            Part::Operator(operator) => *operator,
        };
        let number = |stack: &mut Vec<Item>| match stack.pop() {
            Some(Item::Number(number)) => Ok(number),
            _ => Err(None),
        };
        let boolean = |stack: &mut Vec<Item>| match stack.pop() {
            Some(Item::Bool(value)) => Ok(value),
            _ => Err(None),
        };
        // Numbers that grow, as nothing else does without a reader
        // stopping at it first.
        let grown = |value: f64| {
            if value.is_finite() {
                Ok(Item::Number(value))
            } else {
                Err(Some(Failure::Infinite))
            }
        };
        let result = match operator {
            b"add" | b"sub" | b"mul" | b"exp" => {
                let (b, a) = (number(stack)?, number(stack)?);
                grown(match operator {
                    b"add" => a + b,
                    b"sub" => a - b,
                    b"mul" => a * b,
                    _ => a.powf(b),
                })?
            }
            b"div" | b"idiv" | b"mod" | b"atan" => {
                let (b, a) = (number(stack)?, number(stack)?);
                let value = match operator {
                    b"div" => a / b,
                    b"idiv" => (a / b).trunc(),
                    b"mod" => a % b,
                    _ => b.atan2(a).to_degrees().rem_euclid(360.0),
                };
                if !value.is_finite() {
                    return Err(None);
                }
                Item::Number(value)
            }
            b"abs" | b"neg" | b"ceiling" | b"floor" | b"round" | b"truncate" | b"cvi" | b"cvr"
            | b"sqrt" | b"sin" | b"cos" | b"ln" | b"log" => {
                let a = number(stack)?;
                let value = match operator {
                    b"abs" => a.abs(),
                    b"neg" => -a,
                    b"ceiling" => a.ceil(),
                    b"floor" => a.floor(),
                    b"round" => (a + 0.5).floor(),
                    b"truncate" | b"cvi" => a.trunc(),
                    b"sqrt" => a.sqrt(),
                    b"sin" => a.to_radians().sin(),
                    b"cos" => a.to_radians().cos(),
                    b"ln" => a.ln(),
                    b"log" => a.log10(),
                    _ => a,
                };
                if !value.is_finite() {
                    return Err(None);
                }
                Item::Number(value)
            }
            b"eq" | b"ne" | b"gt" | b"ge" | b"lt" | b"le" => {
                let (b, a) = (number(stack)?, number(stack)?);
                Item::Bool(match operator {
                    b"eq" => a == b,
                    b"ne" => a != b,
                    b"gt" => a > b,
                    b"ge" => a >= b,
                    b"lt" => a < b,
                    _ => a <= b,
                })
            }
            b"and" | b"or" | b"xor" => match (stack.pop(), stack.pop()) {
                (Some(Item::Bool(b)), Some(Item::Bool(a))) => Item::Bool(match operator {
                    b"and" => a && b,
                    b"or" => a || b,
                    _ => a ^ b,
                }),
                (Some(Item::Number(b)), Some(Item::Number(a))) => {
                    let (a, b) = (a as i64, b as i64);
                    Item::Number(match operator {
                        b"and" => a & b,
                        b"or" => a | b,
                        _ => a ^ b,
                    } as f64)
                }
                _ => return Err(None),
            },
            b"not" => match stack.pop() {
                Some(Item::Bool(value)) => Item::Bool(!value),
                Some(Item::Number(value)) => Item::Number(!(value as i64) as f64),
                None => return Err(None),
            },
            b"bitshift" => {
                let (shift, a) = (number(stack)?, number(stack)? as i64);
                let shift = shift as i64;
                Item::Number(match shift {
                    0..=63 => a.wrapping_shl(shift as u32),
                    -63..=-1 => a >> -shift,
                    _ => 0,
                } as f64)
            }
            b"true" => Item::Bool(true),
            b"false" => Item::Bool(false),
            b"pop" => {
                stack.pop().ok_or(None)?;
                continue;
            }
            b"dup" => *stack.last().ok_or(None)?,
            b"exch" => {
                let length = stack.len();
                if length < 2 {
                    return Err(None);
                }
                stack.swap(length - 1, length - 2);
                continue;
            }
            b"copy" | b"index" => {
                let count = number(stack)?;
                if count < 0.0 || count.fract() != 0.0 {
                    return Err(None);
                }
                let count = count as usize;
                if count >= stack.len() + usize::from(operator == b"copy") {
                    return Err(None);
                }
                if operator == b"index" {
                    stack[stack.len() - 1 - count]
                } else {
                    if stack.len() + count > limit {
                        return Err(Some(Failure::Stack));
                    }
                    stack.extend_from_within(stack.len() - count..);
                    continue;
                }
            }
            b"roll" => {
                let (shift, count) = (number(stack)?, number(stack)?);
                if count < 0.0 || count as usize > stack.len() || shift.fract() != 0.0 {
                    return Err(None);
                }
                let count = count as usize;
                if count > 0 {
                    let start = stack.len() - count;
                    let shift = (shift as i64).rem_euclid(count as i64) as usize;
                    stack[start..].rotate_right(shift);
                }
                continue;
            }
            b"if" | b"ifelse" => {
                // The procedures are the parts before the operator.
                let procedures = if operator == b"if" { 1 } else { 2 };
                let before = index.checked_sub(1 + procedures).ok_or(None)?;
                let chosen = if boolean(stack)? {
                    before
                } else if procedures == 2 {
                    before + 1
                } else {
                    continue;
                };
                let Some(Part::Procedure(procedure)) = body.get(chosen) else {
                    return Err(None);
                };
                run_calculator(procedure, stack)?;
                continue;
            }
            _ => return Err(None),
        };
        stack.push(result);
        if stack.len() > limit {
            return Err(Some(Failure::Stack));
        }
    }
    Ok(())
}

/// Where the data of each stream lies, in file order and without overlaps.
/// What stands there is the stream's, whatever it looks like.
fn merged(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
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
        .filter(|object| !object.packed() && !inside(streams, object.offset))
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
        let differ = || {
            let (one, other) = (doc.value(first), doc.value(second));
            let data = |object: &Object, value: &Value| {
                let dict = value.as_dict()?;
                doc.stream_data(object, dict)
            };
            one != other || data(first, &one) != data(second, &other)
        };
        if same_revision && differ() {
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
    fn disguised_addresses() {
        for plain in [
            &b"https://www.irs.gov/forms/f1040.pdf"[..],
            b"http://Notice.comments@irscounsel.treas.gov/",
            b"http://lavozarizona.com/",
            b"https://example.com:8443/report?id=1",
            b"mailto:someone@example.com",
            b"https://bit.ly.example.com/",
        ] {
            assert_eq!(
                disguised_address(plain),
                None,
                "{}",
                String::from_utf8_lossy(plain)
            );
        }
        for disguised in [
            &b"http://bit.ly/2ggC9L5"[..],
            b" HTTPS://TinyURL.com/abc",
            b"http://192.168.10.4/login",
            b"http://[::1]:80/",
            b"https://xn--pple-43d.com/",
            b"https://dutitujazekap.weebly.com/uploads/1/a.pdf",
            b"https://cdn.example.com/files/fufenulefazagetefiv.pdf",
            b"\xFE\xFF\0h\0t\0t\0p\0:\0/\0/\0g\0o\0o\0.\0g\0l\0/\0x",
        ] {
            assert!(
                disguised_address(disguised).is_some(),
                "{}",
                String::from_utf8_lossy(disguised)
            );
        }
    }

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
            // Files on the reader's own machine that do not run.
            b"file:///etc/passwd",
            b"file:///C|/book/index.html",
            b"file://localhost/home/reader/notes.txt",
            b"file://C:/app/scripts/exit.jsp%3fdest=http:/example.com/",
            b"C:\\Users\\reader\\report.docx",
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
            &b"\\\\host\\share\\file"[..],
            b"smb://host/share",
            b"file://host/share/file.txt",
            b"file:////host/share/file.txt",
            b"FILE:\\\\\\\\host\\share",
            b"C:\\Windows\\system32\\calc.exe",
            b"file:///C:/Windows/System32/calc.exe . ",
            b"file:///C|/tools/run.BAT?x=1",
            b"file:/tmp/x.sh",
        ] {
            assert_eq!(verdict(local), Some(Severity::Medium), "{local:?}");
        }
    }

    #[test]
    fn calculator_functions_are_run_on_their_domain() {
        let run = |program: &[u8]| calculator_failure(program, &[0.0, 1.0]);
        // Ordinary ones: a tint transform, a choice, one that divides by
        // its input at zero.
        assert_eq!(run(b"{ dup 0.5 mul exch 1 exch sub }"), None);
        assert_eq!(run(b"{ dup 0.5 gt { 1 } { 0 } ifelse 3 1 roll }"), None);
        assert_eq!(run(b"{ 1 exch div }"), None);
        assert_eq!(run(b"{ 2 2 exp cvi 2 exp 2 exp }"), None);
        // Squares of squares, and copies of copies.
        let squares = b"{ 2 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi 2 exp cvi }";
        assert_eq!(run(squares), Some(Failure::Infinite));
        assert_eq!(
            run(b"{ 1 copy 2 copy 4 copy 8 copy 16 copy 32 copy 64 copy }"),
            Some(Failure::Stack)
        );
        assert_eq!(
            run(b"{ true { 1e300 1e300 mul } if }"),
            Some(Failure::Infinite)
        );
        assert_eq!(run(b"{ false { 1e300 1e300 mul } if }"), None);
        // Not run: no procedure, nested too deep, inputs not given.
        assert_eq!(run(b"1e300 1e300 mul"), None);
        let deep = [
            b"{".repeat(40),
            b"1e300 1e300 mul".to_vec(),
            b"}".repeat(40),
        ]
        .concat();
        assert_eq!(run(&deep), None);
        assert_eq!(calculator_failure(squares, &[]), None);
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
        assert!(!overflows_stack(b"{ 2 copy 99 index }"));
        assert!(overflows_stack(
            b"{ 2 copy 4 copy 8 copy 16 copy 32 copy 64 copy 128 copy }"
        ));
        assert!(overflows_stack(b"{1000 index}"));
        assert!(!overflows_stack(b"{ 1000 2 copy }"));
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
