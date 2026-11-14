//! PDF analysis. The cross-reference table is deliberately ignored: it is the
//! first thing a malicious file lies about. Instead every `N G obj` in the
//! file is parsed where it stands, object streams are unpacked, and every
//! dictionary found either way is inspected for active content.
//!
//! What is kept of an object is where it stands. Its value is parsed again
//! for each check that looks at it, and dropped; only the values that
//! references lead to stay in memory.

mod content;
pub(crate) mod crypt;
mod deep;
pub(crate) mod filters;
pub(crate) mod parser;

use std::borrow::Cow;
use std::cell::{Cell, OnceCell};
use std::collections::HashMap;

use memchr::memmem;

use crate::detect::{self, FileType};
use crate::limits::{Budget, LimitExceeded};
use crate::report::{Finding, Severity};
use content::{Drawn, Operators};
use crypt::{Decryptor, StreamKind};
use filters::{DecodeError, Params, Step};
use parser::{Dict, Name, Parser, Value, is_regular, is_whitespace};

/// Callback that scans a file extracted from the PDF.
pub(crate) type NestedScan<'a> = dyn FnMut(&[u8], &mut Budget, &mut Vec<Finding>) + 'a;

/// Objects and parsed values kept in memory for one document: this many for
/// any file, and one for every `BYTES_PER_NODE` bytes of a larger one. An
/// object counts as one whatever it holds, and so does every value of an
/// object that a reference leads to, which is kept once parsed. Either
/// costs some forty bytes, so what is kept is bounded by a few times the
/// size of the file: a file made of nothing but object headers, or of
/// references to one large object after another, stops here instead of
/// filling memory. Documents of hundreds of thousands of objects are real,
/// and far below it: an object and its `obj` and `endobj` take twenty bytes
/// with nothing in it.
const MIN_NODES: usize = 2_000_000;
const MAX_NODES: usize = 32_000_000;
const BYTES_PER_NODE: usize = 16;
const MAX_FILTERS: usize = 8;
/// How many times the size of the file may be decoded as stream data. The
/// streams of a document do not overlap, and each is decoded for the few
/// checks that concern it. In a file made of thousands of streams that all
/// run to one `endstream` at its end, each of them is most of the file.
const STREAM_WORK: u64 = 8;
/// How far past an unparsable object's start to look for names.
const FALLBACK_WINDOW: usize = 64 << 10;
/// Dictionaries naming `/Encrypt` that are tried as the source of the key.
const MAX_ENCRYPT_SOURCES: usize = 8;
/// Passwords tried on one document, the empty one included.
const MAX_PASSWORDS: usize = 33;

/// Names whose `#xx`-escaped spelling is reported as obfuscation.
const SENSITIVE_NAMES: &[&[u8]] = &[
    b"JS",
    b"JavaScript",
    b"OpenAction",
    b"AA",
    b"Launch",
    b"EmbeddedFile",
    b"EmbeddedFiles",
    b"EF",
    b"RichMedia",
    b"XFA",
    b"Encrypt",
    b"ObjStm",
    b"SubmitForm",
    b"ImportData",
    b"GoToR",
    b"GoToE",
    b"URI",
    b"S",
    b"Type",
    b"Subtype",
    b"Filter",
    b"Length",
    b"Names",
    b"AcroForm",
    b"FlateDecode",
    b"ASCIIHexDecode",
    b"ASCII85Decode",
    b"LZWDecode",
    b"RunLengthDecode",
];

static NULL: Value = Value::Null;

/// What the dictionary of an object says it is, in so many words or through
/// a reference that may lead to them: the objects to parse again for a check
/// that concerns few of them.
const OBJECT_STREAM: u8 = 1;
const EMBEDDED: u8 = 1 << 1;
const DRAWS: u8 = 1 << 2;

struct Object {
    number: u32,
    generation: u16,
    /// `OBJECT_STREAM` and the others, known once the object has been
    /// walked.
    hints: Cell<u8>,
    /// The unpacked object stream the object was stored in, counted from
    /// one, or zero for the file itself.
    source: u32,
    /// Where the object (or the object stream holding it) starts in the file.
    offset: usize,
    /// Where its value starts in its source.
    body: usize,
    /// First byte of stream data, for stream objects; zero for the others.
    stream_start: usize,
    /// The value, once a reference has led to it.
    kept: OnceCell<Box<Value>>,
}

impl Object {
    /// The object was stored in an object stream.
    fn packed(&self) -> bool {
        self.source != 0
    }

    fn is_stream(&self) -> bool {
        self.stream_start != 0
    }

    fn stream_start(&self) -> Option<usize> {
        self.is_stream().then_some(self.stream_start)
    }
}

/// See [`OBJECT_STREAM`].
fn hints(value: &Value) -> u8 {
    let Some(dict) = value.as_dict() else {
        return 0;
    };
    let may_be = |key: &[u8], name: &[u8]| match dict.get(key) {
        Some(Value::Ref(_)) => true,
        Some(value) => value.as_name() == Some(name),
        None => false,
    };
    let mut hints = 0;
    if may_be(b"Type", b"ObjStm") {
        hints |= OBJECT_STREAM;
    }
    if may_be(b"Type", b"EmbeddedFile") || may_be(b"Subtype", b"PS") || may_be(b"Subtype2", b"PS") {
        hints |= EMBEDDED;
    }
    if may_be(b"Subtype", b"Form") || dict.get(b"PatternType").is_some() {
        hints |= DRAWS;
    }
    hints
}

struct Document<'a> {
    data: &'a [u8],
    objects: Vec<Object>,
    /// Latest definition of each object number, as incremental updates intend.
    by_number: HashMap<u32, u32>,
    /// The object streams, decoded: what the objects stored in them are
    /// parsed from.
    unpacked: Vec<Vec<u8>>,
    /// Set when the document is encrypted and the empty password opens it.
    crypt: Option<Decryptor>,
    /// Objects and kept values the document may still have.
    nodes_left: Cell<usize>,
    /// A reference led to a value that there was no room to keep, or a
    /// stream to data that there was no work left to read.
    exhausted: Cell<bool>,
    /// Bytes of stream data that may still be decoded. See [`STREAM_WORK`].
    stream_work: Cell<u64>,
    /// Where every `endstream` keyword stands, found once.
    stream_ends: OnceCell<Vec<usize>>,
}

impl<'a> Document<'a> {
    fn add(&mut self, object: Object) {
        self.by_number
            .insert(object.number, self.objects.len() as u32);
        self.objects.push(object);
    }

    fn source(&self, object: &Object) -> &[u8] {
        match object.source {
            0 => self.data,
            stream => &self.unpacked[stream as usize - 1],
        }
    }

    /// An object's value, parsed where it stands. An object is one that
    /// parsed when it was found, or one with nothing before its `endobj`.
    fn value(&self, object: &Object) -> Value {
        let mut parser = Parser::new(self.source(object), object.body, usize::MAX);
        parser.parse_value().unwrap_or(Value::Null)
    }

    /// The value of the object at `index`, parsed once and kept.
    fn kept(&self, index: u32) -> &Value {
        let object = &self.objects[index as usize];
        object.kept.get_or_init(|| {
            let mut parser = Parser::new(self.source(object), object.body, self.nodes_left.get());
            let value = parser.parse_value();
            if parser.nodes_left == 0 {
                self.exhausted.set(true);
            }
            self.nodes_left.set(parser.nodes_left);
            Box::new(value.unwrap_or(Value::Null))
        })
    }

    /// Follow indirect references; missing values and targets resolve to null.
    fn resolve<'v>(&'v self, value: Option<&'v Value>) -> &'v Value {
        let mut value = value.unwrap_or(&NULL);
        for _ in 0..16 {
            match value {
                Value::Ref(number) => match self.by_number.get(number) {
                    Some(&index) => value = self.kept(index),
                    None => return &NULL,
                },
                _ => return value,
            }
        }
        &NULL
    }

    fn name_is(&self, value: Option<&Value>, name: &[u8]) -> bool {
        self.resolve(value).as_name() == Some(name)
    }

    /// Raw bytes of a stream object: `/Length` when it checks out, otherwise
    /// everything up to the `endstream` keyword.
    fn stream_data(&self, object: &Object, dict: &Dict) -> Option<&'a [u8]> {
        let rest = self.data.get(object.stream_start()?..)?;
        if let Some(length) = self.resolve(dict.get(b"Length")).as_usize()
            && let Some(after) = rest.get(length..)
            && after.trim_ascii_start().starts_with(b"endstream")
        {
            return Some(&rest[..length]);
        }
        // The next of the keywords, which are found once for all streams:
        // looking for it from each stream is the square of a file in which
        // few streams end.
        let start = self.data.len() - rest.len();
        let ends = self
            .stream_ends
            .get_or_init(|| memmem::find_iter(self.data, b"endstream").collect());
        let end = ends.get(ends.partition_point(|&end| end < start));
        let body = &rest[..end.map_or(rest.len(), |end| end - start)];
        Some(
            body.strip_suffix(b"\r\n")
                .or_else(|| body.strip_suffix(b"\n"))
                .or_else(|| body.strip_suffix(b"\r"))
                .unwrap_or(body),
        )
    }

    /// Stream contents with the whole filter chain undone.
    fn decode(
        &self,
        object: &Object,
        dict: &Dict,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, DecodeError> {
        let mut content = Vec::new();
        let mut keep = |block: &[u8]| content.extend_from_slice(block);
        self.decode_into(object, dict, budget, &mut keep)?;
        Ok(content)
    }

    /// The same, a block at a time, for what need not be held whole. What
    /// `sink` is given is the stream's content only if this ends well.
    fn decode_into(
        &self,
        object: &Object,
        dict: &Dict,
        budget: &mut Budget,
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DecodeError> {
        let raw = self.stream_data(object, dict).ok_or(DecodeError::Corrupt)?;
        let Some(work) = self.stream_work.get().checked_sub(raw.len() as u64) else {
            self.exhausted.set(true);
            return Err(DecodeError::Corrupt);
        };
        self.stream_work.set(work);
        let filters: Vec<&[u8]> = match self.resolve(dict.get(b"Filter")) {
            Value::Null => Vec::new(),
            Value::Name(name) => vec![name.text()],
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    self.resolve(Some(item))
                        .as_name()
                        .ok_or(DecodeError::Corrupt)
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(DecodeError::Corrupt),
        };
        if filters.len() > MAX_FILTERS {
            return Err(DecodeError::Unsupported);
        }
        let parms = self.resolve(dict.get(b"DecodeParms"));

        let data = match &self.crypt {
            Some(crypt) => {
                let is = |key: &[u8], name: &[u8]| self.name_is(dict.get(key), name);
                let kind = if is(b"Type", b"XRef") {
                    StreamKind::CrossReference
                } else if is(b"Type", b"EmbeddedFile") {
                    StreamKind::EmbeddedFile
                } else if is(b"Type", b"Metadata") {
                    StreamKind::Metadata
                } else {
                    StreamKind::Ordinary
                };
                let plain = crypt.decrypt(object.number, object.generation, kind, raw);
                Cow::Owned(plain.ok_or(DecodeError::Corrupt)?)
            }
            None => Cow::Borrowed(raw),
        };
        let steps = filters.iter().enumerate().map(|(index, filter)| {
            let parm_dict = match parms {
                Value::Dict(dict) if index == 0 => Some(dict),
                Value::Array(items) => self.resolve(items.get(index)).as_dict(),
                _ => None,
            };
            Step {
                filter,
                params: self.params(parm_dict),
            }
        });
        let steps: Vec<Step<'_>> = steps.collect();
        let (used, outcome) = filters::run(&steps, &data, budget.remaining(), sink);
        budget.consume(used).map_err(|_| DecodeError::Limit)?;
        outcome
    }

    fn params(&self, dict: Option<&Dict>) -> Params {
        let defaults = Params::default();
        let Some(dict) = dict else {
            return defaults;
        };
        let get = |key: &[u8], default| self.resolve(dict.get(key)).as_usize().unwrap_or(default);
        Params {
            predictor: get(b"Predictor", defaults.predictor),
            columns: get(b"Columns", defaults.columns),
            colors: get(b"Colors", defaults.colors),
            bits_per_component: get(b"BitsPerComponent", defaults.bits_per_component),
            early_change: get(b"EarlyChange", 1) != 0,
        }
    }
}

struct Output<'a> {
    findings: &'a mut Vec<Finding>,
    /// Object numbers that file specifications name as embedded files.
    embedded: Vec<u32>,
    /// Object numbers that pages, fonts and patterns name as content streams.
    contents: Vec<u32>,
    /// Object numbers that an `/XFA` entry names as form packets.
    xfa: Vec<u32>,
    /// Where the objects stand whose type is that of an embedded file.
    file_streams: Vec<usize>,
    /// Where `/Encrypt` was seen: the trailer or object that names it.
    encrypt_sources: Vec<usize>,
}

impl Output<'_> {
    /// Record a finding once per code and severity.
    fn report(&mut self, code: &'static str, severity: Severity, message: &str, offset: usize) {
        let seen = |f: &Finding| f.code == code && f.severity == severity;
        if !self.findings.iter().any(seen) {
            self.findings
                .push(Finding::new(code, severity, message).at(offset));
        }
    }

    fn malformed(&mut self, message: &str, offset: usize) {
        self.report("pdf.malformed", Severity::Medium, message, offset);
    }

    fn limit(&mut self, limit: LimitExceeded) {
        if !self.findings.iter().any(|f| f.code == limit.code()) {
            self.findings.push(limit.finding());
        }
    }

    /// Record a finding made elsewhere, as [`Output::report`] would have.
    fn add(&mut self, finding: Finding) {
        let seen = |f: &Finding| f.code == finding.code && f.severity == finding.severity;
        if !self.findings.iter().any(seen) {
            self.findings.push(finding);
        }
    }

    fn encrypted(&mut self, offset: usize) {
        if !self.encrypt_sources.contains(&offset) {
            self.encrypt_sources.push(offset);
        }
    }
}

pub(crate) fn analyze(
    data: &[u8],
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    passwords: &[Vec<u8>],
    max_pixels: u64,
    nested: &mut NestedScan<'_>,
) {
    let mut out = Output {
        findings,
        embedded: Vec::new(),
        contents: Vec::new(),
        xfa: Vec::new(),
        file_streams: Vec::new(),
        encrypt_sources: Vec::new(),
    };
    let mut doc = Document {
        data,
        objects: Vec::new(),
        by_number: HashMap::new(),
        unpacked: Vec::new(),
        crypt: None,
        nodes_left: Cell::new((data.len() / BYTES_PER_NODE).clamp(MIN_NODES, MAX_NODES)),
        exhausted: Cell::new(false),
        stream_work: Cell::new(data.len() as u64 * STREAM_WORK + (1 << 20)),
        stream_ends: OnceCell::new(),
    };

    check_header(data, &mut out);
    discover_objects(&mut doc, budget, &mut out);

    for at in memmem::find_iter(data, b"trailer") {
        let mut parser = Parser::new(data, at + b"trailer".len(), doc.nodes_left.get());
        if let Some(trailer) = parser.parse_value() {
            walk(&doc, &trailer, at, &mut out);
        }
    }
    // An object is parsed for this walk, and would be again for the deeper
    // checks at the end. Those are made here instead, ahead of their turn
    // and with what they find set aside, while nothing says that they will
    // read differently then: no encryption, and no object stream that may
    // define an object anew.
    let mut early = deep::Early::default();
    let mut ahead = true;
    for (index, object) in doc.objects.iter().enumerate() {
        let value = walk_object(&doc, object, &mut out);
        ahead &= out.encrypt_sources.is_empty() && object.hints.get() & OBJECT_STREAM == 0;
        if ahead {
            early.visit(&doc, index, &value, max_pixels);
        }
    }

    // In an encrypted file, object streams and embedded files are ciphertext
    // unless the empty password opens it, as it does in any reader, or one
    // of the passwords the caller knows does.
    let encrypted = out.encrypt_sources.first().copied();
    if let Some(offset) = encrypted {
        let opened = std::iter::once(&[][..])
            .chain(passwords.iter().map(Vec::as_slice))
            .take(MAX_PASSWORDS)
            .find_map(|password| open_with(&doc, &out.encrypt_sources, password));
        let (severity, message) = match (&opened, passwords.is_empty()) {
            (Some((_, false)), _) => (
                Severity::Info,
                "document is encrypted with an empty password; it was decrypted and inspected",
            ),
            (Some((_, true)), _) => (
                Severity::Info,
                "document is encrypted; it was decrypted with a supplied password and inspected",
            ),
            (None, true) => (
                Severity::Medium,
                "document is encrypted; strings, streams and object streams cannot be inspected",
            ),
            (None, false) => (
                Severity::Medium,
                "document is encrypted and no supplied password opens it; \
                 strings, streams and object streams cannot be inspected",
            ),
        };
        out.report("pdf.encrypted", severity, message, offset);
        doc.crypt = opened.map(|(crypt, _)| crypt);
    }
    let readable = encrypted.is_none() || doc.crypt.is_some();
    let top_level = doc.objects.len();
    if readable {
        expand_object_streams(&mut doc, budget, &mut out);
    }
    // The objects that the deeper checks have seen by the time they run.
    let seen_from = if ahead && doc.objects.len() == top_level {
        0
    } else {
        early = deep::Early::default();
        top_level
    };
    if readable {
        // Nothing changes for the objects of object streams once they are
        // unpacked and the document is open.
        for (index, object) in doc.objects.iter().enumerate().skip(top_level) {
            let value = walk_object(&doc, object, &mut out);
            early.visit(&doc, index, &value, max_pixels);
        }
        report_file_streams(&doc, &mut out);
        scan_embedded_files(&doc, budget, &mut out, nested);
        scan_content_streams(&doc, budget, &mut out);
        scan_xfa(&doc, budget, &mut out);
    } else {
        report_file_streams(&doc, &mut out);
    }

    let pass = deep::Pass {
        doc: &doc,
        readable,
        max_pixels,
    };
    deep::inspect(&pass, early, seen_from, budget, &mut out);

    if doc.objects.is_empty() {
        out.malformed("PDF contains no objects", 0);
    }
    // What a reference led to was not looked at.
    if doc.exhausted.get() {
        out.limit(LimitExceeded::Complexity);
    }
    check_end(data, &mut out);
}

fn check_header(data: &[u8], out: &mut Output<'_>) {
    let head = &data[..data.len().min(1024)];
    let Some(at) = memmem::find(head, b"%PDF-") else {
        return out.malformed("PDF header not found", 0);
    };
    let before = head[..at]
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(&head[..at]);
    if !before.iter().all(|&b| is_whitespace(b)) {
        out.malformed("data before the PDF header", 0);
    }
}

fn check_end(data: &[u8], out: &mut Output<'_>) {
    let Some(first) = memmem::find(data, b"%%EOF") else {
        return out.malformed("PDF has no %%EOF marker", data.len());
    };
    // From the end: in a large file the last marker is the nearest thing.
    let last = memmem::rfind(data, b"%%EOF").filter(|&last| last != first);
    if last.is_some() {
        out.report(
            "pdf.incremental_update",
            Severity::Info,
            "several %%EOF markers: the file was updated incrementally or is linearized",
            first,
        );
    }

    // Readers stop at the last marker; whatever follows is carried along
    // unseen by them and by whoever looks at the document.
    let end = last.unwrap_or(first) + b"%%EOF".len();
    let trailing = &data[end..];
    let padding = trailing
        .iter()
        .take_while(|&&b| b == 0 || b.is_ascii_whitespace())
        .count();
    if padding == trailing.len() {
        return;
    }
    out.report(
        "pdf.trailing_data",
        Severity::Low,
        &format!("{} bytes after the last %%EOF marker", trailing.len()),
        end,
    );
    let appended = detect::detect(&trailing[padding..]);
    if appended != FileType::Unknown {
        out.report(
            "pdf.polyglot",
            Severity::High,
            &format!("data after the document is a {} file", appended.as_str()),
            end + padding,
        );
    } else if let Some(offset) = detect::zip_end_record(data) {
        out.report(
            "pdf.polyglot",
            Severity::High,
            "ZIP end-of-central-directory record closes the file; it also opens as an archive",
            offset,
        );
    }
}

/// Try each dictionary that names `/Encrypt` as the source of the key.
/// Returns the decryptor and whether `password` was a real one.
fn open_with(doc: &Document<'_>, sources: &[usize], password: &[u8]) -> Option<(Decryptor, bool)> {
    let data = doc.data;
    // The trailer or cross-reference stream dictionary follows its keyword.
    let dict_after = |offset: usize| {
        let window = data.get(offset..)?;
        let window = &window[..window.len().min(256)];
        Some(offset + memmem::find(window, b"<<")?)
    };
    sources
        .iter()
        .take(MAX_ENCRYPT_SOURCES)
        .find_map(|&source| {
            let entries = crypt::raw_entries(data, dict_after(source)?)?;
            let range = |key: &[u8]| {
                let found = entries.iter().find(|(name, _)| name == key);
                found.map(|(_, range)| range.clone())
            };
            let id = crypt::first_id(data, &range(b"ID")?)?;
            let encrypt = range(b"Encrypt")?;
            let mut parser = Parser::new(&data[..encrypt.end], encrypt.start, 64);
            let at = match parser.parse_value()? {
                Value::Dict(_) => encrypt.start,
                Value::Ref(number) => {
                    let object = &doc.objects[*doc.by_number.get(&number)? as usize];
                    dict_after(object.offset)?
                }
                _ => return None,
            };
            Decryptor::open(data, at, &id, password)
        })
        .map(|crypt| (crypt, !password.is_empty()))
}

/// Parse every `N G obj` in the file, wherever it is.
fn discover_objects(doc: &mut Document<'_>, budget: &Budget, out: &mut Output<'_>) {
    let data = doc.data;
    // Objects cannot legitimately overlap, so total parsing work is bounded
    // by a small multiple of the file size.
    let work_limit = data.len() as u64 * 8 + (1 << 20);
    let mut work = 0u64;
    for (count, at) in memmem::find_iter(data, b"obj").enumerate() {
        if count % 256 == 0
            && let Err(limit) = budget.check_time()
        {
            return out.limit(limit);
        }
        let body = at + b"obj".len();
        if data.get(body).is_some_and(|&b| is_regular(b)) {
            continue;
        }
        let Some((number, generation, offset)) = object_header(data, at) else {
            continue;
        };

        // The value is read to see that it is one and where it ends, and is
        // not kept: an object of more values than may be kept at all is
        // more than this goes through, and so are more objects.
        let nodes_left = doc.nodes_left.get();
        let mut parser = Parser::new(data, body, nodes_left);
        parser.skip_whitespace();
        let start = parser.pos;
        let is_value = parser.rest().starts_with(b"endobj") || parser.skip_value();
        work += (parser.pos - at) as u64;
        if work > work_limit || parser.nodes_left == 0 || nodes_left <= 1 {
            return out.limit(LimitExceeded::Complexity);
        }

        if !is_value {
            out.malformed("object could not be parsed", offset);
            fallback_names(&data[body..], offset, out);
            continue;
        }
        parser.skip_whitespace();
        let is_dict = data[start..].starts_with(b"<<");
        let is_stream = is_dict && parser.rest().starts_with(b"stream");
        let stream_start = is_stream.then(|| {
            let start = parser.pos + b"stream".len();
            match data.get(start..) {
                Some([b'\r', b'\n', ..]) => start + 2,
                Some([b'\r' | b'\n', ..]) => start + 1,
                _ => start,
            }
        });
        doc.nodes_left.set(nodes_left - 1);
        doc.add(Object {
            number,
            generation,
            hints: Cell::new(0),
            source: 0,
            offset,
            body: start,
            stream_start: stream_start.unwrap_or(0),
            kept: OnceCell::new(),
        });
    }
}

/// Read `N G` backwards from the `obj` keyword at `obj_at`; returns the
/// object number, the generation and where the header starts.
fn object_header(data: &[u8], obj_at: usize) -> Option<(u32, u16, usize)> {
    let field = |pos: &mut usize| -> Option<u64> {
        let after_space = *pos;
        while *pos > 0 && is_whitespace(data[*pos - 1]) {
            *pos -= 1;
        }
        if *pos == after_space {
            return None;
        }
        let end = *pos;
        while *pos > 0 && data[*pos - 1].is_ascii_digit() && end - *pos < 10 {
            *pos -= 1;
        }
        std::str::from_utf8(&data[*pos..end]).ok()?.parse().ok()
    };
    let mut pos = obj_at;
    let generation = field(&mut pos)?;
    let number = field(&mut pos)?;
    // The generation only matters as key material, where it is 16 bits wide.
    Some((u32::try_from(number).ok()?, generation as u16, pos))
}

/// Unpack `/Type /ObjStm` streams and add the objects stored inside them.
/// The decoded streams stay, for those objects to be parsed from.
fn expand_object_streams(doc: &mut Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    let mut streams = Vec::new();
    let mut unpacked = Vec::new();
    for object in &doc.objects {
        if !object.is_stream() || object.hints.get() & OBJECT_STREAM == 0 {
            continue;
        }
        let value = doc.value(object);
        let Some(dict) = value.as_dict() else {
            continue;
        };
        if !doc.name_is(dict.get(b"Type"), b"ObjStm") {
            continue;
        }
        if let Err(limit) = budget.check_time() {
            return out.limit(limit);
        }
        let offset = object.offset;
        let decoded = match doc.decode(object, dict, budget) {
            Ok(decoded) => decoded,
            Err(DecodeError::Limit) => {
                out.limit(LimitExceeded::Decompression);
                continue;
            }
            // Whatever is inside stays unseen, so the file cannot be cleared.
            Err(_) => {
                out.malformed("object stream cannot be decoded", offset);
                continue;
            }
        };
        let count = doc.resolve(dict.get(b"N")).as_usize();
        let first = doc.resolve(dict.get(b"First")).as_usize();
        let (Some(count), Some(first)) = (count, first) else {
            out.malformed("object stream has no index", offset);
            continue;
        };

        // The index is `count` pairs of object number and relative offset.
        let mut index = Parser::new(&decoded, 0, usize::MAX);
        let mut entries = Vec::new();
        for _ in 0..count.min(decoded.len()) {
            let (Some(number), Some(relative)) = (index.integer(), index.integer()) else {
                break;
            };
            entries.push((number, first.saturating_add(relative)));
        }
        for (number, start) in entries {
            let nodes_left = doc.nodes_left.get();
            let mut parser = Parser::new(&decoded, start, nodes_left);
            let is_value = parser.skip_value();
            if parser.nodes_left == 0 || nodes_left <= 1 {
                return out.limit(LimitExceeded::Complexity);
            }
            match (is_value, u32::try_from(number)) {
                (true, Ok(number)) => {
                    doc.nodes_left.set(nodes_left - 1);
                    unpacked.push(Object {
                        number,
                        generation: 0,
                        hints: Cell::new(0),
                        source: streams.len() as u32 + 1,
                        offset,
                        body: start,
                        stream_start: 0,
                        kept: OnceCell::new(),
                    });
                }
                _ => {
                    out.malformed("object inside an object stream could not be parsed", offset);
                    fallback_names(decoded.get(start..).unwrap_or(&[]), offset, out);
                }
            }
        }
        streams.push(decoded);
    }
    doc.unpacked = streams;
    for object in unpacked {
        doc.add(object);
    }
}

/// Parse an object and inspect what it holds.
fn walk_object(doc: &Document<'_>, object: &Object, out: &mut Output<'_>) -> Value {
    let value = doc.value(object);
    object.hints.set(hints(&value));
    walk(doc, &value, object.offset, out);
    value
}

/// Inspect every dictionary reachable inside one object.
fn walk(doc: &Document<'_>, value: &Value, offset: usize, out: &mut Output<'_>) {
    match value {
        Value::Dict(dict) => {
            check_postscript(doc, dict, offset, out);
            for (key, item) in &dict.0 {
                check_name(key, offset, out);
                check_entry(doc, key, item, offset, out);
                walk(doc, item, offset, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(doc, item, offset, out);
            }
        }
        Value::Name(name) => check_name(name, offset, out),
        _ => {}
    }
}

fn check_name(name: &Name, offset: usize, out: &mut Output<'_>) {
    if name.obfuscated() && SENSITIVE_NAMES.contains(&name.text()) {
        out.report(
            "pdf.obfuscated_name",
            Severity::High,
            "keyword disguised with hex escapes",
            offset,
        );
    }
}

fn check_entry(doc: &Document<'_>, key: &Name, value: &Value, offset: usize, out: &mut Output<'_>) {
    match key.text() {
        b"JS" => javascript(offset, out),
        // The name tree of the document's scripts. Writers put one in the
        // catalog whether or not there is a script to list.
        b"JavaScript" if !is_empty_tree(doc, value) => javascript(offset, out),
        b"OpenAction" => match classify_action(doc, value) {
            Action::Harmless => {}
            Action::Other => out.report(
                "pdf.open_action",
                Severity::Medium,
                "performs an action when opened",
                offset,
            ),
            Action::Code => out.report(
                "pdf.open_action",
                Severity::High,
                "runs a script or program when opened",
                offset,
            ),
        },
        b"AA" => {
            let worst = match doc.resolve(Some(value)) {
                Value::Dict(actions) => actions
                    .0
                    .iter()
                    .map(|(_, action)| classify_action(doc, action))
                    .max()
                    .unwrap_or(Action::Harmless),
                _ => Action::Other,
            };
            match worst {
                Action::Harmless => {}
                Action::Other => out.report(
                    "pdf.additional_action",
                    Severity::Medium,
                    "performs an action on a document or page event",
                    offset,
                ),
                Action::Code => out.report(
                    "pdf.additional_action",
                    Severity::High,
                    "runs a script or program on a document or page event",
                    offset,
                ),
            }
        }
        b"EF" => match doc.resolve(Some(value)) {
            // Not a file specification's: the rights that a signature
            // grants over attachments are an array under the same key.
            Value::Array(_) => {}
            files => {
                embedded_file(offset, out);
                if let Value::Dict(files) = files {
                    out.embedded
                        .extend(files.0.iter().filter_map(|(_, file)| as_ref(file)));
                }
            }
        },
        b"EmbeddedFiles" if !is_empty_tree(doc, value) => embedded_file(offset, out),
        // A page's content, or the glyph procedures of a Type 3 font. An
        // annotation's /Contents is a string and names nothing.
        b"Contents" => match (value, doc.resolve(Some(value))) {
            (_, Value::Array(items)) => out.contents.extend(items.iter().filter_map(as_ref)),
            (Value::Ref(number), _) => out.contents.push(*number),
            _ => {}
        },
        b"CharProcs" => {
            if let Value::Dict(procedures) = doc.resolve(Some(value)) {
                let streams = procedures.0.iter().filter_map(|(_, item)| as_ref(item));
                out.contents.extend(streams);
            }
        }
        b"XFA" => {
            xfa(offset, out);
            // One stream, or an array pairing packet names with streams.
            match (value, doc.resolve(Some(value))) {
                (_, Value::Array(items)) => out.xfa.extend(items.iter().filter_map(as_ref)),
                (Value::Ref(number), _) => out.xfa.push(*number),
                _ => {}
            }
        }
        b"Encrypt" => out.encrypted(offset),
        b"URI" => uri(offset, out),
        b"S" => match doc.resolve(Some(value)).as_name() {
            Some(b"JavaScript") => javascript(offset, out),
            Some(b"Launch") => launch(offset, out),
            Some(b"SubmitForm" | b"ImportData") => out.report(
                "pdf.submit_form",
                Severity::Low,
                "form action exchanges data with a remote server",
                offset,
            ),
            Some(b"GoToR" | b"GoToE") => out.report(
                "pdf.remote_goto",
                Severity::Low,
                "action opens another document",
                offset,
            ),
            Some(b"URI") => uri(offset, out),
            _ => {}
        },
        // Whether it is one is known once every object has been walked.
        b"Type" if doc.name_is(Some(value), b"EmbeddedFile") => {
            if out.file_streams.last() != Some(&offset) {
                out.file_streams.push(offset);
            }
        }
        b"Subtype" => {
            if let Some(b"RichMedia" | b"3D" | b"Movie" | b"Sound" | b"Screen" | b"U3D" | b"PRC") =
                doc.resolve(Some(value)).as_name()
            {
                rich_media(offset, out);
            }
        }
        _ => {}
    }
}

/// Whether a name tree is known to list nothing: a dictionary without names
/// and without children, or with empty arrays of them. One that cannot be
/// read is not known to.
fn is_empty_tree(doc: &Document<'_>, value: &Value) -> bool {
    let Value::Dict(tree) = doc.resolve(Some(value)) else {
        return false;
    };
    [&b"Names"[..], b"Kids"].into_iter().all(|key| {
        tree.all(key).all(
            |entry| matches!(doc.resolve(Some(entry)), Value::Array(items) if items.is_empty()),
        )
    })
}

fn as_ref(value: &Value) -> Option<u32> {
    match value {
        Value::Ref(number) => Some(*number),
        _ => None,
    }
}

/// PostScript XObjects are passed to the interpreter of a PostScript
/// printer or converter as they are. They come as `/Subtype /PS`, or as a
/// form XObject marked with `/Subtype2 /PS` or carrying a `/PS` stream.
fn check_postscript(doc: &Document<'_>, dict: &Dict, offset: usize, out: &mut Output<'_>) {
    let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
    let form_with_alternative =
        dict.get(b"PS").is_some() && (is(b"Subtype", b"Form") || is(b"Type", b"XObject"));
    if is(b"Subtype", b"PS") || is(b"Subtype2", b"PS") || form_with_alternative {
        // The stream is scanned with the embedded files.
        out.embedded.extend(dict.get(b"PS").and_then(as_ref));
        postscript("embeds a PostScript XObject", offset, out);
    }
}

fn postscript(message: &str, offset: usize, out: &mut Output<'_>) {
    out.report("pdf.postscript", Severity::High, message, offset);
}

fn javascript(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.javascript",
        Severity::High,
        "document contains JavaScript",
        offset,
    );
}

fn launch(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.launch",
        Severity::High,
        "action launches an external program or file",
        offset,
    );
}

fn embedded_file(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.embedded_file",
        Severity::Medium,
        "document carries embedded files",
        offset,
    );
}

/// A stream of the type of an embedded file is an attachment, unless it is
/// a packet of an XFA form: the programs that write those forms give their
/// packets that type. The form is reported as one, and its packets are
/// searched as packets and as files.
fn report_file_streams(doc: &Document<'_>, out: &mut Output<'_>) {
    let packets: Vec<usize> = out
        .xfa
        .iter()
        .filter_map(|number| doc.by_number.get(number))
        .map(|&index| doc.objects[index as usize].offset)
        .collect();
    for offset in std::mem::take(&mut out.file_streams) {
        if !packets.contains(&offset) {
            embedded_file(offset, out);
        }
    }
}

fn rich_media(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.rich_media",
        Severity::Medium,
        "document embeds Flash, video or 3D content",
        offset,
    );
}

fn xfa(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.xfa",
        Severity::Medium,
        "document contains an XFA form",
        offset,
    );
}

fn uri(offset: usize, out: &mut Output<'_>) {
    out.report(
        "pdf.uri",
        Severity::Info,
        "document links to external URIs",
        offset,
    );
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    /// A destination or a jump within the document.
    Harmless,
    Other,
    /// JavaScript or a program launch.
    Code,
}

fn classify_action(doc: &Document<'_>, value: &Value) -> Action {
    match doc.resolve(Some(value)) {
        // Explicit and named destinations.
        Value::Array(_) | Value::Name(_) | Value::String(_) => Action::Harmless,
        Value::Dict(action) => match doc.resolve(action.get(b"S")).as_name() {
            Some(b"JavaScript" | b"Launch") => Action::Code,
            Some(b"GoTo") => Action::Harmless,
            None if action.get(b"D").is_some() => Action::Harmless,
            _ => Action::Other,
        },
        // Unresolvable: it may live in a stream that could not be read.
        _ => Action::Other,
    }
}

/// For an object the parser rejected: readers are more forgiving than this
/// parser, so every name token in the object is still checked by itself.
fn fallback_names(region: &[u8], offset: usize, out: &mut Output<'_>) {
    let end = [b"endobj".as_slice(), b"stream"]
        .iter()
        .filter_map(|keyword| memmem::find(region, keyword))
        .min()
        .unwrap_or(region.len())
        .min(FALLBACK_WINDOW);
    let mut parser = Parser::new(&region[..end], 0, usize::MAX);
    while let Some(slash) = memchr::memchr(b'/', parser.rest()) {
        parser.pos += slash;
        let Some(name) = parser.name() else {
            break;
        };
        check_name(&name, offset, out);
        match name.text() {
            b"JS" | b"JavaScript" => javascript(offset, out),
            b"Launch" => launch(offset, out),
            b"OpenAction" => out.report(
                "pdf.open_action",
                Severity::Medium,
                "performs an action when opened",
                offset,
            ),
            b"AA" => out.report(
                "pdf.additional_action",
                Severity::Medium,
                "performs an action on a document or page event",
                offset,
            ),
            b"EmbeddedFile" | b"EmbeddedFiles" | b"EF" => embedded_file(offset, out),
            b"RichMedia" => rich_media(offset, out),
            b"XFA" => xfa(offset, out),
            b"Encrypt" => out.encrypted(offset),
            b"Subtype2" => postscript("embeds a PostScript XObject", offset, out),
            _ => {}
        }
    }
}

/// Decode each embedded file and hand it back to the scanner.
fn scan_embedded_files(
    doc: &Document<'_>,
    budget: &mut Budget,
    out: &mut Output<'_>,
    nested: &mut NestedScan<'_>,
) {
    let typed = doc
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object.is_stream() && object.hints.get() & EMBEDDED != 0)
        .filter_map(|(index, object)| {
            let value = doc.value(object);
            let dict = value.as_dict()?;
            let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
            (is(b"Type", b"EmbeddedFile") || is(b"Subtype", b"PS") || is(b"Subtype2", b"PS"))
                .then_some(index)
        });
    let referenced = out
        .embedded
        .iter()
        .filter_map(|number| doc.by_number.get(number).map(|&index| index as usize));
    let mut targets: Vec<usize> = typed.chain(referenced).collect();
    targets.sort_unstable();
    targets.dedup();

    for index in targets {
        if let Err(limit) = budget.check_time() {
            return out.limit(limit);
        }
        let object = &doc.objects[index];
        let value = doc.value(object);
        let Some(dict) = value.as_dict().filter(|_| object.is_stream()) else {
            continue;
        };
        if let Err(limit) = budget.enter() {
            return out.limit(limit);
        }
        match doc.decode(object, dict, budget) {
            Ok(content) => {
                let mut inner = Vec::new();
                nested(&content, budget, &mut inner);
                for finding in inner {
                    if finding.code.starts_with("limit.") {
                        out.findings.push(finding);
                    } else {
                        let message = format!("embedded file: {}", finding.message);
                        out.report(finding.code, finding.severity, &message, object.offset);
                    }
                }
            }
            Err(DecodeError::Limit) => out.limit(LimitExceeded::Decompression),
            Err(_) => out.malformed("embedded file cannot be decoded", object.offset),
        }
        budget.leave();
    }
}

/// Search page content, form XObjects, patterns and glyph procedures for the
/// `PS` operator, which hands its string operand to a PostScript interpreter.
/// The streams are read a block at a time as they are decoded.
fn scan_content_streams(doc: &Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    let named = out
        .contents
        .iter()
        .filter_map(|number| doc.by_number.get(number).map(|&index| index as usize));
    let typed = doc
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object.is_stream() && object.hints.get() & DRAWS != 0)
        .filter_map(|(index, object)| {
            let value = doc.value(object);
            let dict = value.as_dict()?;
            (doc.name_is(dict.get(b"Subtype"), b"Form") || dict.get(b"PatternType").is_some())
                .then_some(index)
        });
    let mut targets: Vec<usize> = named.chain(typed).collect();
    targets.sort_unstable();
    targets.dedup();

    // What each form draws by name, for the forms that draw anything.
    let mut draws: HashMap<usize, Vec<Drawn>> = HashMap::new();
    for index in targets {
        if let Err(limit) = budget.check_time() {
            return out.limit(limit);
        }
        let object = &doc.objects[index];
        let value = doc.value(object);
        let Some(dict) = value.as_dict().filter(|_| object.is_stream()) else {
            continue;
        };
        let mut operators = Operators::new();
        let mut read = |block: &[u8]| operators.feed(block);
        match doc.decode_into(object, dict, budget, &mut read) {
            Ok(()) => {
                let found = operators.finish();
                if found.postscript {
                    return postscript(
                        "content stream uses the PostScript operator",
                        object.offset,
                        out,
                    );
                }
                if !found.drawn.is_empty() {
                    draws.insert(index, found.drawn);
                }
            }
            Err(DecodeError::Limit) => return out.limit(LimitExceeded::Decompression),
            // A stream no reader can decode draws nothing.
            Err(_) => {}
        }
    }
    draw_recursion(doc, &draws, out);
}

/// A form that draws itself, directly or through other forms. A renderer
/// follows the calls until it runs out of stack or of time.
fn draw_recursion(doc: &Document<'_>, draws: &HashMap<usize, Vec<Drawn>>, out: &mut Output<'_>) {
    // The forms that `table` lists under the names that `form` draws.
    let called = |form: usize, table: &Dict, targets: &mut Vec<usize>| {
        for name in &draws[&form] {
            let listed = table.0.iter().filter(|(key, _)| name.is(key.text()));
            targets.extend(
                listed
                    .filter_map(|(_, item)| as_ref(item))
                    .filter_map(|number| doc.by_number.get(&number).map(|&index| index as usize))
                    .filter(|target| draws.contains_key(target)),
            );
        }
    };
    let mut calls: HashMap<usize, Vec<usize>> = HashMap::new();
    // Forms without resources of their own draw with those of whatever
    // draws them: any dictionary of XObjects in the document may apply.
    let mut borrowing = Vec::new();
    for &index in draws.keys() {
        let value = doc.value(&doc.objects[index]);
        let Some(dict) = value.as_dict() else {
            continue;
        };
        let own = doc
            .resolve(dict.get(b"Resources"))
            .as_dict()
            .and_then(|resources| doc.resolve(resources.get(b"XObject")).as_dict());
        let targets = calls.entry(index).or_default();
        match own {
            Some(table) => called(index, table, targets),
            None => borrowing.push(index),
        }
    }
    if !borrowing.is_empty() {
        for object in &doc.objects {
            let value = doc.value(object);
            let mut tables = Vec::new();
            xobject_tables(doc, &value, &mut tables);
            for table in tables {
                for &index in &borrowing {
                    called(index, table, calls.entry(index).or_default());
                }
            }
        }
    }

    // Depth-first over the calls, with the forms on the current path marked.
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        OnPath,
        Done,
    }
    let mut states: HashMap<usize, State> = HashMap::new();
    for &start in calls.keys() {
        if states.contains_key(&start) {
            continue;
        }
        states.insert(start, State::OnPath);
        let mut path = vec![(start, 0usize)];
        while let Some((form, next)) = path.last_mut() {
            let form = *form;
            let Some(&target) = calls[&form].get(*next) else {
                states.insert(form, State::Done);
                path.pop();
                continue;
            };
            *next += 1;
            match states.get(&target) {
                Some(State::OnPath) => {
                    return out.report(
                        "pdf.draw_recursion",
                        Severity::Medium,
                        "form draws itself; rendering it never ends",
                        doc.objects[target].offset,
                    );
                }
                Some(State::Done) => {}
                None => {
                    states.insert(target, State::OnPath);
                    path.push((target, 0));
                }
            }
        }
    }
}

/// Collect every dictionary stored under `/XObject` in `value`.
fn xobject_tables<'v>(doc: &'v Document<'_>, value: &'v Value, tables: &mut Vec<&'v Dict>) {
    match value {
        Value::Dict(dict) => {
            for (key, item) in &dict.0 {
                if key.text() == b"XObject"
                    && let Some(table) = doc.resolve(Some(item)).as_dict()
                {
                    tables.push(table);
                }
                xobject_tables(doc, item, tables);
            }
        }
        Value::Array(items) => {
            for item in items {
                xobject_tables(doc, item, tables);
            }
        }
        _ => {}
    }
}

/// Search the packets of an XFA form for scripts. XFA has its own scripting
/// hooks, separate from the document's JavaScript actions.
fn scan_xfa(doc: &Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    let mut targets: Vec<usize> = out
        .xfa
        .iter()
        .filter_map(|number| doc.by_number.get(number).map(|&index| index as usize))
        .collect();
    targets.sort_unstable();
    targets.dedup();

    for index in targets {
        if let Err(limit) = budget.check_time() {
            return out.limit(limit);
        }
        let object = &doc.objects[index];
        let value = doc.value(object);
        let Some(dict) = value.as_dict().filter(|_| object.is_stream()) else {
            continue;
        };
        match doc.decode(object, dict, budget) {
            Ok(packet) => {
                deep::xml(&packet, object.offset, out);
                if has_script_element(&packet) {
                    return out.report(
                        "pdf.javascript",
                        Severity::High,
                        "XFA form contains scripts",
                        object.offset,
                    );
                }
            }
            Err(DecodeError::Limit) => return out.limit(LimitExceeded::Decompression),
            // An unread packet may hold the script.
            Err(_) => out.malformed("XFA packet cannot be decoded", object.offset),
        }
    }
}

/// Whether XML text opens a `script` element, with or without a namespace
/// prefix, in UTF-8 or UTF-16.
fn has_script_element(packet: &[u8]) -> bool {
    let text: Vec<u8> = packet
        .iter()
        .filter(|&&byte| byte != 0)
        .map(u8::to_ascii_lowercase)
        .collect();
    memmem::find_iter(&text, b"script").any(|at| {
        let closes_name = text
            .get(at + b"script".len())
            .is_none_or(|&b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'));
        // Directly after `<`, or after a namespace prefix that is.
        let before = &text[..at];
        let opens_name = match before.strip_suffix(b":") {
            Some(prefixed) => {
                let prefix = prefixed
                    .iter()
                    .rev()
                    .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                    .count();
                prefix > 0 && prefixed[..prefixed.len() - prefix].ends_with(b"<")
            }
            None => before.ends_with(b"<"),
        };
        closes_name && opens_name
    })
}

#[cfg(test)]
mod tests {
    use miniz_oxide::deflate::compress_to_vec_zlib;

    use super::crypt::testing::{Encrypted, ID, OWNER_PASSWORD, Scheme};
    use super::*;
    use crate::limits::Limits;

    fn pdf(objects: &[&[u8]]) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n".to_vec();
        for (index, body) in objects.iter().enumerate() {
            out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        out
    }

    fn stream(entries: &str, data: &[u8]) -> Vec<u8> {
        let mut out = format!("<< {entries} /Length {} >>\nstream\n", data.len()).into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\nendstream");
        out
    }

    fn run(data: &[u8]) -> Vec<(&'static str, Severity)> {
        run_with(data, &[])
    }

    fn run_with(data: &[u8], passwords: &[Vec<u8>]) -> Vec<(&'static str, Severity)> {
        let mut budget = Budget::new(&Limits::default());
        let mut findings = Vec::new();
        let mut nested = |inner: &[u8], _: &mut Budget, findings: &mut Vec<Finding>| {
            if inner.starts_with(b"\x7fELF") {
                findings.push(Finding::new("type.executable", Severity::Critical, "elf"));
            }
        };
        analyze(
            data,
            &mut budget,
            &mut findings,
            passwords,
            Limits::default().max_pixels,
            &mut nested,
        );
        findings.iter().map(|f| (f.code, f.severity)).collect()
    }

    fn codes(data: &[u8]) -> Vec<&'static str> {
        run(data).into_iter().map(|(code, _)| code).collect()
    }

    const CATALOG: &[u8] = b"<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>";
    const PAGES: &[u8] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    const PAGE: &[u8] = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>";

    #[test]
    fn ordinary_document_is_clean() {
        let content = stream("", b"BT /F1 12 Tf (Hello) Tj ET");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &content])),
            [] as [&str; 0]
        );
    }

    #[test]
    fn postscript_xobjects() {
        let program = b"%!PS\n(PAYLOAD) show";
        for entries in [
            "/Type /XObject /Subtype /PS",
            "/Type /XObject /Subtype /Form /Subtype2 /PS",
            "/Type /XObject /Subtype /Form /PS 9 0 R",
        ] {
            let xobject = stream(entries, program);
            assert_eq!(
                codes(&pdf(&[CATALOG, PAGES, PAGE, &xobject])),
                ["pdf.postscript"],
                "{entries}"
            );
        }
        // /PS is only an XObject entry; elsewhere it is a resource name.
        let resources = b"<< /Font << /PS 9 0 R >> >>";
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, resources])),
            [] as [&str; 0]
        );
        // What the program does is reported too.
        let xobject = stream("/Subtype /PS", b"\x7fELF");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &xobject])),
            ["pdf.postscript", "type.executable"]
        );
    }

    #[test]
    fn postscript_operator_in_content() {
        let page = b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>";
        let content = stream("", b"BT (text) Tj ET\n(1 2 moveto) PS\n");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, page, &content])),
            ["pdf.postscript"]
        );
        let packed = stream(
            "/Filter /FlateDecode",
            &compress_to_vec_zlib(b"q (x) PS Q", 6),
        );
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, page, &packed])),
            ["pdf.postscript"]
        );
        let form = stream("/Type /XObject /Subtype /Form", b"(x)PS");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &form])),
            ["pdf.postscript"]
        );
        // The same letters as a string, a name, a comment or part of a word.
        let harmless = stream("", b"(PS) Tj <5053> Tj /PS gs % PS\nPSx EPS BT ET");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, page, &harmless])),
            [] as [&str; 0]
        );
        // Neither inline image data nor a stray parenthesis hides it.
        for hidden in [
            &b"BI /W 1 /H 1 ID (\x00 EI (x) PS"[..],
            b"BI /W 1 /H 1 ID \x00) EI (x) PS",
            b"( (x) PS",
        ] {
            let content = stream("", hidden);
            assert_eq!(
                codes(&pdf(&[CATALOG, PAGES, page, &content])),
                ["pdf.postscript"],
                "{hidden:?}"
            );
        }
        // A stream nothing names as content is not searched.
        let other = stream("/Length1 5", b"(x) PS");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &other])),
            [] as [&str; 0]
        );
    }

    #[test]
    fn javascript_action() {
        let action = b"<< /S /JavaScript /JS (app.alert(1)) >>";
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, action])),
            ["pdf.javascript"]
        );

        let names = b"<< /Names << /JavaScript 9 0 R >> >>";
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, names])),
            ["pdf.javascript"]
        );
    }

    #[test]
    fn name_trees_that_list_nothing() {
        let names = b"<< /Names << /JavaScript 5 0 R /EmbeddedFiles 6 0 R >> >>";
        let with = |scripts: &[u8], files: &[u8]| {
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, names, scripts, files]))
        };
        // What Acrobat writes into a document with no script and no file.
        assert_eq!(with(b"<< >>", b"<< /Names [] >>"), [""; 0]);
        assert_eq!(
            with(b"<< /Kids [] /Names 9 0 R >>", b"<< >>"),
            ["pdf.javascript"]
        );
        assert_eq!(
            with(b"<< /Names [(a) 9 0 R] >>", b"<< /Kids [9 0 R] >>"),
            ["pdf.javascript", "pdf.embedded_file"]
        );
        // A tree that is not there to be read may list anything.
        assert_eq!(
            with(b"null", b"(x)"),
            ["pdf.javascript", "pdf.embedded_file"]
        );
        // The second of two entries counts as much as the first.
        assert_eq!(
            with(b"<< /Names [] /Names [(a) 9 0 R] >>", b"<< >>"),
            ["pdf.javascript"]
        );

        // The rights of a signature over attachments are no attachment.
        let rights = b"<< /Type /TransformParams /EF [/Create /Delete /Modify /Import] >>";
        assert_eq!(codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, rights])), [""; 0]);
        let dangling = b"<< /Type /Filespec /EF 9 0 R >>";
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, dangling])),
            ["pdf.embedded_file"]
        );
    }

    #[test]
    fn open_action_severity_follows_its_target() {
        let scripted = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
        let action = b"<< /S /JavaScript /JS 5 0 R >>";
        assert_eq!(
            run(&pdf(&[scripted, PAGES, PAGE, action])),
            [
                ("pdf.open_action", Severity::High),
                ("pdf.javascript", Severity::High),
            ]
        );

        let link = b"<< /Type /Catalog /OpenAction << /S /URI /URI (http://example.com) >> >>";
        assert_eq!(
            run(&pdf(&[link])),
            [
                ("pdf.open_action", Severity::Medium),
                ("pdf.uri", Severity::Info),
            ]
        );

        let dangling = b"<< /Type /Catalog /OpenAction 99 0 R >>";
        assert_eq!(
            run(&pdf(&[dangling])),
            [("pdf.open_action", Severity::Medium)]
        );
    }

    #[test]
    fn additional_actions_and_launch() {
        let page = b"<< /Type /Page /AA << /O << /S /Launch /F (cmd.exe) >> >> >>";
        assert_eq!(
            run(&pdf(&[CATALOG, PAGES, page])),
            [
                ("pdf.additional_action", Severity::High),
                ("pdf.launch", Severity::High),
            ]
        );
        let harmless = b"<< /Type /Page /AA << /O << /S /GoTo /D [3 0 R /Fit] >> >> >>";
        assert_eq!(codes(&pdf(&[CATALOG, PAGES, harmless])), [] as [&str; 0]);
    }

    #[test]
    fn hex_escaped_keywords() {
        let action = b"<< /S /J#61vaScript /J#53 (app.alert(1)) >>";
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, action])),
            ["pdf.javascript", "pdf.obfuscated_name"]
        );
        let font = b"<< /Type /Font /BaseFont /ABCDEF+Arial#20Bold >>";
        assert_eq!(codes(&pdf(&[CATALOG, PAGES, PAGE, font])), [] as [&str; 0]);
    }

    #[test]
    fn javascript_inside_object_streams() {
        let inner = b"10 0 11 16 << /Foo /Bar >> << /S /JavaScript /JS (x) >>";
        let packed = stream(
            "/Type /ObjStm /N 2 /First 11 /Filter /FlateDecode",
            &compress_to_vec_zlib(inner, 6),
        );
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &packed])),
            ["pdf.javascript"]
        );

        // A filter chain, with the stream length stored in another object.
        let hex: String = compress_to_vec_zlib(inner, 6)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut chained =
            b"<< /Type /ObjStm /N 2 /First 11 /Filter [/ASCIIHexDecode /FlateDecode] /Length 5 0 R >>\nstream\n"
                .to_vec();
        chained.extend_from_slice(hex.as_bytes());
        chained.extend_from_slice(b">\nendstream");
        let length = format!("{}", hex.len() + 1);
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, PAGE, &chained, length.as_bytes()])),
            ["pdf.javascript"]
        );
    }

    #[test]
    fn unreadable_object_streams_are_never_clean() {
        let garbage = stream(
            "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
            b"\xFF\xFF\xFF",
        );
        assert_eq!(codes(&pdf(&[CATALOG, &garbage])), ["pdf.malformed"]);
        let exotic = stream("/Type /ObjStm /N 1 /First 4 /Filter /JBIG2Decode", b"xx");
        assert_eq!(codes(&pdf(&[CATALOG, &exotic])), ["pdf.malformed"]);
    }

    #[test]
    fn embedded_files_are_scanned() {
        let filespec = b"<< /Type /Filespec /F (tool.bin) /EF << /F 3 0 R >> >>";
        let payload = stream(
            "/Filter /FlateDecode",
            &compress_to_vec_zlib(b"\x7fELF\x02\x01", 6),
        );
        assert_eq!(
            run(&pdf(&[CATALOG, filespec, &payload])),
            [
                ("pdf.embedded_file", Severity::Medium),
                ("type.executable", Severity::Critical),
            ]
        );
        let text = stream("/Type /EmbeddedFile", b"plain notes");
        assert_eq!(codes(&pdf(&[CATALOG, &text])), ["pdf.embedded_file"]);
    }

    /// A document whose only script sits in an encrypted object stream.
    fn encrypted_pdf(scheme: Scheme, password: &[u8]) -> Vec<u8> {
        let encrypted = Encrypted::new(scheme, password);
        let inner = b"10 0 11 16 << /Foo /Bar >> << /S /JavaScript /JS (x) >>";
        let packed = stream(
            "/Type /ObjStm /N 2 /First 11 /Filter /FlateDecode",
            &encrypted.seal(2, &compress_to_vec_zlib(inner, 6)),
        );
        let mut out = b"%PDF-1.7\n".to_vec();
        for (index, body) in [CATALOG, &packed, encrypted.dict.as_bytes()]
            .iter()
            .enumerate()
        {
            out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let id: String = ID.iter().map(|byte| format!("{byte:02x}")).collect();
        out.extend_from_slice(
            format!("trailer\n<< /Root 1 0 R /Encrypt 3 0 R /ID [<{id}> <{id}>] >>\n%%EOF\n")
                .as_bytes(),
        );
        out
    }

    const SCHEMES: [Scheme; 5] = [
        Scheme::Rc4Short,
        Scheme::Rc4Long,
        Scheme::Aes128,
        Scheme::Aes256,
        Scheme::Aes256Extension,
    ];

    #[test]
    fn empty_password_encryption_is_seen_through() {
        for scheme in SCHEMES {
            assert_eq!(
                run(&encrypted_pdf(scheme, b"")),
                [
                    ("pdf.encrypted", Severity::Info),
                    ("pdf.javascript", Severity::High),
                ],
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn password_protected_documents_stay_unreadable() {
        for scheme in SCHEMES {
            assert_eq!(
                run(&encrypted_pdf(scheme, b"secret")),
                [("pdf.encrypted", Severity::Medium)],
                "{scheme:?}"
            );
        }
        // A password the caller knows opens them, the owner's included.
        for scheme in SCHEMES {
            let data = encrypted_pdf(scheme, b"secret");
            for password in [&b"secret"[..], OWNER_PASSWORD] {
                assert_eq!(
                    run_with(&data, &[b"wrong".to_vec(), password.to_vec()]),
                    [
                        ("pdf.encrypted", Severity::Info),
                        ("pdf.javascript", Severity::High),
                    ],
                    "{scheme:?}"
                );
            }
            assert_eq!(
                run_with(&data, &[b"wrong".to_vec()]),
                [("pdf.encrypted", Severity::Medium)],
                "{scheme:?}"
            );
        }
        // The encryption dictionary sits inline in a cross-reference stream.
        let inline = Encrypted::new(Scheme::Aes256, b"").dict;
        let id: String = ID.iter().map(|byte| format!("{byte:02x}")).collect();
        let xref = stream(
            &format!("/Type /XRef /Root 1 0 R /Encrypt {inline} /ID [<{id}> <{id}>]"),
            b"\0\0\0",
        );
        assert_eq!(
            run(&pdf(&[CATALOG, &xref])),
            [("pdf.encrypted", Severity::Info)]
        );
    }

    #[test]
    fn data_after_the_end_marker() {
        let mut padded = pdf(&[CATALOG]);
        padded.extend_from_slice(b"\r\n\0\0  \n");
        assert_eq!(codes(&padded), [] as [&str; 0]);

        let mut noted = pdf(&[CATALOG]);
        noted.extend_from_slice(b"generated by an old printer driver");
        assert_eq!(run(&noted), [("pdf.trailing_data", Severity::Low)]);

        for appended in [&b"\n\x7fELF\x02\x01\x01"[..], b"<html><script>x</script>"] {
            let mut polyglot = pdf(&[CATALOG]);
            polyglot.extend_from_slice(appended);
            assert_eq!(
                run(&polyglot),
                [
                    ("pdf.trailing_data", Severity::Low),
                    ("pdf.polyglot", Severity::High),
                ]
            );
        }

        // An archive is found from its end record, wherever it starts.
        let mut archive = pdf(&[CATALOG]);
        archive.extend_from_slice(b"entries");
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0; 18]);
        assert_eq!(codes(&archive), ["pdf.trailing_data", "pdf.polyglot"]);
    }

    #[test]
    fn xfa_packets_are_searched_for_scripts() {
        let form = b"<< /AcroForm << /XFA [(template) 2 0 R (datasets) 3 0 R] >> >>";
        let template = stream(
            "/Filter /FlateDecode",
            &compress_to_vec_zlib(
                b"<template><subform><event activity=\"initialize\">\
                  <xfa:Script contentType=\"application/x-javascript\">x()</xfa:Script>\
                  </event></subform></template>",
                6,
            ),
        );
        let data = stream(
            "",
            b"<xfa:datasets><description>script</description></xfa:datasets>",
        );
        assert_eq!(
            codes(&pdf(&[form, &template, &data])),
            ["pdf.xfa", "pdf.javascript"]
        );
        // A form with fields and no script is only an XFA form.
        assert_eq!(codes(&pdf(&[form, &data, &data])), ["pdf.xfa"]);
        // Its packets have the type of embedded files in what Adobe's
        // programs write, and are still what the form is made of.
        let typed = stream("/Type /EmbeddedFile", b"<xfa:datasets/>");
        assert_eq!(codes(&pdf(&[form, &typed, &typed])), ["pdf.xfa"]);
        let program = stream("/Type /EmbeddedFile", b"\x7fELF\x02\x01");
        assert_eq!(
            codes(&pdf(&[form, &typed, &program])),
            ["pdf.xfa", "type.executable"]
        );
        // A stream that the form does not name is an attachment.
        assert_eq!(
            codes(&pdf(&[form, &typed, &typed, &typed])),
            ["pdf.xfa", "pdf.embedded_file"]
        );

        let single = b"<< /AcroForm << /XFA 2 0 R >> >>";
        let wide: Vec<u8> = "<script>x</script>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            codes(&pdf(&[single, &stream("", &wide)])),
            ["pdf.xfa", "pdf.javascript"]
        );
        let unreadable = stream("/Filter /FlateDecode", b"\xFF\xFF\xFF");
        assert_eq!(
            codes(&pdf(&[single, &unreadable])),
            ["pdf.xfa", "pdf.malformed"]
        );
    }

    #[test]
    fn encryption_and_other_features() {
        let mut encrypted = pdf(&[CATALOG]);
        encrypted.extend_from_slice(b"trailer\n<< /Root 1 0 R /Encrypt 7 0 R >>\n%%EOF\n");
        assert_eq!(
            run(&encrypted),
            [
                ("pdf.encrypted", Severity::Medium),
                ("pdf.incremental_update", Severity::Info),
            ]
        );

        let form = b"<< /AcroForm << /XFA 8 0 R >> >>";
        let media = b"<< /Type /Annot /Subtype /RichMedia >>";
        let submit = b"<< /S /SubmitForm /F (http://example.com) >>";
        let remote = b"<< /S /GoToR /F (other.pdf) >>";
        assert_eq!(
            codes(&pdf(&[form, media, submit, remote])),
            [
                "pdf.xfa",
                "pdf.rich_media",
                "pdf.submit_form",
                "pdf.remote_goto"
            ]
        );
    }

    #[test]
    fn unparsable_objects_are_still_searched() {
        let broken = b"<< /S /JavaScript /JS (app.alert(1)) /Oops >";
        assert_eq!(
            codes(&pdf(&[CATALOG, broken])),
            ["pdf.malformed", "pdf.javascript"]
        );
    }

    #[test]
    fn structural_problems() {
        let mut prefixed = b"GIF89a junk ".to_vec();
        prefixed.extend(pdf(&[CATALOG]));
        assert_eq!(codes(&prefixed), ["pdf.malformed"]);

        assert_eq!(codes(b"%PDF-1.7\n%%EOF\n"), ["pdf.malformed"]);

        let complete = pdf(&[CATALOG]);
        let cut = &complete[..complete.len() - 7];
        assert_eq!(codes(cut), ["pdf.malformed"]);
    }

    #[test]
    fn objects_hidden_inside_stream_data_are_found() {
        let hidden = stream("", b"1 0 obj\n<< /S /JavaScript /JS (x) >>\nendobj");
        assert_eq!(codes(&pdf(&[CATALOG, &hidden])), ["pdf.javascript"]);
    }

    #[test]
    fn decompression_is_budgeted() {
        let limits = Limits {
            max_decompressed: 1000,
            ..Limits::default()
        };
        let bomb = stream(
            "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
            &compress_to_vec_zlib(&vec![b' '; 1_000_000], 6),
        );
        let mut budget = Budget::new(&limits);
        let mut findings = Vec::new();
        analyze(
            &pdf(&[CATALOG, &bomb]),
            &mut budget,
            &mut findings,
            &[],
            limits.max_pixels,
            &mut |_, _, _| {},
        );
        assert_eq!(findings[0].code, "limit.decompression");
    }

    const PLAIN_CATALOG: &[u8] = b"<< /Type /Catalog /Pages 2 0 R >>";

    fn link(address: &str) -> Vec<u8> {
        format!("<< /Subtype /Link /Rect [0 0 9 9] /A << /S /URI /URI {address} >> >>").into_bytes()
    }

    #[test]
    fn links_are_judged_by_where_they_lead() {
        let with = |address: &str| run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &link(address)]));
        assert_eq!(
            with("(https://example.com/)"),
            [("pdf.uri", Severity::Info)]
        );
        for script in [
            "(javascript:alert\\(1\\))",
            "( Java\\tScript:x)",
            // The same in hexadecimal, and in UTF-16.
            "<6A6176617363726970743A78>",
            "<FEFF006A006100760061007300630072006900700074003A>",
            "(ms-msdt:/id x)",
        ] {
            assert!(
                with(script).contains(&("pdf.dangerous_uri", Severity::High)),
                "{script}"
            );
        }
        for local in [
            "(file://host/share/passwd)",
            "(\\\\\\\\host\\\\share\\\\x)",
            "(C:\\\\x.exe)",
        ] {
            assert!(
                with(local).contains(&("pdf.dangerous_uri", Severity::Medium)),
                "{local}"
            );
        }
        // The base that relative links are resolved against.
        let based = b"<< /Type /Catalog /Pages 2 0 R /URI << /Base (javascript:) >> >>";
        assert_eq!(
            run(&pdf(&[based, PAGES, PAGE])),
            [
                ("pdf.uri", Severity::Info),
                ("pdf.dangerous_uri", Severity::High)
            ]
        );
    }

    #[test]
    fn links_in_encrypted_documents_are_read() {
        for scheme in [Scheme::Rc4Long, Scheme::Aes128, Scheme::Aes256] {
            let sealed = Encrypted::new(scheme, b"");
            let address = sealed.seal(4, b"javascript:alert(1)");
            let hex: String = address.iter().map(|byte| format!("{byte:02X}")).collect();
            let link = link(&format!("<{hex}>"));
            let mut document = b"%PDF-1.7\n".to_vec();
            let objects = [PLAIN_CATALOG, PAGES, PAGE, &link, sealed.dict.as_bytes()];
            for (index, body) in objects.iter().enumerate() {
                document.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
                document.extend_from_slice(body);
                document.extend_from_slice(b"\nendobj\n");
            }
            let id: String = ID.iter().map(|byte| format!("{byte:02x}")).collect();
            document.extend_from_slice(
                format!("trailer\n<< /Root 1 0 R /Encrypt 5 0 R /ID [<{id}> <{id}>] >>\n%%EOF\n")
                    .as_bytes(),
            );
            assert_eq!(
                codes(&document),
                ["pdf.uri", "pdf.encrypted", "pdf.dangerous_uri"]
            );
        }
    }

    #[test]
    fn content_outside_the_file() {
        let external = stream(
            "/Subtype /Image /Width 1 /Height 1 /F (//host/share/x.jpg) /FFilter /DCTDecode",
            b"",
        );
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &external])),
            ["pdf.external_ref"]
        );
        // An annotation's /F is its flags, a file specification's its name.
        let annotation = b"<< /Subtype /Text /Rect [0 0 9 9] /F 4 >>";
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, annotation])),
            [""; 0]
        );

        for dictionary in [
            &b"<< /FS /URL /F (https://example.com/x.pdf) >>"[..],
            b"<< /Type /OPI /Version 1.3 >>",
        ] {
            assert_eq!(
                codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, dictionary])),
                ["pdf.external_ref"]
            );
        }
        let reference = stream(
            "/Subtype /Form /BBox [0 0 9 9] /Ref << /F (x.pdf) /Page 0 >>",
            b"",
        );
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &reference])),
            ["pdf.external_ref"]
        );
    }

    #[test]
    fn postscript_in_appearance_strings_and_functions() {
        let form = b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /DA ((quit) PS) >> >>";
        assert_eq!(codes(&pdf(&[form, PAGES, PAGE])), ["pdf.postscript"]);
        let ordinary = b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /DA (/Helv 0 Tf 0 g) >> >>";
        assert_eq!(codes(&pdf(&[ordinary, PAGES, PAGE])), [""; 0]);

        let function = |program: &[u8]| {
            let function = stream("/FunctionType 4 /Domain [0 1] /Range [0 1]", program);
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &function]))
        };
        assert_eq!(function(b"{ 1 exch sub }"), [""; 0]);
        assert_eq!(function(b"{ (%pipe%id) (r) file }"), ["pdf.postscript"]);
    }

    #[test]
    fn multimedia_annotations() {
        for subtype in ["Movie", "Sound", "Screen", "RichMedia", "3D"] {
            let annotation = format!("<< /Subtype /{subtype} /Rect [0 0 9 9] >>");
            assert_eq!(
                codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, annotation.as_bytes()])),
                ["pdf.rich_media"],
                "{subtype}"
            );
        }
    }

    #[test]
    fn xml_that_reaches_outside() {
        let metadata = |text: &[u8]| {
            let metadata = stream("/Type /Metadata /Subtype /XML", text);
            run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &metadata]))
        };
        assert_eq!(metadata(b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>"), []);
        assert_eq!(
            metadata(b"<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>"),
            [("pdf.xml_entity", Severity::High)]
        );
        assert_eq!(
            metadata(b"<!DOCTYPE x><x/>"),
            [("pdf.xml_entity", Severity::Medium)]
        );
        let utf16: Vec<u8> = "<!ENTITY e 'x'>"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert_eq!(metadata(&utf16), [("pdf.xml_entity", Severity::High)]);
        assert_eq!(
            metadata(b"<x xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"/etc/passwd\"/></x>"),
            [("pdf.xml_external_ref", Severity::Medium)]
        );
    }

    #[test]
    fn sizes_that_exhaust_a_renderer() {
        let image = |width: u64, height: u64| {
            let image = stream(
                &format!("/Subtype /Image /Width {width} /Height {height} /BitsPerComponent 8"),
                b"\0",
            );
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &image]))
        };
        assert_eq!(image(4000, 3000), [""; 0]);
        assert_eq!(image(1_000_000, 1_000_000), ["pdf.pixel_bomb"]);

        let page = |entries: &str| {
            let page = format!("<< /Type /Page /Parent 2 0 R {entries} >>");
            codes(&pdf(&[PLAIN_CATALOG, PAGES, page.as_bytes()]))
        };
        // A0, and the largest page the format allows.
        assert_eq!(page("/MediaBox [0 0 2384 3370]"), [""; 0]);
        assert_eq!(page("/MediaBox [0 0 14400 14400]"), [""; 0]);
        assert_eq!(page("/MediaBox [0 0 14400000 100]"), ["pdf.page_size"]);
        assert_eq!(
            page("/MediaBox [0 0 612 792] /CropBox [-99999 0 99999 9]"),
            ["pdf.page_size"]
        );
        assert_eq!(
            page("/MediaBox [0 0 10000 10000] /UserUnit 10"),
            ["pdf.page_size"]
        );
    }

    #[test]
    fn forms_that_draw_themselves() {
        let form = |resources: &str, content: &[u8]| {
            stream(
                &format!("/Subtype /Form /BBox [0 0 9 9] {resources}"),
                content,
            )
        };
        let page = b"<< /Type /Page /Parent 2 0 R /Resources << /XObject << /A 4 0 R >> >> >>";
        let document = |forms: &[&[u8]]| {
            let mut objects = vec![PLAIN_CATALOG, PAGES, &page[..]];
            objects.extend_from_slice(forms);
            codes(&pdf(&objects))
        };

        let itself = form("/Resources << /XObject << /A 4 0 R >> >>", b"q /A Do Q");
        assert_eq!(document(&[&itself]), ["pdf.draw_recursion"]);
        // Through the resources of the page that draws it.
        let inherited = form("", b"/A Do");
        assert_eq!(document(&[&inherited]), ["pdf.draw_recursion"]);
        // Through another form.
        let first = form("/Resources << /XObject << /B 5 0 R >> >>", b"/B Do");
        let second = form("/Resources << /XObject << /A 4 0 R >> >>", b"/A Do");
        assert_eq!(document(&[&first, &second]), ["pdf.draw_recursion"]);

        // Listing a form is not drawing it, and neither is naming it in a string.
        let listed = form("/Resources << /XObject << /A 4 0 R >> >>", b"(/A Do) Tj");
        assert_eq!(document(&[&listed]), [""; 0]);
        let chain = form("/Resources << /XObject << /B 5 0 R >> >>", b"/B Do /B Do");
        let leaf = form("", b"0 0 9 9 re f");
        assert_eq!(document(&[&chain, &leaf]), [""; 0]);
    }

    #[test]
    fn one_object_defined_twice() {
        let twice = |second: &[u8], between: &[u8]| {
            let mut data = pdf(&[PLAIN_CATALOG, PAGES, PAGE]);
            data.extend_from_slice(between);
            data.extend_from_slice(b"3 0 obj\n");
            data.extend_from_slice(second);
            data.extend_from_slice(b"\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
            codes(&data)
        };
        let other = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] >>";
        // A later revision replaces the object: that is what updates are.
        assert_eq!(twice(other, b""), ["pdf.incremental_update"]);
        assert_eq!(twice(PAGE, b""), ["pdf.incremental_update"]);

        let mut conflicting = pdf(&[PLAIN_CATALOG, PAGES, PAGE]);
        let trailer = memmem::find(&conflicting, b"trailer").unwrap();
        let mut second = b"3 0 obj\n".to_vec();
        second.extend_from_slice(other);
        second.extend_from_slice(b"\nendobj\n");
        conflicting.splice(trailer..trailer, second.clone());
        assert_eq!(codes(&conflicting), ["pdf.conflicting_objects"]);

        // The same bytes twice are a careless writer's, and say one thing.
        let mut repeated = pdf(&[PLAIN_CATALOG, PAGES, PAGE]);
        let mut same = b"3 0 obj\n".to_vec();
        same.extend_from_slice(PAGE);
        same.extend_from_slice(b"\nendobj\n");
        repeated.splice(trailer..trailer, same);
        assert_eq!(codes(&repeated), [""; 0]);

        // An object that stands in the data of a stream belongs to the stream.
        let mut carried = b"3 0 obj\n".to_vec();
        carried.extend_from_slice(other);
        carried.extend_from_slice(b"\nendobj");
        let carrier = stream("", &carried);
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &carrier])),
            [""; 0]
        );
    }

    #[test]
    fn other_formats_inside_the_document() {
        let with = |insert: &[u8]| {
            let mut data = pdf(&[PLAIN_CATALOG, PAGES, PAGE]);
            let trailer = memmem::find(&data, b"trailer").unwrap();
            data.splice(trailer..trailer, insert.iter().copied());
            run(&data)
        };
        assert_eq!(with(b"% a comment\n"), []);
        assert_eq!(
            with(b"% PK\x03\x04\x14\0\0\0\n"),
            [("pdf.polyglot", Severity::High)]
        );
        assert_eq!(
            with(b"% <HTML><body>x</body></html>\n"),
            [("pdf.polyglot", Severity::Medium)]
        );
        assert_eq!(with(b"%PDF-1.4\n"), [("pdf.malformed", Severity::Medium)]);

        // In the data of a stream they are data.
        let archive = stream("", b"PK\x03\x04 <html> \n%PDF-1.4\n");
        assert_eq!(run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &archive])), []);
    }

    #[test]
    fn what_is_reported_and_does_not_decide() {
        let image = stream(
            "/Subtype /Image /Width 1 /Height 1 /Filter /JBIG2Decode",
            b"\0",
        );
        assert_eq!(
            run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &image])),
            [("pdf.risky_codec", Severity::Info)]
        );
        let stamp = b"<< /Subtype /Stamp /Rect [0 0 9 9] /F 36 >>";
        assert_eq!(
            run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, stamp])),
            [("pdf.print_only", Severity::Info)]
        );
        let layer = b"<< /Type /OCG /Usage << /Print << /PrintState /ON >> /View << /ViewState /OFF >> >> >>";
        assert_eq!(
            run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, layer])),
            [("pdf.print_only", Severity::Info)]
        );
        let signature = b"<< /Type /Sig /ByteRange [0 10 20 30] /Contents <00> >>";
        assert_eq!(
            run(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, signature])),
            [("pdf.signature_modified", Severity::Info)]
        );
    }

    #[test]
    fn numbers_a_decoder_trusts() {
        let with = |parameters: &str| {
            let data = stream(
                &format!("/Filter /FlateDecode /DecodeParms {parameters}"),
                b"x",
            );
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, &data]))
        };
        assert_eq!(with("<< /Predictor 12 /Columns 5 /Colors 3 >>"), [""; 0]);
        assert_eq!(with("[null << /Predictor 2 >>]"), [""; 0]);
        for wrong in [
            "<< /Predictor 99 >>",
            "<< /Colors 0 >>",
            "<< /BitsPerComponent 7 >>",
            "<< /Columns 4294967296 >>",
            "<< /Columns -1 >>",
        ] {
            assert_eq!(with(wrong), ["pdf.malformed"], "{wrong}");
        }
        let name = format!("<< /{} 1 >>", "N".repeat(300));
        assert_eq!(
            codes(&pdf(&[PLAIN_CATALOG, PAGES, PAGE, name.as_bytes()])),
            ["pdf.malformed"]
        );
    }

    #[test]
    fn content_is_read_as_it_is_decoded() {
        let page = b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>";
        // Many blocks of text, and the operator in the last of them.
        let mut text = b"BT /F1 12 Tf (a string (that) goes \\) on) Tj ET\n".repeat(2000);
        let quiet = stream("/Filter /FlateDecode", &compress_to_vec_zlib(&text, 6));
        assert_eq!(codes(&pdf(&[CATALOG, PAGES, page, &quiet])), [""; 0]);
        text.extend_from_slice(b"(1 2 moveto) PS");
        let hex: String = compress_to_vec_zlib(&text, 6)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let loud = stream("/Filter [/AHx /FlateDecode]", hex.as_bytes());
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, page, &loud])),
            ["pdf.postscript"]
        );

        // A stream that ends badly holds nothing, whatever came out first.
        let mut cut = text.clone();
        cut.splice(0..0, b"(x) PS ".iter().copied());
        let mut broken = compress_to_vec_zlib(&cut, 0);
        broken.truncate(broken.len() / 2);
        let hex: String = broken.iter().map(|byte| format!("{byte:02x}")).collect();
        let unreadable = stream("/Filter [/A85 /FlateDecode]", hex.as_bytes());
        assert_eq!(codes(&pdf(&[CATALOG, PAGES, page, &unreadable])), [""; 0]);
    }

    #[test]
    fn content_larger_than_the_limit() {
        let limits = Limits {
            max_decompressed: 100_000,
            ..Limits::default()
        };
        let scan = |objects: &[&[u8]]| {
            let mut budget = Budget::new(&limits);
            let mut findings = Vec::new();
            let data = pdf(objects);
            analyze(
                &data,
                &mut budget,
                &mut findings,
                &[],
                limits.max_pixels,
                &mut |_, _, _| {},
            );
            let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
            (codes, budget.remaining())
        };
        let page = b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>";
        let fits = stream(
            "/Filter /FlateDecode",
            &compress_to_vec_zlib(&b"q Q ".repeat(20_000), 6),
        );
        assert_eq!(scan(&[CATALOG, PAGES, page, &fits]), (vec![], 20_000));
        // What did not fit is not counted, as when it was decoded whole:
        // the next stream has all of the limit.
        let bomb = stream(
            "/Filter /FlateDecode",
            &compress_to_vec_zlib(&b"q Q ".repeat(30_000), 6),
        );
        let metadata = stream("/Type /Metadata /Subtype /XML", b"<!DOCTYPE x><x/>");
        assert_eq!(
            scan(&[CATALOG, PAGES, page, &bomb, &metadata]),
            (vec!["limit.decompression", "pdf.xml_entity"], 100_000)
        );
    }

    #[test]
    fn many_objects_cost_one_each() {
        // More values than a document may keep, in objects that nothing
        // refers to: each is parsed, looked at and dropped.
        let annotation = format!(
            "<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /Border [{}] >>",
            "0 ".repeat(100)
        );
        let mut objects = vec![PLAIN_CATALOG, PAGES, PAGE];
        objects.resize(3 + MIN_NODES / 100 + 100, annotation.as_bytes());
        let mut data = pdf(&objects);
        assert_eq!(codes(&data), [""; 0]);

        // The last of them is still looked at.
        let trailer = memmem::rfind(&data, b"trailer").unwrap();
        let link = link("(javascript:x)");
        let mut last = b"999999 0 obj\n".to_vec();
        last.extend_from_slice(&link);
        last.extend_from_slice(b"\nendobj\n");
        data.splice(trailer..trailer, last);
        assert_eq!(codes(&data), ["pdf.uri", "pdf.dangerous_uri"]);
    }

    #[test]
    fn values_that_references_lead_to_are_counted() {
        let large = format!("[{}]", "0 ".repeat(MIN_NODES / 2 + 10));
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
        // One of them fits.
        assert_eq!(
            codes(&pdf(&[catalog, PAGES, PAGE, large.as_bytes()])),
            [""; 0]
        );
        let page = b"<< /Type /Page /Parent 2 0 R /AA 5 0 R >>";
        let both = pdf(&[catalog, PAGES, page, large.as_bytes(), large.as_bytes()]);
        assert_eq!(codes(&both), ["pdf.additional_action", "limit.complexity"]);
    }

    #[test]
    fn objects_in_object_streams_are_looked_at_in_their_turn() {
        let link = "<< /Subtype /Link /A << /URI (smb://host/x) >> >>";
        let index = format!("10 0 11 {} ", link.len() + 1);
        let inner = format!("{index}{link} [0 0 99999 9]");
        let packed = stream(
            &format!(
                "/Type /ObjStm /N 2 /First {} /Filter /FlateDecode",
                index.len()
            ),
            &compress_to_vec_zlib(inner.as_bytes(), 6),
        );
        // The box of the page is the array that the object stream defines.
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox 11 0 R >>";
        let stamp = b"<< /Subtype /Stamp /Rect [0 0 9 9] /F 36 >>";
        let earlier: &[u8] = b"[0 0 612 792]";
        let mut objects = vec![PLAIN_CATALOG, PAGES, page, &packed, stamp];
        objects.resize(10, b"null");
        objects.push(earlier);
        assert_eq!(
            codes(&pdf(&objects)),
            [
                "pdf.uri",
                "pdf.page_size",
                "pdf.print_only",
                "pdf.dangerous_uri"
            ]
        );
        // Without the object stream it is the one in the file.
        objects[3] = b"null";
        assert_eq!(codes(&pdf(&objects)), ["pdf.print_only"]);
    }

    #[test]
    fn streams_that_all_run_to_one_end() {
        // Each of them is most of the file, and reading them all is the
        // square of it: the work is cut off, and the file is not cleared.
        let overlapping = |entries: &str, count: usize| {
            let mut data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec();
            for number in 0..count {
                data.extend_from_slice(
                    format!(
                        "{} 0 obj\n<< {entries} >>\nstream\nq (text) Tj Q ",
                        number + 2
                    )
                    .as_bytes(),
                );
            }
            data.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
            data
        };
        for entries in [
            "/Subtype /Form /BBox [0 0 9 9]",
            "/Type /Metadata /Subtype /XML",
        ] {
            assert_eq!(
                codes(&overlapping(entries, 20_000)),
                ["limit.complexity"],
                "{entries}"
            );
            // A few such streams are a damaged file, and are read.
            assert_eq!(codes(&overlapping(entries, 5)), [""; 0], "{entries}");
        }
        // The script behind them is still found.
        let mut scripted = overlapping("/Subtype /Form /BBox [0 0 9 9]", 20_000);
        let trailer = memmem::rfind(&scripted, b"trailer").unwrap();
        scripted.splice(
            trailer..trailer,
            b"99999 0 obj\n<< /S /JavaScript /JS (x) >>\nendobj\n"
                .iter()
                .copied(),
        );
        assert_eq!(codes(&scripted), ["pdf.javascript", "limit.complexity"]);
    }
}
