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
use std::collections::{HashMap, HashSet};

use memchr::memmem;

use crate::detect::{self, FileType};
use crate::limits::{Budget, LimitExceeded};
use crate::report::{Finding, Severity};
use crate::work;
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
        // What the sink holds counts against the scan's memory; past it,
        // nothing more is handed over, and the stream ends at the limit.
        let watch = budget.memory_watch();
        let mut over = false;
        let mut watched = |block: &[u8]| {
            over = over || watch.is_over();
            if !over {
                sink(block);
            }
        };
        let (used, outcome) = filters::run(&steps, &data, budget.remaining(), &mut watched);
        if over {
            budget.memory_spent();
            return Err(DecodeError::Limit);
        }
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
    /// Where file specifications with embedded files and trees of
    /// attachments were seen, and the object numbers of the files they name.
    /// They are reported once it is known what the files are.
    attachments: Vec<usize>,
    attached: Vec<u32>,
    /// A file specification with embedded files that is not that of a C2PA
    /// manifest was seen.
    foreign_attachment: bool,
    /// Links from an object to those it names as the next in a tree or a
    /// chain: see [`reference_loops`].
    links: Vec<(u32, u32)>,
    /// The largest link to a web page, by area, and where it is; and the
    /// largest page: see [`link_lure`].
    web_link: Option<(f64, usize)>,
    page_area: f64,
    /// A dictionary that gives a key that decides what is shown two values:
    /// what, and where. See [`ambiguities`].
    twice: Option<(&'static str, usize)>,
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

    fn attachment(&mut self, offset: usize) {
        if self.attachments.last() != Some(&offset) {
            self.attachments.push(offset);
        }
    }

    /// Only the first [`MAX_ENCRYPT_SOURCES`] are ever tried, so no more are
    /// kept: a file that names `/Encrypt` in every object would otherwise
    /// make this the square of its objects.
    fn encrypted(&mut self, offset: usize) {
        work::done(self.encrypt_sources.len());
        if self.encrypt_sources.len() < MAX_ENCRYPT_SOURCES
            && !self.encrypt_sources.contains(&offset)
        {
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
        attachments: Vec::new(),
        attached: Vec::new(),
        foreign_attachment: false,
        links: Vec::new(),
        web_link: None,
        page_area: 0.0,
        twice: None,
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

    // A trailer is read to where its value ends, which for one whose string
    // never closes is the end of the file: the same bound on that work as
    // for objects.
    let work_limit = data.len() as u64 * 8 + (1 << 20);
    let mut work = 0u64;
    for (count, at) in memmem::find_iter(data, b"trailer").enumerate() {
        if count % 256 == 0
            && let Err(limit) = budget.check_time()
        {
            out.limit(limit);
            break;
        }
        let start = at + b"trailer".len();
        let mut parser = Parser::new(data, start, doc.nodes_left.get());
        let trailer = parser.parse_value();
        work += (parser.pos - start) as u64;
        if work > work_limit {
            out.limit(LimitExceeded::Complexity);
            break;
        }
        if let Some(trailer) = trailer {
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
        report_attachments(&doc, Some(budget), &mut out);
        scan_embedded_files(&doc, budget, &mut out, nested);
        scan_content_streams(&doc, budget, &mut out);
        scan_xfa(&doc, budget, &mut out);
    } else {
        report_attachments(&doc, None, &mut out);
    }

    reference_loops(&doc, &mut out);
    link_lure(&mut out);
    let pass = deep::Pass {
        doc: &doc,
        readable,
        max_pixels,
    };
    deep::inspect(&pass, early, seen_from, budget, &mut out);
    signatures(&doc, &mut out);
    ambiguities(&doc, &mut out);

    if doc.objects.is_empty() {
        out.malformed("PDF contains no objects", 0);
    }
    // What a reference led to was not looked at.
    if doc.exhausted.get() {
        out.limit(LimitExceeded::Complexity);
    }
    check_end(data, &mut out);
}

/// What each signature signs, as far as the file shows it: the certificate
/// and the digest are not checked. A signature signs the bytes its
/// `/ByteRange` names, which are the whole file as it was signed but its own
/// value, a hexadecimal string. The attacks on signed documents (USF, SWA
/// and ISA in pdf-insecurity.org's terms) make readers that check part of
/// that show a document as signed when what it shows was not: a range that
/// names bytes the file does not have, or no value; a gap between ranges
/// that leaves other content out; a signature copied into an update that
/// it does not itself sign; page content written after the last signature.
fn signatures(doc: &Document<'_>, out: &mut Output<'_>) {
    let data = doc.data;
    let mut found = memmem::find_iter(data, b"/ByteRange").peekable();
    if found.peek().is_none() {
        return;
    }
    // The objects of the file by where they start, to tell which one each
    // range is in.
    let mut starts: Vec<(usize, u32)> = (doc.objects.iter().enumerate())
        .filter(|(_, object)| !object.packed())
        .map(|(index, object)| (object.offset, index as u32))
        .collect();
    starts.sort_unstable();
    let invalid = |why: &str, offset: usize, out: &mut Output<'_>| {
        out.report(
            "pdf.signature_invalid",
            Severity::Medium,
            &format!("signature {why}: a reader that checks only part of it shows it as valid"),
            offset,
        );
    };
    let mut signed_end: Option<usize> = None;
    let mut checked = None;
    // Signatures that lie after what they sign, with their ranges, and the
    // ranges of those inside: a reader that saves a document again writes
    // the dictionary of a signature anew, as it was.
    let mut outside: Vec<(Vec<usize>, usize)> = Vec::new();
    let mut inside: Vec<Vec<usize>> = Vec::new();
    for at in found {
        let Some(&(offset, index)) = starts.get(
            starts
                .partition_point(|&(start, _)| start <= at)
                .wrapping_sub(1),
        ) else {
            continue;
        };
        if checked.replace(index) == Some(index) {
            continue;
        }
        // Usage rights and document permissions sign as signatures do,
        // from inside the catalogue.
        let mut signatures = Vec::new();
        signature_dicts(doc.kept(index), 0, &mut signatures);
        for dict in signatures {
            // The usage rights that Adobe's programs give a document to let
            // Reader save it are not shown as a signature, and are broken
            // by any other program that saves it.
            if usage_rights(doc, dict) {
                continue;
            }
            match signed_range(doc, dict) {
                Ok(numbers) => {
                    let end = numbers[numbers.len() - 2] + numbers[numbers.len() - 1];
                    if offset >= end {
                        outside.push((numbers, offset));
                    } else {
                        signed_end = signed_end.max(Some(end));
                        inside.push(numbers);
                    }
                }
                Err(why) => invalid(why, offset, out),
            }
        }
    }
    if let Some((_, offset)) = outside
        .iter()
        .find(|(numbers, _)| !inside.contains(numbers))
    {
        invalid("is not inside what it signs", *offset, out);
    }
    let Some(end) = signed_end else {
        return;
    };
    if end < data.trim_ascii_end().len() {
        out.report(
            "pdf.signature_modified",
            Severity::Info,
            "signature does not cover the whole file: bytes were added after signing, \
             or left out of what was signed",
            end,
        );
    }
    // Page content defined where no signature reaches.
    let unsigned = out.contents.iter().find_map(|number| {
        let object = &doc.objects[*doc.by_number.get(number)? as usize];
        (object.offset >= end).then_some(object.offset)
    });
    if let Some(offset) = unsigned {
        out.report(
            "pdf.unsigned_content",
            Severity::Medium,
            "page content was written after the document was signed, and is not signed",
            offset,
        );
    }
}

/// The dictionaries with a `/ByteRange` in `value`, which is that of one
/// object, through the dictionaries and arrays written in it.
fn signature_dicts<'v>(value: &'v Value, depth: usize, found: &mut Vec<&'v Dict>) {
    match value {
        Value::Dict(dict) if dict.get(b"ByteRange").is_some() => found.push(dict),
        Value::Dict(dict) if depth < 4 => dict
            .0
            .iter()
            .for_each(|(_, value)| signature_dicts(value, depth + 1, found)),
        Value::Array(items) if depth < 4 => items
            .iter()
            .for_each(|value| signature_dicts(value, depth + 1, found)),
        _ => {}
    }
}

/// Whether the signature in `dict` grants usage rights (`/TransformMethod
/// /UR3`, or `/UR` of old) rather than signing the document.
fn usage_rights(doc: &Document<'_>, dict: &Dict) -> bool {
    let references = doc.resolve(dict.get(b"Reference")).as_array();
    references.unwrap_or_default().iter().any(|reference| {
        doc.resolve(Some(reference))
            .as_dict()
            .is_some_and(|reference| {
                let method = doc.resolve(reference.get(b"TransformMethod")).as_name();
                matches!(method, Some(b"UR3" | b"UR"))
            })
    })
}

/// See [`signatures`]: the ranges the signature in `dict` signs, or what is
/// wrong with them.
fn signed_range(doc: &Document<'_>, dict: &Dict) -> Result<Vec<usize>, &'static str> {
    let data = doc.data;
    let ranges = doc
        .resolve(dict.get(b"ByteRange"))
        .as_array()
        .unwrap_or_default();
    let numbers: Option<Vec<usize>> = ranges
        .iter()
        .map(|item| doc.resolve(Some(item)).as_usize())
        .collect();
    let numbers = numbers
        .filter(|numbers| numbers.len() >= 4 && numbers.len() % 2 == 0)
        .ok_or("has no byte range that can be checked")?;
    // From the start of the file, in order, each inside it, with the
    // signature value and nothing else between two of them.
    let mut end = 0;
    for (index, &[start, length]) in numbers.as_chunks::<2>().0.iter().enumerate() {
        let after = start
            .checked_add(length)
            .filter(|&after| after <= data.len() && (index > 0 || start == 0) && start >= end)
            .ok_or("names bytes the file does not have, or not in order")?;
        if index > 0 {
            let gap = &data[end..start];
            let value = gap
                .strip_prefix(b"<")
                .and_then(|gap| gap.strip_suffix(b">"))
                .is_some_and(|digits| {
                    digits
                        .iter()
                        .all(|&b| b.is_ascii_hexdigit() || is_whitespace(b))
                });
            if !value {
                return Err("leaves out of what it signs more than its own value");
            }
        }
        end = after;
    }
    if !matches!(dict.get(b"Contents"), Some(Value::String(_))) {
        return Err("has no value of its own");
    }
    Ok(numbers)
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
    let mut fallback = Fallback::default();
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
            fallback.names(data, body, offset, out);
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
                out.limit(budget.decode_limit());
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
        drop(index);
        // Entries may all point at one large value; reading it for each of
        // them is bounded as reading the objects of the file is.
        let work_limit = decoded.len() as u64 * 8 + (1 << 20);
        let mut work = 0u64;
        let mut unparsed = Vec::new();
        for (number, start) in entries {
            let nodes_left = doc.nodes_left.get();
            let mut parser = Parser::new(&decoded, start, nodes_left);
            let is_value = parser.skip_value();
            work += parser.pos.saturating_sub(start) as u64;
            if parser.nodes_left == 0 || nodes_left <= 1 || work > work_limit {
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
                    unparsed.push(start);
                }
            }
        }
        // Every one is reported at the stream's offset, so the order they
        // are looked at in is free: the order they start in.
        unparsed.sort_unstable();
        unparsed.dedup();
        let mut fallback = Fallback::default();
        for start in unparsed {
            fallback.names(&decoded, start, offset, out);
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
    if let Value::Dict(dict) = &value {
        for key in TREE_LINKS {
            let named = match dict.get(key) {
                Some(Value::Ref(number)) => std::slice::from_ref(number),
                Some(Value::Array(items)) => {
                    let numbers = items.iter().filter_map(as_ref);
                    out.links
                        .extend(numbers.map(|number| (object.number, number)));
                    &[]
                }
                _ => &[],
            };
            out.links
                .extend(named.iter().map(|&number| (object.number, number)));
        }
    }
    value
}

/// The area of a rectangle given as `[x0 y0 x1 y1]`.
fn area(doc: &Document<'_>, value: Option<&Value>) -> Option<f64> {
    let Value::Array(corners) = doc.resolve(value) else {
        return None;
    };
    let [x0, y0, x1, y1] = &corners[..] else {
        return None;
    };
    let number = |value| doc.resolve(Some(value)).as_number();
    let width = number(x1)? - number(x0)?;
    let height = number(y1)? - number(y0)?;
    Some((width * height).abs()).filter(|area| area.is_finite())
}

/// Keep the largest page, and the largest link that opens a web page.
fn measure_links(doc: &Document<'_>, dict: &Dict, offset: usize, out: &mut Output<'_>) {
    if let Some(page) = area(doc, dict.get(b"MediaBox")) {
        out.page_area = out.page_area.max(page);
    }
    if !doc.name_is(dict.get(b"Subtype"), b"Link") {
        return;
    }
    let opens_page = match doc.resolve(dict.get(b"A")) {
        Value::Dict(action) => doc.name_is(action.get(b"S"), b"URI"),
        _ => false,
    };
    if let Some(link) = area(doc, dict.get(b"Rect")).filter(|_| opens_page)
        && out.web_link.is_none_or(|(largest, _)| link > largest)
    {
        out.web_link = Some((link, offset));
    }
}

/// A link to a web page this large a share of the page or more. Text links
/// are a line high; a link this size lies over a picture or most of the
/// page, so that a click anywhere opens it. Many of the phishing documents
/// that carry nothing but that are such: a picture of a document, or of a
/// button, with the link over it. On CIC-Evasive-PDFMal2022, a fifth of the
/// page took 102 of the 396 malicious files that were clean and none of the
/// clean ones; a tenth took 171, and 15 clean files, whose logos link to
/// their publisher.
const LURE_SHARE: f64 = 0.2;

/// See [`LURE_SHARE`].
fn link_lure(out: &mut Output<'_>) {
    if let Some((link, offset)) = out.web_link
        && out.page_area > 0.0
        && link / out.page_area >= LURE_SHARE
    {
        let share = (link / out.page_area * 100.0).min(100.0);
        out.report(
            "pdf.link_lure",
            Severity::Low,
            &format!("a link to a web page covers {share:.0}% of a page"),
            offset,
        );
    }
}

/// The keys that lead down a tree or along a chain: the kids of the page
/// tree, of name and number trees and of form fields; the first child and
/// the next sibling of an outline item, and the next of a chain of actions;
/// the object stream another extends.
const TREE_LINKS: [&[u8]; 4] = [b"Kids", b"First", b"Next", b"Extends"];

/// Trees and chains that lead back to where they started. A reader that
/// follows one goes round it for as long as it is let; none of them loops in
/// a document a program wrote.
fn reference_loops(doc: &Document<'_>, out: &mut Output<'_>) {
    let mut next: HashMap<u32, Vec<u32>> = HashMap::new();
    for &(from, to) in &out.links {
        next.entry(from).or_default().push(to);
    }
    // Depth first, with the objects on the current path and those done.
    // From the lowest object number, so that the loop reported is the same
    // from one scan to the next.
    let mut starts: Vec<u32> = next.keys().copied().collect();
    starts.sort_unstable();
    let (mut on_path, mut done) = (HashSet::new(), HashSet::new());
    for start in starts {
        if done.contains(&start) {
            continue;
        }
        let mut stack = vec![(start, 0)];
        on_path.insert(start);
        while let Some((node, child)) = stack.pop() {
            let Some(&to) = next.get(&node).and_then(|children| children.get(child)) else {
                on_path.remove(&node);
                done.insert(node);
                continue;
            };
            stack.push((node, child + 1));
            if on_path.contains(&to) {
                let offset = doc
                    .by_number
                    .get(&to)
                    .map_or(0, |&index| doc.objects[index as usize].offset);
                return out.report(
                    "pdf.reference_loop",
                    Severity::Medium,
                    "a page tree, outline, chain of actions or object stream leads back to itself",
                    offset,
                );
            }
            if !done.contains(&to) {
                on_path.insert(to);
                stack.push((to, 0));
            }
        }
    }
}

/// Inspect every dictionary reachable inside one object.
fn walk(doc: &Document<'_>, value: &Value, offset: usize, out: &mut Output<'_>) {
    match value {
        Value::Dict(dict) => {
            check_postscript(doc, dict, offset, out);
            if let Some(files) = dict.get(b"EF")
                && !matches!(doc.resolve(Some(files)), Value::Array(_))
                && !is_manifest_spec(doc, dict)
            {
                out.foreign_attachment = true;
            }
            measure_links(doc, dict, offset, out);
            if out.twice.is_none() {
                out.twice = given_twice(dict).map(|key| (key, offset));
            }
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

/// Keys that decide what a document shows, of which a reader takes the
/// first or the last when a dictionary has two.
const DECIDING_KEYS: [&[u8]; 9] = [
    b"Length",
    b"Contents",
    b"Kids",
    b"Count",
    b"Parent",
    b"Type",
    b"Filter",
    b"Root",
    b"Pages",
];

/// The first of [`DECIDING_KEYS`] that `dict` gives two different values.
fn given_twice(dict: &Dict) -> Option<&'static str> {
    if dict.0.len() < 2 {
        return None;
    }
    DECIDING_KEYS.iter().find_map(|&key| {
        let mut values = dict.all(key);
        let first = values.next()?;
        values
            .any(|other| other != first)
            .then(|| std::str::from_utf8(key).unwrap_or_default())
    })
}

/// The filters the format defines, which are all a reader may apply.
const FILTERS: [&[u8]; 17] = [
    b"ASCIIHexDecode",
    b"AHx",
    b"ASCII85Decode",
    b"A85",
    b"LZWDecode",
    b"LZW",
    b"FlateDecode",
    b"Fl",
    b"RunLengthDecode",
    b"RL",
    b"CCITTFaxDecode",
    b"CCF",
    b"JBIG2Decode",
    b"DCTDecode",
    b"DCT",
    b"JPXDecode",
    b"Crypt",
];

/// Structures that a reader that follows the format and one that repairs
/// what it reads take for two different documents: the content masking of
/// pdf-insecurity.org, which shows one page to one reader and another to
/// the next, and to a scanner that reads the file as one of them does.
/// What a scanner can see of it: page content whose `/Length` does not
/// end at its `endstream`, or whose data does not start on the line after
/// its `stream`; a deciding key given twice; a cross-reference table that
/// sends a reader to a different object than the one it names, to one that
/// is commented out, or that marks an entry neither in use nor free. Also
/// reported as malformed: a filter the format does not define, which some
/// readers skip and others stop at.
fn ambiguities(doc: &Document<'_>, out: &mut Output<'_>) {
    let data = doc.data;
    let mut found: Option<(String, usize)> = out
        .twice
        .map(|(key, offset)| (format!("a dictionary gives /{key} two values"), offset));
    let mut unknown_filter = None;
    let contents: HashSet<u32> = out.contents.iter().copied().collect();
    for (index, object) in doc.objects.iter().enumerate() {
        if !object.is_stream() || object.packed() {
            continue;
        }
        let latest = doc.by_number.get(&object.number) == Some(&(index as u32));
        let Some(dict) = doc.kept(index as u32).as_dict() else {
            continue;
        };
        let filters = match doc.resolve(dict.get(b"Filter")) {
            Value::Name(name) => vec![name.text()],
            Value::Array(items) => items
                .iter()
                .filter_map(|item| doc.resolve(Some(item)).as_name())
                .collect(),
            _ => Vec::new(),
        };
        if unknown_filter.is_none() && filters.iter().any(|filter| !FILTERS.contains(filter)) {
            unknown_filter = Some(object.offset);
        }
        if found.is_some() || !latest || !contents.contains(&object.number) {
            continue;
        }
        // Where the keyword stands, and the line after it.
        let keyword = object.stream_start - 1;
        let keyword = memmem::rfind(&data[..=keyword.min(data.len() - 1)], b"stream");
        let line = keyword.map(|at| &data[at + 6..object.stream_start]);
        if !matches!(line, Some(b"\r\n" | b"\n")) {
            found = Some((
                "page content does not start on the line after `stream`".into(),
                object.offset,
            ));
            continue;
        }
        let rest = &data[object.stream_start..];
        let length = doc.resolve(dict.get(b"Length")).as_usize();
        let Some(after) = length
            .and_then(|length| rest.get(length..))
            .map(<[u8]>::trim_ascii_start)
            .filter(|after| after.starts_with(b"endstream"))
        else {
            found = Some((
                "the /Length of page content does not end at its `endstream`".into(),
                object.offset,
            ));
            continue;
        };
        let inside = &rest[..length.unwrap_or_default()];
        work::searched(inside.len(), None, 0);
        if memmem::find(inside, b"endstream").is_some() {
            found = Some((
                "page content holds an `endstream` before the one its /Length ends at".into(),
                object.offset,
            ));
            continue;
        }
        let after = &after[b"endstream".len()..];
        let closed = |rest: &[u8]| rest.first().is_none_or(|&byte| !is_regular(byte));
        let object_end = after.trim_ascii_start();
        if !closed(after) || !object_end.starts_with(b"endobj") || !closed(&object_end[6..]) {
            found = Some((
                "page content is not followed by `endobj`".into(),
                object.offset,
            ));
        }
    }
    if found.is_none() {
        found = cross_reference_confusion(doc).map(|(why, at)| (why.to_string(), at));
    }
    if let Some(offset) = unknown_filter {
        out.malformed("stream names a filter the format does not define", offset);
    }
    if let Some((why, offset)) = found {
        out.report(
            "pdf.ambiguous_structure",
            Severity::Medium,
            &format!("{why}: readers differ on what the document shows"),
            offset,
        );
    }
}

/// See [`ambiguities`]: an entry of a cross-reference table that sends a
/// reader that trusts it elsewhere than one that reads the objects where
/// they stand, and where the table is.
fn cross_reference_confusion(doc: &Document<'_>) -> Option<(&'static str, usize)> {
    let data = doc.data;
    // After bytes before the header, readers count from either, and a table
    // that is right for one is wrong for the other: that is malformed.
    let prefixed = !data.starts_with(b"%PDF-");
    for at in memmem::find_iter(data, b"xref") {
        // A table, not the `startxref` keyword or a name.
        if at >= 5 && &data[at - 5..at] == b"start" || at > 0 && !is_whitespace(data[at - 1]) {
            continue;
        }
        let mut parser = Parser::new(data, at + 4, usize::MAX);
        loop {
            parser.skip_whitespace();
            let Some(first) = parser.integer() else {
                break;
            };
            parser.skip_whitespace();
            let Some(count) = parser.integer() else {
                break;
            };
            for number in first..first.saturating_add(count) {
                parser.skip_whitespace();
                let (Some(offset), Some(_generation)) = ({
                    let offset = parser.integer();
                    parser.skip_whitespace();
                    (offset, parser.integer())
                }) else {
                    return None;
                };
                parser.skip_whitespace();
                let kind = parser.rest().first().copied();
                parser.pos += 1;
                match kind {
                    Some(b'f') => continue,
                    Some(b'n') => {}
                    _ => return Some(("a cross-reference entry is neither in use nor free", at)),
                }
                let Some(place) = data.get(offset..) else {
                    continue;
                };
                // A `%` that starts the line, or the place itself.
                let line = &data[..offset];
                let line = &line[line
                    .iter()
                    .rposition(|&byte| byte == b'\n' || byte == b'\r')
                    .map_or(0, |at| at + 1)..];
                work::done(line.len());
                let (commented, place) = match place.strip_prefix(b"%") {
                    Some(rest) => (true, rest),
                    // A writer that put the next object right after the
                    // `%%EOF` of an update is not hiding it.
                    None => {
                        let line = line.trim_ascii_start();
                        let digit = place.first().is_some_and(u8::is_ascii_digit);
                        (
                            digit && line.starts_with(b"%") && !line.starts_with(b"%%EOF"),
                            place,
                        )
                    }
                };
                let mut header = Parser::new(place, 0, 16);
                let named = header.integer();
                header.skip_whitespace();
                let generation = header.integer();
                header.skip_whitespace();
                if generation.is_none() || !header.rest().starts_with(b"obj") {
                    continue;
                }
                if named != Some(number) && !prefixed {
                    return Some((
                        "the cross-reference table sends a reader to another object",
                        offset,
                    ));
                }
                if commented {
                    return Some((
                        "the cross-reference table sends a reader to an object that is commented out",
                        offset,
                    ));
                }
            }
        }
    }
    objects_after_the_end(doc)
}

/// See [`ambiguities`]: an object after the last `startxref`, which no
/// table lists, that defines again one defined before it: an update that
/// a reader that repairs what it reads applies, and one that follows the
/// tables does not.
fn objects_after_the_end(doc: &Document<'_>) -> Option<(&'static str, usize)> {
    let last = memmem::rfind(doc.data, b"startxref")?;
    work::done(doc.data.len() - last + doc.objects.len());
    let before: HashSet<u32> = (doc.objects.iter())
        .filter(|object| !object.packed() && object.offset < last)
        .map(|object| object.number)
        .collect();
    (doc.objects.iter())
        .find(|object| !object.packed() && object.offset > last && before.contains(&object.number))
        .map(|object| {
            (
                "an object is defined again after the last cross-reference",
                object.offset,
            )
        })
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
                out.attachment(offset);
                if let Value::Dict(files) = files {
                    let named = files.0.iter().filter_map(|(_, file)| as_ref(file));
                    let start = out.attached.len();
                    out.attached.extend(named);
                    out.embedded.extend_from_slice(&out.attached[start..]);
                }
            }
        },
        b"EmbeddedFiles" if !is_empty_tree(doc, value) => out.attachment(offset),
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
///
/// Attachments that are all C2PA manifests, the provenance record that
/// document and image programs now write, are reported at Info. A manifest
/// is only taken for one when its content is: with a `budget` the files are
/// decoded to tell, and without one, in a document that cannot be read,
/// they are attachments.
fn report_attachments(doc: &Document<'_>, budget: Option<&mut Budget>, out: &mut Output<'_>) {
    let packets: HashSet<usize> = out
        .xfa
        .iter()
        .filter_map(|number| doc.by_number.get(number))
        .map(|&index| doc.objects[index as usize].offset)
        .collect();
    let streams: HashSet<usize> = std::mem::take(&mut out.file_streams)
        .into_iter()
        .filter(|offset| !packets.contains(offset))
        .collect();
    let sightings = std::mem::take(&mut out.attachments);
    let attached = std::mem::take(&mut out.attached);
    let Some(first) = sightings.first().or(streams.iter().min()).copied() else {
        return;
    };
    let mut files: Vec<usize> = doc
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| streams.contains(&object.offset))
        .map(|(index, _)| index)
        .chain(
            attached
                .iter()
                .filter_map(|number| doc.by_number.get(number).map(|&index| index as usize)),
        )
        .collect();
    files.sort_unstable();
    files.dedup();
    let manifests = !std::mem::take(&mut out.foreign_attachment)
        && budget.is_some_and(|budget| {
            !files.is_empty()
                && files.len() <= MAX_MANIFESTS
                && files
                    .iter()
                    .all(|&index| is_c2pa_manifest(doc, index, budget))
        });
    if manifests {
        out.report(
            "pdf.c2pa_manifest",
            Severity::Info,
            "document carries a C2PA provenance manifest (Content Credentials)",
            first,
        );
    } else {
        embedded_file(first, out);
    }
}

/// A file specification of a C2PA manifest says so, and names the file, if
/// it does, without an extension or with `.c2pa`: a reader lists it with
/// the attachments, and one named for a page or a program would be opened
/// as one.
fn is_manifest_spec(doc: &Document<'_>, spec: &Dict) -> bool {
    let named_safely = |key: &[u8]| match spec.get(key) {
        None => true,
        Some(name) => doc.resolve(Some(name)).as_string().is_some_and(|name| {
            // Text strings may be UTF-16 with a byte order mark; the letters
            // of a file name are then every other byte.
            let name: Vec<u8> = match name.strip_prefix(b"\xFE\xFF") {
                Some(wide) => wide.iter().skip(1).step_by(2).copied().collect(),
                None => name.to_vec(),
            };
            let file = name
                .rsplit(|&byte| byte == b'/' || byte == b'\\')
                .next()
                .unwrap_or(&[]);
            !file.contains(&b'.') || file.to_ascii_lowercase().ends_with(b".c2pa")
        }),
    };
    doc.name_is(spec.get(b"AFRelationship"), b"C2PA_Manifest")
        && named_safely(b"F")
        && named_safely(b"UF")
}

/// More files than this are not looked at as manifests: a document has one,
/// or one for each of the documents it was made from.
const MAX_MANIFESTS: usize = 16;

/// Whether an object is a stream of the type C2PA gives its manifests
/// whose content is a manifest store.
fn is_c2pa_manifest(doc: &Document<'_>, index: usize, budget: &mut Budget) -> bool {
    let object = &doc.objects[index];
    let value = doc.value(object);
    let Some(dict) = value.as_dict().filter(|_| object.is_stream()) else {
        return false;
    };
    doc.name_is(dict.get(b"Subtype"), b"application/c2pa")
        && doc
            .decode(object, dict, budget)
            .is_ok_and(|content| c2pa_store_data(&content).is_some())
}

/// The UUID of a C2PA manifest store's description box.
const C2PA_UUID: &[u8; 16] = b"c2pa\x00\x11\x00\x10\x80\x00\x00\xaa\x00\x38\x9b\x71";

/// What a C2PA manifest store carries as data, to be scanned as files: the
/// content of its binary boxes, a thumbnail or an icon. None if it is not a
/// store: one JUMBF superbox (`jumb`) over all of the data, the first of
/// whose boxes is a description (`jumd`) with the C2PA UUID and the label
/// `c2pa`, and every box down the tree one that C2PA writes, filling its
/// superbox exactly.
fn c2pa_store_data(data: &[u8]) -> Option<Vec<&[u8]>> {
    let top = boxes(data)?;
    let [(b"jumb", store)] = top.as_slice() else {
        return None;
    };
    let children = boxes(store)?;
    let (b"jumd", description) = children.first()? else {
        return None;
    };
    // The UUID, a byte of flags of which 2 says a label follows, and the
    // label, ended by a zero byte.
    let labelled = description.get(16).is_some_and(|flags| flags & 2 != 0);
    let label = description
        .get(17..)
        .is_some_and(|label| label.starts_with(b"c2pa\0"));
    if !(description.starts_with(C2PA_UUID) && labelled && label) {
        return None;
    }
    let mut carried = Vec::new();
    jumbf_data(store, 0, &mut carried)?;
    Some(carried)
}

/// Superboxes nest this deep at most: a store, a manifest, its assertions,
/// and one more for what an assertion may hold.
const MAX_JUMBF_DEPTH: usize = 6;

/// Gather the content of the binary boxes of a superbox's content, or None
/// if a box is not one C2PA writes or the boxes do not fill it.
fn jumbf_data<'d>(content: &'d [u8], depth: usize, carried: &mut Vec<&'d [u8]>) -> Option<()> {
    if depth > MAX_JUMBF_DEPTH {
        return None;
    }
    for (kind, inner) in boxes(content)? {
        match kind {
            b"jumb" => jumbf_data(inner, depth + 1, carried)?,
            b"bidb" => carried.push(inner),
            b"uuid" => carried.push(inner.get(16..)?),
            b"jumd" | b"cbor" | b"json" | b"bfdb" | b"c2sh" | b"free" => {}
            _ => return None,
        }
    }
    Some(())
}

/// The ISO boxes that fill `data` exactly, or none if they do not.
fn boxes(data: &[u8]) -> Option<Vec<(&[u8; 4], &[u8])>> {
    let mut found = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let size = u32::from_be_bytes(data.get(pos..pos + 4)?.try_into().ok()?) as usize;
        let kind: &[u8; 4] = data.get(pos + 4..pos + 8)?.try_into().ok()?;
        let (header, size) = match size {
            0 => (8, data.len() - pos),
            1 => {
                let wide = u64::from_be_bytes(data.get(pos + 8..pos + 16)?.try_into().ok()?);
                (16, usize::try_from(wide).ok()?)
            }
            size => (8, size),
        };
        let end = pos
            .checked_add(size)
            .filter(|&end| size >= header && end <= data.len())?;
        found.push((kind, &data[pos + header..end]));
        pos = end;
    }
    Some(found)
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

/// Where the names of objects the parser rejected have been looked for in
/// one source, for objects taken in the order they start. Each region runs
/// from an object to the next `endobj` or `stream`; regions of objects close
/// together overlap, and what was read for one is not read again for the
/// next, nor is the next keyword looked for again from each of them.
#[derive(Default)]
struct Fallback {
    /// Where the next region starts reading: the last name read, which may
    /// have been cut short by the end of its region.
    resume: usize,
    /// The next `endobj` and `stream` from where the last region started,
    /// `usize::MAX` for none, and where that was.
    ends: [usize; 2],
    searched_from: Option<usize>,
}

impl Fallback {
    /// For an object the parser rejected, whose value starts at `start` in
    /// `source`: readers are more forgiving than this parser, so every name
    /// token in the object is still checked by itself.
    fn names(&mut self, source: &[u8], start: usize, offset: usize, out: &mut Output<'_>) {
        if self.searched_from.is_none_or(|from| from > start) {
            *self = Self::default();
        }
        for (end, keyword) in self.ends.iter_mut().zip([&b"endobj"[..], b"stream"]) {
            if self.searched_from.is_none() || (*end != usize::MAX && *end < start) {
                let rest = source.get(start..).unwrap_or_default();
                let found = memmem::find(rest, keyword);
                work::searched(rest.len(), found, keyword.len());
                *end = found.map_or(usize::MAX, |at| start + at);
            }
        }
        self.searched_from = Some(start);
        let end = self.ends[0]
            .min(self.ends[1])
            .min(start.saturating_add(FALLBACK_WINDOW))
            .min(source.len());
        let from = start.max(self.resume);
        if from >= end {
            return;
        }
        self.resume = end;
        let region = &source[from..end];
        let mut parser = Parser::new(region, 0, usize::MAX);
        while let Some(slash) = memchr::memchr(b'/', parser.rest()) {
            parser.pos += slash;
            self.resume = from + parser.pos;
            let Some(name) = parser.name() else {
                break;
            };
            fallback_name(&name, offset, out);
        }
    }
}

/// See [`Fallback::names`].
fn fallback_name(name: &Name, offset: usize, out: &mut Output<'_>) {
    check_name(name, offset, out);
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
                // A manifest store is not a file of its own, but what it
                // carries is.
                let manifest = doc.name_is(dict.get(b"Subtype"), b"application/c2pa");
                let parts = manifest.then(|| c2pa_store_data(&content)).flatten();
                let mut inner = Vec::new();
                for part in parts.unwrap_or_else(|| vec![&content]) {
                    nested(part, budget, &mut inner);
                }
                for finding in inner {
                    if finding.code.starts_with("limit.") {
                        out.findings.push(finding);
                    } else {
                        let message = format!("embedded file: {}", finding.message);
                        out.report(finding.code, finding.severity, &message, object.offset);
                    }
                }
            }
            Err(DecodeError::Limit) => out.limit(budget.decode_limit()),
            Err(_) => out.malformed("embedded file cannot be decoded", object.offset),
        }
        budget.leave();
    }
}

/// Search page content, form XObjects, patterns and glyph procedures for the
/// `PS` operator, which hands its string operand to a PostScript interpreter.
/// The streams are read a block at a time as they are decoded.
fn scan_content_streams(doc: &Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    // A page's content is a stream or an array of them, and the array may
    // stand in an object stream, which the walk that names it has not
    // opened yet: an array named here holds the streams.
    let mut named = Vec::new();
    let mut misplaced = None;
    for &index in out
        .contents
        .iter()
        .filter_map(|number| doc.by_number.get(number))
    {
        let object = &doc.objects[index as usize];
        match doc.kept(index) {
            Value::Array(items) => {
                for item in items {
                    match item {
                        Value::Ref(number) => named.extend(doc.by_number.get(number)),
                        _ => misplaced = misplaced.or(Some(object.offset)),
                    }
                }
            }
            _ => named.push(index),
        }
    }
    if let Some(offset) = misplaced {
        out.malformed("page content is not a stream", offset);
    }
    let named = named.into_iter().map(|index| index as usize);
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
            // Content is streams; an array or a dictionary in its place is
            // what readers that follow it into itself are given.
            if matches!(value, Value::Array(_) | Value::Dict(_)) {
                out.malformed("page content is not a stream", object.offset);
            }
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
            Err(DecodeError::Limit) => return out.limit(budget.decode_limit()),
            // A stream no reader can decode draws nothing.
            Err(_) => {}
        }
    }
    draw_recursion(doc, &draws, out);
}

/// A form that draws itself, directly or through other forms. A renderer
/// follows the calls until it runs out of stack or of time.
///
/// The calls go through the names a form draws, each looked up in a table
/// of XObjects: a form calls the forms its table lists under that name.
/// Forms that share a table share what each name in it leads to, so the
/// graph walked has a node for each table and name between the forms, and
/// as many edges as there are names drawn and entries listed. Joining every
/// form to every form it calls would be their product.
fn draw_recursion(doc: &Document<'_>, draws: &HashMap<usize, Vec<Drawn>>, out: &mut Output<'_>) {
    let mut graph = Calls::default();
    // Forms without resources of their own draw with those of whatever
    // draws them: any dictionary of XObjects in the document may apply.
    let mut borrowing = Vec::new();
    let mut forms: Vec<usize> = draws.keys().copied().collect();
    forms.sort_unstable();
    for &index in &forms {
        let value = doc.value(&doc.objects[index]);
        let Some(dict) = value.as_dict() else {
            continue;
        };
        let resources = dict.get(b"Resources");
        let own = doc.resolve(resources).as_dict().and_then(|resources_dict| {
            let item = resources_dict.get(b"XObject");
            let table = doc.resolve(item).as_dict()?;
            // A table reached through a reference is kept, and may be
            // shared; one written in the form is the form's alone.
            let shared =
                matches!(resources, Some(Value::Ref(_))) || matches!(item, Some(Value::Ref(_)));
            Some((table, shared))
        });
        graph.forms.entry(index).or_default();
        match own {
            Some((table, shared)) => {
                let id = if shared {
                    TableId::Kept(std::ptr::from_ref(table) as usize)
                } else {
                    TableId::Own(index)
                };
                graph
                    .tables
                    .entry(id)
                    .or_insert_with(|| TableIndex::of(doc, table, draws, None));
                graph.draw(index, id, &draws[&index]);
            }
            None => borrowing.push(index),
        }
    }
    if !borrowing.is_empty() {
        let mut wanted = Wanted::default();
        for index in &borrowing {
            wanted.add(&draws[index]);
        }
        let mut every = TableIndex::default();
        let mut kept = HashSet::new();
        for object in &doc.objects {
            let value = doc.value(object);
            every.add_tables(doc, &value, draws, &wanted, &mut kept);
        }
        every.finish();
        graph.tables.insert(TableId::Every, every);
        for index in borrowing {
            graph.draw(index, TableId::Every, &draws[&index]);
        }
    }
    if let Some(form) = graph.cycle() {
        out.report(
            "pdf.draw_recursion",
            Severity::Medium,
            "form draws itself; rendering it never ends",
            doc.objects[form].offset,
        );
    }
}

/// Which table of XObjects a name is looked up in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum TableId {
    /// One reached through a reference, which is kept where it is: by its
    /// address.
    Kept(usize),
    /// One written in the form at this index.
    Own(usize),
    /// Every table in the document, for forms that have none.
    Every,
}

/// The names a form draws, as the table it draws from is searched for them.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Name(Vec<u8>),
    /// A name too long to have been kept: any key that may have been as
    /// long.
    Long,
}

impl Key {
    fn of(drawn: &Drawn) -> Self {
        match drawn {
            Drawn::Name(name) => Self::Name(name.clone()),
            Drawn::Long => Self::Long,
        }
    }
}

/// The names that forms without tables of their own draw: the only ones
/// looked for in every table.
#[derive(Default)]
struct Wanted {
    names: HashSet<Vec<u8>>,
    long: bool,
}

impl Wanted {
    fn add(&mut self, drawn: &[Drawn]) {
        for name in drawn {
            match name {
                Drawn::Name(name) => {
                    self.names.insert(name.clone());
                }
                Drawn::Long => self.long = true,
            }
        }
    }
}

/// What each name of a table leads to: the forms, among those that draw
/// anything, that it lists under that name.
#[derive(Default)]
struct TableIndex {
    names: HashMap<Vec<u8>, Vec<usize>>,
    /// The forms listed under names a name too long to be kept may be.
    long: Vec<usize>,
}

impl TableIndex {
    fn of(
        doc: &Document<'_>,
        table: &Dict,
        draws: &HashMap<usize, Vec<Drawn>>,
        wanted: Option<&Wanted>,
    ) -> Self {
        let mut index = Self::default();
        index.add(doc, table, draws, wanted);
        index.finish();
        index
    }

    fn add(
        &mut self,
        doc: &Document<'_>,
        table: &Dict,
        draws: &HashMap<usize, Vec<Drawn>>,
        wanted: Option<&Wanted>,
    ) {
        for (key, item) in &table.0 {
            let Some(target) = as_ref(item)
                .and_then(|number| doc.by_number.get(&number))
                .map(|&index| index as usize)
                .filter(|target| draws.contains_key(target))
            else {
                continue;
            };
            let key = key.text();
            if wanted.is_none_or(|wanted| wanted.names.contains(key)) {
                self.names.entry(key.to_vec()).or_default().push(target);
            }
            if wanted.is_none_or(|wanted| wanted.long) && Drawn::Long.is(key) {
                self.long.push(target);
            }
        }
    }

    /// Every dictionary stored under `/XObject` in `value`. One reached
    /// through a reference is added once, however many objects name it.
    fn add_tables(
        &mut self,
        doc: &Document<'_>,
        value: &Value,
        draws: &HashMap<usize, Vec<Drawn>>,
        wanted: &Wanted,
        kept: &mut HashSet<usize>,
    ) {
        match value {
            Value::Dict(dict) => {
                for (key, item) in &dict.0 {
                    if key.text() == b"XObject"
                        && let Some(table) = doc.resolve(Some(item)).as_dict()
                        && (!matches!(item, Value::Ref(_))
                            || kept.insert(std::ptr::from_ref(table) as usize))
                    {
                        self.add(doc, table, draws, Some(wanted));
                    }
                    self.add_tables(doc, item, draws, wanted, kept);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.add_tables(doc, item, draws, wanted, kept);
                }
            }
            _ => {}
        }
    }

    fn finish(&mut self) {
        for targets in self.names.values_mut().chain([&mut self.long]) {
            targets.sort_unstable();
            targets.dedup();
        }
    }

    fn targets(&self, key: &Key) -> &[usize] {
        match key {
            Key::Name(name) => self.names.get(name).map_or(&[], Vec::as_slice),
            Key::Long => &self.long,
        }
    }
}

/// The calls between forms, through the names they draw.
#[derive(Default)]
struct Calls {
    /// For each form that draws anything, the names it draws, as nodes.
    forms: HashMap<usize, Vec<usize>>,
    tables: HashMap<TableId, TableIndex>,
    /// Each table and name a form draws from, once.
    nodes: HashMap<(TableId, Key), usize>,
    /// What each of those is looked up in, and for what.
    lookups: Vec<(TableId, Key)>,
}

impl Calls {
    /// `form` draws `names` from `table`.
    fn draw(&mut self, form: usize, table: TableId, names: &[Drawn]) {
        let mut nodes = Vec::with_capacity(names.len());
        for name in names {
            let key = (table, Key::of(name));
            let next = self.lookups.len();
            let node = *self.nodes.entry(key.clone()).or_insert(next);
            if node == next {
                self.lookups.push(key);
            }
            nodes.push(node);
        }
        nodes.sort_unstable();
        nodes.dedup();
        self.forms.insert(form, nodes);
    }

    fn called(&self, node: usize) -> &[usize] {
        let (table, key) = &self.lookups[node];
        self.tables[table].targets(key)
    }

    /// A form on a cycle of calls, if there is one: depth first, with what
    /// is on the current path marked.
    fn cycle(&self) -> Option<usize> {
        #[derive(Clone, Copy, PartialEq)]
        enum State {
            OnPath,
            Done,
        }
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum At {
            Form(usize),
            Name(usize),
        }
        let mut states: HashMap<At, State> = HashMap::new();
        let mut starts: Vec<usize> = self.forms.keys().copied().collect();
        starts.sort_unstable();
        for start in starts {
            if states.contains_key(&At::Form(start)) {
                continue;
            }
            states.insert(At::Form(start), State::OnPath);
            let mut path = vec![(At::Form(start), 0usize)];
            while let Some(&mut (at, ref mut next)) = path.last_mut() {
                let following = match at {
                    At::Form(form) => self
                        .forms
                        .get(&form)
                        .and_then(|names| names.get(*next))
                        .map(|&node| At::Name(node)),
                    At::Name(node) => self.called(node).get(*next).map(|&form| At::Form(form)),
                };
                let Some(target) = following else {
                    states.insert(at, State::Done);
                    path.pop();
                    continue;
                };
                *next += 1;
                work::done(1);
                match states.get(&target) {
                    Some(State::OnPath) => {
                        // The cycle closes at a form, or at a name that the
                        // form after it on the path was found through.
                        return match target {
                            At::Form(form) => Some(form),
                            At::Name(_) => path
                                .iter()
                                .skip_while(|(on, _)| *on != target)
                                .find_map(|(on, _)| match on {
                                    At::Form(form) => Some(*form),
                                    At::Name(_) => None,
                                }),
                        };
                    }
                    Some(State::Done) => {}
                    None => {
                        states.insert(target, State::OnPath);
                        path.push((target, 0));
                    }
                }
            }
        }
        None
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
            Err(DecodeError::Limit) => return out.limit(budget.decode_limit()),
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

    /// A JUMBF box of `kind` around `content`.
    fn jumbf(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let size = (content.len() + 8) as u32;
        [&size.to_be_bytes()[..], kind, content].concat()
    }

    /// A C2PA manifest store holding one manifest box.
    fn manifest_store() -> Vec<u8> {
        let description = [&C2PA_UUID[..], b"\x03c2pa\0"].concat();
        let manifest = jumbf(b"jumb", &jumbf(b"jumd", b"c2ma"));
        jumbf(b"jumb", &[jumbf(b"jumd", &description), manifest].concat())
    }

    /// Attached as the programs that write C2PA attach it: a file
    /// specification in the tree of attachments and in `/AF`.
    fn with_manifest(store: &[u8], others: &[&[u8]]) -> Vec<u8> {
        let filespec = "/AFRelationship /C2PA_Manifest /F (Content Credentials.c2pa)";
        with_manifest_in(filespec, store, others)
    }

    fn with_manifest_in(filespec: &str, store: &[u8], others: &[&[u8]]) -> Vec<u8> {
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /AF [4 0 R] \
            /Names << /EmbeddedFiles << /Names [(Content Credentials) 4 0 R] >> >> >>";
        let pages = b"<< /Type /Pages /Kids [] /Count 0 >>";
        let file = stream("/Type /EmbeddedFile /Subtype /application#2Fc2pa", store);
        let filespec = format!("<< /Type /Filespec {filespec} /EF << /F 3 0 R >> >>");
        let mut objects: Vec<&[u8]> = vec![catalog, pages, &file, filespec.as_bytes()];
        objects.extend_from_slice(others);
        pdf(&objects)
    }

    #[test]
    fn c2pa_manifests_are_not_attachments() {
        let manifest = [("pdf.c2pa_manifest", Severity::Info)];
        assert_eq!(run(&with_manifest(&manifest_store(), &[])), manifest);

        // Another file beside it is an attachment.
        let notes = stream("/Type /EmbeddedFile", b"plain notes");
        assert_eq!(
            codes(&with_manifest(&manifest_store(), &[&notes])),
            ["pdf.embedded_file"]
        );
        // So is a file of that type that is not a manifest store: another
        // UUID or label, bytes after the store, or a box cut short.
        let mut other_uuid = manifest_store();
        other_uuid[16] ^= 1;
        let mut other_label = manifest_store();
        other_label[33] = b'x';
        let mut longer = manifest_store();
        longer.extend_from_slice(b"MZ");
        let mut cut = manifest_store();
        cut.truncate(cut.len() - 1);
        let elf = b"\x7fELF\x02\x01".to_vec();
        for store in [other_uuid, other_label, longer, cut, elf] {
            assert_eq!(codes(&with_manifest(&store, &[]))[0], "pdf.embedded_file");
        }
        // And one whose file specification does not say it is a manifest,
        // or names it for what a reader would open as a page or a program.
        for filespec in [
            "/F (Content Credentials)",
            "/AFRelationship /Data /F (Content Credentials)",
            "/AFRelationship /C2PA_Manifest /F (Content Credentials.html)",
            "/AFRelationship /C2PA_Manifest /UF <FEFF0061002E006500780065>",
        ] {
            let file = with_manifest_in(filespec, &manifest_store(), &[]);
            assert_eq!(codes(&file), ["pdf.embedded_file"], "{filespec}");
        }
        let unnamed = with_manifest_in("/AFRelationship /C2PA_Manifest", &manifest_store(), &[]);
        assert_eq!(codes(&unnamed), ["pdf.c2pa_manifest"]);

        // What a manifest carries is scanned as files: here a program in
        // the box of a thumbnail.
        let store = manifest_store();
        let thumbnail = jumbf(b"bidb", b"\x7fELF\x02\x01");
        let carrying = jumbf(
            b"jumb",
            &[&store[8..], &jumbf(b"jumb", &thumbnail)].concat(),
        );
        assert_eq!(
            run(&with_manifest(&carrying, &[])),
            [
                ("pdf.c2pa_manifest", Severity::Info),
                ("type.executable", Severity::Critical),
            ]
        );
        // A box C2PA does not write is not part of a manifest.
        let odd = jumbf(b"jumb", &[&store[8..], &jumbf(b"mdat", b"x")].concat());
        assert_eq!(codes(&with_manifest(&odd, &[])), ["pdf.embedded_file"]);
    }

    #[test]
    fn links_over_most_of_a_page_are_lures() {
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Annots [4 0 R] >>";
        let link = |rect: &str, action: &str| {
            format!("<< /Type /Annot /Subtype /Link /Rect [{rect}] /A {action} >>")
        };
        let web = "<< /S /URI /URI (https://example.com/) >>";
        let run_with =
            |annotation: String| run(&pdf(&[PLAIN_CATALOG, PAGES, page, annotation.as_bytes()]));
        // A picture's worth of the page, a fifth of it.
        assert!(run_with(link("0 0 600 160", web)).contains(&("pdf.link_lure", Severity::Low)));
        // A line of text, and a link within the document.
        assert!(
            !codes(&pdf(&[
                PLAIN_CATALOG,
                PAGES,
                page,
                link("50 700 400 714", web).as_bytes()
            ]))
            .contains(&"pdf.link_lure")
        );
        let inside = link("0 0 600 800", "<< /S /GoTo /D [3 0 R /Fit] >>");
        assert!(
            !codes(&pdf(&[PLAIN_CATALOG, PAGES, page, inside.as_bytes()]))
                .contains(&"pdf.link_lure")
        );
    }

    #[test]
    fn trees_and_chains_that_lead_back_are_loops() {
        let looped = |objects: &[&[u8]]| codes(&pdf(objects)).contains(&"pdf.reference_loop");
        // A page tree that lists itself, or a node further down.
        let pages = b"<< /Type /Pages /Kids [3 0 R 2 0 R] /Count 2 >>";
        assert!(looped(&[PLAIN_CATALOG, pages, PAGE]));
        let pages = b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>";
        let deeper = b"<< /Type /Pages /Kids [2 0 R] /Count 1 >>";
        assert!(looped(&[PLAIN_CATALOG, pages, PAGE, deeper]));
        // Outline items whose next sibling is an earlier one; links back to
        // the previous one and the parent are what outlines have.
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >>";
        let outlines = b"<< /Type /Outlines /First 5 0 R /Last 6 0 R >>";
        let first = b"<< /Title (a) /Parent 4 0 R /Next 6 0 R >>";
        let second = b"<< /Title (b) /Parent 4 0 R /Prev 5 0 R >>";
        assert!(!looped(&[catalog, PAGES, PAGE, outlines, first, second]));
        let second = b"<< /Title (b) /Parent 4 0 R /Prev 5 0 R /Next 5 0 R >>";
        assert!(looped(&[catalog, PAGES, PAGE, outlines, first, second]));
        // A chain of actions, and an object stream that extends itself.
        let action = b"<< /S /GoTo /D [3 0 R /Fit] /Next 4 0 R >>";
        assert!(looped(&[PLAIN_CATALOG, PAGES, PAGE, action]));
        let extends = stream("/Type /ObjStm /N 0 /First 0 /Extends 4 0 R", b"");
        assert!(looped(&[PLAIN_CATALOG, PAGES, PAGE, &extends]));
    }

    #[test]
    fn content_is_streams() {
        // An array of content streams that stands in an object stream: the
        // streams are read.
        let page = b"<< /Type /Page /Parent 2 0 R /Contents 10 0 R >>";
        let inner = b"10 0 [5 0 R]";
        let packed = stream(
            "/Type /ObjStm /N 1 /First 5 /Filter /FlateDecode",
            &compress_to_vec_zlib(inner, 6),
        );
        let content = stream("", b"(x) PS");
        assert_eq!(
            codes(&pdf(&[CATALOG, PAGES, page, &packed, &content])),
            ["pdf.postscript"]
        );
        // Arrays and dictionaries in their place, which lead a reader that
        // follows them back to themselves.
        let page = b"<< /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R] >>";
        let text = stream("", b"BT ET");
        for misplaced in [&b"[6 0 R]"[..], b"<< /bar 5 0 R >>"] {
            let objects = [CATALOG, PAGES, page, &text, misplaced, b"[5 0 R]"];
            assert_eq!(codes(&pdf(&objects)), ["pdf.malformed"]);
        }
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
            data.extend_from_slice(b"\nendobj\ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
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
    }

    /// A document with one page, whose content is object 4, signed by
    /// object 5 as `ranges` says: `None` for what a signer writes.
    fn signed(ranges: Option<&str>, contents: &str) -> Vec<u8> {
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] /Contents 4 0 R >>";
        let content = stream("", b"0 0 9 9 re f");
        let placeholder = "[0 0000000000 0000000000 0000000000]";
        let signature = format!(
            "<< /Type /Sig /Filter /Adobe.PPKLite /ByteRange {placeholder} /Contents {contents} >>"
        );
        let mut data = pdf(&[PLAIN_CATALOG, PAGES, page, &content, signature.as_bytes()]);
        let at = memmem::find(&data, placeholder.as_bytes()).unwrap();
        let value = memmem::find(&data, contents.as_bytes()).unwrap();
        let after = value + contents.len();
        let written = ranges.map_or_else(
            || format!("[0 {value} {after} {}]", data.len() - after),
            str::to_string,
        );
        let written = format!("{written:<width$}", width = placeholder.len());
        data.splice(at..at + placeholder.len(), written.bytes());
        data
    }

    #[test]
    fn signatures_sign_what_they_claim() {
        let value = "<3082ABCD 00>";
        let plain = signed(None, value);
        assert_eq!(run(&plain), []);
        // Filling in a form or signing again after signing, as readers allow.
        let update =
            |body: &str| [plain.as_slice(), body.as_bytes(), b"startxref\n0\n%%EOF\n"].concat();
        let sorted = |data: &[u8]| {
            let mut found = run(data);
            found.sort();
            found
        };
        let noted = [
            ("pdf.incremental_update", Severity::Info),
            ("pdf.signature_modified", Severity::Info),
        ];
        assert_eq!(sorted(&update("6 0 obj << /T (field) >> endobj\n")), noted);
        // The page drawn anew where no signature reaches.
        let content = stream("", b"0 0 1 1 re f");
        let shadowed = format!("4 0 obj\n{}\nendobj\n", String::from_utf8_lossy(&content));
        assert_eq!(
            sorted(&update(&shadowed)),
            [
                ("pdf.incremental_update", Severity::Info),
                ("pdf.signature_modified", Severity::Info),
                ("pdf.unsigned_content", Severity::Medium),
            ]
        );

        let invalid = [("pdf.signature_invalid", Severity::Medium)];
        // Ranges past the end of the file, or not from its start.
        assert_eq!(run(&signed(Some("[0 10 20 99999]"), value)), invalid);
        assert_eq!(run(&signed(Some("[5 10 20 30]"), value)), invalid);
        // A gap that leaves the page out along with the value.
        assert_eq!(run(&signed(Some("[0 10 20 30]"), value)), invalid);
        // No value of its own, or no range at all.
        assert_eq!(run(&signed(None, "4 0 R")).first(), invalid.first());
        let removed = String::from_utf8_lossy(&plain).replace("/ByteRange", "/Removed");
        assert!(run(removed.as_bytes()).contains(&invalid[0]));
        // In an update that it does not sign: written again as it was, as
        // a reader that saves the document does, or not.
        let text = String::from_utf8_lossy(&plain).into_owned();
        let range = text.find("/ByteRange [").unwrap();
        let range = text[range..].split(']').next().unwrap().to_string() + "]";
        let again = format!("7 0 obj << /Type /Sig {range} /Contents <00> >> endobj\n");
        assert_eq!(sorted(&update(&again)), noted);
        let other = again.replace("/ByteRange [0 ", "/ByteRange [0 1");
        assert!(run(&update(&other)).contains(&invalid[0]));
        // Usage rights are not looked at.
        let rights = "<< /Type /Sig /ByteRange [0 10 20 99999] /Contents <00> \
                      /Reference [<< /TransformMethod /UR3 >>] >>";
        let catalog = format!("<< /Type /Catalog /Pages 2 0 R /Perms << /UR3 {rights} >> >>");
        assert_eq!(run(&pdf(&[catalog.as_bytes(), PAGES, PAGE])), []);
    }

    #[test]
    fn content_that_readers_find_in_different_places_is_ambiguous() {
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 9 9] /Contents 4 0 R >>";
        let with = |content: &[u8]| pdf(&[PLAIN_CATALOG, PAGES, page, content]);
        let shown = stream("", b"0 0 9 9 re f");
        assert_eq!(run(&with(&shown)), []);
        let ambiguous = [("pdf.ambiguous_structure", Severity::Medium)];
        // A /Length that reaches past a first `endstream`, which a reader
        // that looks for the keyword stops at.
        let two = stream("", b"0 0 9 9 re f\nendstream\n0 0 1 1 re f");
        assert_eq!(run(&with(&two)), ambiguous);
        // A keyword that runs on, or no `endobj` after the stream.
        let mut runs_on = shown.clone();
        runs_on.push(b'x');
        assert_eq!(run(&with(&runs_on)), ambiguous);
        let unclosed =
            String::from_utf8_lossy(&with(&shown)).replace("endstream\nendobj", "endstream\n");
        assert_eq!(run(unclosed.as_bytes()), ambiguous);
        // The page drawn anew after the last cross-reference, where only a
        // reader that repairs what it reads looks.
        let mut after = with(&shown);
        after.extend_from_slice(b"4 0 obj\n");
        after.extend_from_slice(&stream("", b"0 0 1 1 re f"));
        after.extend_from_slice(b"\nendobj\n");
        assert!(run(&after).contains(&ambiguous[0]));
        // A filter no reader is required to know.
        let unknown = stream("/Filter /Rot13Decode", b"0 0 9 9 re f");
        let found = run(&with(&unknown));
        assert!(
            found.iter().any(|(code, _)| *code == "pdf.malformed"),
            "{found:?}"
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

    /// Structures repeated to make a scanner read each part of a file again
    /// for each repetition: each is read a few times at most.
    #[test]
    fn repeated_structures_cost_what_the_file_does() {
        let file = |body: &[u8]| [b"%PDF-1.7\n".as_slice(), body, b"\n%%EOF\n"].concat();
        // What is read for a file of `size` bytes, once inflated: a few times
        // that, where reading each structure to the end once took the square.
        let cost = |data: &[u8], size: usize| {
            let (found, work) = work::counted(|| codes(data));
            assert!(work < 16 * size as u64, "{work} for {size}");
            found
        };

        // Trailers whose strings never close, each read to the end.
        let trailers =
            file(&[&b"1 0 obj << >> endobj\n"[..], &b"trailer(".repeat(200_000)].concat());
        assert!(cost(&trailers, trailers.len()).contains(&"limit.complexity"));

        // Broken objects, each of whose names was looked for up to the next
        // `endobj`, which there is none of. The last name is still found.
        let broken = file(&[b"1 0 obj >\n".repeat(100_000), b"2 0 obj > /JS\n".to_vec()].concat());
        assert_eq!(
            cost(&broken, broken.len()),
            ["pdf.malformed", "pdf.javascript"]
        );

        // `/Encrypt` in every object.
        let named: Vec<u8> = (0..200_000)
            .flat_map(|n| format!("{n} 0 obj << /Encrypt 1 >> endobj\n").into_bytes())
            .collect();
        let named = file(&named);
        assert!(cost(&named, named.len()).contains(&"pdf.encrypted"));

        // An object stream whose entries all point at one large array.
        let entries = 20_000;
        let index: String = (0..entries).map(|n| format!("{} 0 ", n + 10)).collect();
        let array = format!("[{}]", "0 ".repeat(50_000));
        let packed = compress_to_vec_zlib(format!("{index}{array}").as_bytes(), 6);
        let entries_object = stream(
            &format!(
                "/Type /ObjStm /N {entries} /First {} /Filter /FlateDecode",
                index.len()
            ),
            &packed,
        );
        let overlapping = pdf(&[PLAIN_CATALOG, PAGES, PAGE, &entries_object]);
        let inflated = overlapping.len() + index.len() + array.len();
        assert!(cost(&overlapping, inflated).contains(&"limit.complexity"));

        // Forms without resources, each drawing a name that one large table
        // lists for all of them.
        let forms = 2_000;
        let table: String = (0..20_000)
            .map(|n| format!("/X0 {} 0 R ", 2 + n % forms))
            .collect();
        let mut body = format!("1 0 obj << /Resources << /XObject << {table} >> >> >> endobj\n");
        for n in 0..forms {
            body += &format!(
                "{} 0 obj << /Subtype /Form /Length 6 >>\nstream\n/X0 Do\nendstream endobj\n",
                n + 2
            );
        }
        let forms = file(body.as_bytes());
        assert_eq!(cost(&forms, forms.len()), ["pdf.draw_recursion"]);
    }

    #[test]
    fn forms_that_share_their_resources_draw_through_them() {
        let resources = b"<< /XObject << /A 5 0 R /B 6 0 R >> >>";
        let form = |content: &[u8]| stream("/Subtype /Form /Resources 4 0 R", content);
        let (first, second) = (form(b"/B Do"), form(b"/A Do"));
        let objects = [PLAIN_CATALOG, PAGES, PAGE, &resources[..], &first, &second];
        assert_eq!(codes(&pdf(&objects)), ["pdf.draw_recursion"]);
        let leaf = form(b"0 0 9 9 re f");
        let objects = [PLAIN_CATALOG, PAGES, PAGE, &resources[..], &first, &leaf];
        assert_eq!(codes(&pdf(&objects)), [""; 0]);
    }
}
