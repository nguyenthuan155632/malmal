//! PDF analysis. The cross-reference table is deliberately ignored: it is the
//! first thing a malicious file lies about. Instead every `N G obj` in the
//! file is parsed where it stands, object streams are unpacked, and every
//! dictionary found either way is inspected for active content.

pub(crate) mod crypt;
pub(crate) mod filters;
pub(crate) mod parser;

use std::borrow::Cow;
use std::collections::HashMap;

use memchr::memmem;

use crate::detect::{self, FileType};
use crate::limits::{Budget, LimitExceeded};
use crate::report::{Finding, Severity};
use crypt::{Decryptor, StreamKind};
use filters::{DecodeError, Params};
use parser::{Dict, Name, Parser, Value, is_regular, is_whitespace};

/// Callback that scans a file extracted from the PDF.
pub(crate) type NestedScan<'a> = dyn FnMut(&[u8], &mut Budget, &mut Vec<Finding>) + 'a;

/// Parsed values kept in memory for one document.
const MAX_NODES: usize = 2_000_000;
const MAX_FILTERS: usize = 8;
/// How far past an unparsable object's start to look for names.
const FALLBACK_WINDOW: usize = 64 << 10;
/// Dictionaries naming `/Encrypt` that are tried as the source of the key.
const MAX_ENCRYPT_SOURCES: usize = 8;

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

struct Object {
    number: u32,
    generation: u16,
    /// Where the object (or the object stream holding it) starts in the file.
    offset: usize,
    value: Value,
    /// First byte of stream data, for stream objects.
    stream_start: Option<usize>,
}

struct Document<'a> {
    data: &'a [u8],
    objects: Vec<Object>,
    /// Latest definition of each object number, as incremental updates intend.
    by_number: HashMap<u32, usize>,
    /// Set when the document is encrypted and the empty password opens it.
    crypt: Option<Decryptor>,
}

impl<'a> Document<'a> {
    fn add(&mut self, object: Object) {
        self.by_number.insert(object.number, self.objects.len());
        self.objects.push(object);
    }

    /// Follow indirect references; missing values and targets resolve to null.
    fn resolve<'v>(&'v self, value: Option<&'v Value>) -> &'v Value {
        let mut value = value.unwrap_or(&NULL);
        for _ in 0..16 {
            match value {
                Value::Ref(number) => match self.by_number.get(number) {
                    Some(&index) => value = &self.objects[index].value,
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
    fn stream_data(&self, object: &Object) -> Option<&'a [u8]> {
        let dict = object.value.as_dict()?;
        let rest = self.data.get(object.stream_start?..)?;
        if let Some(length) = self.resolve(dict.get(b"Length")).as_usize()
            && let Some(after) = rest.get(length..)
            && after.trim_ascii_start().starts_with(b"endstream")
        {
            return Some(&rest[..length]);
        }
        let body = &rest[..memmem::find(rest, b"endstream").unwrap_or(rest.len())];
        Some(
            body.strip_suffix(b"\r\n")
                .or_else(|| body.strip_suffix(b"\n"))
                .or_else(|| body.strip_suffix(b"\r"))
                .unwrap_or(body),
        )
    }

    /// Stream contents with the whole filter chain undone.
    fn decode(&self, object: &Object, budget: &mut Budget) -> Result<Vec<u8>, DecodeError> {
        let dict = object.value.as_dict().ok_or(DecodeError::Corrupt)?;
        let raw = self.stream_data(object).ok_or(DecodeError::Corrupt)?;
        let filters: Vec<&[u8]> = match self.resolve(dict.get(b"Filter")) {
            Value::Null => Vec::new(),
            Value::Name(name) => vec![name.text.as_slice()],
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

        let mut data = match &self.crypt {
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
        for (index, filter) in filters.iter().enumerate() {
            let parm_dict = match parms {
                Value::Dict(dict) if index == 0 => Some(dict),
                Value::Array(items) => self.resolve(items.get(index)).as_dict(),
                _ => None,
            };
            let limit = usize::try_from(budget.remaining()).unwrap_or(usize::MAX);
            let decoded = filters::apply(filter, &data, &self.params(parm_dict), limit)?;
            budget
                .consume(decoded.len() as u64)
                .map_err(|_| DecodeError::Limit)?;
            data = Cow::Owned(decoded);
        }
        Ok(data.into_owned())
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
    nested: &mut NestedScan<'_>,
) {
    let mut out = Output {
        findings,
        embedded: Vec::new(),
        contents: Vec::new(),
        xfa: Vec::new(),
        encrypt_sources: Vec::new(),
    };
    let mut doc = Document {
        data,
        objects: Vec::new(),
        by_number: HashMap::new(),
        crypt: None,
    };
    let mut nodes_left = MAX_NODES;

    check_header(data, &mut out);
    discover_objects(&mut doc, &mut nodes_left, budget, &mut out);
    for at in memmem::find_iter(data, b"trailer") {
        let mut parser = Parser::new(data, at + b"trailer".len(), nodes_left);
        if let Some(trailer) = parser.parse_value() {
            walk(&doc, &trailer, at, &mut out);
        }
        nodes_left = parser.nodes_left;
    }
    for object in &doc.objects {
        walk(&doc, &object.value, object.offset, &mut out);
    }

    // In an encrypted file, object streams and embedded files are ciphertext
    // unless the empty password opens it, as it does in any reader.
    let encrypted = out.encrypt_sources.first().copied();
    if let Some(offset) = encrypted {
        doc.crypt = open_with_empty_password(&doc, &out.encrypt_sources);
        if doc.crypt.is_some() {
            out.report(
                "pdf.encrypted",
                Severity::Info,
                "document is encrypted with an empty password; it was decrypted and inspected",
                offset,
            );
        } else {
            out.report(
                "pdf.encrypted",
                Severity::Medium,
                "document is encrypted; strings, streams and object streams cannot be inspected",
                offset,
            );
        }
    }
    if encrypted.is_none() || doc.crypt.is_some() {
        let top_level = doc.objects.len();
        expand_object_streams(&mut doc, &mut nodes_left, budget, &mut out);
        for object in &doc.objects[top_level..] {
            walk(&doc, &object.value, object.offset, &mut out);
        }
        scan_embedded_files(&doc, budget, &mut out, nested);
        scan_content_streams(&doc, budget, &mut out);
        scan_xfa(&doc, budget, &mut out);
    }

    if doc.objects.is_empty() {
        out.malformed("PDF contains no objects", 0);
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
    let mut markers = memmem::find_iter(data, b"%%EOF");
    let Some(first) = markers.next() else {
        return out.malformed("PDF has no %%EOF marker", data.len());
    };
    let last = markers.last();
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
fn open_with_empty_password(doc: &Document<'_>, sources: &[usize]) -> Option<Decryptor> {
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
                    let object = &doc.objects[*doc.by_number.get(&number)?];
                    dict_after(object.offset)?
                }
                _ => return None,
            };
            Decryptor::open(data, at, &id)
        })
}

/// Parse every `N G obj` in the file, wherever it is.
fn discover_objects(
    doc: &mut Document<'_>,
    nodes_left: &mut usize,
    budget: &Budget,
    out: &mut Output<'_>,
) {
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

        let mut parser = Parser::new(data, body, *nodes_left);
        parser.skip_whitespace();
        let value = if parser.rest().starts_with(b"endobj") {
            Some(Value::Null)
        } else {
            parser.parse_value()
        };
        *nodes_left = parser.nodes_left;
        work += (parser.pos - at) as u64;
        if work > work_limit || *nodes_left == 0 {
            return out.limit(LimitExceeded::Complexity);
        }

        let Some(value) = value else {
            out.malformed("object could not be parsed", offset);
            fallback_names(&data[body..], offset, out);
            continue;
        };
        parser.skip_whitespace();
        let is_stream = value.as_dict().is_some() && parser.rest().starts_with(b"stream");
        let stream_start = is_stream.then(|| {
            let start = parser.pos + b"stream".len();
            match data.get(start..) {
                Some([b'\r', b'\n', ..]) => start + 2,
                Some([b'\r' | b'\n', ..]) => start + 1,
                _ => start,
            }
        });
        doc.add(Object {
            number,
            generation,
            offset,
            value,
            stream_start,
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
fn expand_object_streams(
    doc: &mut Document<'_>,
    nodes_left: &mut usize,
    budget: &mut Budget,
    out: &mut Output<'_>,
) {
    let mut unpacked = Vec::new();
    for object in &doc.objects {
        let Some(dict) = object.value.as_dict() else {
            continue;
        };
        if object.stream_start.is_none() || !doc.name_is(dict.get(b"Type"), b"ObjStm") {
            continue;
        }
        let offset = object.offset;
        let decoded = match doc.decode(object, budget) {
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
            let mut parser = Parser::new(&decoded, start, *nodes_left);
            let value = parser.parse_value();
            *nodes_left = parser.nodes_left;
            if *nodes_left == 0 {
                return out.limit(LimitExceeded::Complexity);
            }
            match (value, u32::try_from(number)) {
                (Some(value), Ok(number)) => unpacked.push(Object {
                    number,
                    generation: 0,
                    offset,
                    value,
                    stream_start: None,
                }),
                _ => {
                    out.malformed("object inside an object stream could not be parsed", offset);
                    fallback_names(decoded.get(start..).unwrap_or(&[]), offset, out);
                }
            }
        }
    }
    for object in unpacked {
        doc.add(object);
    }
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
    if name.obfuscated && SENSITIVE_NAMES.contains(&name.text.as_slice()) {
        out.report(
            "pdf.obfuscated_name",
            Severity::High,
            "keyword disguised with hex escapes",
            offset,
        );
    }
}

fn check_entry(doc: &Document<'_>, key: &Name, value: &Value, offset: usize, out: &mut Output<'_>) {
    match key.text.as_slice() {
        b"JS" | b"JavaScript" => javascript(offset, out),
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
        b"EF" => {
            embedded_file(offset, out);
            if let Value::Dict(files) = doc.resolve(Some(value)) {
                out.embedded
                    .extend(files.0.iter().filter_map(|(_, file)| match file {
                        Value::Ref(number) => Some(*number),
                        _ => None,
                    }));
            }
        }
        b"EmbeddedFiles" => embedded_file(offset, out),
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
        b"Type" if doc.name_is(Some(value), b"EmbeddedFile") => embedded_file(offset, out),
        b"Subtype" => {
            if let Some(b"RichMedia" | b"3D") = doc.resolve(Some(value)).as_name() {
                rich_media(offset, out);
            }
        }
        _ => {}
    }
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
        Value::Array(_) | Value::Name(_) | Value::String => Action::Harmless,
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
        match name.text.as_slice() {
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
        .filter_map(|(index, object)| {
            let dict = object.value.as_dict()?;
            let is = |key: &[u8], name: &[u8]| doc.name_is(dict.get(key), name);
            (is(b"Type", b"EmbeddedFile") || is(b"Subtype", b"PS") || is(b"Subtype2", b"PS"))
                .then_some(index)
        });
    let referenced = out
        .embedded
        .iter()
        .filter_map(|number| doc.by_number.get(number).copied());
    let mut targets: Vec<usize> = typed.chain(referenced).collect();
    targets.sort_unstable();
    targets.dedup();

    for index in targets {
        let object = &doc.objects[index];
        if object.stream_start.is_none() {
            continue;
        }
        if let Err(limit) = budget.enter() {
            return out.limit(limit);
        }
        match doc.decode(object, budget) {
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
fn scan_content_streams(doc: &Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    let named = out
        .contents
        .iter()
        .filter_map(|number| doc.by_number.get(number).copied());
    let typed = doc
        .objects
        .iter()
        .enumerate()
        .filter_map(|(index, object)| {
            let dict = object.value.as_dict()?;
            (doc.name_is(dict.get(b"Subtype"), b"Form") || dict.get(b"PatternType").is_some())
                .then_some(index)
        });
    let mut targets: Vec<usize> = named.chain(typed).collect();
    targets.sort_unstable();
    targets.dedup();

    for index in targets {
        let object = &doc.objects[index];
        if object.stream_start.is_none() {
            continue;
        }
        match doc.decode(object, budget) {
            Ok(content) if uses_operator(&content, b"PS") => {
                return postscript(
                    "content stream uses the PostScript operator",
                    object.offset,
                    out,
                );
            }
            Err(DecodeError::Limit) => return out.limit(LimitExceeded::Decompression),
            // A stream no reader can decode draws nothing.
            _ => {}
        }
    }
}

/// Search the packets of an XFA form for scripts. XFA has its own scripting
/// hooks, separate from the document's JavaScript actions.
fn scan_xfa(doc: &Document<'_>, budget: &mut Budget, out: &mut Output<'_>) {
    let mut targets: Vec<usize> = out
        .xfa
        .iter()
        .filter_map(|number| doc.by_number.get(number).copied())
        .collect();
    targets.sort_unstable();
    targets.dedup();

    for index in targets {
        let object = &doc.objects[index];
        if object.stream_start.is_none() {
            continue;
        }
        match doc.decode(object, budget) {
            Ok(packet) if has_script_element(&packet) => {
                return out.report(
                    "pdf.javascript",
                    Severity::High,
                    "XFA form contains scripts",
                    object.offset,
                );
            }
            Ok(_) => {}
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

/// Whether a content stream has `operator` as a token of its own, outside
/// strings, names and comments.
fn uses_operator(content: &[u8], operator: &[u8]) -> bool {
    let mut unclosed_string = false;
    let mut pos = 0;
    while let Some(&byte) = content.get(pos) {
        match byte {
            b'%' => pos += memchr::memchr2(b'\n', b'\r', &content[pos..]).unwrap_or(content.len()),
            // Once a string runs to the end, so does every later one: step
            // over the parenthesis so that it cannot hide what follows.
            b'(' if unclosed_string => pos += 1,
            b'(' => {
                let start = pos;
                let mut depth = 0usize;
                while let Some(&inner) = content.get(pos) {
                    pos += 1;
                    match inner {
                        b'\\' => pos += 1,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                }
                if depth > 0 {
                    unclosed_string = true;
                    pos = start + 1;
                }
            }
            b'<' if content.get(pos + 1) != Some(&b'<') => {
                pos += memchr::memchr(b'>', &content[pos..]).unwrap_or(content.len());
            }
            _ if is_regular(byte) => {
                let length = content[pos..]
                    .iter()
                    .take_while(|&&b| is_regular(b))
                    .count();
                let token = &content[pos..pos + length];
                if token == operator {
                    return true;
                }
                pos += length;
                // Inline image data is binary up to the `EI` that closes it.
                if token == b"ID" {
                    let end = memmem::find_iter(&content[pos..], b"EI").find(|&at| {
                        let before = content[pos + at - 1];
                        let after = content.get(pos + at + 2);
                        is_whitespace(before) && after.is_none_or(|&b| !is_regular(b))
                    });
                    pos += end.unwrap_or(0);
                }
            }
            b'/' => {
                pos += 1;
                pos += content[pos..]
                    .iter()
                    .take_while(|&&b| is_regular(b))
                    .count();
            }
            _ => pos += 1,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use miniz_oxide::deflate::compress_to_vec_zlib;

    use super::crypt::testing::{Encrypted, ID, Scheme};
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
        let mut budget = Budget::new(&Limits::default());
        let mut findings = Vec::new();
        let mut nested = |inner: &[u8], _: &mut Budget, findings: &mut Vec<Finding>| {
            if inner.starts_with(b"\x7fELF") {
                findings.push(Finding::new("type.executable", Severity::Critical, "elf"));
            }
        };
        analyze(data, &mut budget, &mut findings, &mut nested);
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
            &mut |_, _, _| {},
        );
        assert_eq!(findings[0].code, "limit.decompression");
    }
}
