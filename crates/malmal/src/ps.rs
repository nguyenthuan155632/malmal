//! PostScript, EPS and pre-PDF Illustrator files. PostScript is a full
//! programming language that Ghostscript and ImageMagick will run on the
//! server, so the question is not whether a file is valid but whether it
//! reaches for the file system, a shell, or interpreter internals.
//!
//! Static analysis of a Turing-complete language cannot be complete. What
//! this module guarantees is narrower: the operators below are found when
//! written plainly, when hidden in strings that are executed, inside eexec
//! sections and inside declared data sections, and code that is decoded at
//! run time is reported as such instead of being called clean.

use memchr::memmem;
use sha2::{Digest, Sha256};

use crate::detect::FileType;
use crate::image;
use crate::limits::{Budget, LimitExceeded, Limits};
use crate::pdf::filters::{self, Params};
use crate::pdf::parser::{is_regular, is_whitespace};
use crate::report::{Finding, Severity};

const DOS_EPS_MAGIC: &[u8] = b"\xC5\xD0\xD3\xC6";
/// Nesting of executed strings and declared data sections.
const MAX_DEPTH: usize = 8;
/// Interpreters cap strings at 65535 bytes; allow for escapes.
const MAX_STRING_SOURCE: usize = 4 * 65536;
const MAX_EEXEC: usize = 16 << 20;
const TIME_CHECK_INTERVAL: usize = 4096;

/// Operators that read, write, delete or enumerate files.
const FILE_OPERATORS: &[&[u8]] = &[
    b"run",
    b"deletefile",
    b"renamefile",
    b"filenameforall",
    b"runlibfile",
    b"findlibfile",
];
/// Pseudo-files that `file` may open without touching the file system.
const STANDARD_FILES: &[&[u8]] = &[
    b"%stdin",
    b"%stdout",
    b"%stderr",
    b"%lineedit",
    b"%statementedit",
];
const SYSTEM_OPERATORS: &[&[u8]] = &[b"superexec", b"getenv", b"setsystemparams", b"setdevparams"];
/// Ghostscript extensions that only affect rendering. Every other name
/// starting with a dot is an interpreter internal.
const HARMLESS_DOT_NAMES: &[&[u8]] = &[
    b".notdef",
    b".setopacityalpha",
    b".setshapealpha",
    b".setblendmode",
    b".settextknockout",
    b".setfillconstantalpha",
    b".setstrokeconstantalpha",
    b".setalphaisshape",
    b".setoverprintmode",
    b".currentopacityalpha",
    b".currentshapealpha",
    b".currentblendmode",
    b".begintransparencygroup",
    b".endtransparencygroup",
    b".begintransparencymaskgroup",
    b".endtransparencymask",
    b".pushpdf14devicefilter",
    b".poppdf14devicefilter",
];
/// Internals behind published sandbox escapes, searched for in the raw
/// bytes regardless of how the surrounding text tokenizes.
const KNOWN_INTERNALS: &[&[u8]] = &[
    b".forceput",
    b".forcedef",
    b".forceundef",
    b".libfile",
    b".runandhide",
    b".tempfile",
    b".putdeviceprops",
    b".putdeviceparams",
    b".setdevice",
    b".bindnow",
    b".trysetparams",
    b".eqproc",
    b".rsdparams",
    b".loadfontfile",
    b".setsafe",
    b".locksafe",
    b".addcontrolpath",
    b".activatepathcontrol",
    b".execn",
    b".buildfont1",
    b".type1execchar",
    b".setuserparams2",
];
/// Operators that turn a literal name into the object it names. `known` and
/// `where` only test for existence, which prologs do for feature detection.
const LOOKUP_OPERATORS: &[&[u8]] = &[b"load", b"get", b"cvx", b"exec"];
/// Tokens after which `cvx` cannot be hiding code: operators that leave a
/// number, and the end of an array whose elements were all just tokenized.
const TRANSPARENT_CVX_OPERANDS: &[&[u8]] = &[b"cvr", b"cvi", b"]"];

/// SHA-256 of procsets that Adobe Illustrator writes into every EPS, taken
/// over the resource body with every line end written as a line feed. They open a scratch file, use
/// `superexec` to patch fonts and run `cvx exec` on fill patterns, so each
/// would be reported; a body that differs by one byte still is.
const KNOWN_PROCSETS: &[&str] = &[
    // Adobe_AGM_Utils 1.0 0
    "4ace816a9065299b038ff77e9cab6c64b1b215a56b2701cf8850585379c831c1",
    // Adobe_CoolType_Core 2.31 0
    "6197d7260fdeb15e82d40e66702dd7b3097a7ab2c03648233589b9bf52f9ed38",
    // Adobe_CoolType_Utility_MAKEOCF 1.23 0
    "9edc806ae83e9731a91acd2e354b113c67d11e13153030a354363b30b6c69950",
    // Adobe_pattern_AI5 1.1 0
    "5da6ea2f6bdb4a90e68d802f6cad38a89dc6551ed9b9978761a951d92feba46d",
];
/// How much ASCII85 text must precede a name for it to count as image data.
const A85_DATA_LEAD: usize = 200;

pub(crate) fn analyze(
    data: &[u8],
    limits: &Limits,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
) {
    let (program, base) = if data.starts_with(DOS_EPS_MAGIC) {
        match dos_eps_sections(data, limits, budget, findings) {
            Some(section) => section,
            None => return,
        }
    } else {
        (data, 0)
    };
    let mut scanner = Scanner {
        budget,
        findings,
        tokens: 0,
    };
    let text = program.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(program);
    let text = text.trim_ascii_start();
    // Print spoolers prepend a Ctrl-D job separator.
    if !text
        .strip_prefix(b"\x04")
        .unwrap_or(text)
        .starts_with(b"%!")
    {
        scanner.report(
            "ps.malformed",
            Severity::Medium,
            "PostScript header not found",
            base,
        );
    }
    scanner.raw_scan(program, base);
    scanner.program(program, base, 0);
}

/// A DOS EPS binary file wraps the PostScript with a TIFF or WMF preview.
/// Returns the PostScript section and its offset; the preview is analyzed
/// here.
fn dos_eps_sections<'a>(
    data: &'a [u8],
    limits: &Limits,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
) -> Option<(&'a [u8], usize)> {
    let field = |index: usize| {
        let offset = 4 + index * 4;
        data.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let section = |index: usize| {
        let (start, length) = (field(index)?, field(index + 1)?);
        data.get(start..start.checked_add(length)?)
            .map(|s| (s, start))
    };
    let (Some(postscript), Some((wmf, _)), Some((tiff, _))) = (section(0), section(2), section(4))
    else {
        findings.push(Finding::new(
            "ps.malformed",
            Severity::Medium,
            "EPS binary header points outside the file",
        ));
        return None;
    };
    if !tiff.is_empty() {
        image::analyze(tiff, FileType::Tiff, limits, budget, findings);
    }
    if !wmf.is_empty() {
        findings.push(Finding::new(
            "ps.wmf_preview",
            Severity::Info,
            "EPS carries a Windows Metafile preview, which is not analyzed",
        ));
    }
    Some(postscript)
}

struct Scanner<'a> {
    budget: &'a mut Budget,
    findings: &'a mut Vec<Finding>,
    tokens: usize,
}

/// The two most recent tokens, as decoded strings when they were strings.
type Recent = [Option<Vec<u8>>; 2];

impl Scanner<'_> {
    /// Record a finding once per code and severity.
    fn report(&mut self, code: &'static str, severity: Severity, message: &str, offset: usize) {
        let seen = |f: &Finding| f.code == code && f.severity == severity;
        if !self.findings.iter().any(seen) {
            self.findings
                .push(Finding::new(code, severity, message).at(offset));
        }
    }

    fn file_access(&mut self, message: &str, offset: usize) {
        self.report("ps.file_access", Severity::High, message, offset);
    }

    fn internal(&mut self, offset: usize) {
        self.report(
            "ps.ghostscript_internal",
            Severity::High,
            "uses an interpreter-internal or system-level operator",
            offset,
        );
    }

    /// Search bytes for a pipe device or a known-dangerous internal without
    /// tokenizing, so nothing the tokenizer misreads can hide them.
    fn raw_scan(&mut self, data: &[u8], base: usize) {
        if let Some(at) = memmem::find(data, b"%pipe%") {
            self.report(
                "ps.pipe",
                Severity::Critical,
                "opens a pipe to a shell command",
                base + at,
            );
        }
        for name in KNOWN_INTERNALS {
            let found = memmem::find_iter(data, name).find(|&at| {
                let before = at.checked_sub(1).map(|i| data[i]);
                let after = data.get(at + name.len());
                before.is_none_or(|b| !is_regular(b)) && after.is_none_or(|&b| !is_regular(b))
            });
            if let Some(at) = found {
                self.internal(base + at);
            }
        }
    }

    /// Tokenize a program and check every operator and string in it.
    fn program(&mut self, data: &[u8], base: usize, depth: usize) {
        let mut recent: Recent = [None, None];
        let mut since_cvx = usize::MAX;
        let mut previous_name: &[u8] = b"";
        let mut no_a85_terminator = false;
        let mut inline_data = InlineData::default();
        let mut pos = 0;
        while let Some(&byte) = data.get(pos) {
            self.tokens += 1;
            if self.tokens.is_multiple_of(TIME_CHECK_INTERVAL)
                && let Err(limit) = self.budget.check_time()
            {
                return self.limit_exceeded(limit);
            }
            let offset = base + pos;
            let mut string = None;
            // What this token is, for the `cvx` check on the next one; stays
            // empty for strings and literal names.
            let mut current: &[u8] = b"";
            match byte {
                _ if is_whitespace(byte) => {
                    pos += 1;
                    continue;
                }
                b'%' => {
                    let line_end = pos + line_len(&data[pos..]);
                    let after_line = line_end + eol_len(&data[line_end..]);
                    if let Some(length) =
                        known_procset_len(&data[pos..line_end], &data[after_line..])
                    {
                        recent = [None, None];
                        pos = after_line + length;
                        continue;
                    }
                    let region = data_section_len(&data[pos..line_end], &data[after_line..]);
                    pos = match region {
                        // Interpreters ignore the comment, so the section may
                        // be data or may be code: read it both ways, each
                        // from a clean state.
                        Some(length) if depth < MAX_DEPTH => {
                            let section = &data[after_line..after_line + length];
                            self.program(section, base + after_line, depth + 1);
                            recent = [None, None];
                            after_line + length
                        }
                        _ => line_end,
                    };
                    continue;
                }
                b'(' => match literal_string(&data[pos..]) {
                    Some((decoded, length)) => {
                        pos += length;
                        string = Some(decoded);
                    }
                    // Not a string after all (binary data): step over it.
                    None => pos += 1,
                },
                b'<' => match data.get(pos + 1) {
                    Some(b'<') => pos += 2,
                    // Once a search finds no terminator ahead, there is none
                    // for any later `<~` either, so it is not repeated.
                    Some(b'~') if no_a85_terminator => pos += 2,
                    // The search starts after `<~`, whose own `~` would
                    // otherwise pair with the `>` of an empty `<~>`.
                    Some(b'~') => match memmem::find(&data[pos + 2..], b"~>") {
                        Some(length) => {
                            let end = 2 + length;
                            let encoded = &data[pos + 2..pos + end];
                            let decoded = filters::apply(
                                b"ASCII85Decode",
                                encoded,
                                &Params::default(),
                                usize::MAX,
                            );
                            pos += end + 2;
                            string = Some(decoded.unwrap_or_default());
                        }
                        None => {
                            no_a85_terminator = true;
                            pos += 2;
                        }
                    },
                    _ => match hex_string(&data[pos..]) {
                        Some((decoded, length)) => {
                            pos += length;
                            string = Some(decoded);
                        }
                        None => pos += 1,
                    },
                },
                b')' | b'>' | b'[' | b']' | b'{' | b'}' => {
                    pos += 1;
                    // Lets `] cvx` below see that its operand is an array.
                    current = &data[pos - 1..pos];
                }
                b'/' => {
                    let immediate = data.get(pos + 1) == Some(&b'/');
                    let start = pos + 1 + usize::from(immediate);
                    let name = &data[start..start + name_len(&data[start..])];
                    pos = start + name.len();
                    if immediate {
                        // `//name` fetches the operator itself.
                        self.operator(name, &[None, None], offset);
                    } else {
                        self.literal_name(name, &data[pos..], offset);
                    }
                }
                _ => {
                    let name = &data[pos..pos + name_len(&data[pos..])];
                    pos += name.len();
                    match name {
                        // Photoshop's prolog runs `version cvr cvx exec` and
                        // `[blendColor] cvx exec`.
                        b"cvx" if TRANSPARENT_CVX_OPERANDS.contains(&previous_name) => {}
                        b"cvx" => {
                            since_cvx = 0;
                            if let Some(code) = &recent[1]
                                && depth < MAX_DEPTH
                            {
                                self.raw_scan(code, offset);
                                self.program(code, offset, depth + 1);
                            }
                        }
                        // The string names an operator.
                        b"cvn" => {
                            if let Some(name) = recent[1].take() {
                                self.operator(&name, &[None, None], offset);
                            }
                        }
                        b"exec" if since_cvx <= 3 => self.report(
                            "ps.exec_dynamic",
                            Severity::Medium,
                            "executes code that is built or decoded at run time",
                            offset,
                        ),
                        b"eexec" => pos += self.eexec(&data[pos..], base + pos),
                        [b'.', ..] if inline_data.contains(data, pos - name.len()) => {}
                        _ => self.operator(name, &recent, offset),
                    }
                    current = name;
                }
            }
            if let Some(decoded) = &string
                && memmem::find(decoded, b"%pipe%").is_some()
            {
                self.report(
                    "ps.pipe",
                    Severity::Critical,
                    "opens a pipe to a shell command",
                    offset,
                );
            }
            previous_name = current;
            recent = [recent[1].take(), string];
            since_cvx = since_cvx.saturating_add(1);
        }
    }

    /// Check an executable name. `recent` holds the operands before it.
    fn operator(&mut self, name: &[u8], recent: &Recent, offset: usize) {
        match name {
            b"file" => {
                // Operands are (filename) (access); the name is two back.
                let standard = recent[0].as_deref().is_some_and(|target| {
                    STANDARD_FILES
                        .iter()
                        .any(|device| target.starts_with(device))
                });
                if !standard {
                    self.file_access("opens a file", offset);
                }
            }
            _ if FILE_OPERATORS.contains(&name) => {
                self.file_access("runs, deletes, renames or enumerates files", offset)
            }
            _ if SYSTEM_OPERATORS.contains(&name) => self.internal(offset),
            [b'.', letter, ..]
                if letter.is_ascii_alphabetic() && !HARMLESS_DOT_NAMES.contains(&name) =>
            {
                self.internal(offset)
            }
            _ => {}
        }
    }

    /// A literal `/name` is harmless as a definition, but naming a dangerous
    /// operator and then looking it up is the same as calling it.
    fn literal_name(&mut self, name: &[u8], rest: &[u8], offset: usize) {
        if name == b"OutputFile" {
            return self.file_access("redirects page output to a file or command", offset);
        }
        let rest = rest.trim_ascii_start();
        let next = &rest[..name_len(rest)];
        if LOOKUP_OPERATORS.contains(&next) {
            self.operator(name, &[None, None], offset);
        }
    }

    /// Decrypt the eexec section that starts after the operator and search
    /// it; returns how many bytes it occupies. Type 1 fonts are the usual
    /// content, but any code can be put there.
    fn eexec(&mut self, rest: &[u8], base: usize) -> usize {
        let start = rest.len() - rest.trim_ascii_start().len();
        let body = &rest[start..];
        let length = memmem::find(body, b"cleartomark")
            .unwrap_or(body.len())
            .min(MAX_EEXEC);
        let section = &body[..length];
        // The section is hexadecimal unless one of its first four bytes says otherwise.
        let is_hex = section.iter().take(4).all(u8::is_ascii_hexdigit);
        let cipher = if is_hex {
            filters::apply(b"ASCIIHexDecode", section, &Params::default(), usize::MAX)
                .unwrap_or_default()
        } else {
            section.to_vec()
        };
        if self.budget.consume(cipher.len() as u64).is_err() {
            self.limit_exceeded(LimitExceeded::Decompression);
            return start + length;
        }
        let mut key: u16 = 55665;
        let plain: Vec<u8> = cipher
            .iter()
            .map(|&byte| {
                let decrypted = byte ^ (key >> 8) as u8;
                key = (byte as u16)
                    .wrapping_add(key)
                    .wrapping_mul(52845)
                    .wrapping_add(22719);
                decrypted
            })
            .collect();
        // The first four bytes are random padding.
        self.raw_scan(plain.get(4..).unwrap_or(&[]), base + start);
        start + length
    }

    fn limit_exceeded(&mut self, limit: LimitExceeded) {
        if !self.findings.iter().any(|f| f.code == limit.code()) {
            self.findings.push(limit.finding());
        }
    }
}

/// Image data that the program reads from its own text through an
/// ASCII85 filter. The tokenizer cannot tell where such data starts, and in
/// megabytes of it some run of characters will look like a `.name`.
#[derive(Default)]
struct InlineData {
    /// End of the data run most recently recognized.
    until: usize,
    /// No data run can contain a position before this one.
    not_before: usize,
}

impl InlineData {
    /// Whether the name at `at` sits in a run of ASCII85 text: solid encoded
    /// lines before it, and nothing but encoded text from it to a `~>`.
    /// Only names that are reported for their spelling alone rely on this;
    /// the raw search for known internals does not.
    fn contains(&mut self, data: &[u8], at: usize) -> bool {
        if at < self.until {
            return true;
        }
        if at < self.not_before || !follows_a85_lines(&data[..at]) {
            return false;
        }
        for (index, &byte) in data.iter().enumerate().skip(at) {
            let next = data.get(index + 1);
            match byte {
                b'~' if next == Some(&b'>') => {
                    self.until = index;
                    return true;
                }
                b'<' if next == Some(&b'~') => {}
                _ if is_a85_digit(byte) || is_whitespace(byte) => continue,
                _ => {}
            }
            self.not_before = index + 1;
            return false;
        }
        self.not_before = data.len();
        false
    }
}

fn is_a85_digit(byte: u8) -> bool {
    matches!(byte, b'!'..=b'u' | b'z')
}

/// Whether `before` ends in [`A85_DATA_LEAD`] bytes of ASCII85 text with no
/// blanks inside a line; a blank may open a line, which is how encoders
/// keep a `%` out of the first column.
fn follows_a85_lines(before: &[u8]) -> bool {
    let mut digits = 0;
    for (index, &byte) in before.iter().enumerate().rev() {
        let opens_line = index
            .checked_sub(1)
            .is_none_or(|i| matches!(before[i], b'\r' | b'\n'));
        match byte {
            _ if is_a85_digit(byte) => digits += 1,
            b'\r' | b'\n' => {}
            b' ' | b'\t' if opens_line => {}
            _ => return false,
        }
        if digits == A85_DATA_LEAD {
            return true;
        }
    }
    false
}

/// Length of the resource that a `%%BeginResource:` or `%%BeginProcSet:`
/// comment opens, when it is one of [`KNOWN_PROCSETS`].
fn known_procset_len(comment: &[u8], following: &[u8]) -> Option<usize> {
    if !(comment.starts_with(b"%%BeginResource:") || comment.starts_with(b"%%BeginProcSet:")) {
        return None;
    }
    let ends = [b"%%EndResource".as_slice(), b"%%EndProcSet"];
    let length = ends
        .iter()
        .filter_map(|end| memmem::find(following, end))
        .min()?;
    let mut hasher = Sha256::new();
    let mut body = &following[..length];
    while !body.is_empty() {
        let (line, rest) = body.split_at(line_len(body));
        hasher.update(line);
        let eol = eol_len(rest);
        if eol > 0 {
            hasher.update(b"\n");
        }
        body = &rest[eol..];
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    KNOWN_PROCSETS.contains(&digest.as_str()).then_some(length)
}

fn name_len(data: &[u8]) -> usize {
    data.iter().take_while(|&&b| is_regular(b)).count()
}

fn line_len(data: &[u8]) -> usize {
    memchr::memchr2(b'\n', b'\r', data).unwrap_or(data.len())
}

fn eol_len(data: &[u8]) -> usize {
    match data {
        [b'\r', b'\n', ..] => 2,
        [b'\r' | b'\n', ..] => 1,
        _ => 0,
    }
}

/// Length of the data that a `%%BeginData:` or `%%BeginBinary:` comment
/// announces, clamped to what follows.
fn data_section_len(comment: &[u8], following: &[u8]) -> Option<usize> {
    let arguments = comment
        .strip_prefix(b"%%BeginData:")
        .or_else(|| comment.strip_prefix(b"%%BeginBinary:"))?;
    let mut arguments = arguments
        .split(|b| b.is_ascii_whitespace())
        .filter(|a| !a.is_empty());
    let count: usize = std::str::from_utf8(arguments.next()?).ok()?.parse().ok()?;
    if arguments.any(|argument| argument == b"Lines") {
        let mut length = 0;
        for _ in 0..count {
            if length >= following.len() {
                break;
            }
            length += line_len(&following[length..]);
            length += eol_len(&following[length..]);
        }
        Some(length)
    } else {
        Some(count.min(following.len()))
    }
}

/// Decode the literal string starting at `(`; returns it and its source length.
fn literal_string(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut decoded = Vec::new();
    let mut depth = 0usize;
    let mut pos = 0;
    while pos < data.len().min(MAX_STRING_SOURCE) {
        let byte = data[pos];
        pos += 1;
        match byte {
            b'(' => {
                depth += 1;
                if depth > 1 {
                    decoded.push(byte);
                }
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((decoded, pos));
                }
                decoded.push(byte);
            }
            b'\\' => {
                let escaped = *data.get(pos)?;
                pos += 1;
                match escaped {
                    b'n' => decoded.push(b'\n'),
                    b'r' => decoded.push(b'\r'),
                    b't' => decoded.push(b'\t'),
                    b'b' => decoded.push(8),
                    b'f' => decoded.push(12),
                    b'0'..=b'7' => {
                        let mut value = (escaped - b'0') as u32;
                        for _ in 0..2 {
                            match data.get(pos) {
                                Some(&digit @ b'0'..=b'7') => {
                                    value = value * 8 + (digit - b'0') as u32;
                                    pos += 1;
                                }
                                _ => break,
                            }
                        }
                        decoded.push(value as u8);
                    }
                    // A backslash before a line end continues the string.
                    b'\r' => pos += usize::from(data.get(pos) == Some(&b'\n')),
                    b'\n' => {}
                    other => decoded.push(other),
                }
            }
            _ => decoded.push(byte),
        }
    }
    None
}

/// Decode the hex string starting at `<`; `None` if it is not one.
fn hex_string(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    // Stop at the first byte that cannot be part of one, so binary data full
    // of `<` costs nothing.
    let body = &data[1..];
    let length = body
        .iter()
        .take_while(|&&b| b.is_ascii_hexdigit() || is_whitespace(b))
        .count();
    if body.get(length) != Some(&b'>') {
        return None;
    }
    let (digits, end) = (&body[..length], length + 1);
    let decoded = filters::apply(b"ASCIIHexDecode", digits, &Params::default(), usize::MAX).ok()?;
    Some((decoded, end + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_bytes(program: &[u8]) -> Vec<(&'static str, Severity)> {
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let mut findings = Vec::new();
        analyze(program, &limits, &mut budget, &mut findings);
        findings.iter().map(|f| (f.code, f.severity)).collect()
    }

    fn codes(body: &str) -> Vec<&'static str> {
        run_bytes(format!("%!PS-Adobe-3.0 EPSF-3.0\n{body}\n%%EOF\n").as_bytes())
            .into_iter()
            .map(|(code, _)| code)
            .collect()
    }

    const NONE: [&str; 0] = [];

    /// Encoded lines that happen to contain `.kPkh`, as real image data does.
    fn a85_lines(count: usize) -> String {
        let plain = "s4IA>!\"M;*Ddm8XA,lT0!!*&R!(-_f!WiH*!sAZ,9eo1eu5U,&6#R:S>#6tMBpAY+,#hhD6\n";
        let dotted = "kA04Lrc7q^moO57>,goU`Fa;WBdJbWRY]3Q&[*q).kPkhXHHbbGCJm:4o#,=-[PL<PFt:lR\n";
        plain.repeat(4) + &dotted.repeat(count)
    }

    #[test]
    fn names_inside_inline_image_data_are_not_operators() {
        let data = a85_lines(8);
        let body = format!("/src currentfile /ASCII85Decode filter def\nsrc image\n{data}~>\n");
        assert_eq!(codes(&body), NONE);
        // A blank may open a line, never sit inside one.
        let body = format!("src image\n {data} {data}~>\n");
        assert_eq!(codes(&body), NONE);
    }

    #[test]
    fn inline_image_data_does_not_hide_operators() {
        let internal = ["ps.ghostscript_internal"];
        let data = a85_lines(8);
        // No encoded text before the name.
        assert_eq!(codes(".kPkh (~>) pop"), internal);
        // Encoded text before it, but code after it.
        assert_eq!(
            codes(&format!("({data}) pop .kPkh {{ }} pop (~>)")),
            internal
        );
        assert_eq!(codes(&format!("({data}) pop\n.kPkh <~~> pop")), internal);
        // No terminator at all.
        assert_eq!(codes(&format!("src image\n{data}")), internal);
        // Known internals are found whatever surrounds them.
        assert_eq!(
            codes(&format!("src image\n{data}\n.forceput\n{data}~>")),
            internal
        );
        // Only names starting with a dot are affected.
        assert_eq!(
            codes(&format!("src image\n{data}(/etc/hosts)(r)file\n~>")),
            ["ps.file_access"]
        );
    }

    #[test]
    fn unknown_procsets_are_analyzed() {
        let body = "%%BeginResource: procset Adobe_AGM_Utils 1.0 0\n\
                    {(AGMUTIL_imagefile)(w+)file}stopped pop\n%%EndResource";
        assert_eq!(codes(body), ["ps.file_access"]);
        assert_eq!(
            known_procset_len(b"%%BeginResource: procset x", b"a\r\nb\n%%EndResource"),
            None
        );
    }

    #[test]
    fn ordinary_drawing_is_clean() {
        let body = r"%%BoundingBox: 0 0 100 100
/box { newpath moveto 10 0 rlineto 0 10 rlineto closepath fill } bind def
/Helvetica findfont 12 scalefont setfont
gsave 0.5 setgray 10 10 box grestore
20 20 moveto (Run the file \(draft\) at 100%) show
/str 256 string def
currentfile str readline pop pop
<48656c6c6f> show <~87cURD]i,~> show
<< /PageSize [100 100] >> setpagedevice
(%stdout) (w) file (done\n) writestring
.5 .25 scale .setopacityalpha
/Encoding [ /.notdef /space ] def
showpage";
        assert_eq!(codes(body), NONE);
    }

    #[test]
    fn file_system_operators() {
        assert_eq!(codes("(/etc/passwd) (r) file"), ["ps.file_access"]);
        assert_eq!(codes("(lib.ps) run"), ["ps.file_access"]);
        assert_eq!(codes("(/tmp/x) deletefile"), ["ps.file_access"]);
        assert_eq!(
            codes("(*) { print } 100 string filenameforall"),
            ["ps.file_access"]
        );
        assert_eq!(codes("name (r) file"), ["ps.file_access"]);
        assert_eq!(
            codes("<< /OutputFile (/tmp/out) >> setpagedevice"),
            ["ps.file_access"]
        );
        // Operators with similar names are not file access.
        assert_eq!(
            codes("currentfile closefile /runs 1 def /profile 2 def"),
            NONE
        );
    }

    #[test]
    fn pipe_device_in_every_spelling() {
        for body in [
            "(%pipe%id) (r) file",
            r"(\045pipe\045id) (w) file",
            "<25706970652569 64> (r) file",
            "mark /OutputFile (%pipe%id) currentdevice putdeviceprops",
            "% a comment mentioning %pipe%id",
        ] {
            assert!(codes(body).contains(&"ps.pipe"), "{body}");
        }
    }

    #[test]
    fn interpreter_internals() {
        assert_eq!(codes("null .forceput"), ["ps.ghostscript_internal"]);
        assert_eq!(codes("(x) .libfile"), ["ps.ghostscript_internal"]);
        assert_eq!(
            codes("{ .someNewInternal } stopped"),
            ["ps.ghostscript_internal"]
        );
        assert_eq!(codes("(HOME) getenv"), ["ps.ghostscript_internal"]);
        assert_eq!(codes("//superexec"), ["ps.ghostscript_internal"]);
        // Hidden inside a string that is never tokenized as code.
        assert_eq!(codes("(a ( .forceput b) pop"), ["ps.ghostscript_internal"]);
    }

    #[test]
    fn operators_reached_by_name() {
        assert_eq!(codes("systemdict /file get exec"), ["ps.file_access"]);
        assert_eq!(codes("/run load exec"), ["ps.file_access"]);
        assert_eq!(codes("(deletefile) cvn load exec"), ["ps.file_access"]);
        assert_eq!(
            codes(r"(\056libfile) cvn load exec"),
            ["ps.ghostscript_internal"]
        );
        // Defining a procedure with that name is not a lookup, and neither
        // is testing whether an operator exists.
        assert_eq!(codes("/file 12 def /run { } def"), NONE);
        assert_eq!(
            codes("systemdict /.makeoperator known /run where { pop } if"),
            NONE
        );
    }

    #[test]
    fn code_hidden_in_executed_strings() {
        assert_eq!(
            codes("((/etc/passwd) (r) file) cvx exec"),
            ["ps.file_access", "ps.exec_dynamic"]
        );
        assert_eq!(
            codes("<282f746d702f782920286229 2066696c65> cvx exec"),
            ["ps.file_access", "ps.exec_dynamic"]
        );
        // Nested twice.
        assert_eq!(
            codes(r"((\(x\) run) cvx exec) cvx exec"),
            ["ps.file_access", "ps.exec_dynamic"]
        );
        // A whole program decoded from the input stream cannot be inspected.
        assert_eq!(
            codes("currentfile /ASCII85Decode filter cvx exec"),
            ["ps.exec_dynamic"]
        );
        assert_eq!(codes("{ 1 2 add } exec"), NONE);
        // Found by fuzzing: `<~>` is not an empty ASCII85 string.
        assert_eq!(codes("<~> show (x) run"), ["ps.file_access"]);
        assert_eq!(codes("<~~> show <~ unterminated"), NONE);
        assert_eq!(codes("mark {version cvr cvx exec} stopped"), NONE);
        assert_eq!(codes("[blendColor] cvx exec"), NONE);
        // The exemption covers only the token directly before `cvx`.
        assert_eq!(
            codes("1 cvr pop ((x) run) cvx exec ] ((y) run) cvx exec"),
            ["ps.file_access", "ps.exec_dynamic"]
        );
        assert_eq!(codes("[(x) /run load] cvx exec"), ["ps.file_access"]);
    }

    #[test]
    fn declared_data_sections_are_read_as_data_and_as_code() {
        // Unbalanced parentheses in binary data must not swallow what follows.
        let body = "%%BeginData: 12 Binary Bytes\n((((((((((((\n%%EndData\n(x) run";
        assert_eq!(codes(body), ["ps.file_access"]);
        // Code placed inside a section that claims to be data still counts.
        let body = "%%BeginData: 2 ASCII Lines\n(x) run\n1 pop\n%%EndData\nshowpage";
        assert_eq!(codes(body), ["ps.file_access"]);
        let body = "%%BeginBinary: 9\n(y) run \n%%EndBinary";
        assert_eq!(codes(body), ["ps.file_access"]);
    }

    #[test]
    fn unterminated_string_does_not_hide_later_code() {
        let mut body = "( never closed ".to_string();
        body.push_str(&"x".repeat(MAX_STRING_SOURCE));
        body.push_str("\n(x) run");
        assert_eq!(codes(&body), ["ps.file_access"]);
    }

    fn eexec_encrypt(plain: &[u8]) -> Vec<u8> {
        let mut key: u16 = 55665;
        plain
            .iter()
            .map(|&byte| {
                let cipher = byte ^ (key >> 8) as u8;
                key = (cipher as u16)
                    .wrapping_add(key)
                    .wrapping_mul(52845)
                    .wrapping_add(22719);
                cipher
            })
            .collect()
    }

    #[test]
    fn eexec_sections_are_decrypted() {
        let hidden = eexec_encrypt(b"XXXX null .forceput ");
        let hex: String = hidden.iter().map(|byte| format!("{byte:02X}")).collect();
        let body = format!(
            "currentfile eexec\n{hex}\n{}\ncleartomark\nshowpage",
            "0".repeat(64)
        );
        assert_eq!(codes(&body), ["ps.ghostscript_internal"]);

        let font = eexec_encrypt(b"XXXX dup /Private 8 dict dup begin /BlueValues [] def end");
        let hex: String = font.iter().map(|byte| format!("{byte:02X}")).collect();
        let body = format!("currentfile eexec\n{hex}\ncleartomark\nshowpage");
        assert_eq!(codes(&body), NONE);

        let mut binary = b"%!PS\ncurrentfile eexec ".to_vec();
        binary.extend(eexec_encrypt(b"\x01\x02\x03\x04 (%pipe%id) (r) file "));
        binary.extend_from_slice(b"\ncleartomark\n");
        assert!(run_bytes(&binary).contains(&("ps.pipe", Severity::Critical)));
    }

    #[test]
    fn header_and_dos_eps_wrapper() {
        assert_eq!(
            run_bytes(b"\x04%!PS\nshowpage\n"),
            [] as [(&str, Severity); 0]
        );

        let program = b"%!PS-Adobe-3.0 EPSF-3.0\n(x) run\n";
        let mut tiff = b"II*\0\x08\0\0\0\x01\0".to_vec();
        tiff.extend_from_slice(b"\x00\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0");
        let mut eps = DOS_EPS_MAGIC.to_vec();
        for value in [30, program.len(), 0, 0, 30 + program.len(), tiff.len()] {
            eps.extend_from_slice(&(value as u32).to_le_bytes());
        }
        eps.extend_from_slice(&[0xFF, 0xFF]);
        eps.extend_from_slice(program);
        eps.extend_from_slice(&tiff);
        assert_eq!(run_bytes(&eps), [("ps.file_access", Severity::High)]);

        let mut broken = eps.clone();
        broken[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(run_bytes(&broken), [("ps.malformed", Severity::Medium)]);

        let mut headerless = DOS_EPS_MAGIC.to_vec();
        for value in [30u32, 8, 0, 0, 0, 0] {
            headerless.extend_from_slice(&value.to_le_bytes());
        }
        headerless.extend_from_slice(b"\xFF\xFFshowpage");
        assert_eq!(run_bytes(&headerless), [("ps.malformed", Severity::Medium)]);
    }
}
