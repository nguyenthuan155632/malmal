//! SVG is an XML application that browsers execute: scripts, event handlers,
//! script URLs and externally loaded content all run in the origin serving
//! the file. This module walks the document and reports each of those.

use std::borrow::Cow;
use std::collections::HashMap;

use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_with_limit};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::limits::{Budget, LimitExceeded};
use crate::report::{Finding, Severity};

/// Attributes whose value is a URL the browser may load or navigate to.
const URL_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "data",
    "poster",
    "background",
    "base",
];
const ANIMATION_ELEMENTS: &[&str] = &[
    "set",
    "animate",
    "animatetransform",
    "animatemotion",
    "animatecolor",
];
const SCRIPT_SCHEMES: &[&str] = &["javascript", "vbscript", "livescript"];
/// Bitmap types that are safe to embed as `data:` URLs.
const RASTER_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/avif",
    "image/tiff",
    "image/x-icon",
    "image/vnd.microsoft.icon",
];
/// `data:` types a browser parses as a document or runs as code.
const SCRIPTABLE_MIMES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "text/xml",
    "application/xml",
    "text/xsl",
    "text/javascript",
    "application/javascript",
    "application/ecmascript",
    "text/ecmascript",
];
/// ASCII-compatible encodings old design tools declare; bytes above 0x7F only
/// occur in text, never in markup.
const SINGLE_BYTE_ENCODINGS: &[&str] = &[
    "us-ascii",
    "ascii",
    "iso-8859-1",
    "iso-8859-15",
    "latin1",
    "windows-1252",
];
const MAX_ENTITY_LEN: usize = 4096;
const TIME_CHECK_INTERVAL: usize = 1024;

pub(crate) fn analyze(data: &[u8], budget: &mut Budget, findings: &mut Vec<Finding>) {
    let mut analyzer = Analyzer {
        budget,
        findings,
        entities: HashMap::new(),
    };
    analyzer.document(data);
}

struct Analyzer<'a> {
    budget: &'a mut Budget,
    findings: &'a mut Vec<Finding>,
    /// Internal entities declared in the DOCTYPE, expanded on use.
    entities: HashMap<String, String>,
}

impl Analyzer<'_> {
    /// Record a finding once per code and severity; a file with a thousand
    /// event handlers needs one line, not a thousand.
    fn report(&mut self, code: &'static str, severity: Severity, message: &str, offset: usize) {
        let seen = |f: &Finding| f.code == code && f.severity == severity;
        if !self.findings.iter().any(seen) {
            self.findings
                .push(Finding::new(code, severity, message).at(offset));
        }
    }

    fn malformed(&mut self, message: &str, offset: usize) {
        self.report("svg.malformed", Severity::Medium, message, offset);
    }

    fn limit_exceeded(&mut self, limit: LimitExceeded) {
        if !self.findings.iter().any(|f| f.code == limit.code()) {
            self.findings.push(limit.finding());
        }
    }

    fn document(&mut self, data: &[u8]) {
        // XML syntax is ASCII in every encoding accepted below, so a lossy
        // decode loses nothing the checks look at.
        let text = String::from_utf8_lossy(data);
        let mut needs_utf8 = matches!(text, Cow::Owned(_));
        let body = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
        let base = text.len() - body.len();
        let mut reader = Reader::from_str(body);

        // One entry per open element: whether it is a <style>.
        let mut open: Vec<bool> = Vec::new();
        let mut style = String::new();
        let mut root_seen = false;
        for event_index in 0usize.. {
            if event_index % TIME_CHECK_INTERVAL == 0
                && let Err(limit) = self.budget.check_time()
            {
                return self.limit_exceeded(limit);
            }
            let offset = base + reader.buffer_position() as usize;
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(_) => {
                    let at = base + reader.error_position() as usize;
                    return self.malformed("SVG is not well-formed XML", at);
                }
            };
            let in_style = open.last() == Some(&true);
            match event {
                Event::Eof => break,
                Event::Decl(declaration) => {
                    let encoding = match declaration.encoding() {
                        Some(Ok(encoding)) => encoding.to_ascii_lowercase(),
                        Some(Err(_)) => return self.malformed("invalid XML declaration", offset),
                        None => "utf-8".to_string(),
                    };
                    if SINGLE_BYTE_ENCODINGS.contains(&encoding.as_str()) {
                        needs_utf8 = false;
                    } else if encoding != "utf-8" {
                        // A parser honouring it would see different markup.
                        return self.malformed("unsupported character encoding", offset);
                    }
                }
                Event::DocType(doctype) => self.doctype(&doctype, offset),
                Event::PI(instruction) => {
                    self.processing_instruction(instruction.target(), instruction.content(), offset)
                }
                Event::Start(_) | Event::Empty(_) if open.is_empty() && root_seen => {
                    return self.malformed("content after the root element", offset);
                }
                Event::Start(element) => {
                    let name = self.element(&element, !root_seen, offset);
                    root_seen = true;
                    open.push(name == "style");
                }
                Event::Empty(element) => {
                    self.element(&element, !root_seen, offset);
                    root_seen = true;
                }
                Event::End(_) => {
                    if open.pop() == Some(true) {
                        self.check_css(&style, offset);
                        style.clear();
                    }
                }
                Event::Text(text) if in_style => style.push_str(&text),
                Event::CData(text) if in_style => style.push_str(&text),
                Event::GeneralRef(reference) if in_style => {
                    let resolved = self.unescape(&format!("&{};", &*reference), offset);
                    style.push_str(&resolved);
                }
                Event::Text(text) if open.is_empty() && !text.trim().is_empty() => {
                    return self.malformed("text outside the root element", offset);
                }
                _ => {}
            }
        }
        if needs_utf8 {
            self.malformed("SVG is not valid UTF-8", 0);
        } else if !open.is_empty() {
            self.malformed("SVG ends with unclosed elements", data.len());
        } else if !root_seen {
            self.malformed("SVG has no root element", 0);
        }
    }

    /// Check one start tag; returns its lowercase local name.
    fn element(&mut self, element: &BytesStart<'_>, is_root: bool, offset: usize) -> String {
        let name = local_name(element.name().0);
        if is_root && name != "svg" {
            self.malformed("root element is not <svg>", offset);
        }
        match name.as_str() {
            "script" | "handler" | "listener" => {
                self.report("svg.script", Severity::High, "script element", offset)
            }
            "foreignobject" => self.report(
                "svg.foreign_object",
                Severity::Medium,
                "foreignObject embeds arbitrary HTML",
                offset,
            ),
            _ => {}
        }

        let is_animation = ANIMATION_ELEMENTS.contains(&name.as_str());
        for attribute in element.attributes() {
            let Ok(attribute) = attribute else {
                self.malformed("malformed or duplicate attribute", offset);
                break;
            };
            let key = local_name(attribute.key.0);
            let value = self.unescape(&attribute.value, offset);

            if key.len() > 2 && key.starts_with("on") {
                self.report(
                    "svg.event_handler",
                    Severity::High,
                    "event handler attribute",
                    offset,
                );
            }
            if URL_ATTRIBUTES.contains(&key.as_str()) {
                self.check_url(&name, &value, offset);
            }
            if key == "style" || value.to_ascii_lowercase().contains("url(") {
                self.check_css(&value, offset);
            }
            if is_animation {
                self.check_animation(&key, &value, offset);
            }
        }
        name
    }

    /// Animations can rewrite an attribute after load, turning a harmless
    /// link into a script URL or installing an event handler.
    fn check_animation(&mut self, key: &str, value: &str, offset: usize) {
        match key {
            "attributename" if local_name(value.trim()).starts_with("on") => self.report(
                "svg.event_handler",
                Severity::High,
                "animation sets an event handler attribute",
                offset,
            ),
            "to" | "from" | "by" | "values" => {
                let scripted = value.split(';').any(|part| {
                    scheme_of(&clean_url(part))
                        .is_some_and(|s| SCRIPT_SCHEMES.contains(&s.as_str()))
                });
                if scripted {
                    self.report(
                        "svg.javascript_uri",
                        Severity::High,
                        "animation sets a script URL",
                        offset,
                    );
                }
            }
            _ => {}
        }
    }

    fn check_url(&mut self, element: &str, value: &str, offset: usize) {
        let url = clean_url(value);
        let scheme = scheme_of(&url);
        match scheme.as_deref() {
            Some(scheme) if SCRIPT_SCHEMES.contains(&scheme) => {
                self.report("svg.javascript_uri", Severity::High, "script URL", offset)
            }
            Some("data") => self.check_data_url(&url["data:".len()..], offset),
            // Links are only followed on a click; everything else loads by itself.
            _ if element == "a" => {}
            Some(_) => self.report(
                "svg.external_ref",
                Severity::Medium,
                "element loads an external resource",
                offset,
            ),
            None if url.starts_with("//") => self.report(
                "svg.external_ref",
                Severity::Medium,
                "element loads an external resource",
                offset,
            ),
            None => {}
        }
    }

    /// `rest` is a data URL without its scheme: `[type][;param]*[;base64],payload`.
    fn check_data_url(&mut self, rest: &str, offset: usize) {
        let Some((header, payload)) = rest.split_once(',') else {
            return self.report(
                "svg.data_uri",
                Severity::Medium,
                "malformed data: URL",
                offset,
            );
        };
        let header = header.to_ascii_lowercase();
        let mut params = header.split(';').map(str::trim);
        let mime = params.next().unwrap_or("");
        let is_base64 = params.any(|param| param == "base64");

        if RASTER_MIMES.contains(&mime) {
            return;
        }
        if mime == "image/svg+xml" {
            let decoded = if is_base64 {
                decode_base64(payload)
            } else {
                Some(percent_decode(payload))
            };
            return match decoded {
                Some(nested) => self.nested(&nested, offset),
                None => self.report(
                    "svg.data_uri",
                    Severity::High,
                    "embedded SVG cannot be decoded",
                    offset,
                ),
            };
        }
        if SCRIPTABLE_MIMES.contains(&mime) {
            self.report(
                "svg.data_uri",
                Severity::High,
                "data: URL holds a scriptable document",
                offset,
            );
        } else {
            self.report(
                "svg.data_uri",
                Severity::Medium,
                "data: URL of a non-image type",
                offset,
            );
        }
    }

    /// Analyze an SVG embedded as a data URL, reporting at the embedding site.
    fn nested(&mut self, data: &[u8], offset: usize) {
        let entered = self
            .budget
            .enter()
            .and_then(|()| self.budget.consume(data.len() as u64));
        if let Err(limit) = entered {
            return self.limit_exceeded(limit);
        }
        let mut inner = Vec::new();
        analyze(data, self.budget, &mut inner);
        self.budget.leave();
        for finding in inner {
            if finding.code.starts_with("limit.") {
                self.findings.push(finding);
            } else {
                let message = format!("embedded SVG: {}", finding.message);
                self.report(finding.code, finding.severity, &message, offset);
            }
        }
    }

    fn check_css(&mut self, css: &str, offset: usize) {
        let css = normalize_css(css);
        if SCRIPT_SCHEMES
            .iter()
            .any(|scheme| css.contains(&format!("{scheme}:")))
        {
            self.report(
                "svg.javascript_uri",
                Severity::High,
                "script URL in CSS",
                offset,
            );
        }
        let mut external = css.contains("@import");
        let mut rest = css.as_str();
        while let Some(index) = rest.find("url(") {
            rest = &rest[index + 4..];
            let end = rest.find(')').unwrap_or(rest.len());
            let url = rest[..end].trim().trim_matches(['"', '\'']).trim();
            // Script URLs were reported above; data: URLs carry fonts and bitmaps.
            external |= url.starts_with("//")
                || scheme_of(url).is_some_and(|scheme| {
                    scheme != "data" && !SCRIPT_SCHEMES.contains(&scheme.as_str())
                });
        }
        if external {
            self.report(
                "svg.external_ref",
                Severity::Medium,
                "CSS loads an external resource",
                offset,
            );
        }
    }

    fn processing_instruction(&mut self, target: &str, content: &str, offset: usize) {
        if !target.eq_ignore_ascii_case("xml-stylesheet") {
            return;
        }
        if content.to_ascii_lowercase().contains("xsl") {
            // XSLT can emit script into the rendered document.
            self.report("svg.script", Severity::High, "XSLT stylesheet", offset);
        } else {
            self.report(
                "svg.external_ref",
                Severity::Medium,
                "external stylesheet",
                offset,
            );
        }
    }

    /// Inspect the DOCTYPE's internal subset. Plain string entities are kept
    /// for expansion (Illustrator declares its namespaces that way); anything
    /// that can read files, inject markup or blow up in size is reported.
    fn doctype(&mut self, doctype: &str, offset: usize) {
        let Some(mut rest) = find_unquoted(doctype, '[').map(|open| &doctype[open + 1..]) else {
            return;
        };
        while let Some(start) = rest.find("<!") {
            let declaration = &rest[start + 2..];
            if let Some(comment) = declaration.strip_prefix("--") {
                rest = comment.split_once("-->").map_or("", |(_, after)| after);
                continue;
            }
            let end = find_unquoted(declaration, '>').unwrap_or(declaration.len());
            let body = &declaration[..end];
            if let Some(entity) = body.strip_prefix("ENTITY") {
                self.entity(entity, offset);
            } else if body.starts_with("ATTLIST") {
                self.report(
                    "svg.entity",
                    Severity::High,
                    "DOCTYPE declares default attributes",
                    offset,
                );
            }
            rest = &declaration[end..];
        }
    }

    fn entity(&mut self, declaration: &str, offset: usize) {
        let declaration = declaration.trim_start();
        if declaration.starts_with('%') {
            return self.report("svg.entity", Severity::High, "parameter entity", offset);
        }
        let Some((name, rest)) = declaration.split_once(char::is_whitespace) else {
            return;
        };
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(quote @ ('"' | '\'')) => rest[1..].split(quote).next(),
            _ => None,
        };
        let Some(value) = value else {
            return self.report("svg.entity", Severity::High, "external entity", offset);
        };
        if value.contains(['&', '<']) || value.len() > MAX_ENTITY_LEN {
            return self.report(
                "svg.entity",
                Severity::High,
                "entity holds markup, references or oversized text",
                offset,
            );
        }
        self.entities.insert(name.to_string(), value.to_string());
    }

    /// Resolve character and entity references in attribute or text content.
    fn unescape(&mut self, raw: &str, offset: usize) -> String {
        if !raw.contains('&') {
            return raw.to_string();
        }
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            let after = &rest[amp + 1..];
            let Some((name, tail)) = after.split_once(';') else {
                self.malformed("unterminated entity reference", offset);
                rest = after;
                continue;
            };
            rest = tail;
            if let Some(character) = resolve_builtin(name) {
                out.push(character);
            } else if let Some(value) = self.entities.get(name) {
                // Repeated references multiply the input size.
                if let Err(limit) = self.budget.consume(value.len() as u64) {
                    self.limit_exceeded(limit);
                    return out;
                }
                out.push_str(value);
            } else {
                self.malformed("undefined entity reference", offset);
            }
        }
        out.push_str(rest);
        out
    }
}

fn resolve_builtin(name: &str) -> Option<char> {
    if let Some(number) = name.strip_prefix('#') {
        let code = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => number.parse(),
        };
        return code.ok().and_then(char::from_u32);
    }
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// Name without its namespace prefix, lowercased.
fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase()
}

/// Apply the URL parser's preprocessing: tabs and newlines are removed from
/// anywhere, control characters and spaces from the start.
fn clean_url(value: &str) -> String {
    value
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// Lowercased scheme of an absolute URL.
fn scheme_of(url: &str) -> Option<String> {
    let (scheme, _) = url.split_once(':')?;
    let valid = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Lowercase CSS with comments removed and backslash escapes decoded, so
/// `java\73 cript:` and `@im/**/port` read as what the browser sees.
fn normalize_css(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                for c in chars.by_ref() {
                    if previous == '*' && c == '/' {
                        break;
                    }
                    previous = c;
                }
            }
            '\\' => {
                let mut hex = String::new();
                while hex.len() < 6
                    && let Some(&digit) = chars.peek().filter(|c| c.is_ascii_hexdigit())
                {
                    hex.push(digit);
                    chars.next();
                }
                if hex.is_empty() {
                    out.extend(chars.next());
                } else {
                    // One whitespace character terminates a hex escape.
                    chars.next_if(|c| c.is_whitespace());
                    out.extend(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32));
                }
            }
            '\t' | '\n' | '\r' => {}
            c => out.push(c),
        }
    }
    out.make_ascii_lowercase();
    out
}

/// Offset of the first `target` that is not inside a quoted string.
fn find_unquoted(text: &str, target: char) -> Option<usize> {
    let mut quote = None;
    for (index, c) in text.char_indices() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if c == target => return Some(index),
            None if c == '"' || c == '\'' => quote = Some(c),
            None => {}
        }
    }
    None
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

/// Standard or URL-safe alphabet; whitespace and padding are skipped.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut bits, mut count) = (0u32, 0);
    for byte in percent_decode(text) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\t' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        bits = bits << 6 | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

pub(crate) enum GunzipError {
    Corrupt,
    Limit,
}

/// Inflate a gzip member (SVGZ) to at most `cap` bytes under the scan budget.
pub(crate) fn gunzip(data: &[u8], cap: u64, budget: &mut Budget) -> Result<Vec<u8>, GunzipError> {
    const FHCRC: u8 = 2;
    const FEXTRA: u8 = 4;
    const FNAME: u8 = 8;
    const FCOMMENT: u8 = 16;

    let flags = *data.get(3).ok_or(GunzipError::Corrupt)?;
    let mut pos = 10;
    if flags & FEXTRA != 0 {
        let length = data.get(pos..pos + 2).ok_or(GunzipError::Corrupt)?;
        pos += 2 + u16::from_le_bytes([length[0], length[1]]) as usize;
    }
    for field in [FNAME, FCOMMENT] {
        if flags & field != 0 {
            let rest = data.get(pos..).ok_or(GunzipError::Corrupt)?;
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(GunzipError::Corrupt)?;
            pos += nul + 1;
        }
    }
    if flags & FHCRC != 0 {
        pos += 2;
    }
    let deflate = data.get(pos..).ok_or(GunzipError::Corrupt)?;

    let limit = budget.remaining().min(cap);
    match decompress_to_vec_with_limit(deflate, limit as usize) {
        Ok(inflated) => {
            let _ = budget.consume(inflated.len() as u64);
            Ok(inflated)
        }
        Err(error) if error.status == TINFLStatus::HasMoreOutput => {
            let _ = budget.consume(limit);
            Err(GunzipError::Limit)
        }
        Err(_) => Err(GunzipError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    fn run_with(svg: &str, limits: &Limits) -> Vec<(&'static str, Severity)> {
        let mut budget = Budget::new(limits);
        let mut findings = Vec::new();
        analyze(svg.as_bytes(), &mut budget, &mut findings);
        findings.iter().map(|f| (f.code, f.severity)).collect()
    }

    fn codes(svg: &str) -> Vec<&'static str> {
        run_with(svg, &Limits::default())
            .into_iter()
            .map(|(code, _)| code)
            .collect()
    }

    fn wrap(inner: &str) -> String {
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">{inner}</svg>"#
        )
    }

    #[test]
    fn ordinary_drawings_are_clean() {
        let svg = r##"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<!-- made by hand -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">
  <defs>
    <linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient>
    <style><![CDATA[ .a { fill: url(#g); font-family: "Open Sans" } ]]></style>
  </defs>
  <rect class="a" width="10" height="10" style="stroke:#000" fill="url(#g)"/>
  <use xlink:href="#g"/>
  <a href="https://example.com/page"><text x="1" y="5">R&amp;D &#169; one</text></a>
  <image href="data:image/png;base64,iVBORw0KGgo="/>
  <animate attributeName="opacity" values="0;1" dur="1s"/>
</svg>
"##;
        assert_eq!(codes(svg), [] as [&str; 0]);
    }

    #[test]
    fn script_elements() {
        assert_eq!(codes(&wrap("<script>alert(1)</script>")), ["svg.script"]);
        assert_eq!(codes(&wrap("<SCRIPT xlink:href='x.js'/>")), ["svg.script"]);
        assert_eq!(
            codes(&wrap(
                "<x:script xmlns:x='http://www.w3.org/1999/xhtml'>1</x:script>"
            )),
            ["svg.script"]
        );
    }

    #[test]
    fn event_handlers() {
        assert_eq!(
            codes(r#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>"#),
            ["svg.event_handler"]
        );
        assert_eq!(codes(&wrap("<rect OnClick='x()'/>")), ["svg.event_handler"]);
        assert_eq!(
            codes(&wrap("<set attributeName='onmouseover' to='alert(1)'/>")),
            ["svg.event_handler"]
        );
        // Reported once however often it occurs.
        assert_eq!(
            codes(&wrap("<g onclick='a()'/><g onclick='b()'/>")),
            ["svg.event_handler"]
        );
    }

    #[test]
    fn script_urls_in_every_disguise() {
        for href in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "  javascript:alert(1)",
            "jav&#x09;ascript:alert(1)",
            "java&#10;script:alert(1)",
            "&#106;avascript:alert(1)",
            "&#x1;javascript:alert(1)",
            "vbscript:msgbox(1)",
        ] {
            let svg = wrap(&format!(r#"<a xlink:href="{href}"><text>x</text></a>"#));
            assert_eq!(codes(&svg), ["svg.javascript_uri"], "{href}");
        }
        assert_eq!(
            codes(&wrap(
                "<a href='#x'><animate attributeName='href' values='#a;javascript:alert(1)'/></a>"
            )),
            ["svg.javascript_uri"]
        );
    }

    #[test]
    fn data_urls() {
        let html = wrap("<a href='data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;'>x</a>");
        assert_eq!(
            run_with(&html, &Limits::default()),
            [("svg.data_uri", Severity::High)]
        );

        let other = wrap("<image href='data:application/octet-stream;base64,AAAA'/>");
        assert_eq!(
            run_with(&other, &Limits::default()),
            [("svg.data_uri", Severity::Medium)]
        );
    }

    #[test]
    fn nested_svg_is_scanned() {
        // <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
        let base64 =
            "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoMSkiLz4=";
        let svg = wrap(&format!(
            "<image href='data:image/svg+xml;base64,{base64}'/>"
        ));
        assert_eq!(codes(&svg), ["svg.event_handler"]);

        let encoded = wrap("<use href='data:image/svg+xml,%3Csvg%3E%3Cscript/%3E%3C/svg%3E'/>");
        assert_eq!(codes(&encoded), ["svg.script"]);

        let clean = wrap("<image href='data:image/svg+xml,%3Csvg%3E%3Crect/%3E%3C/svg%3E'/>");
        assert_eq!(codes(&clean), [] as [&str; 0]);

        let broken = wrap("<image href='data:image/svg+xml;base64,!!!'/>");
        assert_eq!(codes(&broken), ["svg.data_uri"]);
    }

    #[test]
    fn nesting_depth_is_limited() {
        let limits = Limits {
            max_depth: 0,
            ..Limits::default()
        };
        let svg = wrap("<image href='data:image/svg+xml,%3Csvg/%3E'/>");
        assert_eq!(run_with(&svg, &limits), [("limit.depth", Severity::Medium)]);
    }

    #[test]
    fn external_resources() {
        assert_eq!(
            codes(&wrap("<image href='https://evil.example/track.png'/>")),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes(&wrap("<use xlink:href='//evil.example/x.svg#a'/>")),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes(&wrap(
                "<style>@import 'https://evil.example/x.css';</style>"
            )),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes(&wrap("<rect fill='url(http://evil.example/p.svg#g)'/>")),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes("<?xml-stylesheet href='theme.css'?><svg xmlns='http://www.w3.org/2000/svg'/>"),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes(&wrap("<foreignObject><p>hi</p></foreignObject>")),
            ["svg.foreign_object"]
        );
    }

    #[test]
    fn css_obfuscation() {
        for css in [
            "a { background: url(javascript:alert(1)) }",
            "a { background: url('java\\73 cript:alert(1)') }",
            "a { background: url(java/**/script:alert(1)) }",
        ] {
            let svg = wrap(&format!("<style>{css}</style>"));
            assert!(codes(&svg).contains(&"svg.javascript_uri"), "{css}");
        }
        assert_eq!(
            codes(&wrap(
                "<style>@im/**/port url(&#x68;ttp://evil.example/x.css);</style>"
            )),
            ["svg.external_ref"]
        );
        assert_eq!(
            codes(&wrap("<rect style='fill:url(JAVASCRIPT:alert(1))'/>")),
            ["svg.javascript_uri"]
        );
    }

    #[test]
    fn xslt_stylesheet_is_script() {
        assert_eq!(
            codes(
                "<?xml-stylesheet type='text/xsl' href='#x'?><svg xmlns='http://www.w3.org/2000/svg'/>"
            ),
            ["svg.script"]
        );
    }

    #[test]
    fn doctype_entities() {
        let doctype = |subset: &str, body: &str| {
            format!("<!DOCTYPE svg [{subset}]><svg xmlns='http://www.w3.org/2000/svg'>{body}</svg>")
        };
        // Illustrator-style namespace entities are expanded, not reported.
        let illustrator = doctype(
            r#"<!ENTITY ns_svg "http://www.w3.org/2000/svg"> <!-- > --> <!ENTITY ns_ai "http://ns.adobe.com/AdobeIllustrator/10.0/">"#,
            "<g xmlns:i='&ns_ai;' i:extraneous='self'/>",
        );
        assert_eq!(codes(&illustrator), [] as [&str; 0]);

        // The entity's content is checked where it is used.
        let hidden = doctype(
            r#"<!ENTITY u "javascript:alert(1)">"#,
            "<a href='&u;'>x</a>",
        );
        assert_eq!(codes(&hidden), ["svg.javascript_uri"]);

        let xxe = doctype(
            r#"<!ENTITY x SYSTEM "file:///etc/passwd">"#,
            "<text>&x;</text>",
        );
        assert_eq!(codes(&xxe), ["svg.entity"]);
        let laughs = doctype(
            r#"<!ENTITY a "ha"><!ENTITY b "&a;&a;&a;">"#,
            "<text>&b;</text>",
        );
        assert_eq!(codes(&laughs), ["svg.entity"]);
        let parameter = doctype(r#"<!ENTITY % p SYSTEM "http://evil.example/x.dtd">"#, "");
        assert_eq!(codes(&parameter), ["svg.entity"]);
        let defaults = doctype("<!ATTLIST svg onload CDATA 'alert(1)'>", "");
        assert_eq!(codes(&defaults), ["svg.entity"]);
    }

    #[test]
    fn entity_expansion_is_budgeted() {
        let limits = Limits {
            max_decompressed: 10_000,
            ..Limits::default()
        };
        let big = "A".repeat(4000);
        let svg = format!(
            "<!DOCTYPE svg [<!ENTITY a '{big}'>]><svg xmlns='http://www.w3.org/2000/svg'><g id='&a;&a;&a;'/></svg>"
        );
        assert_eq!(
            run_with(&svg, &limits),
            [("limit.decompression", Severity::Medium)]
        );
    }

    #[test]
    fn malformed_documents() {
        for svg in [
            "<svg xmlns='http://www.w3.org/2000/svg'><g></svg>",
            "<svg xmlns='http://www.w3.org/2000/svg'><g>",
            "<svg xmlns='http://www.w3.org/2000/svg'/><svg/>",
            "<svg xmlns='http://www.w3.org/2000/svg'/>trailing",
            "<svg a='1' a='2'/>",
            "<svg><g id='&nope;'/></svg>",
            "<html><svg/></html>",
            "",
        ] {
            assert_eq!(codes(svg), ["svg.malformed"], "{svg}");
        }
    }

    fn codes_of_bytes(svg: &[u8]) -> Vec<&'static str> {
        let mut budget = Budget::new(&Limits::default());
        let mut findings = Vec::new();
        analyze(svg, &mut budget, &mut findings);
        findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn character_encodings() {
        assert_eq!(
            codes_of_bytes(b"<svg><text>caf\xE9</text></svg>"),
            ["svg.malformed"]
        );
        // Latin-1 text is fine when declared, and still analyzed.
        let latin1 = b"<?xml version='1.0' encoding='ISO-8859-1'?><svg><text>caf\xE9</text></svg>";
        assert_eq!(codes_of_bytes(latin1), [] as [&str; 0]);
        let scripted = b"<?xml version='1.0' encoding='ISO-8859-1'?><svg onload='x()'>\xE9</svg>";
        assert_eq!(codes_of_bytes(scripted), ["svg.event_handler"]);
        // Encodings that remap ASCII bytes could hide markup from this parser.
        let shifted = b"<?xml version='1.0' encoding='ISO-2022-JP'?><svg/>";
        assert_eq!(codes_of_bytes(shifted), ["svg.malformed"]);
    }

    #[test]
    fn gunzip_reads_optional_header_fields() {
        let mut gz = b"\x1F\x8B\x08\x08\0\0\0\0\0\x03drawing.svg\0".to_vec();
        gz.extend(miniz_oxide::deflate::compress_to_vec(b"<svg/>", 6));
        gz.extend_from_slice(&[0; 8]);
        let limits = Limits::default();
        let inflated = gunzip(&gz, 1024, &mut Budget::new(&limits));
        assert_eq!(inflated.ok().as_deref(), Some(&b"<svg/>"[..]));

        assert!(matches!(
            gunzip(&gz, 3, &mut Budget::new(&limits)),
            Err(GunzipError::Limit)
        ));
        assert!(matches!(
            gunzip(
                b"\x1F\x8B\x08\0\0\0\0\0\0\x03garbage!",
                1024,
                &mut Budget::new(&limits)
            ),
            Err(GunzipError::Corrupt)
        ));
    }
}
