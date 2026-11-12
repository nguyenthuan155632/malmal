//! ICAP (RFC 3507), the protocol a proxy uses to hand the requests and
//! responses passing through it to a scanner. A proxy configured with
//! `icap://host:1344/scan` sends uploads as `REQMOD` and downloads as
//! `RESPMOD`.
//!
//! What is judged is a file, not an HTTP message:
//!
//! - a `multipart/form-data` request is taken apart and every part with a
//!   file name is scanned, with that name and the part's `Content-Type` as
//!   the claims;
//! - a URL-encoded form carries no file and passes;
//! - any other body is the file itself.
//!
//! A clean message is answered `204 No Modifications`, or echoed back when
//! the client did not allow that. Anything else, including a body that is
//! too large or cannot be taken apart, is answered with a `403 Forbidden`
//! response to put in its place, and the finding in `X-Infection-Found`.

use std::io::{self, BufRead, Read, Write};

use malmal::{ScanHints, Verdict};

use crate::serve::{Line, MAX_HEADER_LEN, Service, percent_decode, read_line, signature};

/// Longest encapsulated HTTP header section.
const MAX_ENCAPSULATED: usize = 64 << 10;
const MAX_HEADERS: usize = 64;
const MAX_CHUNK_LINE: u64 = 256;
/// Parts of one form; more than this is not a form a browser sent.
const MAX_PARTS: usize = 256;

const BLOCK_PAGE: &str = "The file was rejected by the upload scanner.\n";

fn ascii_prefix<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Value of the parameter `name` in a header value such as
/// `form-data; name="file"; filename="a.png"`.
fn parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim().eq_ignore_ascii_case(name).then(|| {
            let value = value.trim();
            let unquoted = value
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'));
            unquoted.unwrap_or(value).replace("\\\"", "\"")
        })
    })
}

/// The file name a `Content-Disposition` value declares.
fn disposition_filename(value: &str) -> Option<String> {
    // The extended form is `charset'language'percent-encoded`.
    let extended = parameter(value, "filename*").and_then(|value| {
        value
            .rsplit_once('\'')
            .map(|(_, name)| percent_decode(name))
    });
    extended.or_else(|| parameter(value, "filename"))
}

/// Value of the header `name` in an HTTP header section; the first line is
/// the request or status line.
fn http_header<'a>(section: &'a str, name: &str) -> Option<&'a str> {
    section.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The `Encapsulated` header: where each section starts in what follows the
/// ICAP headers. The last entry is the body, or says there is none.
struct Encapsulated {
    sections: Vec<(String, usize)>,
}

impl Encapsulated {
    fn parse(value: &str) -> Option<Self> {
        let sections: Vec<(String, usize)> = value
            .split(',')
            .map(|entry| {
                let (name, offset) = entry.trim().split_once('=')?;
                Some((name.to_ascii_lowercase(), offset.trim().parse().ok()?))
            })
            .collect::<Option<_>>()?;
        let (last, offset) = sections.last()?;
        let ordered = sections.windows(2).all(|pair| pair[0].1 <= pair[1].1);
        (ordered && last.ends_with("-body") && *offset <= MAX_ENCAPSULATED)
            .then_some(Self { sections })
    }

    /// Length of the header sections before the body.
    fn head_len(&self) -> usize {
        self.sections.last().map_or(0, |(_, offset)| *offset)
    }

    fn has_body(&self) -> bool {
        self.sections
            .last()
            .is_some_and(|(name, _)| name != "null-body")
    }

    fn section<'a>(&self, head: &'a [u8], name: &str) -> &'a [u8] {
        let index = self.sections.iter().position(|(found, _)| found == name);
        index
            .and_then(|index| head.get(self.sections[index].1..self.sections[index + 1].1))
            .unwrap_or_default()
    }
}

enum Chunks {
    /// The terminating chunk, and whether it said the whole body was sent.
    End {
        complete: bool,
    },
    TooLarge,
    Malformed,
}

/// Append chunks to `body` up to the terminating one.
fn read_chunks(reader: &mut impl BufRead, body: &mut Vec<u8>, limit: u64) -> io::Result<Chunks> {
    loop {
        let Line::Text(line) = read_line(reader, MAX_CHUNK_LINE)? else {
            return Ok(Chunks::Malformed);
        };
        let (size, extension) = line.split_once(';').unwrap_or((&line, ""));
        let Ok(size) = u64::from_str_radix(size.trim(), 16) else {
            return Ok(Chunks::Malformed);
        };
        if size == 0 {
            // Trailers, if any, up to the empty line.
            for _ in 0..MAX_HEADERS {
                match read_line(reader, MAX_HEADER_LEN)? {
                    Line::Text(line) if line.is_empty() => {
                        let complete = extension.trim().eq_ignore_ascii_case("ieof");
                        return Ok(Chunks::End { complete });
                    }
                    Line::Text(_) => {}
                    _ => break,
                }
            }
            return Ok(Chunks::Malformed);
        }
        if body.len() as u64 + size > limit {
            return Ok(Chunks::TooLarge);
        }
        if reader.by_ref().take(size).read_to_end(body)? as u64 != size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if !matches!(read_line(reader, MAX_CHUNK_LINE)?, Line::Text(line) if line.is_empty()) {
            return Ok(Chunks::Malformed);
        }
    }
}

struct Part<'a> {
    filename: Option<String>,
    content_type: Option<String>,
    data: &'a [u8],
}

/// The parts of a `multipart/form-data` body. `None` when the body does not
/// follow the format to its closing boundary.
fn multipart<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<Part<'a>>> {
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut rest = &body[find(body, &delimiter)? + delimiter.len()..];
    while parts.len() <= MAX_PARTS {
        if rest.starts_with(b"--") {
            return Some(parts);
        }
        rest = &rest[find(rest, b"\r\n")? + 2..];
        // A part without headers starts with the empty line itself.
        let (head, after) = match rest.strip_prefix(b"\r\n") {
            Some(after) => (&rest[..0], after),
            None => {
                let end = find(rest, b"\r\n\r\n")?;
                (&rest[..end], &rest[end + 4..])
            }
        };
        let closing = [b"\r\n", &delimiter[..]].concat();
        let end = find(after, &closing)?;
        // A status line stands in for the one `http_header` skips.
        let head = format!("\r\n{}", String::from_utf8_lossy(head));
        parts.push(Part {
            filename: http_header(&head, "content-disposition").and_then(disposition_filename),
            content_type: http_header(&head, "content-type").map(str::to_owned),
            data: &after[..end],
        });
        rest = &after[end + closing.len()..];
    }
    None
}

/// Why a message is not let through.
enum Blocked {
    Threat(String),
    NotScanned(&'static str),
}

/// Scan the files `body` carries. `Ok` when every one of them is clean.
fn judge(service: &Service, request: bool, headers: &str, body: &[u8]) -> Result<(), Blocked> {
    let scan = |data: &[u8], filename: Option<&str>, content_type: Option<&str>| {
        let hints = ScanHints {
            filename,
            content_type,
        };
        match service.scan(data, hints) {
            Some(report) if report.verdict == Verdict::Clean => Ok(()),
            Some(report) => Err(Blocked::Threat(signature(&report))),
            None => Err(Blocked::NotScanned("internal error while scanning")),
        }
    };
    let content_type = http_header(headers, "content-type");
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());

    match media_type.as_deref() {
        Some("multipart/form-data") if request => {
            let boundary = content_type
                .and_then(|value| parameter(value, "boundary"))
                .filter(|boundary| !boundary.is_empty());
            let parts = boundary
                .and_then(|boundary| multipart(body, &boundary))
                .ok_or(Blocked::NotScanned("malformed multipart body"))?;
            for part in parts {
                // A file field left empty is sent with an empty name.
                let named = part.filename.as_deref().filter(|name| !name.is_empty());
                if let Some(name) = named {
                    scan(part.data, Some(name), part.content_type.as_deref())?;
                }
            }
            Ok(())
        }
        Some("application/x-www-form-urlencoded") if request => Ok(()),
        _ if body.is_empty() => Ok(()),
        _ => {
            let declared =
                http_header(headers, "content-disposition").and_then(disposition_filename);
            // An upload by `PUT` is named by its URL.
            let from_url = headers
                .lines()
                .next()
                .filter(|line| request && ascii_prefix(line, "PUT ").is_some())
                .and_then(|line| line.split(' ').nth(1))
                .and_then(|target| target.split(['?', '#']).next())
                .and_then(|path| path.rsplit('/').next())
                .filter(|name| !name.is_empty())
                .map(percent_decode);
            scan(body, declared.or(from_url).as_deref(), content_type)
        }
    }
}

/// An ICAP response: the status, extra headers, and the encapsulated HTTP
/// header section and body, if any.
struct Reply<'a> {
    status: &'a str,
    headers: String,
    /// `req` or `res`, naming the kind of the encapsulated message.
    kind: &'a str,
    head: &'a [u8],
    body: Option<&'a [u8]>,
}

impl Reply<'_> {
    fn status(status: &str) -> Reply<'_> {
        Reply {
            status,
            headers: String::new(),
            kind: "res",
            head: &[],
            body: None,
        }
    }

    fn write(&self, mut writer: impl Write) -> io::Result<()> {
        let version = env!("CARGO_PKG_VERSION");
        let mut encapsulated = String::new();
        if !self.head.is_empty() {
            encapsulated = format!("{}-hdr=0, ", self.kind);
        }
        match self.body {
            Some(_) => encapsulated += &format!("{}-body={}", self.kind, self.head.len()),
            None => encapsulated += &format!("null-body={}", self.head.len()),
        }
        write!(
            writer,
            "ICAP/1.0 {}\r\nISTag: \"malmal-{version}\"\r\nService: malmal {version}\r\n\
             {}Encapsulated: {encapsulated}\r\n\r\n",
            self.status, self.headers,
        )?;
        writer.write_all(self.head)?;
        if let Some(body) = self.body {
            if !body.is_empty() {
                write!(writer, "{:x}\r\n", body.len())?;
                writer.write_all(body)?;
                writer.write_all(b"\r\n")?;
            }
            writer.write_all(b"0\r\n\r\n")?;
        }
        writer.flush()
    }
}

fn block(writer: impl Write, reason: &Blocked) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        BLOCK_PAGE.len()
    );
    let headers = match reason {
        Blocked::Threat(name) => format!(
            "X-Infection-Found: Type=0; Resolution=2; Threat={name};\r\nX-Virus-ID: {name}\r\n"
        ),
        Blocked::NotScanned(why) => format!("X-Block-Reason: {why}\r\n"),
    };
    Reply {
        status: "200 OK",
        headers,
        kind: "res",
        head: head.as_bytes(),
        body: Some(BLOCK_PAGE.as_bytes()),
    }
    .write(writer)
}

/// Serve `OPTIONS`, `REQMOD` and `RESPMOD` on one connection, which may
/// carry any number of requests. The service path is not looked at.
pub fn icap(
    reader: &mut impl BufRead,
    mut writer: impl Write,
    service: &Service,
) -> io::Result<()> {
    loop {
        let refuse = |writer, status: &str| {
            service.metrics().reject();
            Reply::status(status).write(writer)
        };
        let request_line = match read_line(reader, MAX_HEADER_LEN)? {
            Line::Text(line) => line,
            Line::End => return Ok(()),
            Line::Overlong => return refuse(writer, "400 Bad Request"),
        };
        let mut parts = request_line.split(' ');
        let (Some(method), Some(_), Some(version)) = (parts.next(), parts.next(), parts.next())
        else {
            return refuse(writer, "400 Bad Request");
        };
        if version != "ICAP/1.0" {
            return refuse(writer, "505 ICAP Version Not Supported");
        }

        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let line = match read_line(reader, MAX_HEADER_LEN)? {
                Line::Text(line) if headers.len() < MAX_HEADERS => line,
                Line::End => return Ok(()),
                _ => return refuse(writer, "400 Bad Request"),
            };
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let header = |name: &str| {
            let found = headers.iter().find(|(key, _)| key == name);
            found.map(|(_, value)| value.as_str())
        };

        let request = match method {
            "OPTIONS" => {
                let mut reply = Reply::status("200 OK");
                reply.headers =
                    "Methods: REQMOD, RESPMOD\r\nAllow: 204\r\nOptions-TTL: 3600\r\n".into();
                reply.write(&mut writer)?;
                continue;
            }
            "REQMOD" => true,
            "RESPMOD" => false,
            _ => return refuse(writer, "405 Method Not Allowed"),
        };
        let Some(encapsulated) = header("encapsulated").and_then(Encapsulated::parse) else {
            return refuse(writer, "400 Bad Request");
        };
        let mut head = vec![0; encapsulated.head_len()];
        reader.read_exact(&mut head)?;

        let mut body = Vec::new();
        let preview = header("preview").is_some();
        if encapsulated.has_body() {
            let mut outcome = read_chunks(reader, &mut body, service.max_size())?;
            // A preview that is not the whole body: ask for the rest.
            if preview && matches!(outcome, Chunks::End { complete: false }) {
                writer.write_all(b"ICAP/1.0 100 Continue\r\n\r\n")?;
                writer.flush()?;
                outcome = read_chunks(reader, &mut body, service.max_size())?;
            }
            match outcome {
                Chunks::End { .. } => {}
                // The rest of the body cannot be skipped safely.
                Chunks::TooLarge => {
                    service.metrics().reject();
                    return block(writer, &Blocked::NotScanned("file exceeds the size limit"));
                }
                Chunks::Malformed => return refuse(writer, "400 Bad Request"),
            }
        }

        let kind = if request { "req" } else { "res" };
        let section = encapsulated.section(&head, &format!("{kind}-hdr"));
        match judge(service, request, &String::from_utf8_lossy(section), &body) {
            Err(reason) => block(&mut writer, &reason)?,
            // Inside a preview, 204 is allowed without being asked for.
            Ok(()) if preview || header("allow").is_some_and(allows_204) => {
                Reply::status("204 No Modifications").write(&mut writer)?
            }
            Ok(()) => Reply {
                status: "200 OK",
                headers: String::new(),
                kind,
                head: section,
                body: encapsulated.has_body().then_some(&body),
            }
            .write(&mut writer)?,
        }
    }
}

fn allows_204(value: &str) -> bool {
    value.split(',').any(|code| code.trim() == "204")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use malmal::Scanner;

    use super::*;

    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
    const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B";

    fn service() -> Service {
        Service::new(Scanner::builder().build())
    }

    fn run(service: &Service, input: &[u8]) -> String {
        let mut output = Vec::new();
        // A peer that hangs up mid-request is an error the caller ignores.
        let _ = icap(&mut Cursor::new(input.to_vec()), &mut output, service);
        String::from_utf8_lossy(&output).into_owned()
    }

    fn chunked(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in body.chunks(10) {
            out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            out.extend_from_slice(chunk);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    /// An ICAP request carrying the HTTP message `head` + `body`.
    fn message(method: &str, icap_headers: &str, head: &str, body: Option<&[u8]>) -> Vec<u8> {
        let kind = if method == "REQMOD" { "req" } else { "res" };
        let last = match body {
            Some(_) => format!("{kind}-body"),
            None => "null-body".into(),
        };
        let mut out = format!(
            "{method} icap://localhost/scan ICAP/1.0\r\nHost: localhost\r\n{icap_headers}\
             Encapsulated: {kind}-hdr=0, {last}={}\r\n\r\n{head}",
            head.len()
        )
        .into_bytes();
        if let Some(body) = body {
            out.extend(chunked(body));
        }
        out
    }

    fn upload(icap_headers: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let head = format!("POST /upload HTTP/1.1\r\nContent-Type: {content_type}\r\n\r\n");
        message("REQMOD", icap_headers, &head, Some(body))
    }

    fn form(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body =
            b"preamble\r\n--XYZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nplain text"
                .to_vec();
        for (name, data) in files {
            body.extend_from_slice(
                format!(
                    "\r\n--XYZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{name}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(data);
        }
        body.extend_from_slice(b"\r\n--XYZ--\r\n");
        body
    }

    const ALLOW: &str = "Allow: 204\r\n";
    const FORM: &str = "multipart/form-data; boundary=XYZ";

    #[test]
    fn options_describe_the_service() {
        let reply = run(
            &service(),
            b"OPTIONS icap://localhost/scan ICAP/1.0\r\n\r\n",
        );
        assert!(reply.starts_with("ICAP/1.0 200 OK\r\n"), "{reply}");
        for line in ["Methods: REQMOD, RESPMOD", "Allow: 204", "ISTag: \"malmal-"] {
            assert!(reply.contains(line), "{reply}");
        }
    }

    #[test]
    fn clean_messages_pass() {
        let service = service();
        let mut input = upload(ALLOW, "image/gif", GIF);
        input.extend(upload(
            ALLOW,
            FORM,
            &form(&[("a.gif", GIF), ("b.gif", GIF)]),
        ));
        // A form without files, a field left empty, and a request without a body.
        input.extend(upload(
            ALLOW,
            "application/x-www-form-urlencoded",
            b"a=1&b=2",
        ));
        input.extend(upload(ALLOW, FORM, &form(&[("", b"")])));
        input.extend(message("REQMOD", ALLOW, "GET / HTTP/1.1\r\n\r\n", None));
        let head = "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\n\r\n";
        input.extend(message("RESPMOD", ALLOW, head, Some(GIF)));
        let reply = run(&service, &input);
        assert_eq!(reply.matches("ICAP/1.0 204 No Modifications").count(), 6);
        assert_eq!(reply.matches("ICAP/1.0").count(), 6, "{reply}");
        assert!(service.metrics().render().contains("verdict=\"clean\"} 4"));
    }

    #[test]
    fn clean_messages_are_echoed_when_204_is_not_allowed() {
        let reply = run(&service(), &upload("", "image/gif", GIF));
        let head = "POST /upload HTTP/1.1\r\nContent-Type: image/gif\r\n\r\n";
        let expected = format!(
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n{head}{:x}\r\n",
            head.len(),
            GIF.len()
        );
        assert!(reply.starts_with("ICAP/1.0 200 OK\r\n"), "{reply}");
        assert!(reply.contains(&expected), "{reply}");
        assert!(reply.ends_with("\x3B\r\n0\r\n\r\n"), "{reply}");

        let empty = message("RESPMOD", "", "HTTP/1.1 304 Not Modified\r\n\r\n", None);
        let reply = run(&service(), &empty);
        assert!(
            reply.contains("Encapsulated: res-hdr=0, null-body=29\r\n"),
            "{reply}"
        );
    }

    #[test]
    fn files_that_are_not_clean_are_replaced() {
        let service = service();
        let blocked = |input: &[u8]| {
            let reply = run(&service, input);
            assert!(reply.starts_with("ICAP/1.0 200 OK\r\n"), "{reply}");
            assert!(
                reply.contains("\r\n\r\nHTTP/1.1 403 Forbidden\r\n"),
                "{reply}"
            );
            assert!(reply.ends_with("\r\n0\r\n\r\n"), "{reply}");
            reply
        };
        let threat = "X-Infection-Found: Type=0; Resolution=2; Threat=Malmal.Malicious";
        assert!(blocked(&upload(ALLOW, "image/gif", ELF)).contains(threat));
        // One bad file among good ones, and a name the content does not match.
        let mixed = form(&[("a.gif", GIF), ("b.gif", ELF)]);
        assert!(blocked(&upload(ALLOW, FORM, &mixed)).contains(threat));
        let renamed = form(&[("a.png", GIF)]);
        assert!(blocked(&upload(ALLOW, FORM, &renamed)).contains("type.mismatch"));
        let head = "HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename*=UTF-8''a%20b.gif\r\n\r\n";
        assert!(blocked(&message("RESPMOD", ALLOW, head, Some(ELF))).contains(threat));
        // An upload by PUT is named by its URL.
        let put = message(
            "REQMOD",
            ALLOW,
            "PUT /files/a.png?v=1 HTTP/1.1\r\n\r\n",
            Some(GIF),
        );
        assert!(blocked(&put).contains("type.mismatch"));

        // A form that cannot be taken apart is not let through.
        for broken in [&b"--XYZ\r\nno end"[..], b"no boundary at all"] {
            let reply = blocked(&upload(ALLOW, FORM, broken));
            assert!(reply.contains("X-Block-Reason: malformed multipart body"));
        }
        let reply = blocked(&upload(ALLOW, "multipart/form-data", &form(&[])));
        assert!(reply.contains("X-Block-Reason"));
    }

    #[test]
    fn previews_are_continued() {
        let service = service();
        let head = "POST /upload HTTP/1.1\r\nContent-Type: image/gif\r\n\r\n";
        let start = format!(
            "REQMOD icap://localhost/scan ICAP/1.0\r\nPreview: 4\r\n\
             Encapsulated: req-hdr=0, req-body={}\r\n\r\n{head}4\r\n",
            head.len()
        );
        // The preview is the start of an executable; the rest follows.
        let mut input = start.clone().into_bytes();
        input.extend_from_slice(&ELF[..4]);
        input.extend_from_slice(b"\r\n0\r\n\r\n");
        input.extend(chunked(&ELF[4..]));
        let reply = run(&service, &input);
        assert!(reply.starts_with("ICAP/1.0 100 Continue\r\n\r\nICAP/1.0 200 OK\r\n"));
        assert!(
            reply.contains("Threat=Malmal.Malicious.type.executable"),
            "{reply}"
        );

        // A body that fits the preview is not continued.
        let mut input = format!(
            "REQMOD icap://localhost/scan ICAP/1.0\r\nPreview: 64\r\n\
             Encapsulated: req-hdr=0, req-body={}\r\n\r\n{head}{:x}\r\n",
            head.len(),
            GIF.len()
        )
        .into_bytes();
        input.extend_from_slice(GIF);
        input.extend_from_slice(b"\r\n0; ieof\r\n\r\n");
        assert!(run(&service, &input).starts_with("ICAP/1.0 204 No Modifications\r\n"));
    }

    #[test]
    fn refuses_what_it_cannot_judge() {
        let limits = malmal::Limits {
            max_file_size: 8,
            ..malmal::Limits::default()
        };
        let small = Service::new(Scanner::builder().limits(limits).build());
        let reply = run(&small, &upload(ALLOW, "image/gif", GIF));
        assert!(
            reply.contains("X-Block-Reason: file exceeds the size limit"),
            "{reply}"
        );
        assert!(reply.contains("HTTP/1.1 403 Forbidden"));

        let service = service();
        let status = |input: &[u8]| {
            run(&service, input)
                .lines()
                .next()
                .unwrap_or("")
                .to_string()
        };
        assert_eq!(status(b"nonsense\r\n\r\n"), "ICAP/1.0 400 Bad Request");
        assert_eq!(
            status(b"REQMOD icap://x/ ICAP/2.0\r\n\r\n"),
            "ICAP/1.0 505 ICAP Version Not Supported"
        );
        assert_eq!(
            status(b"GET icap://x/ ICAP/1.0\r\n\r\n"),
            "ICAP/1.0 405 Method Not Allowed"
        );
        assert_eq!(
            status(b"REQMOD icap://x/ ICAP/1.0\r\n\r\n"),
            "ICAP/1.0 400 Bad Request"
        );
        assert_eq!(
            status(b"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-body=0\r\n\r\nzz\r\n"),
            "ICAP/1.0 400 Bad Request"
        );
        // A body that ends early gets no answer at all.
        let mut cut = upload(ALLOW, "image/gif", GIF);
        cut.truncate(cut.len() - 12);
        assert_eq!(run(&service, &cut), "");
    }
}
