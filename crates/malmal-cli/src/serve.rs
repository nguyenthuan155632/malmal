//! The protocols the daemon speaks. Each handler serves one connection and
//! is written against a reader and a writer, so it is the same code on a
//! Unix socket, a TCP socket and a test buffer.
//!
//! - [`json`]: one line of JSON, then the file; the daemon's own protocol.
//! - [`http`]: `POST /scan` with the file as the body, plus `/metrics` and
//!   `/healthz`.
//! - [`clamd`]: the `INSTREAM` command of ClamAV's daemon, for clients that
//!   already speak it.
//! - [`icap`](crate::icap::icap): ICAP, for proxies that hand over the
//!   requests and responses passing through them.
//!
//! Whatever the protocol, a file that was not scanned is never answered as
//! clean.

use std::io::{self, BufRead, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use malmal::{Report, ScanHints, Scanner, Severity, Verdict};
use serde::Deserialize;

use crate::watchdog::Watchdog;

pub(crate) const MAX_HEADER_LEN: u64 = 16 << 10;
const MAX_HTTP_HEADERS: usize = 64;
const MAX_COMMAND_LEN: u64 = 1024;

/// Counters exposed in the Prometheus text format.
#[derive(Debug, Default)]
pub struct Metrics {
    clean: AtomicU64,
    suspicious: AtomicU64,
    malicious: AtomicU64,
    /// Scans that ended in an internal error.
    errors: AtomicU64,
    /// Requests refused before any scan: malformed or too large.
    rejected: AtomicU64,
    bytes: AtomicU64,
    micros: AtomicU64,
    /// Images written anew by `/sanitize`.
    rebuilt: AtomicU64,
}

impl Metrics {
    fn record(&self, report: &Report, elapsed: Duration) {
        let counter = match report.verdict {
            Verdict::Clean => &self.clean,
            Verdict::Suspicious => &self.suspicious,
            Verdict::Malicious => &self.malicious,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(report.size, Ordering::Relaxed);
        self.micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    pub(crate) fn reject(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            "# HELP malmal_scans_total Files scanned, by verdict.\n\
             # TYPE malmal_scans_total counter\n\
             malmal_scans_total{{verdict=\"clean\"}} {}\n\
             malmal_scans_total{{verdict=\"suspicious\"}} {}\n\
             malmal_scans_total{{verdict=\"malicious\"}} {}\n\
             # HELP malmal_scan_errors_total Scans that ended in an internal error.\n\
             # TYPE malmal_scan_errors_total counter\n\
             malmal_scan_errors_total {}\n\
             # HELP malmal_rejected_requests_total Requests refused before a scan.\n\
             # TYPE malmal_rejected_requests_total counter\n\
             malmal_rejected_requests_total {}\n\
             # HELP malmal_scanned_bytes_total Size of the files scanned.\n\
             # TYPE malmal_scanned_bytes_total counter\n\
             malmal_scanned_bytes_total {}\n\
             # HELP malmal_scan_seconds_total Time spent scanning.\n\
             # TYPE malmal_scan_seconds_total counter\n\
             malmal_scan_seconds_total {:.6}\n\
             # HELP malmal_rebuilt_images_total Images rebuilt from their pixels.\n\
             # TYPE malmal_rebuilt_images_total counter\n\
             malmal_rebuilt_images_total {}\n\
             # HELP malmal_build_info Version of the running daemon.\n\
             # TYPE malmal_build_info gauge\n\
             malmal_build_info{{version=\"{}\"}} 1\n",
            get(&self.clean),
            get(&self.suspicious),
            get(&self.malicious),
            get(&self.errors),
            get(&self.rejected),
            get(&self.bytes),
            get(&self.micros) as f64 / 1e6,
            get(&self.rebuilt),
            env!("CARGO_PKG_VERSION"),
        )
    }
}

/// The scanner and its counters, shared by every connection.
#[derive(Debug)]
pub struct Service {
    scanner: Scanner,
    metrics: Metrics,
    watchdog: Watchdog,
}

impl Service {
    pub fn new(scanner: Scanner) -> Self {
        Self {
            scanner,
            metrics: Metrics::default(),
            watchdog: Watchdog::default(),
        }
    }

    /// End the process when a scan runs for as long as `watchdog` allows.
    pub fn watched_by(mut self, watchdog: Watchdog) -> Self {
        self.watchdog = watchdog;
        self
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Largest body a request may carry.
    pub(crate) fn max_size(&self) -> u64 {
        self.scanner.limits().max_file_size
    }

    /// `None` when the scanner itself failed; the caller reports an error.
    pub(crate) fn scan(&self, body: &[u8], hints: ScanHints<'_>) -> Option<Report> {
        let started = Instant::now();
        let _running = self.watchdog.watch();
        match catch_unwind(AssertUnwindSafe(|| self.scanner.scan_bytes(body, hints))) {
            Ok(report) => {
                self.metrics.record(&report, started.elapsed());
                Some(report)
            }
            Err(_) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

impl Service {
    /// Scan and rebuild. `None` when the scanner itself failed.
    #[cfg(feature = "cdr")]
    fn sanitize(
        &self,
        body: &[u8],
        hints: ScanHints<'_>,
    ) -> Option<Result<malmal::cdr::Sanitized, malmal::cdr::Error>> {
        use malmal::cdr::{Error, Options};

        let started = Instant::now();
        let _running = self.watchdog.watch();
        let options = Options::default();
        let run = || self.scanner.sanitize(body, hints, &options);
        let Ok(outcome) = catch_unwind(AssertUnwindSafe(run)) else {
            self.metrics.errors.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        match &outcome {
            Ok(sanitized) => {
                self.metrics.record(&sanitized.report, started.elapsed());
                self.metrics.rebuilt.fetch_add(1, Ordering::Relaxed);
            }
            Err(Error::Rejected(report)) => self.metrics.record(report, started.elapsed()),
            // Scanned and clean, but not rebuilt; the scan is not counted twice.
            Err(_) => self.metrics.reject(),
        }
        Some(outcome)
    }
}

pub(crate) enum Line {
    Text(String),
    /// The input ended before another line started.
    End,
    /// Longer than the limit, or cut off before its line ending.
    Overlong,
}

/// One line of at most `limit` bytes, without its line ending.
pub(crate) fn read_line(reader: &mut impl BufRead, limit: u64) -> io::Result<Line> {
    let mut line = Vec::new();
    reader.by_ref().take(limit).read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Ok(Line::End);
    }
    if line.pop() != Some(b'\n') {
        return Ok(Line::Overlong);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Line::Text(String::from_utf8_lossy(&line).into_owned()))
}

fn read_body(reader: &mut impl BufRead, size: u64) -> io::Result<Vec<u8>> {
    let mut body = vec![0; size as usize];
    reader.read_exact(&mut body)?;
    Ok(body)
}

#[derive(Deserialize)]
struct Request {
    size: u64,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

/// A request is one line of JSON, `{"size": N, "filename": ..., "content_type": ...}`
/// (the last two optional), followed by exactly N bytes of file content. The
/// reply is one line of JSON: `{"ok": true, "report": {...}}` or
/// `{"ok": false, "error": "..."}`. A connection may carry any number of
/// requests. Anything but `"ok": true` means the file was not scanned.
pub fn json(
    reader: &mut impl BufRead,
    mut writer: impl Write,
    service: &Service,
) -> io::Result<()> {
    let mut reply = |value: serde_json::Value| {
        let mut line = value.to_string();
        line.push('\n');
        writer.write_all(line.as_bytes())
    };
    let error = |message: &str| serde_json::json!({ "ok": false, "error": message });
    loop {
        let mut header = String::new();
        if reader
            .by_ref()
            .take(MAX_HEADER_LEN)
            .read_line(&mut header)?
            == 0
        {
            return Ok(());
        }
        let request: Request = match serde_json::from_str(&header) {
            Ok(request) => request,
            Err(problem) => {
                service.metrics.reject();
                return reply(error(&format!("invalid request: {problem}")));
            }
        };
        // The body cannot be skipped safely, so the connection ends here.
        if request.size > service.max_size() {
            service.metrics.reject();
            return reply(error("file exceeds the size limit"));
        }
        let body = read_body(reader, request.size)?;

        let hints = ScanHints {
            filename: request.filename.as_deref(),
            content_type: request.content_type.as_deref(),
        };
        match service.scan(&body, hints) {
            Some(report) => reply(serde_json::json!({ "ok": true, "report": report }))?,
            None => reply(error("internal error while scanning"))?,
        }
    }
}

struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn text(status: &'static str, body: &str) -> Self {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    fn json(status: &'static str, value: serde_json::Value) -> Self {
        let mut body = value.to_string().into_bytes();
        body.push(b'\n');
        Response {
            status,
            content_type: "application/json",
            body,
        }
    }

    fn error(status: &'static str, message: &str) -> Self {
        Self::json(status, serde_json::json!({ "ok": false, "error": message }))
    }

    fn write(&self, mut writer: impl Write, keep_alive: bool) -> io::Result<()> {
        let connection = if keep_alive { "keep-alive" } else { "close" };
        write!(
            writer,
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len(),
        )?;
        writer.write_all(&self.body)?;
        writer.flush()
    }
}

/// Undo `%xx` escapes; anything that is not one is kept as written.
pub(crate) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        let escaped = (bytes[pos] == b'%')
            .then(|| text.get(pos + 1..pos + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                pos += 3;
            }
            None => {
                out.push(bytes[pos]);
                pos += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A minimal HTTP/1.1 server:
///
/// - `POST /scan` (or `PUT`): the body is the file. `Content-Length` is
///   required; `Content-Type` is taken as the claimed type and the
///   `X-Filename` header or `?filename=` parameter as the claimed name. The
///   reply is `200` with the same JSON as [`json`], whatever the verdict.
/// - `POST /sanitize` (with the `cdr` feature): the same request; the reply
///   is `200` with the image rebuilt from its pixels as the body, its type
///   in `Content-Type`. `422` with the report means the file is not clean,
///   `415` that it is not an image that can be rebuilt.
/// - `GET /metrics`: counters in the Prometheus text format.
/// - `GET /healthz`: `200 ok`.
///
/// Any other status means the file was not scanned, and closes the
/// connection. From `/sanitize`, anything but `200` means there is no file
/// to keep.
pub fn http(
    reader: &mut impl BufRead,
    mut writer: impl Write,
    service: &Service,
) -> io::Result<()> {
    loop {
        let too_large = |writer| {
            service.metrics.reject();
            Response::error("431 Request Header Fields Too Large", "headers too large")
                .write(writer, false)
        };
        let request_line = match read_line(reader, MAX_HEADER_LEN)? {
            Line::Text(line) => line,
            Line::End => return Ok(()),
            Line::Overlong => return too_large(writer),
        };
        let mut parts = request_line.split(' ');
        let (Some(method), Some(target), Some(version)) =
            (parts.next(), parts.next(), parts.next())
        else {
            service.metrics.reject();
            return Response::error("400 Bad Request", "malformed request line")
                .write(writer, false);
        };

        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let line = match read_line(reader, MAX_HEADER_LEN)? {
                Line::Text(line) if headers.len() < MAX_HTTP_HEADERS => line,
                Line::End => return Ok(()),
                _ => return too_large(writer),
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
        let keep_alive = version == "HTTP/1.1"
            && !header("connection").is_some_and(|value| value.eq_ignore_ascii_case("close"));
        let (path, query) = target.split_once('?').unwrap_or((target, ""));

        let response = match (method, path) {
            ("GET", "/healthz") => Response::text("200 OK", "ok\n"),
            ("GET", "/metrics") => Response {
                status: "200 OK",
                content_type: "text/plain; version=0.0.4; charset=utf-8",
                body: service.metrics.render().into_bytes(),
            },
            ("POST" | "PUT", "/scan" | "/sanitize") => {
                let refuse = |status: &'static str, message: &str| {
                    service.metrics.reject();
                    Response::error(status, message)
                };
                if header("transfer-encoding").is_some() {
                    return refuse("501 Not Implemented", "send the body with Content-Length")
                        .write(writer, false);
                }
                let Some(size) = header("content-length").and_then(|v| v.parse::<u64>().ok())
                else {
                    return refuse("411 Length Required", "Content-Length is required")
                        .write(writer, false);
                };
                // The body cannot be skipped safely, so the connection ends here.
                if size > service.max_size() {
                    return refuse("413 Content Too Large", "file exceeds the size limit")
                        .write(writer, false);
                }
                if header("expect").is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
                {
                    writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                    writer.flush()?;
                }
                let body = read_body(reader, size)?;

                let from_query = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("filename="))
                    .map(percent_decode);
                let filename = header("x-filename").map(percent_decode).or(from_query);
                let hints = ScanHints {
                    filename: filename.as_deref(),
                    content_type: header("content-type"),
                };
                let response = if path == "/scan" {
                    service.scan(&body, hints).map(|report| {
                        Response::json(
                            "200 OK",
                            serde_json::json!({ "ok": true, "report": report }),
                        )
                    })
                } else {
                    sanitize(service, &body, hints)
                };
                match response {
                    Some(response) => response,
                    None => {
                        return Response::error(
                            "500 Internal Server Error",
                            "internal error while scanning",
                        )
                        .write(writer, false);
                    }
                }
            }
            // A body this server did not read may follow, so these close too.
            (_, "/healthz" | "/metrics" | "/scan" | "/sanitize") => {
                return Response::error("405 Method Not Allowed", "method not allowed")
                    .write(writer, false);
            }
            _ => return Response::error("404 Not Found", "not found").write(writer, false),
        };
        response.write(&mut writer, keep_alive)?;
        if !keep_alive {
            return Ok(());
        }
    }
}

/// The reply to `POST /sanitize`; `None` when the scanner itself failed.
#[cfg(feature = "cdr")]
fn sanitize(service: &Service, body: &[u8], hints: ScanHints<'_>) -> Option<Response> {
    use malmal::FileType;
    use malmal::cdr::Error;

    Some(match service.sanitize(body, hints)? {
        Ok(sanitized) => Response {
            status: "200 OK",
            content_type: match sanitized.image.file_type {
                FileType::Jpeg => "image/jpeg",
                FileType::Png => "image/png",
                FileType::Gif => "image/gif",
                FileType::Webp => "image/webp",
                _ => "application/octet-stream",
            },
            body: sanitized.image.data,
        },
        Err(Error::Rejected(report)) => Response::json(
            "422 Unprocessable Content",
            serde_json::json!({ "ok": false, "error": "file is not clean", "report": report }),
        ),
        Err(error @ Error::Unsupported { .. }) => {
            Response::error("415 Unsupported Media Type", &error.to_string())
        }
        Err(error) => Response::error("422 Unprocessable Content", &error.to_string()),
    })
}

#[cfg(not(feature = "cdr"))]
fn sanitize(_: &Service, _: &[u8], _: ScanHints<'_>) -> Option<Response> {
    let message = "this build has no image rebuilding";
    Some(Response::error("501 Not Implemented", message))
}

/// The finding that decided the verdict, as a ClamAV-style signature name.
pub(crate) fn signature(report: &Report) -> String {
    let verdict = match report.verdict {
        Verdict::Clean => "Clean",
        Verdict::Suspicious => "Suspicious",
        Verdict::Malicious => "Malicious",
    };
    let worst = report
        .findings
        .iter()
        // Of several equally severe findings, the first one names the file.
        .rev()
        .max_by_key(|finding| finding.severity)
        .filter(|finding| finding.severity > Severity::Info);
    format!("Malmal.{verdict}.{}", worst.map_or("unknown", |f| f.code))
}

/// The subset of the ClamAV daemon protocol that upload scanners use:
/// `PING`, `VERSION` and `INSTREAM`, with the `z` and `n` command prefixes
/// and `IDSESSION`/`END`. The stream is a sequence of chunks, each a 4-byte
/// big-endian length and that many bytes, ended by a zero length.
///
/// The protocol has two answers, so a suspicious file is answered `FOUND`
/// like a malicious one: `stream: Malmal.Suspicious.pdf.encrypted FOUND`.
/// It also carries no file name or type, so those are not checked.
pub fn clamd(
    reader: &mut impl BufRead,
    mut writer: impl Write,
    service: &Service,
) -> io::Result<()> {
    let mut session = false;
    let mut id = 0u32;
    loop {
        let Some(&first) = reader.fill_buf()?.first() else {
            return Ok(());
        };
        // `z` commands and their replies end with a NUL, the others with a newline.
        let delimiter = if first == b'z' { 0 } else { b'\n' };
        let mut raw = Vec::new();
        reader
            .by_ref()
            .take(MAX_COMMAND_LEN)
            .read_until(delimiter, &mut raw)?;
        if raw.pop() != Some(delimiter) {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&raw);
        let command = text.trim();
        let command = command
            .strip_prefix(['z', 'n'])
            .filter(|rest| rest.chars().next().is_some_and(char::is_uppercase))
            .unwrap_or(command);

        id += 1;
        let reply = match command {
            "PING" => "PONG".to_string(),
            "VERSION" => format!("malmal {}", env!("CARGO_PKG_VERSION")),
            "IDSESSION" => {
                session = true;
                id = 0;
                continue;
            }
            "END" => return Ok(()),
            "INSTREAM" => {
                let mut body = Vec::new();
                loop {
                    let mut length = [0; 4];
                    reader.read_exact(&mut length)?;
                    let length = u32::from_be_bytes(length) as u64;
                    if length == 0 {
                        break;
                    }
                    // The rest of the stream cannot be skipped safely.
                    if body.len() as u64 + length > service.max_size() {
                        service.metrics.reject();
                        writer.write_all(b"INSTREAM size limit exceeded. ERROR")?;
                        return writer.write_all(&[delimiter]);
                    }
                    reader.by_ref().take(length).read_to_end(&mut body)?;
                }
                match service.scan(&body, ScanHints::default()) {
                    Some(report) if report.verdict == Verdict::Clean => "stream: OK".to_string(),
                    Some(report) => format!("stream: {} FOUND", signature(&report)),
                    None => "stream: internal error while scanning ERROR".to_string(),
                }
            }
            _ => {
                service.metrics.reject();
                "UNKNOWN COMMAND".to_string()
            }
        };
        if session {
            write!(writer, "{id}: ")?;
        }
        writer.write_all(reply.as_bytes())?;
        writer.write_all(&[delimiter])?;
        writer.flush()?;
        // Outside a session, one command is one connection.
        if !session {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
    const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B";

    fn service() -> Service {
        Service::new(Scanner::builder().build())
    }

    #[derive(Clone, Copy)]
    enum Protocol {
        Json,
        Http,
        Clamd,
    }
    use Protocol::{Clamd, Http, Json};

    fn run(protocol: Protocol, service: &Service, input: &[u8]) -> Vec<u8> {
        let mut reader = Cursor::new(input.to_vec());
        let mut output = Vec::new();
        // A peer that hangs up mid-request is an error the caller ignores.
        let _ = match protocol {
            Json => json(&mut reader, &mut output, service),
            Http => http(&mut reader, &mut output, service),
            Clamd => clamd(&mut reader, &mut output, service),
        };
        output
    }

    fn http_request(head: &str, body: &[u8]) -> Vec<u8> {
        [head.as_bytes(), body].concat()
    }

    /// Status line and body of each response in `output`.
    fn responses(output: &[u8]) -> Vec<(String, String)> {
        let mut rest = output;
        let mut found = Vec::new();
        while !rest.is_empty() {
            let head_end = rest.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = String::from_utf8_lossy(&rest[..head_end]).into_owned();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map_or(0, |value| value.parse().unwrap());
            let body = String::from_utf8_lossy(&rest[head_end..head_end + length]).into_owned();
            found.push((head.lines().next().unwrap().to_string(), body));
            rest = &rest[head_end + length..];
        }
        found
    }

    #[test]
    fn json_protocol() {
        let service = service();
        let mut input =
            format!("{{\"size\": {}, \"filename\": \"a.gif\"}}\n", GIF.len()).into_bytes();
        input.extend_from_slice(GIF);
        input.extend_from_slice(format!("{{\"size\": {}}}\n", ELF.len()).as_bytes());
        input.extend_from_slice(ELF);
        input.extend_from_slice(b"not json\n");
        let output = String::from_utf8(run(Json, &service, &input)).unwrap();
        let replies: Vec<serde_json::Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["report"]["verdict"], "clean");
        assert_eq!(replies[1]["report"]["verdict"], "malicious");
        assert_eq!(replies[2]["ok"], false);
    }

    #[test]
    fn http_scans_and_keeps_the_connection() {
        let service = service();
        let mut input = http_request(
            &format!(
                "POST /scan?filename=a%20b.gif HTTP/1.1\r\nHost: x\r\nContent-Type: image/gif\r\nContent-Length: {}\r\n\r\n",
                GIF.len()
            ),
            GIF,
        );
        input.extend(http_request(
            &format!(
                "PUT /scan HTTP/1.1\r\ncontent-length: {}\r\nX-Filename: photo.jpg\r\nExpect: 100-continue\r\n\r\n",
                ELF.len()
            ),
            ELF,
        ));
        input.extend_from_slice(b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n");
        input.extend_from_slice(b"GET /metrics HTTP/1.1\r\n\r\n");

        let replies = responses(&run(Http, &service, &input));
        assert_eq!(replies.len(), 4, "{replies:?}");
        assert_eq!(replies[0].0, "HTTP/1.1 200 OK");
        let report: serde_json::Value = serde_json::from_str(&replies[0].1).unwrap();
        assert_eq!(report["report"]["verdict"], "clean", "{report}");
        assert_eq!(report["report"]["declared_types"][0], "gif");

        assert_eq!(replies[1].0, "HTTP/1.1 100 Continue");
        let report: serde_json::Value = serde_json::from_str(&replies[2].1).unwrap();
        assert_eq!(report["report"]["verdict"], "malicious");
        assert!(replies[2].1.contains("type.mismatch"), "{}", replies[2].1);

        // `Connection: close` ends the exchange before the last request.
        assert_eq!(replies[3], ("HTTP/1.1 200 OK".into(), "ok\n".into()));
    }

    #[test]
    fn http_refuses_what_it_cannot_scan() {
        let service = service();
        let status = |input: &[u8]| responses(&run(Http, &service, input))[0].0.clone();
        assert_eq!(
            status(b"POST /scan HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 411 Length Required"
        );
        assert_eq!(
            status(b"POST /scan HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n"),
            "HTTP/1.1 413 Content Too Large"
        );
        assert_eq!(
            status(b"POST /scan HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            "HTTP/1.1 501 Not Implemented"
        );
        assert_eq!(
            status(b"GET /scan HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 405 Method Not Allowed"
        );
        assert_eq!(status(b"GET / HTTP/1.1\r\n\r\n"), "HTTP/1.1 404 Not Found");
        assert_eq!(status(b"nonsense\r\n\r\n"), "HTTP/1.1 400 Bad Request");
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(20_000));
        assert_eq!(
            status(long.as_bytes()),
            "HTTP/1.1 431 Request Header Fields Too Large"
        );
        // A body shorter than announced gets no answer at all.
        assert!(
            run(
                Http,
                &service,
                b"POST /scan HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort"
            )
            .is_empty()
        );
        // HTTP/1.0 closes after one response.
        let two = b"GET /healthz HTTP/1.0\r\n\r\nGET /healthz HTTP/1.0\r\n\r\n";
        assert_eq!(responses(&run(Http, &service, two)).len(), 1);
    }

    #[test]
    fn metrics_count_scans_and_refusals() {
        let service = service();
        let scan = |body: &[u8]| {
            let head = format!(
                "POST /scan HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            run(Http, &service, &http_request(&head, body));
        };
        scan(GIF);
        scan(GIF);
        scan(ELF);
        run(Http, &service, b"POST /scan HTTP/1.1\r\n\r\n");
        let metrics = responses(&run(Http, &service, b"GET /metrics HTTP/1.1\r\n\r\n"))[0]
            .1
            .clone();
        for line in [
            "malmal_scans_total{verdict=\"clean\"} 2",
            "malmal_scans_total{verdict=\"suspicious\"} 0",
            "malmal_scans_total{verdict=\"malicious\"} 1",
            "malmal_scan_errors_total 0",
            "malmal_rejected_requests_total 1",
            &format!("malmal_scanned_bytes_total {}", GIF.len() * 2 + ELF.len()),
        ] {
            assert!(
                metrics.lines().any(|found| found == line),
                "{line}\n{metrics}"
            );
        }
    }

    fn instream(command: &[u8], chunks: &[&[u8]]) -> Vec<u8> {
        let mut input = command.to_vec();
        for chunk in chunks {
            input.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            input.extend_from_slice(chunk);
        }
        input.extend_from_slice(&[0; 4]);
        input
    }

    #[test]
    fn clamd_protocol() {
        let service = service();
        let reply = |input: &[u8]| String::from_utf8(run(Clamd, &service, input)).unwrap();
        assert_eq!(reply(b"zPING\0"), "PONG\0");
        assert_eq!(reply(b"nPING\n"), "PONG\n");
        assert_eq!(reply(b"PING\r\n"), "PONG\n");
        assert!(reply(b"zVERSION\0").starts_with("malmal "));
        assert_eq!(reply(b"zSCAN /etc/passwd\0"), "UNKNOWN COMMAND\0");

        let (head, tail) = GIF.split_at(10);
        assert_eq!(
            reply(&instream(b"zINSTREAM\0", &[head, tail])),
            "stream: OK\0"
        );
        assert_eq!(
            reply(&instream(b"nINSTREAM\n", &[ELF])),
            "stream: Malmal.Malicious.type.executable FOUND\n"
        );
        // A suspicious file is not answered as clean.
        assert_eq!(
            reply(&instream(b"zINSTREAM\0", &[b"plain text"])),
            "stream: Malmal.Suspicious.type.unknown FOUND\0"
        );
        // A stream that ends early gets no verdict.
        assert_eq!(reply(b"zINSTREAM\0\0\0\0\x09short"), "");

        let mut session = b"zIDSESSION\0zPING\0".to_vec();
        session.extend(instream(b"zINSTREAM\0", &[ELF]));
        session.extend_from_slice(b"zEND\0zPING\0");
        assert_eq!(
            reply(&session),
            "1: PONG\x002: stream: Malmal.Malicious.type.executable FOUND\0"
        );
    }

    #[test]
    fn clamd_stream_size_is_limited() {
        let limits = malmal::Limits {
            max_file_size: 8,
            ..malmal::Limits::default()
        };
        let service = Service::new(Scanner::builder().limits(limits).build());
        let output = run(
            Clamd,
            &service,
            &instream(b"zINSTREAM\0", &[b"123456", b"789"]),
        );
        assert_eq!(output, b"INSTREAM size limit exceeded. ERROR\0");
    }
}
