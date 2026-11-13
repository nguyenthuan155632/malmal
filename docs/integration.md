# Integrating malmal

Three ways to put the scanner in front of an upload handler, from the closest to the most
detached. In all of them the rule is the same: anything but a clean verdict, including an
error or no answer at all, means the file is not accepted.

- [In a Rust service](#in-a-rust-service): link the crate.
- [As a daemon](#as-a-daemon): any language, over a Unix socket, HTTP, the ClamAV protocol
  or ICAP.
- [From C](#from-c) and [from Python](#from-python): link or load the library.

## In a Rust service

```toml
[dependencies]
malmal = "0.2"
```

Build one `Scanner` at start-up and share it; it holds no per-scan state. Scanning is CPU
work that can take up to `Limits::max_duration`, so run it on a blocking thread. Limit the
request body in the framework too: the scanner reports an oversized file, but only after the
service has buffered it.

### axum

Dependencies: `axum` 0.8 with the `multipart` feature, and `tokio`.

```rust
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use malmal::{ScanHints, Scanner, Verdict};

type Rejection = (StatusCode, String);

fn rejection(status: StatusCode) -> impl Fn(axum::extract::multipart::MultipartError) -> Rejection {
    move |error| (status, error.to_string())
}

async fn upload(
    State(scanner): State<Arc<Scanner>>,
    mut multipart: Multipart,
) -> Result<StatusCode, Rejection> {
    let bad_request = rejection(StatusCode::BAD_REQUEST);
    while let Some(field) = multipart.next_field().await.map_err(&bad_request)? {
        let filename = field.file_name().map(str::to_owned);
        let content_type = field.content_type().map(str::to_owned);
        let data = field.bytes().await.map_err(&bad_request)?;

        // Scanning is CPU work: keep it off the async executor.
        let scanner = Arc::clone(&scanner);
        let (report, data) = tokio::task::spawn_blocking(move || {
            let hints = ScanHints {
                filename: filename.as_deref(),
                content_type: content_type.as_deref(),
            };
            (scanner.scan_bytes(&data, hints), data)
        })
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

        if report.verdict != Verdict::Clean {
            let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
            return Err((StatusCode::UNPROCESSABLE_ENTITY, codes.join(", ")));
        }
        store(&report.sha256, &data).await;
    }
    Ok(StatusCode::CREATED)
}

async fn store(_name: &str, _data: &[u8]) {}

#[tokio::main]
async fn main() {
    let scanner = Arc::new(Scanner::builder().build());
    let app = Router::new()
        .route("/upload", post(upload))
        // Refuse oversized bodies before they are buffered.
        .layer(DefaultBodyLimit::max(64 << 20))
        .with_state(scanner);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### actix-web

Dependencies: `actix-web` 4 and `serde_json`.

```rust
use actix_web::http::header::CONTENT_TYPE;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use malmal::{ScanHints, Scanner, Verdict};

/// `PUT /upload/{filename}` with the file as the request body.
async fn upload(
    scanner: web::Data<Scanner>,
    filename: web::Path<String>,
    request: HttpRequest,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let filename = filename.into_inner();

    // Scanning is CPU work: keep it off the async workers.
    let report = web::block(move || {
        let hints = ScanHints {
            filename: Some(&filename),
            content_type: content_type.as_deref(),
        };
        scanner.scan_bytes(&body, hints)
    })
    .await?;

    Ok(match report.verdict {
        Verdict::Clean => HttpResponse::Created().finish(),
        _ => HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "findings": report.findings.iter().map(|f| f.code).collect::<Vec<_>>(),
        })),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let scanner = web::Data::new(Scanner::builder().build());
    HttpServer::new(move || {
        App::new()
            .app_data(scanner.clone())
            // Refuse oversized bodies before they are buffered.
            .app_data(web::PayloadConfig::new(64 << 20))
            .route("/upload/{filename}", web::put().to(upload))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}
```

### What to do with the report

- Reject on `report.verdict != Verdict::Clean`. Log `report.findings` and `report.sha256`;
  show the user a generic message, not the findings.
- Store the file under a name you generate, never under the uploaded one, with the extension
  that belongs to `report.detected_type`.
- For raster images, decode and re-encode what passed. The scanner decides which files get
  that far; re-encoding is what removes whatever a scanner cannot see. The next section
  does both in one call.
- The codes are listed in [findings.md](findings.md). To accept something the default policy
  flags, lower that one code with `Policy::with_override` rather than ignoring verdicts.

### Rebuilding images

```toml
[dependencies]
malmal = { version = "0.2", features = ["cdr"] }
```

`Scanner::sanitize` scans and, when the file is clean and of a type that can be rebuilt,
returns a new file. Store that one; the upload itself is not kept. A raster image is
written from its pixels. Two more features add the document types: `cdr-svg` filters an
SVG down to what draws, and `cdr-pdf` draws each page of a PDF and writes a PDF of the
drawings, in which text is no longer text. The commands and the C library are built with
the first and, unless asked, without the second. `Options::types` names the types to
rebuild when you take only some; the decoders for the others are then never run.

```rust
use malmal::cdr::{Error, Options};
use malmal::{ScanHints, Scanner};

fn accept(scanner: &Scanner, upload: &[u8], hints: ScanHints<'_>) -> Result<Vec<u8>, String> {
    match scanner.sanitize(upload, hints, &Options::default()) {
        // `image.file_type` names what to store it as; it is PNG for a BMP, TIFF or ICO.
        Ok(sanitized) => Ok(sanitized.image.data),
        Err(Error::Rejected(report)) => {
            let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
            Err(format!("not clean: {}", codes.join(", ")))
        }
        // Not an image that can be rebuilt, too large, or not decodable.
        Err(other) => Err(other.to_string()),
    }
}
```

A service that also takes PDF or SVG scans those with `scan_bytes` and keeps them as they
are: only raster images can be rebuilt. Like scanning, rebuilding is CPU work for a blocking
thread.

### Encrypted PDFs

A PDF encrypted with the empty password is opened as any reader opens it. For documents
your users protect with a password you know, give the scanner the candidates:

```rust
let scanner = malmal::Scanner::builder()
    .pdf_passwords(["first candidate", "second candidate"])
    .build();
```

Each is tried as the user password and as the owner password. A document none of them
opens is `pdf.encrypted` at Medium, as before.

## As a daemon

`malmald` serves any combination of four endpoints. An address is `host:port`, or the path
of a Unix socket.

```bash
malmald --socket /run/malmal.sock --http 127.0.0.1:8080 --clamd 127.0.0.1:3310 --icap 127.0.0.1:1344 --require-sandbox
```

It has no authentication and no TLS. Bind it to the loopback interface or a Unix socket, and
let only the upload service reach it.

### HTTP

The request body is the file itself, not a multipart form.

```bash
curl --data-binary @upload.pdf -H 'Content-Type: application/pdf' 'http://127.0.0.1:8080/scan?filename=upload.pdf'
```

| Request | Reply |
|---|---|
| `POST /scan` or `PUT /scan` | `200` and `{"ok": true, "report": {...}}`, whatever the verdict |
| `POST /sanitize` or `PUT /sanitize` | `200` and the rebuilt image as the body; see below |
| `GET /metrics` | Counters in the Prometheus text format |
| `GET /healthz` | `200 ok` |

`Content-Length` is required. `Content-Type` is checked against the content as the claimed
type; the claimed name comes from the `X-Filename` header or the `filename` query parameter,
percent-encoded. Any status other than `200` means the file was not scanned: `411` without a
length, `413` over the size limit, `501` for a chunked body.

The report has the fields of `malmal::Report`:

```json
{"ok": true, "report": {"verdict": "malicious", "detected_type": "pdf", "declared_types": ["pdf"],
 "size": 1409, "sha256": "...", "findings": [
  {"code": "pdf.javascript", "severity": "high", "message": "document contains JavaScript", "offset": 15}]}}
```

`/sanitize` takes the same request and answers with the image written anew from its pixels,
its type in `Content-Type` (a BMP, TIFF or ICO comes back as `image/png`). Anything but
`200` means there is no file to keep: `422` with `{"ok": false, "error": ..., "report": {...}}`
when the scan was not clean, or without the report when the image could not be decoded or
took too long, and `415` when the file is not an image that can be rebuilt.

```bash
curl --fail --data-binary @upload.jpg -o stored.jpg http://127.0.0.1:8080/sanitize
```

`/metrics` exposes `malmal_scans_total{verdict=...}`, `malmal_scan_errors_total`,
`malmal_rejected_requests_total`, `malmal_scanned_bytes_total`, `malmal_scan_seconds_total`,
`malmal_rebuilt_images_total` and `malmal_build_info`.

### Unix socket

Each request is one JSON line followed by exactly `size` bytes of file content:

```
{"size": 1234, "filename": "a.png", "content_type": "image/png"}\n<1234 bytes>
```

The reply is one JSON line, the same object as over HTTP, or `{"ok": false, "error": "..."}`.
A connection can carry many requests.

```python
import json, socket

def scan(path, data, name):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.sendall(json.dumps({"size": len(data), "filename": name}).encode() + b"\n" + data)
        reply = json.loads(sock.makefile().readline())
    if not reply.get("ok"):
        raise RuntimeError(reply.get("error", "not scanned"))
    return reply["report"]
```

### ClamAV protocol

For software that already knows how to ask `clamd`: point it at the `--clamd` address.
`PING`, `VERSION` and `INSTREAM` are answered, with the `z` and `n` prefixes and `IDSESSION`;
commands that name a path on the server are not.

The protocol has two answers and no way to name the file, so:

- a suspicious file is answered `FOUND`, like a malicious one:
  `stream: Malmal.Suspicious.pdf.encrypted FOUND`;
- the file name and `Content-Type` are not checked against the content.

### ICAP

For a proxy that speaks ICAP (RFC 3507): it hands each request or response to the daemon
and forwards it only if the daemon lets it through. With Squid:

```
icap_enable on
icap_service malmal_req reqmod_precache icap://127.0.0.1:1344/scan bypass=off
icap_service malmal_resp respmod_precache icap://127.0.0.1:1344/scan bypass=off
# Uploads on the way in, files on the way out.
acl uploads method POST PUT
acl downloads urlpath_regex -i \.(png|jpe?g|gif|webp|pdf)$
adaptation_access malmal_req allow uploads
adaptation_access malmal_resp allow downloads
```

`bypass=off` is what keeps this fail-closed: with it, Squid refuses the request when the
daemon cannot be reached.

What is judged is a file, not an HTTP message:

- every part of a `multipart/form-data` request that has a file name is scanned, with that
  name and the part's `Content-Type` as the claims; the other fields are not looked at;
- a URL-encoded form passes if its body is made of form fields, as does a message without
  a body. A body sent under that name that is not one, a script or an executable, say, is
  scanned as a file;
- any other body is scanned as the file itself. A `PUT` is named by its URL, a response by
  its `Content-Disposition`.

So send it the requests that carry uploads and the responses that carry files, as the
`acl` lines above do, not everything: a JSON API call or an HTML page is not a file the
scanner knows and would be blocked as `type.unknown`.

A clean message is answered `204`, or echoed when the proxy did not send `Allow: 204`.
Anything else is replaced by a `403 Forbidden` response, with the reason in
`X-Infection-Found: Type=0; Resolution=2; Threat=Malmal.Malicious.pdf.javascript;`, or in
`X-Block-Reason` when the body was too large or could not be taken apart. Those are ICAP
headers: the proxy sees them and can log them, the client gets the `403` alone. Previews
are supported.

The endpoint is tested against the RFC and has been run behind Squid 6 with the
configuration above: uploads raw, by `PUT` and in forms, downloads, bodies over the size
limit, and some hundreds of requests at once. Other proxies have not been tried.

### Connections and workers

Every connection has a thread of its own, up to `--connections` (256); beyond that they
wait to be accepted. `--workers` (4) is the number of requests worked on at once, across
all endpoints, and is what bounds memory and processors: each can hold a file of
`--max-size`. A connection kept open between requests holds no worker, so clients that
keep theirs, as proxies and HTTP clients do, do not keep others waiting.

### Limits and timeouts

`--max-size` and `--scan-timeout` set `Limits::max_file_size` and `Limits::max_duration` for
every request; `--timeout` is how long an idle connection is kept. The time limit is checked
between steps of the analysis, so it bounds a scan without cutting it off at an exact moment.
A file over the size limit is refused outright by the daemon rather than scanned in part.

A step that never ends never reaches that check, and a thread cannot be stopped from
outside. `--hard-timeout <S>` is the answer to that: when a scan or a rebuild has run for
that many seconds, the daemon prints a line and exits with status 3. Every connection it
was serving is cut, which no client can take for a clean verdict, and the supervisor
starts it again (`Restart=on-failure` under systemd, a restart policy in a container).
The default is six times `--scan-timeout`, one minute as shipped; `0` turns it off, which
leaves a stuck worker stuck. `malmal scan` and `malmal sanitize` take the same option and
exit the same way. The time a client takes to send its file does not count.

## From C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
malmal_string_free(report);
malmal_scanner_free(scanner);
```

`malmal_sanitize` scans and rebuilds in one call:

```c
uint8_t *image = NULL;
size_t image_len = 0;
char *info = NULL;
int status = malmal_sanitize(scanner, data, len, "a.png", "image/png", 0,
                             &image, &image_len, &info);
if (status == MALMAL_CLEAN) {
  /* Store image[0..image_len] in place of the upload. */
}
malmal_bytes_free(image, image_len);
malmal_string_free(info);
```

Any other status means there is nothing to store: the scan was not clean
(`MALMAL_SUSPICIOUS`, `MALMAL_MALICIOUS`), the file is not an image that can be rebuilt
(`MALMAL_NOT_REBUILT`), or the call failed (`MALMAL_ERROR`). `info` says which type the new
file has, or why there is none.

The header is `crates/malmal-ffi/include/malmal.h`, the full example
`crates/malmal-ffi/examples/scan.c`.

## From Python

`bindings/python` loads the same library with `ctypes`:

```python
import malmal

scanner = malmal.Scanner()          # build once, share between threads
report = scanner.scan(data, filename="a.png", content_type="image/png")
if not report.clean:
    reject([finding["code"] for finding in report.findings])
```

A `malmal.ScanError` means the file was not scanned. `Scanner.sanitize` returns the rebuilt
image, and raises when there is none:

```python
try:
    image = scanner.sanitize(data, filename="a.png", content_type="image/png")
except malmal.Rejected as rejected:       # the scan did not come back clean
    reject([finding["code"] for finding in rejected.report.findings])
except malmal.NotRebuilt as problem:      # clean, but not an image that can be rebuilt
    reject(str(problem))
else:
    store(image.data, image.file_type)    # "png" for an uploaded BMP, TIFF or ICO
```

Both exceptions are a `malmal.SanitizeError`. The wheels attached to a release carry the
library for x86-64 and ARM64 Linux; building one, or using the package from a checkout, is
described in `bindings/python/README.md`.

## In a container

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/nguyenthuan155632/malmal
```

The image contains the two static binaries and runs `malmald --http 0.0.0.0:8080` as an
unprivileged user. Arguments replace that default:

```bash
docker run --rm -p 127.0.0.1:3310:3310 ghcr.io/nguyenthuan155632/malmal --clamd 0.0.0.0:3310 --max-size 20000000
```

Publish the port to the upload service only; inside the container the daemon listens on
every interface and has no authentication.
