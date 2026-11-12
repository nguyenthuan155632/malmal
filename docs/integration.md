# Integrating malmal

Three ways to put the scanner in front of an upload handler, from the closest to the most
detached. In all of them the rule is the same: anything but a clean verdict, including an
error or no answer at all, means the file is not accepted.

- [In a Rust service](#in-a-rust-service): link the crate.
- [As a daemon](#as-a-daemon): any language, over a Unix socket, HTTP or the ClamAV protocol.
- [From C](#from-c): link the static library.

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
  that far; re-encoding is what removes whatever a scanner cannot see.
- The codes are listed in [findings.md](findings.md). To accept something the default policy
  flags, lower that one code with `Policy::with_override` rather than ignoring verdicts.

## As a daemon

`malmald` serves any combination of three endpoints. An address is `host:port`, or the path
of a Unix socket.

```bash
malmald --socket /run/malmal.sock --http 127.0.0.1:8080 --clamd 127.0.0.1:3310 --require-sandbox
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

`/metrics` exposes `malmal_scans_total{verdict=...}`, `malmal_scan_errors_total`,
`malmal_rejected_requests_total`, `malmal_scanned_bytes_total`, `malmal_scan_seconds_total`
and `malmal_build_info`.

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

### Limits and timeouts

`--max-size` and `--scan-timeout` set `Limits::max_file_size` and `Limits::max_duration` for
every request; `--timeout` is how long an idle connection is kept. The time limit is checked
between steps of the analysis, so it bounds a scan without cutting it off at an exact moment.
A file over the size limit is refused outright by the daemon rather than scanned in part.

## From C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
malmal_string_free(report);
malmal_scanner_free(scanner);
```

The header is `crates/malmal-ffi/include/malmal.h`, the full example
`crates/malmal-ffi/examples/scan.c`.
