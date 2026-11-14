# malmal

[![CI](https://github.com/nguyenthuan155632/malmal/actions/workflows/ci.yml/badge.svg)](https://github.com/nguyenthuan155632/malmal/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

malmal checks uploaded images, SVG, PDF and PostScript files before your application
processes them. It answers three questions that antivirus usually does not:

- **Is the file what it claims to be?** The content is compared with the file name and
  `Content-Type`.
- **Does it carry active content?** Scripts, actions, embedded files, shell commands.
- **Is it well formed?** Trailing data, polyglots, decompression bombs, truncation.

A file that cannot be analyzed completely is never reported as clean. malmal can also
rebuild an image, SVG or PDF from what it draws, so that nothing else from the upload is
kept.

It ships as a Rust library, a command-line tool, a daemon (HTTP, Unix socket, ClamAV
protocol, ICAP), a C library and a Python package.

## Contents

- [Supported formats](#supported-formats)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage): [command line](#command-line), [Rust](#rust), [Python](#python),
  [C](#c), [daemon](#daemon)
- [Configuration](#configuration)
- [Rebuilding files](#rebuilding-files)
- [Deployment](#deployment)
- [Accuracy and performance](#accuracy-and-performance)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## Supported formats

| Format | Type name | Scanned | Rebuilt as |
|---|---|:---:|---|
| JPEG | `jpeg` | yes | JPEG |
| PNG, APNG | `png` | yes | PNG |
| GIF | `gif` | yes | GIF |
| WebP | `webp` | yes | lossless WebP |
| BMP | `bmp` | yes | PNG |
| TIFF, BigTIFF | `tiff` | yes | PNG |
| ICO | `ico` | yes | PNG |
| JPEG XL | `jxl` | yes | PNG |
| PSD, PSB | `psd` | yes | no |
| HEIC | `heif` | yes | no |
| AVIF | `avif` | yes | no |
| SVG | `svg` | yes | SVG |
| PDF | `pdf` | yes | PDF of page images (optional `cdr-pdf` feature) |
| PostScript, EPS, Illustrator (PS-based) | `postscript` | yes | no |

Any other file is reported as `type.unknown`. Office documents, archives and video are out
of scope.

## Installation

**Prebuilt binaries** for x86-64 and ARM64 Linux are attached to every
[release](https://github.com/nguyenthuan155632/malmal/releases). They are static and need
no other packages. Each archive contains `malmal`, `malmald`, `libmalmal_ffi.a` and
`malmal.h`.

```bash
cargo binstall malmal-cli     # downloads the prebuilt binaries
cargo install malmal-cli      # builds from source
```

**Container image:**

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/nguyenthuan155632/malmal
```

**Rust library:**

```bash
cargo add malmal
```

**Python package:** wheels for x86-64 and ARM64 Linux are attached to each release. See
[bindings/python/README.md](bindings/python/README.md).

**From source:**

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

The sandbox is available on Linux only. On macOS, build without `--target`, and do not
pass `--require-sandbox`.

## Quick start

```bash
malmal scan upload.pdf
```

```text
upload.pdf: MALICIOUS (pdf)
  [High] pdf.javascript: document contains JavaScript at offset 186
```

The exit status gives the verdict, so a shell script can act on it directly:

```bash
malmal scan "$file" || rm -- "$file"
```

| Exit status | Meaning |
|---:|---|
| 0 | Clean (for `sanitize`: the new file was written) |
| 1 | Suspicious |
| 2 | Malicious |
| 3 | Error: the file was not scanned |

Treat anything other than `0` as a rejection.

## Usage

### Command line

```bash
malmal scan [OPTIONS] <FILE>...
malmal sanitize [OPTIONS] <INPUT> <OUTPUT>
```

`scan` checks each file; `-` reads standard input. With several files, the exit status is
that of the worst one. `--json` prints one JSON object per file:

```bash
malmal scan --json incoming/*
```

```json
{"path":"incoming/a.pdf","report":{"verdict":"malicious","detected_type":"pdf","declared_types":["pdf"],
 "size":285,"sha256":"8e38c368...","findings":[
  {"code":"pdf.javascript","severity":"high","message":"document contains JavaScript","offset":186}]}}
```

`sanitize` scans `INPUT` and, if it is clean, writes a rebuilt copy to `OUTPUT` (see
[Rebuilding files](#rebuilding-files)). `OUTPUT` is replaced atomically on success and left
untouched otherwise.

Every finding has a stable `code`. Match on the code, not the message. All codes are listed
in [docs/findings.md](docs/findings.md).

See [Configuration](#configuration) for all options.

### Rust

```rust
use malmal::{ScanHints, Scanner, Verdict};

// Build once and share between threads: Scanner is Send + Sync.
let scanner = Scanner::builder().build();

let report = scanner.scan_bytes(&data, ScanHints {
    filename: Some("logo.svg"),           // as sent by the client
    content_type: Some("image/svg+xml"),
});

if report.verdict != Verdict::Clean {
    for finding in &report.findings {
        log::warn!("{} [{:?}] {}", finding.code, finding.severity, finding.message);
    }
    return Err(Rejected);
}
```

- `scan_bytes` never fails or panics; anything that could not be analyzed becomes a
  finding.
- `scan_reader` takes any `impl Read` and stops reading at the size limit.
- A scan is CPU-bound and can run up to the time limit. In async code, run it on a
  blocking thread (`tokio::task::spawn_blocking`).

A configured scanner:

```rust
use std::time::Duration;
use malmal::{FileType, HashList, Limits, Policy, Scanner};

let policy = Policy::default()
    .with_allowed_types([FileType::Jpeg, FileType::Png, FileType::Pdf])
    .allow("pdf.xfa")?;

let scanner = Scanner::builder()
    .policy(policy)
    .limits(Limits {
        max_file_size: 20 << 20,
        max_duration: Duration::from_secs(5),
        ..Limits::default()
    })
    .hashlist(HashList::parse(&std::fs::read_to_string("blocklist.txt")?)?)
    .pdf_passwords(["statement-password"])
    .build();
```

Complete axum and actix-web handlers are in
[docs/integration.md](docs/integration.md#in-a-rust-service).

| Cargo feature | Adds |
|---|---|
| `cdr` | `Scanner::sanitize` and `malmal::cdr`: rebuilding raster images |
| `cdr-svg` | Rebuilding SVG (implies `cdr`) |
| `cdr-pdf` | Rebuilding PDF as page images (implies `cdr`) |
| `yara` | `ScannerBuilder::yara` and `YaraRules` |

All features are off by default in the library.

### Python

The package loads the C library with `ctypes` and has no other dependencies.

```python
import malmal

scanner = malmal.Scanner()      # build once, share between threads
report = scanner.scan(data, filename="a.png", content_type="image/png")
if not report.clean:
    reject([finding["code"] for finding in report.findings])
```

```python
scanner = malmal.Scanner(
    strict=False,                                # strict policy
    hashlist=open("blocklist.txt").read(),       # SHA-256 blocklist
    pdf_passwords=["statement-password"],        # str or bytes
    allow=["pdf.xfa", "pdf.embedded_file"],      # or "pdf.xfa|pdf.embedded_file"
    library=None,                                # path to libmalmal_ffi, if not found
)
```

| Call | Returns | Raises |
|---|---|---|
| `Scanner(...)` | a scanner | `ValueError` for an invalid blocklist, password or code |
| `scan(data, filename=None, content_type=None)` | `Report` | `ScanError` if the file was not scanned |
| `sanitize(data, filename=None, content_type=None, jpeg_quality=90)` | `Sanitized` | `Rejected` (with `.report`), `NotRebuilt`, `ScanError` |

`Report` has `verdict`, `clean`, `detected_type`, `declared_types`, `size`, `sha256` and
`findings`. `Sanitized` has `data`, `file_type`, `width`, `height`, `frames` and `report`.
A `Scanner` is also a context manager.

### C

Include `malmal.h` and link `libmalmal_ffi.a`. A scanner can be used from several threads
at once.

```c
#include <malmal.h>

char *error = NULL;
malmal_scanner *scanner = malmal_scanner_new_with_allow(
    0,                 /* strict policy: 0 or 1 */
    NULL, 0,           /* SHA-256 blocklist text, or NULL */
    NULL, 0,           /* PDF passwords, one per line, or NULL */
    "pdf.xfa",         /* codes to allow, or NULL */
    &error);
if (!scanner) {
    fprintf(stderr, "malmal: %s\n", error);
    malmal_string_free(error);
    return 1;
}

char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
if (verdict != MALMAL_CLEAN) {
    /* reject; `report` holds the JSON report, or NULL on MALMAL_ERROR */
}
malmal_string_free(report);
malmal_scanner_free(scanner);
```

| Function | Purpose |
|---|---|
| `malmal_scanner_new(strict, hashlist, len)` | Create a scanner |
| `malmal_scanner_new_with_passwords(..., pdf_passwords, len)` | Also try passwords on encrypted PDFs |
| `malmal_scanner_new_with_allow(..., allow, &error)` | Also allow finding codes; reports why creation failed |
| `malmal_scan(scanner, data, len, filename, content_type, &json)` | Scan a buffer |
| `malmal_sanitize(scanner, data, len, filename, content_type, quality, &out, &out_len, &json)` | Scan and rebuild |
| `malmal_string_free`, `malmal_bytes_free`, `malmal_scanner_free` | Release what the library returned |

Return values are `MALMAL_CLEAN`, `MALMAL_SUSPICIOUS`, `MALMAL_MALICIOUS`, `MALMAL_ERROR`
and, from `malmal_sanitize` only, `MALMAL_NOT_REBUILT`. The full contract is in
[malmal.h](crates/malmal-ffi/include/malmal.h); an example is in
[examples/scan.c](crates/malmal-ffi/examples/scan.c).

### Daemon

`malmald` serves the scanner to any language over one or more endpoints:

```bash
malmald --http 127.0.0.1:8080 --socket /run/malmal.sock --require-sandbox
```

| Option | Protocol | Use it for |
|---|---|---|
| `--http <ADDR>` | HTTP | Any language with an HTTP client |
| `--socket <PATH>` | JSON over a Unix socket | Local services; no HTTP overhead |
| `--clamd <ADDR>` | ClamAV `clamd` protocol | Software that already calls ClamAV |
| `--icap <ADDR>` | ICAP | Proxies such as Squid |

`ADDR` is `host:port` or the path of a Unix socket. The daemon has no authentication and no
TLS: bind it to loopback or a Unix socket, and let only your upload service reach it.

**HTTP.** The request body is the file itself, not a multipart form. Any status other than
`200` means the file was not scanned.

```bash
curl --data-binary @upload.pdf -H 'Content-Type: application/pdf' \
  'http://127.0.0.1:8080/scan?filename=upload.pdf'
```

| Request | Response |
|---|---|
| `POST /scan` | `200` and `{"ok": true, "report": {...}}`, whatever the verdict |
| `POST /sanitize` | `200` and the rebuilt file; `422` if not clean, `415` if it cannot be rebuilt |
| `GET /healthz` | `200 ok` |
| `GET /metrics` | Prometheus counters: scans by verdict, errors, bytes, time, rebuilt files |

The file name can also be sent in an `X-Filename` header.

**Unix socket.** Each request is one JSON line followed by `size` bytes of file; the reply is
one JSON line. A connection can carry many requests.

```python
import json, socket

def scan(data, name):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect("/run/malmal.sock")
        sock.sendall(json.dumps({"size": len(data), "filename": name}).encode() + b"\n" + data)
        reply = json.loads(sock.makefile().readline())
    if not reply.get("ok"):
        raise RuntimeError(reply.get("error", "not scanned"))
    return reply["report"]
```

**ClamAV protocol.** `PING`, `VERSION` and `INSTREAM` are supported. The protocol has only
two answers, so suspicious files are reported as `FOUND`, like malicious ones
(`stream: Malmal.Suspicious.pdf.encrypted FOUND`). It carries no file name, so the name and
type are not checked.

**ICAP.** With Squid:

```text
icap_enable on
icap_service malmal_req reqmod_precache icap://127.0.0.1:1344/scan bypass=off
icap_service malmal_resp respmod_precache icap://127.0.0.1:1344/scan bypass=off
acl uploads method POST PUT
acl downloads urlpath_regex -i \.(png|jpe?g|gif|webp|pdf)$
adaptation_access malmal_req allow uploads
adaptation_access malmal_resp allow downloads
```

`bypass=off` makes Squid refuse requests when the daemon is unreachable. Each part of a
`multipart/form-data` upload is scanned separately; a message that is not clean is
replaced by `403 Forbidden`. Send only uploads and downloads of files, as above: an HTML
page or a JSON request is not a supported file type and would be blocked.

Status codes, metrics and protocol details are in
[docs/integration.md](docs/integration.md#as-a-daemon).

## Configuration

### Options

`malmal` and `malmald` accept the same scanning options.

| Option | Default | Rust | Python | C |
|---|---|---|---|---|
| `--policy default\|strict` | `default` | `Policy::strict()` | `strict=True` | `strict` |
| `--types <LIST>` | all types | `Policy::with_allowed_types` | | |
| `--allow <CODES>` | none | `Policy::allow` | `allow=` | `allow` |
| `--hashlist <FILE>` | none | `ScannerBuilder::hashlist` | `hashlist=` | `hashlist` |
| `--pdf-passwords <FILE>` | none | `ScannerBuilder::pdf_passwords` | `pdf_passwords=` | `pdf_passwords` |
| `--no-hash` | off | `ScannerBuilder::without_hash` | | |
| `--max-size <BYTES>` | 64 MiB | `Limits::max_file_size` | | |
| `--max-decompressed <BYTES>` | 256 MiB | `Limits::max_decompressed` | | |
| `--max-pixels <N>` | 2^28 | `Limits::max_pixels` | | |
| `--scan-timeout <S>` | 10 | `Limits::max_duration` | | |
| `--hard-timeout <S>` | 6 × scan timeout | | | |
| `--yara <PATH>` | none | `ScannerBuilder::yara` | | |
| `--require-sandbox` | off | | | |
| `--no-sandbox` | off | | | |

The Python and C interfaces use the default limits. Embedded files are scanned up to
`Limits::max_depth` (4) levels deep.

`malmal sanitize` also takes:

| Option | Default | Effect |
|---|---|---|
| `--jpeg-quality <N>` | 90 | Quality of rebuilt JPEG files, 1–100 |
| `--pdf-dpi <N>` | 150 | Resolution of rebuilt PDF pages, 36–600 |
| `--pdf-jpeg` | off | Store a PDF page as JPEG when that is smaller |

`malmald` also takes:

| Option | Default | Effect |
|---|---|---|
| `--workers <N>` | 4 | Requests processed at once; bounds CPU and memory |
| `--connections <N>` | 256 | Connections kept open at once |
| `--timeout <S>` | 30 | Idle time before a connection is closed |
| `--spool-dir <DIR>` | none | Keep files of 1 MiB or more in temporary files in `DIR` instead of memory |

### Severity and policy

Each finding has a severity. The policy turns the most severe finding into the verdict:

| Policy | Info | Low | Medium | High, Critical |
|---|---|---|---|---|
| `default` | clean | suspicious | suspicious | malicious |
| `strict` | clean | suspicious | malicious | malicious |

We recommend rejecting every file that is not clean. The two policies then reject the
same files; `strict` only changes which are labelled malicious.

### Allowing finding codes

If your users legitimately send files with a feature malmal flags, allow that finding code
instead of ignoring the verdict:

```bash
malmal scan --allow 'pdf.xfa|pdf.embedded_file' tax-form.pdf
```

Codes are separated by `,` or `|`, and `--allow` can be repeated. An allowed finding is
still reported, at `info`, and the rest of the file is still checked: attachments are
still scanned, and a script inside an XFA form is still reported as `pdf.javascript`.

An unknown code is an error, so a typo cannot silently allow nothing. `limit.*` codes
cannot be allowed, because a file that was not fully analyzed is never clean; raise the
limit instead.

Codes that legitimate files often carry:

| Code | Severity | Common in | Risk if allowed |
|---|---|---|---|
| `pdf.xfa` | Medium | Tax and government forms | Forms render differently between readers |
| `pdf.embedded_file` | Medium | Source documents, e-invoices (ZUGFeRD, Factur-X) | Attached files the reader can open; each is still scanned |
| `pdf.javascript` | High | Forms that calculate or validate fields | Scripts run by the reader; the most common PDF attack |
| `pdf.open_action`, `pdf.additional_action` | Medium/High | Documents that open at a page or react to events | Actions that run without a click |
| `pdf.rich_media` | Medium | Brochures with video, sound or 3D | Media decoders with a history of exploits |
| `pdf.external_ref` | Medium | Prepress files, documents that include other files | Rendered content that was not scanned |
| `pdf.encrypted` | Medium | Documents locked with a password you do not have | Content that was not scanned at all |
| `pdf.submit_form`, `pdf.remote_goto` | Low | Forms that submit data, links to other documents | Requests to addresses the file chooses |
| `pdf.trailing_data`, `image.trailing_data` | Low | Files saved by some editors and cameras | Unread bytes after the end of the file |
| `pdf.launch` | High | Old documents that open a local file | Starts a program on the reader's machine |
| `svg.foreign_object` | Medium | Diagrams from tools such as draw.io | HTML rendered inside the image |
| `svg.external_ref` | Medium | Images that load web fonts or pictures | Requests to other sites when displayed |
| `type.mismatch` | Medium | Files with the wrong extension | Files served as the wrong type |

Never allow codes that only attacks produce: `type.executable`, `payload.*`,
`hash.blocklisted`, `yara.match`, `*.polyglot`, `*.malformed`, `svg.script`,
`svg.event_handler`, `svg.javascript_uri`, `svg.entity`, `pdf.obfuscated_name`,
`pdf.dangerous_uri`, `pdf.postscript`, `pdf.xml_entity`, and the `ps.*` codes for file and
device access.

In Rust, `Policy::with_override(code, severity)` sets any severity, for example to reject
something the default policy accepts:

```rust
use malmal::{Policy, Severity};

let policy = Policy::default()
    .with_override("pdf.risky_codec", Severity::Medium);  // refuse JBIG2 and JPEG 2000 images
```

### File types

All supported types are accepted by default. To accept fewer, list them; other files are
reported as `type.not_allowed`:

```bash
malmal scan --types jpeg,png,webp,pdf upload.eps
```

### Encrypted PDFs

PDFs encrypted with an empty password are always decrypted and inspected. Others are
reported as `pdf.encrypted` (Medium) unless you supply their password. The password file
has one password per line; each is tried as user and owner password.

```bash
malmal scan --pdf-passwords passwords.txt statement.pdf
```

### Blocklist and YARA

A SHA-256 blocklist rejects known files. The output of `sha256sum` can be used directly:

```bash
sha256sum known-bad/* > blocklist.txt
malmal scan --hashlist blocklist.txt upload.png
```

YARA rules are matched against every file and every file embedded in a PDF. They need a
build with the `yara` feature, which makes the binary about 16 MB and cannot be built
for musl:

```bash
cargo install malmal-cli --features yara
malmal scan --yara rules/ upload.jpg
```

`--yara` takes a rule file or a directory of `.yar` and `.yara` files, and can be repeated.

## Rebuilding files

A scan reports what a scanner can see. Rebuilding goes further: the file is decoded and a
new one is written from its content, so metadata, comments, unknown chunks and appended
data are dropped.

```bash
malmal sanitize upload.jpg stored.jpg
curl --fail --data-binary @upload.jpg -o stored.jpg http://127.0.0.1:8080/sanitize
```

```rust
// malmal = { version = "0.2", features = ["cdr"] }
use malmal::cdr::{Error, Options};

match scanner.sanitize(&data, hints, &Options::default()) {
    Ok(sanitized) => store(&sanitized.image.data, sanitized.image.file_type),
    Err(Error::Rejected(report) | Error::Unclean(report)) => reject(&report.findings),
    Err(other) => reject_with(other.to_string()),  // unsupported, too large, undecodable
}
```

```python
try:
    image = scanner.sanitize(data, filename="a.png")
except malmal.SanitizeError:        # Rejected or NotRebuilt
    reject()
else:
    store(image.data, image.file_type)
```

In C, use `malmal_sanitize`. In every interface, if rebuilding fails, store nothing.

- **Images** keep their pixels, animation frames, frame delays and loop count. Colors are
  converted to sRGB and the color profile is dropped. JPEG is re-encoded at the chosen
  quality and rotated as its Exif orientation says. BMP, TIFF, ICO and JPEG XL become PNG,
  so store the file under the type the result reports.
- **SVG** is filtered through an allowlist
  ([svg-hush](https://github.com/cloudflare/svg-hush)) that keeps only what draws.
  The result is scanned again and refused if it is not clean.
- **PDF** pages are rendered ([hayro](https://github.com/LaurenzV/hayro)) and the new PDF
  contains only the page images. Text can no longer be selected or searched, links and
  forms are removed, and text documents become about ten times larger. This needs the
  `cdr-pdf` feature, which is not included in the released binaries, container or wheels:

  ```bash
  cargo install malmal-cli --features cdr-pdf
  ```

Every rebuilt file is scanned again, because pixels themselves can encode another file.

## Deployment

### Sandbox

Before reading a file, `malmal` and `malmald` restrict themselves: Landlock limits file
access to the inputs, seccomp blocks `execve`, new sockets and other dangerous system
calls, and an rlimit caps address space. Pass `--require-sandbox` in production so that the
process exits if the sandbox cannot be applied. Linux only.

### Limits

A file that exceeds a limit gets a `limit.*` finding and is never clean. A scan that runs
past `--hard-timeout` ends the process with exit status 3, so run the daemon under a
supervisor:

```ini
[Service]
ExecStart=/usr/local/bin/malmald --socket /run/malmal/malmal.sock --http 127.0.0.1:8080 --require-sandbox
Restart=always
DynamicUser=yes
RuntimeDirectory=malmal
```

### Memory

`malmal scan` maps files instead of reading them, so memory depends on the structure of a
file, not its size: a 1 GB PDF is scanned within a 96 MB memory limit. The daemon keeps
uploads in memory unless `--spool-dir` is set; with it, files of 1 MiB or more are kept in
unnamed temporary files that are removed when the request ends.

The worst case per request is set by `--max-decompressed` and `--max-pixels`, and the
total by `--workers`. At the defaults, a single hostile file can use 250–550 MB; four
workers handling such files at once peaked at about 2 GB. Lower these options, or the
number of workers, to fit your memory budget. Details and measurements are in
[docs/integration.md](docs/integration.md#memory).

### Container

The image runs `malmald --http 0.0.0.0:8080` as an unprivileged user. Arguments replace the
default command:

```bash
docker run --rm -p 127.0.0.1:3310:3310 ghcr.io/nguyenthuan155632/malmal \
  --clamd 0.0.0.0:3310 --max-size 20000000
```

## Accuracy and performance

Results on [CIC-Evasive-PDFMal2022](https://www.unb.ca/cic/datasets/pdfmal-2022.html)
(9,107 clean and 21,899 malicious PDF files):

| Configuration | Malicious rejected | Clean accepted |
|---|---:|---:|
| Default policy | 98.19% | 87.32% |
| `--allow 'pdf.xfa\|pdf.embedded_file'` | 98.18% | 92.38% |
| `--allow 'pdf.xfa\|pdf.embedded_file\|pdf.javascript'` | 76.19% | 97.11% |

Every clean file that is rejected carries active content or an attachment: JavaScript
(660), XFA forms (260), attachments (207), launch actions (12), media (9) and a few others.
Of the 396 malicious files accepted, 379 contain only a picture and a link to an ordinary
web address; judging those requires a URL reputation service.

To measure false positives on your own files before you deploy:

```bash
cargo run --release --example survey -- --expect-clean DIR...
```

Scan times on a six-core desktop from 2018 (files in the page cache):

| File | Size | Time | With `--no-hash` | Memory |
|---|---:|---:|---:|---:|
| PDF, mostly images | 60 MB | 0.26 s | 0.03 s | 4 MB |
| PDF, mostly images | 1 GB | 4.5 s | 0.41 s | 4 MB |
| PDF, 100,000 objects | 10 MB | 0.18 s | 0.18 s | 12 MB |
| PDF, 500,000 objects | 51 MB | 0.89 s | 0.88 s | 42 MB |
| PDF, 200 MB of page content once inflated | 8 MB | 0.63 s | 0.63 s | 5 MB |

Memory is the peak resident size minus the mapped file. For large files most of the time
goes to the SHA-256 hash; `--no-hash` skips it when you do not need it.

## Limitations

- **PostScript** is a programming language, so static analysis cannot be complete. Code
  built at run time is reported as `ps.exec_dynamic`, not analyzed. Always run Ghostscript
  with `-dSAFER` and in a sandbox.
- **PDF JavaScript** is reported because it is present, not because of what it does.
- **Links in PDFs** are not judged: a document that only links to a malicious site is
  clean.
- **Pixel data is not decoded during a scan.** For HEIC and AVIF the container is checked,
  not the HEVC or AV1 stream.
- **Encrypted PDFs** support the standard security handler only, not certificate
  encryption.
- **HEIC, AVIF and PSD** are scanned but not rebuilt.
- **Rebuilt images keep their pixels**, and anything encoded in them. Rebuilt files are
  scanned again for that reason; if you call `malmal::cdr::rebuild` directly, scan the
  result yourself.
- **The library cannot interrupt a step that does not finish.** The time limit is checked
  between steps; only the command-line tools enforce `--hard-timeout`. Use the daemon if
  you need that guarantee.
- **The daemon has no authentication or TLS.**
- **macOS** has no sandbox, and the test suite is not run there.

## Development

```bash
cargo test --workspace
cd fuzz && cargo +nightly fuzz run pdf corpus/pdf seeds/pdf
```

- `tests/corpus/clean` and `tests/corpus/malicious` hold sample files.
  `tests/corpus/expected.tsv` records the expected findings for each; after an intended
  change, update it with `MALMAL_RECORD=1 cargo test -p malmal --test corpus`.
- `cargo run --release --example evaluate -- --clean DIR --malicious DIR` measures
  detection and false positives on labelled files. `--allow`, `--strict` and `--tsv` are
  supported.
- `cargo run --release --example throughput -- FILE...` measures throughput.
- `fuzz/` has one target per format; list them with `cargo fuzz list`.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
