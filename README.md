# malmal

Scans uploaded files before a backend processes them: raster images (JPEG, PNG, GIF, WebP,
BMP, TIFF, PSD, HEIC, AVIF, JPEG XL, ICO), SVG, PDF, PostScript/EPS and Illustrator files.
It does not compete with antivirus on signature count; it checks three things antivirus
usually skips:

1. **Is the file the type it claims to be** (content against extension and `Content-Type`).
2. **Does the file carry active content** (scripts, actions, system commands, embedded files).
3. **Is the file structurally sound** (trailing data, polyglots, decompression bombs, truncation).

The rule throughout is fail-closed: a file that cannot be fully analyzed is never reported
clean. It is one layer of defense, not the only one.

## Which way in

| You want to | Use | Section |
|---|---|---|
| Check files by hand, in a script or in CI | `malmal scan` | [Check a file](#check-a-file-from-the-command-line) |
| Reject bad uploads in a Rust service | the `malmal` crate | [In a Rust service](#scan-uploads-in-a-rust-service) |
| Reject bad uploads from any other language | `malmald --http` or `--socket` | [From any language](#scan-uploads-from-any-language) |
| Do the same from Python or C without a daemon | the binding, the C library | [Python](#from-python), [C](#from-c) |
| Keep the picture and nothing else of an image, an SVG or a PDF | `malmal sanitize`, `POST /sanitize` | [Rebuild files](#keep-only-the-picture-of-an-image) |
| Replace ClamAV where software already calls `clamd` | `malmald --clamd` | [ClamAV clients](#serve-software-that-already-talks-to-clamav) |
| Scan what passes through a proxy | `malmald --icap` | [Behind a proxy](#scan-what-passes-through-a-proxy) |

Then, whichever way in: [accept only some types](#accept-only-the-types-you-take),
[open encrypted PDFs](#look-inside-encrypted-pdfs),
[block known files and add rules](#block-known-files-and-add-your-own-rules),
[decide what is rejected](#decide-what-is-rejected), and
[run it in production](#run-it-in-production).

## Install

**Prebuilt, for x86-64 and ARM64 Linux.** Each release on GitHub carries static binaries
that run on a bare install with no extra packages, with the C library and its header, as
`malmal-v<version>-<target>.tar.gz` and a `.sha256` next to it.
[cargo-binstall](https://github.com/cargo-bins/cargo-binstall) fetches the same archive:

```bash
cargo binstall malmal-cli
```

**From crates.io**, built on your machine:

```bash
cargo install malmal-cli
```

**As a container**, holding the two binaries and nothing else:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/nguyenthuan155632/malmal
```

**From a checkout**, static binaries in `target/x86_64-unknown-linux-musl/release/`:

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

| File | What it is |
|---|---|
| `malmal` | The command: `scan` and `sanitize` |
| `malmald` | The daemon: Unix socket, HTTP, ClamAV protocol, ICAP |
| `libmalmal_ffi.a` | Static library for C; the header is `crates/malmal-ffi/include/malmal.h` |

`cargo install --path crates/malmal-cli` puts the two commands in `~/.cargo/bin`, and
`docker build -t malmal .` builds the image. On macOS leave out `--target`; there is no
sandbox there, so `--require-sandbox` exits with an error, and the test suite has not been
run on it.

## Check a file from the command line

```bash
malmal scan upload.pdf
```

```
upload.pdf: MALICIOUS (pdf)
  [High] pdf.javascript: document contains JavaScript at offset 186
```

The exit status is the verdict of the worst file: `0` clean, `1` suspicious, `2`
malicious, `3` error. That is all a script needs:

```bash
malmal scan "$file" || rm -- "$file"
```

Several files can be named at once, `-` reads standard input, and `--json` prints one
object per file for a program to read:

```bash
malmal scan --json incoming/*
```

```json
{"path":"incoming/a.pdf","report":{"declared_types":["pdf"],"detected_type":"pdf","findings":[
  {"code":"pdf.javascript","message":"document contains JavaScript","offset":186,"severity":"high"}],
 "sha256":"8e38c368...","size":285,"verdict":"malicious"}}
```

Every finding has a `code`, which is the stable part to match on. All of them, with their
severity and what to do about each, are in [docs/findings.md](docs/findings.md).

## Scan uploads in a Rust service

```bash
cargo add malmal
```

```rust
use malmal::{ScanHints, Scanner, Verdict};

// Build once and share: a Scanner is Send + Sync.
let scanner = Scanner::builder().build();

let report = scanner.scan_bytes(&data, ScanHints {
    filename: Some("logo.svg"),            // what the uploader claimed
    content_type: Some("image/svg+xml"),
});
if report.verdict != Verdict::Clean {
    for finding in &report.findings {
        log::warn!("{} [{:?}] {}", finding.code, finding.severity, finding.message);
    }
    // reject the upload
}
```

`scan_bytes` never fails and never panics on hostile input; what could not be analyzed is
a finding. `scan_reader` takes an `impl Read` and stops by itself at the size limit.
Scanning is CPU work that can take up to the time limit, so in an async service run it on a
blocking thread. Complete handlers for axum and actix-web are in
[docs/integration.md](docs/integration.md#in-a-rust-service).

What to do with the result:

- Reject anything but `Verdict::Clean`. Log the findings and `report.sha256`; show the user
  a generic message, not the findings.
- Store the file under a name you generate, with the extension that belongs to
  `report.detected_type`, never under the uploaded name.
- For images, go one step further and [rebuild them](#keep-only-the-picture-of-an-image).

## Scan uploads from any language

Run the daemon next to your service and hand it each upload:

```bash
malmald --http 127.0.0.1:8080 --socket /run/malmal.sock --require-sandbox
```

Over HTTP the request body is the file itself, not a form. The name and type the uploader
claimed go in the query and in `Content-Type`:

```bash
curl --data-binary @upload.pdf -H 'Content-Type: application/pdf' 'http://127.0.0.1:8080/scan?filename=upload.pdf'
```

The reply is `200` with `{"ok": true, "report": {...}}` whatever the verdict; the report
is the object shown [above](#check-a-file-from-the-command-line). **Any other status means
the file was not scanned**, and is to be treated as a rejection.

On the Unix socket a request is one line of JSON, then the file, and the reply is one line
of JSON. A connection can carry many requests:

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

The daemon has no authentication and no TLS: bind it to the loopback interface or a Unix
socket, and let only the upload service reach it. Every endpoint, status code and metric
is described in [docs/integration.md](docs/integration.md#as-a-daemon).

### From Python

Without a daemon, `bindings/python` loads the scanner as a library. It needs nothing but
the standard library:

```python
import malmal

scanner = malmal.Scanner()          # build once, share between threads
report = scanner.scan(data, filename="a.png", content_type="image/png")
if not report.clean:
    reject([finding["code"] for finding in report.findings])
```

A `malmal.ScanError` means the file was not scanned. Each release has wheels for x86-64
and ARM64 Linux that carry the library; installing one, or using the package from a
checkout, is described in [bindings/python/README.md](bindings/python/README.md).

### From C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
if (verdict != MALMAL_CLEAN) { /* reject; `report` is the JSON report */ }
malmal_string_free(report);
malmal_scanner_free(scanner);
```

Link `libmalmal_ffi.a` and include `malmal.h`; a scanner may be used from several threads
at once. The full example is `crates/malmal-ffi/examples/scan.c`.

## Keep only the picture of an image

A scan says a file is clean as far as a scanner can tell. For raster images there is a
stronger measure: decode the file and write a new one from the pixels. Metadata, colour
profiles, comments, unknown chunks and anything appended are not carried over, because
nothing but pixels is.

```bash
malmal sanitize upload.jpg stored.jpg
```

scans the file first and rebuilds it only if it is clean. The exit status is `0` only when
the new file was written; it then takes the place of `stored.jpg` in one step, and
otherwise `stored.jpg` is left as it was, or absent. `-` is standard input or output.

| Input | Output |
|---|---|
| JPEG | JPEG at `--jpeg-quality` (90), rotated as its Exif orientation says |
| PNG | PNG; an animated one keeps every frame, at 8 bits a channel |
| GIF | GIF with every frame |
| WebP | lossless WebP, with every frame of an animated one |
| BMP, TIFF, ICO | PNG |
| JPEG XL | PNG |
| SVG | SVG, filtered down to what draws a picture |
| PDF | PDF in which every page is a picture of the page, at `--pdf-dpi` (150) |
| anything else | refused |

An image is the easy case. The other two are documents, and are handled differently:

- **SVG** goes through an allowlist ([svg-hush](https://github.com/cloudflare/svg-hush)):
  elements and attributes that do not draw are left out, scripts, event handlers,
  `foreignObject` and links to other sites among them. A raster image embedded in it is
  rebuilt like one that stands alone. The result then has to pass malmal's own SVG
  analyzer, and is refused if the two disagree about it.
- **PDF** is drawn page by page ([hayro](https://github.com/LaurenzV/hayro)) and the new
  file holds the drawings. What a page *does* is not in a picture of it, but neither is
  its text: it can no longer be selected, searched or read aloud, links and forms are
  gone, and the file is larger, some ten times for a text document. hayro calls itself
  experimental; pages using features it lacks may not look the same.

The same from a service:

```bash
curl --fail --data-binary @upload.jpg -o stored.jpg http://127.0.0.1:8080/sanitize
```

```rust
// malmal = { version = "0.2", features = ["cdr"] }
use malmal::cdr::{Error, Options};

match scanner.sanitize(&data, hints, &Options::default()) {
    Ok(sanitized) => store(&sanitized.image.data, sanitized.image.file_type),
    Err(Error::Rejected(report)) => reject(&report.findings),
    Err(other) => reject_with(other.to_string()),   // not an image, too large, undecodable
}
```

```python
try:
    image = scanner.sanitize(data, filename="a.png")
except malmal.SanitizeError:        # Rejected (with .report) or NotRebuilt
    reject()
else:
    store(image.data, image.file_type)
```

From C it is `malmal_sanitize`. In every form, anything but success means there is no
file to keep, and the upload itself is not to be stored in its place.

Worth knowing:

- The type can change: a BMP, TIFF or ICO comes back as PNG. Store the file as the type
  the result names.
- An animation keeps its frame delays and its loop count.
- The new file carries no colour profile, so it is read as sRGB. The pixels of an image
  with a profile are converted to sRGB first, which keeps its colours as far as sRGB can
  show them: RGB and grey profiles, and the CMYK profile of a CMYK JPEG.
- A JPEG is compressed again, so it loses a little; a lossy WebP grows, because it is
  stored losslessly.

## Serve software that already talks to ClamAV

Many applications can hand uploads to `clamd`. Point them at malmal instead:

```bash
malmald --clamd 127.0.0.1:3310
```

`PING`, `VERSION` and `INSTREAM` are answered, which is what such clients use. The
protocol has only two answers and no way to name the file, so a suspicious file is
answered `FOUND` like a malicious one (`stream: Malmal.Suspicious.pdf.encrypted FOUND`),
and the file name and `Content-Type` are not checked against the content.

## Scan what passes through a proxy

A proxy that speaks ICAP hands each request or response to the daemon and forwards it
only if the daemon lets it through. Nothing in the application changes.

```bash
malmald --icap 127.0.0.1:1344
```

With Squid:

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

`bypass=off` keeps it fail-closed: Squid refuses the request when the daemon cannot be
reached. Each file in a `multipart/form-data` upload is scanned on its own; any other
body is scanned as the file itself. A message that is not clean is replaced by
`403 Forbidden`.

What is judged is a file, so send it uploads and downloads, as the `acl` lines do, and not
every request: a JSON API call or an HTML page is not a file the scanner knows and would
be blocked. The details are in [docs/integration.md](docs/integration.md#icap).

## Accept only the types you take

Every supported type is accepted by default, PostScript included. A service that wants
images and PDFs only says so, and everything else is reported as `type.not_allowed`:

```bash
malmal scan --types jpeg,png,gif,webp,pdf upload.eps
```

`malmald` takes the same option. From Rust:

```rust
use malmal::{FileType, Policy, Scanner};

let policy = Policy::default().with_allowed_types([FileType::Jpeg, FileType::Png, FileType::Pdf]);
let scanner = Scanner::builder().policy(policy).build();
```

The names are `jpeg`, `png`, `gif`, `webp`, `bmp`, `tiff`, `psd`, `heif`, `avif`, `jxl`,
`ico`, `svg`, `pdf` and `postscript`.

## Look inside encrypted PDFs

A PDF encrypted with an empty password, which every reader opens without asking, is
always decrypted and inspected. One that needs a password cannot be, and is reported as
`pdf.encrypted`, which makes it suspicious. If your users send documents with passwords
you know, supply them, and those documents are inspected like any other:

```bash
malmal scan --pdf-passwords passwords.txt statement.pdf
```

The file holds one password per line; each is tried as user and as owner password.
`malmald` takes the same option. From Rust it is
`Scanner::builder().pdf_passwords(["..."])`, from Python
`malmal.Scanner(pdf_passwords=["..."])`, from C `malmal_scanner_new_with_passwords`.

## Block known files and add your own rules

A SHA-256 blocklist rejects files you have seen before, whatever is in them. The file is
one hex digest per line, and the output of `sha256sum` is read as it is:

```bash
sha256sum known-bad/* > blocklist.txt
```

```bash
malmal scan --hashlist blocklist.txt upload.png
```

From Rust it is `HashList::parse` and `Scanner::builder().hashlist(...)`; from Python,
`malmal.Scanner(hashlist=text)`.

YARA rules are matched against every file, and against files embedded in PDFs, in a build
with the `yara` feature:

```bash
cargo build --release -p malmal-cli --features yara
```

```bash
malmal scan --yara rules/ upload.jpg
```

The feature is off by default because it pulls in a WebAssembly runtime and takes the
binary to about 16 MB. That build **does not build for musl**: it links dynamically
against glibc, so build it on the release of the system that will run it. YARA's `pe` and
`elf` modules are not enabled.

## Decide what is rejected

Every finding has a severity, and the policy turns the worst one into the verdict:

| Policy | Low | Medium | High, Critical |
|---|---|---|---|
| `default` | suspicious | suspicious | malicious |
| `strict` | suspicious | malicious | malicious |

Info leaves a file clean. If you reject everything that is not clean, as recommended, the
two differ only in what the report calls it; `strict` matters where suspicious files are
quarantined and malicious ones dropped.

```bash
malmal scan --policy strict upload.pdf
```

To accept something the default policy flags, lower that one code rather than ignoring
verdicts; to reject something it lets through, raise it. This is in the Rust API:

```rust
use malmal::{Policy, Severity};

let policy = Policy::default()
    .with_override("svg.foreign_object", Severity::Info)      // our editor writes these
    .with_override("image.vendor_trailer", Severity::Medium); // no phone camera extras
```

## Run it in production

**The sandbox.** Before it reads the first byte of a file, the process confines itself:
Landlock allows reading only the files it was given, seccomp blocks `execve`, sockets
and other dangerous system calls, and an rlimit caps memory. A bug in a parser then has
nowhere to go. `--require-sandbox` turns a failure to confine into an error, and is what a
deployment should pass; `--no-sandbox` turns confinement off. Linux only.

**Limits.** A file that exceeds one is reported with a `limit.*` finding, never as clean.

| Option | Default | What it bounds |
|---|---|---|
| `--max-size <BYTES>` | 64 MB | The file; the daemon refuses a larger one outright |
| `--scan-timeout <S>` | 10 | One scan, checked between steps of the analysis |
| `--hard-timeout <S>` | 6 × the above | A scan that does not end: the process exits with status 3 |

From Rust, `Limits` holds these and the caps on decompressed data (256 MB), nesting depth
(4) and pixel count (2^28). The hard timeout exists in the commands only; see
[Known limits](#known-limits).

**The daemon.** `--workers` (4) is the number of requests worked on at once and is what
bounds memory and processors; `--connections` (256) is the number of connections kept
open, and an idle one holds no worker. Because a scan past the hard timeout ends the
process, run the daemon under a supervisor that starts it again:

```ini
[Service]
ExecStart=/usr/local/bin/malmald --socket /run/malmal/malmal.sock --http 127.0.0.1:8080 --require-sandbox
Restart=always
DynamicUser=yes
RuntimeDirectory=malmal
```

`GET /healthz` answers `200 ok`, and `GET /metrics` has counters in the Prometheus text
format: scans by verdict, errors, refused requests, bytes, time, rebuilt images.

**In a container** the image runs `malmald --http 0.0.0.0:8080` as an unprivileged user;
arguments replace that default. Publish the port to the upload service only.

```bash
docker run --rm -p 127.0.0.1:3310:3310 ghcr.io/nguyenthuan155632/malmal --clamd 0.0.0.0:3310 --max-size 20000000
```

## Testing

```bash
cargo test --workspace
```

```bash
cd fuzz && cargo +nightly fuzz run pdf corpus/pdf seeds/pdf
```

- `tests/corpus/clean` and `tests/corpus/malicious` are scanned by `cargo test`; drop real
  files in to add test cases.
- `tests/corpus/expected.tsv` records the verdict and findings of every sample. A change to
  an analyzer fails the test with the samples that moved; record an intended change with
  `MALMAL_RECORD=1 cargo test -p malmal --test corpus`.
- `cargo run --release --example survey -- --expect-clean DIR...` scans a directory of
  known-good files and lists those that did not come back clean: the false-positive rate on
  your own uploads. Run it before you deploy.
- `fuzz/` has one target per format (`cargo fuzz list`).
- `cargo run --release --example throughput -- FILE...` measures throughput.

## Known limits

- **PostScript is a full programming language**, so static analysis cannot be complete.
  Operator names assembled at run time are not seen; code decoded at run time is reported as
  `ps.exec_dynamic` rather than read. Always run Ghostscript with `-dSAFER` and in its own
  sandbox.
- **Two PostScript exemptions are deliberate.** Four procsets that Illustrator writes into
  every EPS are skipped when their SHA-256 matches exactly, because they open a scratch file
  and use `superexec`. Names starting with a dot are not reported inside a run of ASCII85
  image data, because megabytes of it spell such names by chance; operators behind published
  Ghostscript escapes are still found there.
- **Short tags (`<?=`, `<%=`, `<%@`) in images are reported only as complete tags**: text that
  is closed, balanced and reaches a call or variable. Uncompressed pixels otherwise match
  them by chance.
- **A scan decodes no pixel data.** For HEIC and AVIF the boxes, the declared sizes and the
  item locations are checked, not the HEVC or AV1 stream.
- **A bare JPEG XL codestream has no end that can be found without decoding it**, so data
  appended to one is not reported as trailing data; it is still searched for payloads. In the
  boxed form the end is known, and Brotli-compressed metadata boxes are decompressed and
  searched.
- **PSD layer records are walked, layer pixels are not decoded.** In 16- and 32-bit
  documents the layer list sits in an extra block, which is read when the block is found.
- **Phone camera trailers** (Samsung metadata, motion photo video) are reported as
  `image.vendor_trailer` at Info when their structure accounts for every byte; raise it with
  `with_override` to reject them. Other trailing data stays `image.trailing_data`.
- **Changes to `errordict` and `systemdict` are not reported.** Exploits use them to keep
  running after an error, and so does the prolog of every Illustrator EPS.
- **PDFs that need a password are decrypted only when it is supplied**; otherwise they
  yield `pdf.encrypted` at Medium. Only the standard security handler is supported, not
  certificate encryption.
- **Strings in a PDF are not inspected**, encrypted or not: JavaScript is reported because
  it is there, not for what it does.
- **XFA forms are searched for scripts and nothing else.**
- **The ClamAV protocol carries no file name**, so `type.mismatch` and
  `name.dangerous_extension` cannot be reported over it.
- **Over ICAP a request body is judged as a file** unless it is a form. The endpoint is
  tested against the protocol as specified and behind Squid 6, not behind other proxies.
- **Rebuilding keeps the pixels**, so data encoded in them survives. That includes the
  bytes of another file: a picture can be drawn whose pixels, written into a new PNG,
  make it a PDF as well, with nothing to see in the upload. `sanitize` therefore scans
  what it has rebuilt and refuses it when that scan is not clean; a caller of
  `malmal::cdr::rebuild` has to do so itself. Rebuilding relies on the
  `image` crate's decoders. HEIC, AVIF and PSD are scanned but not rebuilt: the decoders
  for the first two that are written in safe Rust are under the AGPL, and the one that is
  not brings hand-written assembly with it. An animated PNG with 16 bits a channel comes
  out with 8, and of an animated JPEG XL only the first frame.
- **A rebuilt PDF is a picture book.** Its pages look the same and do nothing; the text
  in them is no longer text. A PDF that needs a password is not rebuilt.
- **The time limit is checked between steps** of the analysis, and between the frames of
  an image being rebuilt; it bounds the work without cutting it off at an exact moment.
  The library cannot stop a step that does not end. The commands can: past
  `--hard-timeout` the process exits with status 3, and whatever else the daemon was
  doing at that moment is lost with it. A service that needs that guarantee calls the
  daemon rather than the library.
- Office documents, archives and video are out of scope; they are rejected with
  `type.not_allowed` or `type.unknown`.
