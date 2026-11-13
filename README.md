# malmal

A Rust library that scans uploaded files before a backend processes them: raster images
(JPEG, PNG, GIF, WebP, BMP, TIFF, PSD, HEIC, AVIF, JPEG XL, ICO), SVG, PDF, PostScript/EPS and
Illustrator files. It does not compete with antivirus on
signature count; it checks three things antivirus usually skips:

1. **Is the file the type it claims to be** (content against extension and `Content-Type`).
2. **Does the file carry active content** (scripts, actions, system commands, embedded files).
3. **Is the file structurally sound** (trailing data, polyglots, decompression bombs, truncation).

The rule throughout is fail-closed: a file that cannot be fully analyzed is never reported
clean.

This is one layer of defense, not the only one. For raster images, decoding and re-encoding
is still the most reliable measure; malmal decides which files get that far, and with the
`cdr` feature does the re-encoding too (`malmal sanitize`, [Rebuilding images](#rebuilding-images)).

## Build

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

The output is in `target/x86_64-unknown-linux-musl/release/`:

| File | What it is |
|---|---|
| `malmal` | CLI, fully statically linked |
| `malmald` | Daemon (Unix socket, HTTP, ClamAV protocol, ICAP), fully statically linked |
| `libmalmal_ffi.a` | Static library for C; the header is `crates/malmal-ffi/include/malmal.h` |

Both binaries run on a bare Debian install with no extra packages.

### macOS

```bash
cargo build --release --workspace
```

Leave out `--target`; the binaries land in `target/release/`. There is no sandbox on macOS,
so `--require-sandbox` exits with an error, and the memory limit is not applied. The test
suite has not been run on macOS.

### Installing the commands

Each release on GitHub carries the static binaries for x86-64 and ARM64 Linux, with the C
library and its header, as `malmal-v<version>-<target>.tar.gz` and a `.sha256` next to it.
[cargo-binstall](https://github.com/cargo-bins/cargo-binstall) fetches the same archive:

```bash
cargo binstall malmal-cli
```

The released version also builds from crates.io, without cloning anything:

```bash
cargo install malmal-cli
```

### Container

The image holds the two binaries and nothing else; it starts the daemon's HTTP endpoint.

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/nguyenthuan155632/malmal
```

```bash
docker run --rm -v "$PWD:/files:ro" --entrypoint /usr/local/bin/malmal ghcr.io/nguyenthuan155632/malmal scan /files/upload.pdf
```

`docker build -t malmal .` builds the same image from a checkout.

From a checkout, building does not put anything on your `PATH`. Either run the binary by
path (`./target/release/malmal`), or install `malmal` and `malmald` into `~/.cargo/bin`:

```bash
cargo install --path crates/malmal-cli
```

## Using it from Rust

```rust
use malmal::{Policy, ScanHints, Scanner, Verdict};

let scanner = Scanner::builder().policy(Policy::strict()).build();
let report = scanner.scan_bytes(&data, ScanHints {
    filename: Some("logo.svg"),
    content_type: Some("image/svg+xml"),
});
if report.verdict != Verdict::Clean {
    for finding in &report.findings {
        log::warn!("{} [{:?}] {}", finding.code, finding.severity, finding.message);
    }
    // reject the upload
}
```

A `Scanner` can be shared between threads. `scan_reader` reads from an `impl Read` and
stops by itself at the size limit.

- **`Policy`** decides the verdict: `default` treats High and above as `Malicious`, `strict`
  treats Medium and above as `Malicious`. `with_override("svg.foreign_object", Severity::Info)`
  changes the severity of one code; `with_allowed_types` narrows the accepted file types.
- **`Limits`** caps file size (64 MB), decompressed data (256 MB), embedded-file depth (4),
  time (10 seconds) and pixel count (2^28).
- **`HashList`** is a SHA-256 blocklist that reads `sha256sum` output directly.
- **`pdf_passwords`** on the builder are tried on encrypted PDFs, as user and as owner
  password. A document one of them opens is decrypted and inspected like any other.

Every finding code, with its severity and what to do about it, is in
[docs/findings.md](docs/findings.md). Examples for axum and actix-web are in
[docs/integration.md](docs/integration.md).

## CLI

```bash
malmal scan --json --policy strict upload.pdf
```

`-` reads from stdin. Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 error.

`--types` replaces the accepted file types; anything else gets `type.not_allowed`. PostScript
is accepted by default, so a service that only wants PDF-based Illustrator files and images
refuses PostScript with:

```bash
malmal scan --types jpeg,png,gif,webp,bmp,tiff,psd,heif,avif,jxl,ico,svg,pdf upload.ai
```

`malmald` takes the same option. From Rust it is `Policy::with_allowed_types`.

`--pdf-passwords FILE` names a file of passwords, one per line, to try on encrypted PDFs.

Before it opens the first file, the process confines itself: Landlock allows reading only
the files passed on the command line, seccomp blocks `execve`, sockets and other dangerous
syscalls, and an rlimit caps memory. `--require-sandbox` turns a failure to confine into an
error; `--no-sandbox` disables confinement. The sandbox exists on Linux only.

## Rebuilding images

```bash
malmal sanitize upload.jpg stored.jpg
```

scans the file and, if it is a clean raster image, decodes it and writes a new file from
the pixels. Metadata, colour profiles, comments, unknown chunks and anything appended are
not carried over, because nothing but pixels is. The exit status is 0 only when the new
file was written; it then takes the place of `stored.jpg` in one step, and otherwise
`stored.jpg` is left as it was, or absent.

| Input | Output |
|---|---|
| JPEG | JPEG at `--jpeg-quality` (90), rotated as its Exif orientation says |
| PNG | PNG; an animated one keeps every frame, at 8 bits a channel |
| GIF | GIF with every frame |
| WebP | lossless WebP, with every frame of an animated one |
| BMP, TIFF, ICO | PNG |

An animation keeps its frame delays and its loop count. Every other type is refused. The
new file carries no colour profile, so it is read as sRGB: the pixels of an image with a
profile are converted to sRGB first, which keeps its colours as far as sRGB can show them.
That covers RGB and grey profiles, and the CMYK profile of a CMYK JPEG; a profile that does
not fit its image is dropped. A lossy WebP grows when it is stored losslessly.

From Rust it is `Scanner::sanitize` and `malmal::cdr::rebuild`, behind the `cdr` feature;
over HTTP it is `POST /sanitize`; from C and Python, `malmal_sanitize` and
`Scanner.sanitize`. The decoders are those of the [`image`](https://crates.io/crates/image)
crate.

## Daemon

```bash
malmald --socket /run/malmal.sock --http 127.0.0.1:8080 --workers 8 --require-sandbox
```

`malmald` serves any combination of four endpoints:

| Option | Protocol |
|---|---|
| `--socket <PATH>` | One JSON line, then the file, on a Unix socket |
| `--http <ADDR>` | `POST /scan` with the file as the body; `POST /sanitize` for the rebuilt image; `GET /metrics` for Prometheus; `GET /healthz` |
| `--clamd <ADDR>` | The `INSTREAM` command of ClamAV's daemon, for clients that already speak it |
| `--icap <ADDR>` | ICAP (`REQMOD`, `RESPMOD`), for a proxy such as Squid to pass uploads and downloads through |

```bash
curl --data-binary @upload.pdf 'http://127.0.0.1:8080/scan?filename=upload.pdf'
```

The reply is `{"ok": true, "report": {...}}`; anything else means the file was not scanned.
The daemon has no authentication: bind it to the loopback interface or a Unix socket.
`--workers` is the number of requests worked on at once and `--connections` the number of
connections kept open; an idle connection holds no worker. `--max-size` and
`--scan-timeout` set the limits for every request. A scan still running
after `--hard-timeout` (six times the scan timeout unless given) ends the daemon, for its
supervisor to start again; see [Limits and timeouts](docs/integration.md#limits-and-timeouts).
The protocols, the metrics and client examples are in
[docs/integration.md](docs/integration.md).

## Using it from C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
malmal_string_free(report);
malmal_scanner_free(scanner);
```

`malmal_sanitize` returns the rebuilt image. Full example:
`crates/malmal-ffi/examples/scan.c`.

## Using it from Python

`bindings/python` wraps the C library with `ctypes`; it needs nothing but the standard
library. The release workflow builds wheels for Linux that carry the library; building
one yourself is described in [bindings/python/README.md](bindings/python/README.md).

```python
import malmal

scanner = malmal.Scanner()
report = scanner.scan(data, filename="a.png", content_type="image/png")
if not report.clean:
    reject([finding["code"] for finding in report.findings])

image = scanner.sanitize(data, filename="a.png")   # raises unless there is a new file
store(image.data, image.file_type)
```

## YARA (optional)

```bash
cargo build --release -p malmal-cli --features yara
malmal scan --yara rules/ upload.jpg
```

This feature is off by default because it pulls in a WebAssembly runtime and takes the
binary to about 16 MB. The YARA build **does not build for musl**; it links
dynamically against glibc, so build it on the Debian release that will run it. YARA's `pe`
and `elf` modules are not enabled.

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
  your own uploads.
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
- **No pixel data is decoded.** For HEIC and AVIF the boxes, the declared sizes and the item
  locations are checked, not the HEVC or AV1 stream.
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
- **PDFs that need a password are decrypted only when it is supplied** (`pdf_passwords`,
  `--pdf-passwords`); otherwise they yield `pdf.encrypted` at Medium. Those encrypted with
  an empty password, which every reader opens without asking, are always decrypted and
  inspected. Only the standard security handler is supported, not certificate encryption.
- **Strings in a PDF are not inspected**, encrypted or not: JavaScript is reported because
  it is there, not for what it does.
- **XFA forms are searched for scripts and nothing else.**
- **The ClamAV protocol carries no file name**, so `type.mismatch` and
  `name.dangerous_extension` cannot be reported over it.
- **Over ICAP a request body is judged as a file** unless it is a form: route only upload
  URLs to it, or JSON API calls are blocked as `type.unknown`. The ICAP endpoint is tested
  against the protocol as specified and behind Squid 6, not behind other proxies.
- **Rebuilding keeps the pixels**, so data encoded in them survives, and it relies on the
  `image` crate's decoders. An animated PNG with 16 bits a channel comes out with 8.
- **The time limit is checked between steps** of the analysis, and between the frames of
  an image being rebuilt; it bounds the work without cutting it off at an exact moment.
  The library cannot stop a step that does not end. The commands can: past
  `--hard-timeout` the process exits with status 3, and whatever else the daemon was
  doing at that moment is lost with it.
- Office documents, archives and video are out of scope; they are rejected with
  `type.not_allowed` or `type.unknown`.
