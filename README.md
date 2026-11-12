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
is still the most reliable measure; malmal decides which files get that far.

## Build

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

The output is in `target/x86_64-unknown-linux-musl/release/`:

| File | What it is |
|---|---|
| `malmal` | CLI, fully statically linked |
| `malmald` | Daemon (Unix socket, HTTP, ClamAV protocol), fully statically linked |
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

The released version installs from crates.io, without cloning anything:

```bash
cargo install malmal-cli
```

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

Before it opens the first file, the process confines itself: Landlock allows reading only
the files passed on the command line, seccomp blocks `execve`, sockets and other dangerous
syscalls, and an rlimit caps memory. `--require-sandbox` turns a failure to confine into an
error; `--no-sandbox` disables confinement. The sandbox exists on Linux only.

## Daemon

```bash
malmald --socket /run/malmal.sock --http 127.0.0.1:8080 --workers 8 --require-sandbox
```

`malmald` serves any combination of three endpoints:

| Option | Protocol |
|---|---|
| `--socket <PATH>` | One JSON line, then the file, on a Unix socket |
| `--http <ADDR>` | `POST /scan` with the file as the body; `GET /metrics` for Prometheus; `GET /healthz` |
| `--clamd <ADDR>` | The `INSTREAM` command of ClamAV's daemon, for clients that already speak it |

```bash
curl --data-binary @upload.pdf 'http://127.0.0.1:8080/scan?filename=upload.pdf'
```

The reply is `{"ok": true, "report": {...}}`; anything else means the file was not scanned.
The daemon has no authentication: bind it to the loopback interface or a Unix socket.
`--max-size` and `--scan-timeout` set the limits for every request. The protocols, the
metrics and client examples are in [docs/integration.md](docs/integration.md).

## Using it from C

```c
malmal_scanner *scanner = malmal_scanner_new(0, NULL, 0);
char *report = NULL;
int verdict = malmal_scan(scanner, data, len, "a.png", "image/png", &report);
malmal_string_free(report);
malmal_scanner_free(scanner);
```

Full example: `crates/malmal-ffi/examples/scan.c`.

## YARA (optional)

```bash
cargo build --release -p malmal-cli --features yara
malmal scan --yara rules/ upload.jpg
```

This feature is off by default because it pulls in a WebAssembly runtime and takes the
binary from 0.8 MB to 16 MB. The YARA build **does not build for musl**; it links
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
  boxed form the end is known. Brotli-compressed metadata boxes are not decompressed and are
  reported as `image.compressed_metadata` at Info.
- **PSD layer records are walked, layer pixels are not decoded.** In 16- and 32-bit
  documents the layer list sits in an extra block, which is read when the block is found.
- **Phone camera trailers** (Samsung metadata, motion photo video) are reported as
  `image.vendor_trailer` at Info when their structure accounts for every byte; raise it with
  `with_override` to reject them. Other trailing data stays `image.trailing_data`.
- **Changes to `errordict` and `systemdict` are not reported.** Exploits use them to keep
  running after an error, and so does the prolog of every Illustrator EPS.
- **PDFs that need a password are not decrypted** and yield `pdf.encrypted` at Medium. Those
  encrypted with an empty password, which every reader opens without asking, are decrypted
  and inspected. Only the standard security handler is supported, not certificate encryption.
- **Strings in a PDF are not inspected**, encrypted or not: JavaScript is reported because
  it is there, not for what it does.
- **XFA forms are searched for scripts and nothing else.**
- **The ClamAV protocol carries no file name**, so `type.mismatch` and
  `name.dangerous_extension` cannot be reported over it.
- Office documents, archives and video are out of scope; they are rejected with
  `type.not_allowed` or `type.unknown`.
