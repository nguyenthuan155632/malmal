# malmal

A Rust library that scans uploaded files before a backend processes them: raster images
(JPEG, PNG, GIF, WebP, BMP, TIFF, PSD), SVG, PDF, PostScript/EPS and Illustrator files. It does not compete with antivirus on
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
| `malmald` | Daemon on a Unix socket, fully statically linked |
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

Building does not put anything on your `PATH`. Either run the binary by path
(`./target/release/malmal`), or install `malmal` and `malmald` into `~/.cargo/bin`:

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

The full table of finding codes is in [PLAN.md](PLAN.md).

## CLI

```bash
malmal scan --json --policy strict upload.pdf
```

`-` reads from stdin. Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 error.

`--types` replaces the accepted file types; anything else gets `type.not_allowed`. PostScript
is accepted by default, so a service that only wants PDF-based Illustrator files and images
refuses PostScript with:

```bash
malmal scan --types jpeg,png,gif,webp,bmp,tiff,psd,svg,pdf upload.ai
```

`malmald` takes the same option. From Rust it is `Policy::with_allowed_types`.

Before it opens the first file, the process confines itself: Landlock allows reading only
the files passed on the command line, seccomp blocks `execve`, sockets and other dangerous
syscalls, and an rlimit caps memory. `--require-sandbox` turns a failure to confine into an
error; `--no-sandbox` disables confinement. The sandbox exists on Linux only.

## Daemon

```bash
malmald --socket /run/malmal.sock --workers 8 --require-sandbox
```

Each request is one JSON line followed by exactly `size` bytes of file content:

```
{"size": 1234, "filename": "a.png", "content_type": "image/png"}\n<1234 bytes>
```

The reply is one JSON line: `{"ok": true, "report": {...}}` or
`{"ok": false, "error": "..."}`. A connection can carry many requests. Anything other than
`"ok": true` means the file was not scanned.

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
- **PSD layers are not parsed.** The header, the image resource blocks and the end of the
  merged image are checked, and the whole file is searched for payloads.
- **Phone camera trailers** (Samsung metadata, motion photo video) are reported as
  `image.vendor_trailer` at Info when their structure accounts for every byte; raise it with
  `with_override` to reject them. Other trailing data stays `image.trailing_data`.
- **Encrypted PDFs are not decrypted**, including those with an empty password; they yield
  `pdf.encrypted`.
- **XFA content and data after a PDF's `%%EOF` are not analyzed.**
- **BigTIFF is not supported** and is reported as `image.malformed`.
- **Files embedded in a PDF do not go through YARA.**
- Office documents, archives and video are out of scope; they are rejected with
  `type.not_allowed` or `type.unknown`.
