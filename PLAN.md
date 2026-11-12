# malmal — implementation plan

A Rust library that scans uploaded files (images, SVG, PDF, PostScript/EPS/AI) as a layer of defense.
It builds to a static binary (`x86_64-unknown-linux-musl`) that runs on Debian with nothing else installed.

## Design decisions

| Question | Decision | Reason |
|---|---|---|
| Distribution | A Rust crate first, with a CLI; C ABI and daemon are optional in M6 | The backend is Rust, so it embeds the crate directly; the CLI is for testing and scripts |
| Parsers | Hand-written for images, PDF and PostScript | Malicious files are often deliberately non-conforming; a "conforming" parser such as `lopdf` rejects them or misses things |
| Parse errors | Never panic, never treat a parse error as "clean" | A parse error produces a `*.malformed` finding |
| `unsafe` | `#![forbid(unsafe_code)]` in every crate except `malmal-ffi` | The scanner must not become a vulnerability |
| Dependencies | Pure-Rust crates only, as few as possible | Keeps the static build simple and the supply-chain surface small |
| YARA | A `yara` feature (off by default) using `yara-x` | `yara-x` pulls in `wasmtime`, which makes the binary large and the build slow |
| Result when a limit is exceeded | `Suspicious` plus a `limit.*` finding | Fail-closed: a file not scanned to the end is not reported clean |

Planned dependencies: `miniz_oxide` (Flate), `weezl` (LZW), `quick-xml` (SVG/XMP), `sha2`,
`serde` + `serde_json`, `landlock` + `seccompiler` (sandbox), `yara-x` (optional).
The CLI parses its own arguments and does not use `clap`.

## Workspace layout

```
malmal/
├── Cargo.toml                 # workspace, release profile (lto, panic=abort in the CLI)
├── crates/
│   ├── malmal/                # core library
│   │   └── src/
│   │       ├── lib.rs         # Scanner, ScanOptions, scan_bytes / scan_reader
│   │       ├── report.rs      # Verdict, Finding, Severity, Report
│   │       ├── limits.rs      # Limits, Budget (decompressed bytes, depth, time)
│   │       ├── detect.rs      # file type detection by magic bytes
│   │       ├── policy.rs      # Policy: maps finding codes to actions
│   │       ├── payload.rs     # shared string scanner (php, script, PE/ELF/ZIP headers)
│   │       ├── image/         # jpeg.rs png.rs gif.rs webp.rs bmp.rs tiff.rs meta.rs
│   │       ├── svg.rs
│   │       ├── pdf/           # lexer.rs object.rs xref.rs filters.rs analyze.rs
│   │       ├── ps/            # lexer.rs analyze.rs (PostScript, EPS, legacy AI)
│   │       ├── hashlist.rs    # SHA-256 blocklist
│   │       └── yara.rs        # behind the "yara" feature
│   ├── malmal-cli/            # the `malmal` binary
│   ├── malmal-ffi/            # cdylib + staticlib, malmal.h header
│   └── malmal-daemon/         # the `malmald` binary, Unix socket
├── fuzz/                      # cargo-fuzz, one target per parser
├── tests/corpus/{clean,malicious}/
└── rules/                     # default YARA rules
```

## Core API

```rust
pub enum Verdict { Clean, Suspicious, Malicious }
pub enum Severity { Info, Low, Medium, High, Critical }

pub struct Finding {
    pub code: &'static str,     // e.g. "pdf.javascript"
    pub severity: Severity,
    pub message: String,
    pub offset: Option<u64>,
}

pub struct Report {
    pub verdict: Verdict,
    pub detected_type: FileType,
    pub declared_type: Option<FileType>,
    pub sha256: [u8; 32],
    pub findings: Vec<Finding>,
}

let scanner = Scanner::builder().limits(Limits::default()).policy(Policy::strict()).build();
let report = scanner.scan_bytes(&data, ScanHints { filename, content_type });
```

The verdict is computed from the findings through a `Policy`: a `Critical`/`High` finding
gives `Malicious`, `Medium`/`Low` gives `Suspicious`, `Info` only gives `Clean`. A policy can
override severity per code.

## Finding codes

| Group | Code | Default severity |
|---|---|---|
| General | `type.mismatch` (content differs from extension/Content-Type) | Medium |
| | `type.unknown`, `type.not_allowed` | Medium |
| | `type.executable` (PE/ELF/Mach-O/script with a shebang) | Critical |
| | `name.dangerous_extension` (`shell.php.jpg`, `.htaccess`) | High |
| | `payload.php` (`<?php` in any file type; also a complete `<?= ... ?>` tag in raster images) | High |
| | `payload.script` (`<script`, `<iframe`, `javascript:` in raster images) | High |
| | `payload.template` (a complete `<%= ... %>` or `<%@ ... %>` tag in raster images) | High |
| | `limit.size`, `limit.decompression`, `limit.depth`, `limit.time`, `limit.complexity` | Medium |
| | `hash.blocklisted`, `yara.match` | Critical |
| Images | `image.malformed` | Medium |
| | `image.trailing_data` (ignores zero padding and JPEG MPF frames) | Low |
| | `image.compressed_metadata` (Brotli-compressed metadata box in a JPEG XL file, not decompressed) | Info |
| | `image.vendor_trailer` (a complete Samsung metadata trailer or motion photo video after the image) | Info |
| | `image.polyglot` (the excess is ZIP/PDF/PE/ELF/HTML; a PDF header in the first 1024 bytes; a ZIP record ending the file) | High |
| | `image.metadata.payload` (code in compressed PNG chunks `zTXt`/`iTXt`/`iCCP`) | High |
| | `image.pixel_bomb` | Medium |
| SVG | `svg.script` (`<script>`, `<handler>`, XSLT stylesheets) | High |
| | `svg.event_handler` (`on*` attributes, animations that set `on*`) | High |
| | `svg.javascript_uri` (in `href`/`src`, animations, CSS) | High |
| | `svg.data_uri` | High for HTML/XML/JS, Medium for other non-image types |
| | `svg.foreign_object`, `svg.external_ref` | Medium |
| | `svg.entity` (external entities, parameter entities, nested entities, `ATTLIST`) | High |
| | `svg.malformed` (broken XML, unusual encoding, root is not `<svg>`) | Medium |
| PDF | `pdf.javascript`, `pdf.launch` | High |
| | `pdf.postscript` (PostScript XObject, form XObject with `/Subtype2 /PS` or a `/PS` stream, `PS` operator in page content) | High |
| | `pdf.open_action`, `pdf.additional_action` | Medium; High when it leads to JS/Launch; not reported for a plain page jump |
| | `pdf.embedded_file` (embedded files are also scanned recursively), `pdf.rich_media`, `pdf.xfa` | Medium |
| | `pdf.submit_form`, `pdf.remote_goto`, `pdf.uri` | Low (`uri` is Info) |
| | `pdf.obfuscated_name` (`#xx` in a sensitive key name) | High |
| | `pdf.encrypted` | Medium; Info when the empty password opens it and the content was inspected |
| | `pdf.malformed`, `pdf.incremental_update` | Medium / Info |
| | `pdf.trailing_data` (bytes after the last `%%EOF`), `pdf.polyglot` (those bytes are a recognizable file, or a ZIP record ends the file) | Low / High |
| PostScript | `ps.file_access` (`file` other than `%stdin`/`%stdout`, `run`, `deletefile`, `renamefile`, `status` on a file name, `/OutputFile` however the key is spelled) | High |
| | `ps.device_access` (`putdeviceprops`, `selectdevice`, `finddevice`, `setdevice`, the `/OutputDevice` and `/Driver` keys) | High |
| | `ps.pipe` (`%pipe%` anywhere, including written with escapes or hex) | Critical |
| | `ps.ghostscript_internal` (every operator starting with a dot except a harmless set; `superexec`, `getenv`...; the `/PermitFile*`, `/LockFilePermissions` and `/LIBPATH` keys) | High |
| | `ps.unusual_filter` (`BCPEncode`, `TBCPEncode` and their decoders) | Medium |
| | `ps.exec_dynamic` (`cvx exec` on code decoded at run time) | Medium |
| | `ps.malformed` (missing `%!`, bad binary EPS header) | Medium |
| | `ps.wmf_preview` (EPS with a WMF preview, which is not analyzed) | Info |
| YARA | `yara.match`; `yara.error` when the rules did not finish running | Critical; Medium |

## Milestones

A milestone is done when `cargo test` is green, `cargo clippy -- -D warnings` is clean, and its own criterion is met.

### M0 — Project skeleton
- `git init`, a workspace with `malmal` and `malmal-cli` (the FFI/daemon crates come in M6), `rustup target add x86_64-unknown-linux-musl`.
- `report.rs`, `limits.rs`, `policy.rs` with unit tests.
- **Done when:** `cargo build --release --target x86_64-unknown-linux-musl` produces a binary and `ldd` reports "not a dynamic executable".

### M1 — Core
- `detect.rs`: magic bytes for JPEG, PNG, GIF, WebP, BMP, TIFF, SVG, PDF, PS/EPS, ZIP, PE, ELF, Mach-O, HTML, shebang.
  Look for `%PDF-` in the first 1024 bytes (the way Acrobat reads it), not only at offset 0.
- Compare against the extension and `Content-Type` -> `type.mismatch`.
- `Budget`: every parse loop and every decompression draws from the budget.
- `payload.rs`: scan for `<?php`, `<?=`, `<script`, `<%`, `eval(`, executable headers.
- `hashlist.rs`: load a text file with one SHA-256 per line.
- Minimal CLI: `malmal scan <file>... [--json] [--policy strict|default]`; exit code 0 clean, 1 suspicious, 2 malicious, 3 error.
- **Done when:** EICAR is blocked through the hash list; a `.jpg` containing an ELF yields `type.mismatch` + `type.executable`.

### M2 — Raster images

> **Status: done** (M0 and M1 are done too). Differs from the description below: there is no
> `meta.rs`. Uncompressed metadata (EXIF, XMP, ICC, comments) and trailing data are covered by
> one payload scan over the whole image file, reported through the `payload.*` codes; only
> compressed PNG chunks need their own decompression. The pixel bomb check looks only at the
> total pixel count; there is no pixel-to-byte ratio.
> Outstanding: a real-image corpus for TIFF, WebP, BMP and phone photos (M7).
- One module per format walks the structure to its exact logical end:
  JPEG (markers to EOI), PNG (chunks + CRC to IEND), GIF (blocks to the `0x3B` trailer),
  WebP (RIFF), BMP (size in the header), TIFF (IFD chain, with offset-loop detection).
- Anything after the end -> `image.trailing_data`, then run `payload.rs` and `detect.rs` on the excess.
- `meta.rs`: extract EXIF, XMP, ICC, JPEG comments, PNG `tEXt`/`zTXt`/`iTXt` (decompression under budget), scan for payloads.
- Pixel bomb: `width * height` over a threshold, or an abnormal pixel-to-byte ratio.
- **Done when:** all the hand-made samples are detected: webshell in EXIF, JPEG+ZIP, GIF+JS (GIFAR), PNG with PHP in `tEXt`; every image in `corpus/clean` comes out `Clean`.

### M3 — SVG

> **Status: done.** Differs from the description below: a DOCTYPE is not reported outright.
> Simple string entities (the kind Illustrator uses to declare namespaces) are kept and
> expanded where used, charged to the budget; only external entities, parameter entities,
> entities containing markup or references, and `ATTLIST` are reported. SVG embedded through
> `data:image/svg+xml` is scanned recursively. An `<a href="https://...">` link is not treated
> as an external reference because it only fires when the user clicks it.
> Outstanding: raster images embedded through `data:` are not passed to the image analyzers;
> data after the gzip stream of an SVGZ is not checked.
- `quick-xml` with entity expansion off; report as soon as a DOCTYPE/ENTITY is seen.
- Compare element and attribute names case-insensitively, without the namespace prefix.
- Check `<script>`, `on*` attributes, `href`/`xlink:href` with `javascript:` and `data:` (decode entities, strip whitespace and control characters before comparing), `<foreignObject>`, `<use>`/`<image>` pointing outside, `<style>` with `@import`/external `url()`.
- SVGZ: decompress under budget, then scan.
- **Done when:** the standard set of SVG XSS payloads is caught (including obfuscated variants such as `jav&#x09;ascript:`).

### M4 — PDF

> **Status: done.** Differs from the description below: there is no `xref.rs`. The xref table
> is ignored entirely; every `N G obj` in the file is parsed in place (even inside stream
> data), together with decompressed object streams. An object that does not parse still has
> its tokens scanned for names. A broken or truncated Flate stream still contributes whatever
> decompressed, as PDF readers do.
> Outstanding: a PDF encrypted with an empty password (readers open it without asking) only
> yields `pdf.encrypted` and is not decrypted; XFA content is not analyzed; data after the last
> `%%EOF` is not checked; the TIFF predictor and image filters on an object stream are
> reported as `pdf.malformed`.
- `lexer.rs`: PDF tokens, name normalization (`#xx`), literal and hex strings, error-tolerant.
- `xref.rs`: read xref tables and xref streams; **always** scan the whole file linearly for `N G obj` as well and merge the two results (malicious files often have a wrong xref or hidden objects).
- `filters.rs`: Flate, ASCIIHex, ASCII85, LZW, RunLength, chained filters, the PNG predictor; all under budget.
- Open object streams (`/ObjStm`) and analyze the objects inside.
- `analyze.rs`: produce findings per the table; follow references from `/OpenAction` and `/AA` to raise the severity when they reach JS/Launch.
- Embedded files (`/EmbeddedFile`): decode, then **scan recursively** with the scanner itself (subject to `limit.depth`).
- `/Encrypt` -> `pdf.encrypted`; no attempt to decrypt.
- **Done when:** Didier Stevens' samples are caught (JS in ObjStm, obfuscated names, Launch); clean PDFs in the corpus get no `High` finding.

### M5 — PostScript / EPS / AI

> **Status: done.** A single `ps.rs` replaces the `ps/` directory. Besides the tokenizer there
> is a raw byte pass for `%pipe%` and the known internal operators, so that whatever the
> tokenizer misreads cannot hide them. Strings passed to `cvx`/`cvn` are decoded and analyzed
> as code; `eexec` sections are decrypted and scanned; `%%BeginData` sections are read both as
> data and as code. A file declared as PostScript but missing `%!` is still analyzed.
> Outstanding: AI private data in PDF-based `.ai` files is not analyzed; operator names
> assembled at run time cannot be seen by static analysis; the public PoCs for the Ghostscript
> vulnerabilities have not been run.
- Routing: an `.ai` with `%PDF-` -> the PDF pipeline (plus a scan of the AI private data); `%!PS` -> the PS pipeline.
  Binary EPS (header `C5 D0 D3 C6`): split the PS part from the TIFF/WMF preview and scan each.
- `lexer.rs`: PostScript tokens (names, nested `()` strings, hex `<>`, ASCII85 `<~ ~>`, `{}` procedures, DSC comments).
- `analyze.rs`: compare operator names against a dangerous list; decode hex/ASCII85 strings and rescan (payloads often hide behind `cvx exec`); detect `%pipe%` in every string.
- **Done when:** the public PoCs for the Ghostscript vulnerabilities are caught (`%pipe%`, `.libfile`, `.forceput`); `.ai`/`.eps` files exported from Illustrator in the clean corpus get no `High` finding.

### M6 — YARA and packaging

> **Status: done, except YARA on musl.** The stated risk came true: `yara-x` does not build
> for musl (the `wasmtime` build script fails), so the YARA build exists only dynamically
> linked against glibc; the `pe`/`elf` modules also had to be disabled because they failed to
> compile. Differs from the description below: `malmal.h` is hand-written instead of generated
> by `cbindgen`; the daemon lives in the `malmal-cli` crate (the `malmald` binary) instead of
> its own crate; seccomp is a denylist, not an allowlist; the memory limit is a 4 GB
> `RLIMIT_AS`, and there is no `RLIMIT_CPU`.
> Verified on a bare Debian 13: the CLI, the daemon and the C example all run with
> `--require-sandbox`.
- `yara.rs` behind the `yara` feature: load a rule directory, each match becomes `yara.match`. Check early that `yara-x` builds with musl — this is the project's largest technical risk; if it does not, the YARA build will be a partly static glibc build.
- `malmal-ffi`: `malmal_scanner_new`, `malmal_scan_bytes`, `malmal_report_json`, `malmal_free`; generate `malmal.h` with `cbindgen`; wrap in `catch_unwind`.
- `malmald`: Unix socket, a simple protocol (length + data in, JSON out), a worker pool, a timeout per request.
- Sandbox in the CLI and daemon: Landlock (read-only on the input files), seccomp (no `execve`, no network), `RLIMIT_AS`/`RLIMIT_CPU`; degrade gracefully when the kernel lacks support.
- **Done when:** the musl binary runs in a bare `debian:stable-slim` container; the example calling the FFI from C works.

### M7 — Testing and hardening (runs alongside from M1)

> **Status: done as far as this machine allows.** Ten fuzz targets in `fuzz/`; fuzzing found a
> panic in the PostScript analyzer (`<~>`), now fixed with a regression test. The corpus in
> `tests/corpus` is scanned by `cargo test`. The CI in `.github/workflows/ci.yml` has never
> run.
> Outstanding: no separate property tests (the "no panic" tests that walk every prefix and
> every corrupted byte stand in for them); no clean corpus from phones, Word or LaTeX and no
> third-party malicious corpus (Mitra, Didier Stevens); fuzzing has run only a few minutes per
> target.
- A fuzz target per parser: `detect`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `tiff`, `svg`, `pdf`, `ps`. Invariants: no panic, no budget overrun, no hang.
- Property test: appending random bytes to a clean image always yields `image.trailing_data`.
- A clean corpus from real sources (camera/phone photos, PDFs from Word/LaTeX/Chrome, AI/EPS from Illustrator) to measure the false-positive rate; the goal is zero `High` findings on the clean corpus.
- A malicious corpus: hand-made samples for each finding code + Ange Albertini's polyglots (Mitra) + Didier Stevens' PDF samples.
- Benchmark: the goal is over 100 MB/s for images and a 10 MB PDF in under 200 ms.
- CI: tests, clippy, `cargo deny`, musl build, a short 60-second fuzz run per target.

### M8 — Fixes from a real submission set

> **Status: done.** A scan of 3,045 real submissions (PSD, JPEG, PDF, PNG, EPS) found no
> malicious file and these scanner faults, all fixed: `<?=` matched by chance in pixel data;
> Illustrator's standard procsets reported for `superexec`, `file` and `cvx exec`; inline
> ASCII85 image data tokenized as code; PSD not supported; phone camera trailers reported as
> unexplained trailing data. See the known limits in the README for the exemptions this added.
>
> A second fixture set showed PDFs carrying PostScript passing as clean. `pdf.postscript` now
> covers PostScript XObjects and the `PS` content operator, the XObject's program goes through
> the PostScript analyzer, and `--types` lets the CLI and daemon refuse PostScript files
> outright.
>
> Trigger-only fixtures built from the operators, devices and parameters that public
> Ghostscript advisories name showed 13 of 30 passing as clean. Added: device selection and
> reconfiguration, permission keys, file probing with `status`, keys spelled through `cvn`,
> strings read with `token`, and protocol filters. Changes to `errordict` and `systemdict` are
> still not reported, because Adobe's own prologs make them.

### M9 — Known limits, daemon protocols, API (0.2.0)

Done after the first release, from the list of known limits and what a deployment needs.

- [x] PDF: bytes after the last `%%EOF` (`pdf.trailing_data`, `pdf.polyglot`).
- [x] PDF: the standard security handler with the empty user password, revisions 2 to 6
      (RC4, AES-128, AES-256), checked against files written by qpdf. `md-5` and `aes` join
      the dependencies; RC4 and CBC are a few lines each on top of them.
- [x] PDF: XFA packets are searched for scripts; attachments go through the YARA rules.
- [x] BigTIFF; PSD layer records, including the layer list of 16- and 32-bit documents.
- [x] HEIC and AVIF (boxes, `ispe` sizes, `iloc` bounds), JPEG XL (size header, container
      boxes), ICO (directory, PNG and bitmap images). Accepted by default.
- [x] `malmald`: HTTP endpoint, Prometheus metrics, the ClamAV `INSTREAM` protocol,
      `--max-size` and `--scan-timeout`. Listeners are opened before the sandbox is entered.
- [x] `tests/corpus/expected.tsv` records every sample's findings; the `survey` example
      measures a directory of real files; a nightly workflow fuzzes each target for longer.
- [x] `docs/findings.md` (checked against the sources by a test), `docs/integration.md`.
- [x] API: `FileType`, `Report` and `Finding` are `#[non_exhaustive]`; `payload`, `Budget`
      and `LimitExceeded` are no longer public; every public item is documented.

- [x] PDF passwords supplied by the caller, tried as user and as owner password, checked
      against files written by qpdf for every revision.
- [x] Brotli metadata in JPEG XL is decompressed and searched (`brotli-decompressor`).
- [x] `malmald --icap`: `OPTIONS`, `REQMOD`, `RESPMOD`, previews, multipart forms. Not yet
      run against Squid or c-icap.

### M10 — Distribution

- [x] `.github/workflows/release.yml`: a `v<version>` tag builds static binaries for x86-64
      and ARM64, attaches them to a GitHub release, pushes a multi-arch image to GHCR and
      publishes the crates when `CARGO_REGISTRY_TOKEN` is set.
- [x] `Dockerfile` for building the same image from a checkout; `cargo binstall` metadata.
- [x] `bindings/python`: a `ctypes` wrapper over the C library, tested in CI.
- [x] Wheels that carry the library, for x86-64 and ARM64 Linux (`build_wheel.sh`, linked
      against glibc 2.17 with cargo-zigbuild). The release workflow builds them, attaches
      them to the release and uploads them to PyPI when `PYPI_PUBLISH` is set. No wheels
      for macOS or Windows; there the package works from a checkout.

### M11 — Rebuilding images (CDR)

- [x] `malmal::cdr` behind the `cdr` feature, on the `image` crate: JPEG, PNG, GIF with its
      frames, WebP, and BMP/TIFF/ICO to PNG. Limits apply before and during decoding; a
      panic in a codec is an error, not a crash.
- [x] `Scanner::sanitize` (scan, then rebuild), `malmal sanitize`, `POST /sanitize`.
- [x] Every sample that can be rebuilt is checked to come out clean; a fuzz target does the
      same with arbitrary input.

- [x] Animated PNG (written with the `png` crate) and animated WebP (the container is
      assembled around lossless frames, the encoder having no animation support), with
      delays and loop count. Checked against ffmpeg in both directions.
- [x] RGB colour profiles are applied with `moxcms`, converting the pixels to sRGB; a
      profile that is sRGB already leaves them untouched.
- [x] `malmal_sanitize` in the C interface, `Scanner.sanitize` in Python.
- [x] `malmal sanitize` writes through a second, sandboxed process and renames the result
      into place, so the output is whole or untouched.

Not done: HEIC/AVIF/JPEG XL (no pure-Rust decoder to depend on), animated PNG at 16 bits,
CMYK and grey colour profiles.

### M12 — A time limit that holds

- [x] `--hard-timeout` and a watchdog thread in both commands: a scan or rebuild still
      running after it ends the process with status 3. The library's limit stays a
      cooperative one; `cdr::rebuild` now checks it between frames (`Error::TimedOut`).

## Order and dependencies

```
M0 -> M1 -> M2 -> M3
              \-> M4 -> M5 -> M6
M7 runs alongside from M1
```

M3 and M4 are independent. M5 needs M4 because modern AI files are PDFs. M6 needs every analyzer finished so the API can be fixed.

## Machine setup

- `rustup target add x86_64-unknown-linux-musl`
- `cargo install cargo-fuzz cargo-deny cbindgen` (fuzzing also needs the nightly toolchain)
- Docker or Podman to test on a bare Debian (M6)

## Out of scope (recorded for later)

- Office (DOCX/XLSX macros), archives (recursive ZIP/RAR), video.
- Rebuilding PDF and SVG (CDR for documents): a different problem from pixels.
- Bindings beyond C and Python; wheels for macOS and Windows.
