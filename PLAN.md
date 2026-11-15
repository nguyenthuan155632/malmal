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
│   │       ├── pdf/           # parser.rs filters.rs crypt.rs content.rs deep.rs mod.rs
│   │       ├── ps.rs          # PostScript, EPS, legacy AI
│   │       ├── cdr.rs         # rebuilding files (CDR), behind the "cdr" features
│   │       ├── within.rs      # Scanner::scan_within, a time limit the caller can count on
│   │       ├── hashlist.rs    # SHA-256 blocklist
│   │       └── yara.rs        # behind the "yara" feature
│   ├── malmal-cli/            # the `malmal` and `malmald` binaries (HTTP, Unix socket, clamd, ICAP)
│   └── malmal-ffi/            # cdylib + staticlib, malmal.h header
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

> **Status: done.** YARA builds for musl into a static binary: the `wasmtime` build script
> that failed did so for want of a musl C compiler, not because of musl; with `musl-tools`
> and `CC_x86_64_unknown_linux_musl=musl-gcc`, CI builds it and runs a rule on a bare
> `debian:stable-slim`. The `pe`/`elf` modules failed to compile because `yara-x` 1.23 uses
> `rsa::Pkcs1v15Sign`, which `rsa` 0.10.0 puts behind its `pkcs1v15` feature; `malmal`
> turns that feature on, and both modules are on. Differs from the description below: `malmal.h` is hand-written instead of generated
> by `cbindgen`; the daemon lives in the `malmal-cli` crate (the `malmald` binary) instead of
> its own crate; seccomp is a denylist, not an allowlist (an allowlist breaks with each libc
> and allocator that adds a call); the memory limit is a 4 GB `RLIMIT_AS`, and there is no
> `RLIMIT_CPU`, which counts a daemon's whole life and would end it after enough scans: time
> is bounded per scan by `--hard-timeout` instead.
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
- [x] `malmald --icap`: `OPTIONS`, `REQMOD`, `RESPMOD`, previews, multipart forms. Run
      behind Squid 6, which is what showed the three things below.
- [x] A body called a URL-encoded form passes unscanned only if it is one.
- [x] An oversized body is read to its end before it is refused, so the proxy gets the
      reply rather than a closed connection.
- [x] A thread per connection, with `--workers` bounding the requests in work and
      `--connections` the connections: a proxy's idle connections used to hold every
      worker until they timed out.

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

- [x] Grey profiles on grey images, and CMYK profiles on CMYK JPEGs in both forms the inks
      are stored in (`zune-jpeg` for the inks as stored, `moxcms` for the conversion).
      Checked against ImageMagick with real profiles.
- [x] Animated PNG at 16 bits a channel: the frames are read with the `png` crate and laid
      over one another here, since the `image` crate's decoder refuses them. Checked
      against Pillow.

- [x] JPEG XL through `jxl-oxide`, written as PNG.
- [x] SVG (`cdr-svg`) through Cloudflare's `svg-hush`, an allowlist filter. Embedded raster
      images are rebuilt. The corpus showed the filter keeping an `<animate to="javascript:">`
      whose target it had removed: inert, but the analyzer objects, so the result is run
      through the analyzer and refused when it does. 300 SVG files from a desktop system
      pass, and 60 of them render pixel for pixel as before.
- [x] PDF (`cdr-pdf`), the Dangerzone way: `hayro` draws each page and a small writer here
      puts the drawings in a new PDF. Text is no longer text (until M13).
- [x] `Options::types`: the types to rebuild, so that unused decoders are never run.
- [x] `cdr-pdf` is opt-in for the commands and the C library: it turns a document into
      pictures, doubles the binaries, and rests on a renderer that calls itself
      experimental. Pages can be kept as JPEG where that is smaller (it is for scans, not
      for text), and the passwords given for scanning open a PDF for rebuilding.
- [x] Fuzzing the new decoders turned up three panics in `jxl-oxide`, all caught and
      answered as errors. One is reported upstream with a fix
      (tirr-c/jxl-oxide#514); see `tests/corpus/clean/decoder-panic.jxl`.

Not done:

- AVIF, until `filmcraft-av1` (MIT or Apache-2.0, safe Rust, written from the
  specification): `zenavif` and `rav1d-safe` are AGPL-3.0, which this project cannot
  link, and `avif-decode` builds `rav1d` with its assembly. Done since; see below.
- HEIC: no HEVC decoder in Rust.
- A rebuilt PDF that keeps its links and forms. Its text it keeps, since M13, and draws
  from the outlines of its glyphs where the page shows it plainly; text over a picture,
  in a pattern or behind a transparency stays in the drawing of the page, and so do
  lines and boxes.

### M12 — A time limit that holds

- [x] `--hard-timeout` and a watchdog thread in both commands: a scan or rebuild still
      running after it ends the process with status 3. The library's limit stays a
      cooperative one; `cdr::rebuild` now checks it between frames (`Error::TimedOut`).

### M13 — Large files, deeper PDF checks, measurement

Taken from a comparison with quelda (github.com/tranhuucanh/quelda), a PDF scanner.

- [x] The commands map the file; the hash runs beside the analysis; parsed PDF values
      take about half the memory. 1 GB in 4.4 s, 0.42 s with `--no-hash`, in a 96 MB
      container.
- [x] PDF checks that read strings, numbers and positions: `pdf/deep.rs`.
- [x] `examples/evaluate.rs`, for sets of files with known labels.
- [x] Measured on CIC-Evasive-PDFMal2022: 9,107 clean and 21,899 malicious files.
      Before: 98.20 % of the malicious refused, 82.62 % of the clean accepted. After:
      98.19 % and 87.32 % (the same under the strict policy, which only turns
      suspicious into malicious). The 428 clean files gained were refused for rule
      errors: `/EF` as the array of a signature's rights (365), empty name trees of
      scripts and attachments (60), links to local files left by a conversion (3). XFA
      packets were also reported as attachments, which changed no verdict. Two
      malicious files lost with them had an empty script tree and nothing else but a
      link. Of the new codes, `pdf.conflicting_objects` (89 malicious, 0 clean),
      `pdf.polyglot` (86, 0) and `pdf.external_ref` (120, 2) earn their severity;
      `pdf.dangerous_uri` did not for local files and was narrowed.
      The 1,155 clean files still refused, each counted once: scripts (660), XFA
      forms without a script (260), attachments (207, mostly the Word source of the
      document or the job options of the program that made it), launch actions (12),
      3D and media (9), data after `%%EOF` (4), a password that is not known (1),
      OPI (1), a page of 44 million points (1). The 396 malicious files accepted: 379
      are a picture and a link to a web page, which no structure tells from an
      invoice, and 17 have no active content at all.
- [x] The daemon's memory no longer grows with the file: `--spool-dir`, unnamed files
      opened before the sandbox closes.
- [x] Objects are parsed on demand and not kept as a tree; content streams are read in
      blocks through the whole filter chain.
- [x] What a request can cost in memory, measured with hostile files, and the options
      that bound it (`--max-decompressed`, `--max-pixels`).
- [x] Every loop in the scan whose length the file decides, listed with what bounds it;
      the ones measured to grow with the square of the file, or to run past the time
      limit, bounded: PDF trailers, unparsable objects, object streams, form calls,
      `/Encrypt` sources; SVG references and CSS addresses; PostScript strings and
      resources; icon images; tails of payload tags. Decode output of failed PDF filters
      and of PostScript ASCII85 strings counted against `--max-decompressed`.
- [x] The daemon's workers held only by scans; `--file-budget` for the files held at
      once, `--min-rate` for clients that send or read slowly; multipart boundaries found
      in linear time; spool writes buffered. Soaked over the four endpoints.
- [x] `--max-memory` and `ScannerBuilder::memory_limit`: what one scan's thread holds,
      counted by the tools' allocator and checked per decoded PDF block and between
      steps. 200 MiB bombs 205 MiB → 55 MiB at 64 MiB; eight at once on four workers,
      807 MiB → 201 MiB. No file of CIC, the corpus or PDF Insecurity reaches 16 MiB.
- [x] Measured on the PDF Insecurity samples (pdf-insecurity.org, RUB-NDS/PDF101), 335
      distinct files: 57 malicious, 155 suspicious, 123 clean before; 57, 163, 115 after
      `pdf.reference_loop`, content that is not a stream and the calculator stack. Still
      clean: signature and content-masking attacks and hidden metadata, which carry no
      active content; documents whose only action is a link; the unmodified originals.
- [x] C2PA manifests (`pdf.c2pa_manifest`) and OPPO camera trailers told apart from
      attachments and trailing data, checked to the last box; no verdict changed on CIC.
- [x] `pdf.link_lure`: a web link over a fifth of the page. CIC: 98.19 % → 98.65 % of the
      malicious refused, the clean unchanged at 87.32 %. At a tenth, 15 clean files
      (logos) were marked.
- [x] The memory limit in C (`malmal_scanner_set_max_memory`, the library counting with
      the allocator the CLI uses) and Python (`Scanner(max_memory=…)`), and inside the
      steps that are not PDF streams: PNG chunks, SVGZ, JPEG XL boxes inflate in blocks
      against it; a PostScript ASCII85 string is held to what is left of it.
- [x] Tests of the loops that used to grow with the square of the file count the bytes
      read and the steps taken (`work.rs`, in test builds only) and compare them with
      the file, instead of timing it: payload tails, PostScript resources and strings,
      SVG references and CSS addresses, PDF trailers, objects, object streams, forms
      and `/Encrypt`. Put back, each fix's absence counts 10³ to 10⁴ times the file.
      The daemon's two timed tests wait on what the client sees, not on a clock.
- [x] Signatures (`pdf.signature_invalid`, `pdf.unsigned_content`): ranges checked
      against the file and against the signature's own value; copies outside what is
      signed; usage rights left alone. Calculator functions run on the corners of their
      domain. Content masking (`pdf.ambiguous_structure`): page content whose length,
      keywords or line ends readers take differently; deciding keys given twice;
      cross-reference entries that point elsewhere, at a comment, or are neither kind;
      objects defined again after the last `startxref`. Unknown filters are malformed.
      Each rule was kept only if it marked no clean file of CIC; three that did (free
      entries that point at their object, `%` anywhere earlier on the line, any object
      after the last `startxref`) were narrowed or dropped. PDF Insecurity: 110 clean →
      50; CIC: `pdf.ambiguous_structure` on 1,558 malicious files and no clean one.
- [x] `pdf.disguised_link`: shorteners, numeric hosts, punycode, made-up syllable names.
      CIC: 98.67 % → 99.07 % of the malicious refused, the clean unchanged at 87.32 %.
- [x] A rebuilt PDF keeps its text (`Options::pdf_text`, `--pdf-no-text` to leave it
      out): hayro reports each glyph it draws with its Unicode text and position, and
      the writer puts the characters under the picture in Type 3 fonts whose glyphs
      draw nothing, with a `ToUnicode` map. On 80 clean CIC files, pdftotext finds
      97.9 % of the words of the first three pages in the rebuilt copy (median 99.3 %).
- [x] Text drawn as shapes in a rebuilt PDF (`Options::pdf_vector_text`,
      `--pdf-raster-text` to keep it in the picture). The renderer cannot be told to leave
      text out, so the glyphs are drawn again on their own, as the renderer draws them
      (hinted, uncached), and each one whose pixels are its colour laid over a plain
      background as much as its outline covers them is taken out of the picture and
      written as a Type 3 glyph of its outline. A glyph that fails, and one that shares a
      pixel with it, stays in the picture. On 78 clean CIC files, the 47 with text come out
      a fifth of the size (median), with 2.5 % of the dark pixels left in the picture
      (median); none drawn by poppler further from the original than the picture alone.
- [ ] Not done: reading object streams, attachments, XFA and metadata in blocks;
      recursion through patterns, soft masks and glyphs; embedded fonts and colour
      profiles; locked rules; the content masking that no structure shows
      (unknown operators, inner and outer documents, page trees with too few leaves);
      checking links against a list of known bad sites.

### M14 — Review follow-ups

- [x] Features that did nothing (`zenavif`, `avif-decode`) or only pulled in a dependency
      (`svg-hush`, `hayro`) removed from `malmal`.
- [x] GitHub Actions pinned to commits; `rust-version = "1.95"` (what `yara-x` needs),
      built in CI.
- [x] `Policy::documents()` / `--policy documents`: forms and attachments allowed, what
      they hold still counted. CIC: 92.38 % of the clean accepted, 99.06 % of the
      malicious refused.
- [x] `malmald --token-file`: a bearer token on HTTP (all but `/healthz`), `401` before
      the body is read; a warning at start-up for each endpoint off loopback that anyone
      can use. ClamAV and ICAP have no place for a token.
- [x] `Scanner::scan_within`: the scan on a thread of its own, `limit.time` when it is
      late, at most `MAX_OVERDUE` scans left running, then every file refused at once.
- [x] The token on ICAP too: `REQMOD` and `RESPMOD` carry `Authorization: Bearer`
      (Squid: `adaptation_meta`), `401` before the body is read; `OPTIONS` needs none.
      The ClamAV protocol has no place for one; it is authenticated by client
      certificates (`--clamd-tls` with `--tls-client-ca`) or a Unix socket.
- [x] `scan_within` in the C and Python interfaces: the `wait` option of
      `malmal_scanner_new_json` and `Scanner(wait=)` (M15, step 1).
- [x] TLS: `--https`, `--icaps`, `--clamd-tls` with `--tls-cert`/`--tls-key`, and
      `--tls-client-ca` for client certificates; `rustls` on `ring`, the `tls` feature,
      on by default. The handshake is bounded by `--timeout`; the certificates are read
      before the sandbox, so a renewed one needs a restart.

### M15 — Ruby gem and Rails integration

Two gems from `bindings/ruby/`, released together with the crates:

- **`malmal`**: the scanner for any Ruby program, on the `ffi` gem over
  `libmalmal_ffi`, as the Python package is on `ctypes`. The library ships inside
  per-platform gems; no Rust is needed to install it.
- **`malmal-rails`**: Rails integration (Railtie, Active Storage validator, a scan of
  stored blobs, sanitizing helper). Pure Ruby, depends on `malmal` and `activestorage >= 7.1`.

Why the C ABI and not `magnus`/`rb-sys`: one ABI to keep for every language, already
tested and fuzzed through Python; `ffi` releases the GVL with `blocking: true`; a native
extension would have to be rebuilt for each Ruby minor version, a shared library is not.

**Step 1: a C ABI that carries every option (in `malmal-ffi`, used by Python too).**

- [x] `malmal_scanner_new_json(const char *options, char **error)`: one JSON object with
      `policy` (`default`, `strict`, `documents`), `allow`, `types`, `hashlist`,
      `pdf_passwords`, `limits` (`max_size`, `max_decompressed`, `max_pixels`,
      `scan_timeout`), `max_memory`, `without_hash`, and `wait` (seconds; when set,
      `malmal_scan` goes through `Scanner::scan_within`). Unknown keys are an error, so
      that a misspelling is not a silent default. The older constructors stay.
- [x] `malmal_scanner_overdue(const malmal_scanner *)`, and `malmal_version()`, which the
      gems compare with their own version at load time.
- [x] `malmal_sanitize_json(scanner, data, len, filename, content_type, options_json, ...)`:
      the `cdr::Options` beyond `jpeg_quality` (PDF dpi, text, JPEG pages).
- [x] The Python package moves to the new constructor (`policy=`, `types=`, `limits=`,
      `wait=`), keeping its current arguments.

**Step 2: the `malmal` gem.**

- [x] `Malmal::Scanner.new(policy: :default, allow: [], types: nil, hashlist: nil,
      pdf_passwords: [], max_size: nil, max_memory: nil, wait: nil, ...)`, freed by a
      finalizer and by `#close`. Thread-safe: one scanner shared by every Puma thread.
- [x] `#scan(data_or_io, filename:, content_type:)` returns `Malmal::Report` (`verdict`,
      `clean?`, `findings` as `Malmal::Finding` with `code`, `severity`, `message`,
      `offset`, `sha256`, `detected_type`, `declared_types`, `to_h`). An `IO` is read up to
      `max_size` + 1 bytes, as `Scanner::scan_reader` does. `MALMAL_ERROR` raises
      `Malmal::ScanError`, never returns a report.
- [x] `#sanitize(data, ...)` returns `Malmal::Sanitized` (`data`, `file_type`,
      `content_type`, `report`) or raises `Malmal::Rejected` (with the report),
      `Malmal::NotRebuilt`, `Malmal::SanitizeError`.
- [x] `Malmal::Client.new(url, token:)`: the same `#scan` and `#sanitize` over HTTP against
      `malmald`, with `Net::HTTP` only. For deployments that want `--hard-timeout` and the
      sandbox, or one scanner process for many Ruby processes.
- [x] The library is found at `MALMAL_LIBRARY`, else in the gem
      (`lib/malmal/libmalmal_ffi.so` or `.dylib`), else on the system's library path; a missing or mismatched library raises `Malmal::LoadError` with
      what to do.
- [x] Platform gems: `x86_64-linux-gnu`, `aarch64-linux-gnu` (glibc 2.17 through cargo-zigbuild, as
      the wheels), `x86_64-linux-musl`, `aarch64-linux-musl` (Alpine images, a `cdylib`
      built with `-C target-feature=-crt-static`), `arm64-darwin`, `x86_64-darwin`
      (Rails developers' machines; the library needs no sandbox). A `ruby` platform gem
      without a library, for `MALMAL_LIBRARY`.
- [x] Ruby 3.2 to 4.0 in CI; `rbs` signatures in `sig/`.

**Step 3: the `malmal-rails` gem.**

- [x] Railtie: `config.malmal` (`policy`, `allow`, `types`, limits, `wait`, or
      `client_url` + `client_token` to use the daemon), one scanner built at boot and
      kept in `Malmal::Rails.scanner`. `bin/rails generate malmal:install` writes
      `config/initializers/malmal.rb`.
- [x] Validator: `validates :avatar, malmal: true` (or `malmal: { policy: :strict, types:
      %i[jpeg png] }`), for `has_one_attached` and `has_many_attached`. It scans what is
      being attached before it is uploaded (`attachment_changes`: an
      `ActionDispatch::Http::UploadedFile`, an `IO` hash, a `Rack::Test::UploadedFile`),
      with the file name and the `Content-Type` the client gave. Errors are
      `:malmal_suspicious`, `:malmal_malicious`, `:malmal_error` with I18n messages
      (English; applications add their own translations); the codes are in `record.errors.details`. A blob already
      stored (direct upload, signed id) is downloaded up to `max_size` and scanned.
- [x] Direct uploads skip validations until the record is saved; for them, every blob is
      scanned when Active Storage analyzes it (`ActiveStorage::Blob#analyze`, in the
      analyze job, whatever analyzer the blob gets), the verdict and the finding codes
      written to `blob.metadata["malmal"]`, and a blob that is not clean is purged in the
      same job when `config.malmal.purge_unclean` is on. No separate analyzer or purge
      job: an analyzer runs only for the first that accepts the blob, which would leave
      images and PDFs unscanned.
- [x] `sanitizes_attachment :avatar`: before validation, the attachment is replaced with
      the rebuilt file (same name, the new type and extension); a file that cannot be
      rebuilt is rejected or kept, per `on_not_rebuilt: :reject | :keep`.
- [x] Instrumentation: `ActiveSupport::Notifications` events `scan.malmal` and
      `sanitize.malmal` (verdict, codes, size, duration), and a log line per scan that is
      not clean, without the file name unless `config.malmal.log_filenames`.
- [x] Rails 7.1, 7.2, 8.0, 8.1 in CI (`gemfiles/`), each with a dummy app defined
      in `test/test_helper.rb` using the Disk service.

**Step 4: trying it out.**

- [x] `examples/rails/`: a small Rails 8 app (upload form, `has_one_attached :document`,
      the validator with `policy: :documents`, a sanitized avatar, direct uploads with the
      analyzer), and a `docker compose` file that runs it beside `malmald` for the client
      mode. The README of the example walks through uploading a clean file and one from
      `tests/corpus/malicious`.
- [x] The gems are released as 0.4.0 with the crates, no pre-release: pushed to RubyGems
      from the release workflow with trusted publishing (no API key stored), behind a
      `RUBYGEMS_PUBLISH` switch like PyPI. The workflow installs each built gem and runs
      the tests against it on x86-64 Linux, Alpine and ARM64 macOS, with no Rust on the
      path. `examples/rails/bin/try` uploads corpus files through the example's forms,
      in the process and against `malmald`.
- [x] Measured: scans per second from Ruby against the same files from Rust, to show what
      the copy over FFI and the JSON report cost. `bindings/ruby/malmal/bench/throughput.rb` against
      `examples/throughput.rs`, same machine: a call from Ruby costs 10 to 16 µs more
      (12 µs against 1 µs for a 70-byte PNG, 41 against 25 for a 5 KB ICO); from 22 KB up
      the two are within 5% (3.56 against 3.51 ms for a 511 KB PNG, 11.2 against 10.7 ms
      for a 440 KB PDF).

Not planned: Shrine and CarrierWave plugins (the `malmal` gem is enough for them; added if
asked), a Rack middleware that scans every multipart upload, Windows.

### M16 — Rebuilt as close to the original as can be

- [x] JPEG: the quantised coefficients kept, Exif rotations done on them; CMYK and YCCK
      with an Adobe transform kept as inks on request.
- [x] GIF: palettes and indices kept frame by frame; APNG: frames as laid out, 16 bits.
- [x] Lossy WebP: every VP8 symbol coded again at the same probabilities (`cdr/vp8.rs`),
      alpha coded again without loss, animations frame by frame; kept only if every pixel
      decodes as the original's.
- [x] TIFF: several pages to TIFF; CCITT fax, LZMA (with the delta filter), Zstandard and
      WebP; depths 1 to 64 bits, integer and floating point.
- [x] PSD: ZIP composites, with prediction; multichannel documents in their inks.
- [x] JPEG XL animations as animated PNG.
- [x] AVIF with `filmcraft-av1`, checked sample for sample against libdav1d on aom, SVT
      and rav1e streams, 8 and 10 bits, 4:2:0 and 4:4:4.
- [x] `Inks::Keep` / `--keep-cmyk`: inks and their profile, rewritten from its colour
      tags and checked on a 17⁴ grid of inks at 16 bits.

- [x] JPEG XL made from a JPEG gives the JPEG back (`jbrd`), checked against its render.
- [x] TIFF of JPEG strips or tiles: one JPEG of their coefficients.
- [x] `Profiles::Keep` / `--keep-profile`: RGB profiles rewritten from their colour tags,
      checked on a 17³ grid; JPEG, PNG, TIFF, WebP, BMP.
- [x] Lossy WebP keeps its profile (on request) and its orientation (Exif of it alone).
- [x] Float TIFF of one page stays float.
- [x] Lossless WebP encoder of our own (`cdr/vp8l.rs`); WebP alpha filtered.
- [x] PSD duotone in its inks.
- [x] AVIF on threads for large images, not waited for past the deadline.
- [x] Fuzz targets for WebP, AVIF, TIFF, PSD and JPEG XL.

Not done: HEIC (no HEVC decoder in Rust); AVIF for HDR displays (PQ, HLG) and AVIF image
sequences without a still image.

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
- Ruby 3.2 or later with Bundler, for the gems (M15), or the `ruby:3.4` and
  `ruby:3.4-alpine` images under Podman

## Out of scope (recorded for later)

- Office (DOCX/XLSX macros), archives (recursive ZIP/RAR), video.
- A rebuilt PDF that keeps its links and forms (see M11).
- Bindings beyond C, Python and Ruby (M15); wheels for macOS and Windows.
