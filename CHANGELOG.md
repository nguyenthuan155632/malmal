# Changelog

## 0.2.0

### Added

- HEIC, AVIF, JPEG XL and ICO files are recognized, checked and accepted by default
  (`FileType::Heif`, `Avif`, `Jxl`, `Ico`). Narrow the set with `Policy::with_allowed_types`
  or `--types` if your service does not take them.
- BigTIFF is parsed; it used to be reported as `image.malformed`.
- PSD layer records are walked: a broken record is `image.malformed`, and a layer larger
  than the pixel limit is `image.pixel_bomb`.
- PDFs encrypted with an empty user password are decrypted and inspected. `pdf.encrypted`
  is then reported at Info instead of Medium. `ScannerBuilder::pdf_passwords` and
  `--pdf-passwords` supply passwords to try on the others, as user or owner password.
- `pdf.trailing_data` and `pdf.polyglot` for bytes after the last `%%EOF`. A PDF with a ZIP
  archive appended used to come back clean.
- XFA forms are searched for scripts, reported as `pdf.javascript`.
- Files embedded in a PDF are matched against the YARA rules.
- Brotli-compressed metadata boxes in JPEG XL are decompressed and searched
  (`image.metadata.payload`).
- The `cdr` feature: `Scanner::sanitize` and `malmal::cdr::rebuild` decode a clean raster
  image and write a new file from its pixels. `malmal sanitize INPUT OUTPUT` and the
  daemon's `POST /sanitize` do the same; `malmal-cli` enables the feature by default.
  Animations keep their frames, delays and loop count; RGB, grey and CMYK colour profiles
  are applied, so that the new file, which has none, shows the same colours. `malmal sanitize` puts the
  new file in place of the old one in a single step, or leaves the old one alone.
- Rebuilding beyond raster images: JPEG XL (as PNG); SVG with the `cdr-svg` feature,
  filtered through an allowlist and checked again by the SVG analyzer; PDF with the
  `cdr-pdf` feature, as pictures of its pages, at `--pdf-dpi`. `cdr::Options::types`
  names the types that are rebuilt.
- `malmal_sanitize` in the C interface and `Scanner.sanitize` in the Python binding;
  `malmal_scanner_new_with_passwords` and `Scanner(pdf_passwords=...)` for encrypted PDFs.
- `malmald --connections`. Every connection has its own thread, and `--workers` now counts
  the requests worked on at once across all endpoints, not the connections on each: a
  client that keeps its connection open no longer holds a worker while idle.
- `--hard-timeout`: a scan still running after it ends the process, where the scan's own
  time limit, checked between steps, could be waited for in vain.
- `malmald --icap`: ICAP `REQMOD` and `RESPMOD` for proxies. Multipart forms are taken
  apart and each uploaded file is scanned.
- Release archives with static binaries for x86-64 and ARM64, a container image, a Python
  binding in `bindings/python` with wheels for Linux, and metadata for `cargo binstall`.
- `malmald --http`: `POST /scan`, `GET /metrics` (Prometheus), `GET /healthz`.
- `malmald --clamd`: the `INSTREAM` command of the ClamAV daemon protocol.
- `--max-size` and `--scan-timeout` for both commands; `Scanner::limits()`.
- `docs/findings.md` and `docs/integration.md`; the `survey` example.

### Changed

- `FileType`, `Report` and `Finding` are `#[non_exhaustive]`.
- `malmal::payload`, `Budget` and `LimitExceeded` are no longer public. They were internals
  that no caller needs.
- `malmald --socket` is no longer required on its own: one of `--socket`, `--http`,
  `--clamd` or `--icap` is.
- New dependencies: `md-5` and `aes`, for PDF decryption; `brotli-decompressor`, for JPEG XL
  metadata; `image`, `png`, `moxcms`, `zune-jpeg`, `zune-core` and `jxl-oxide`, only with
  the `cdr` feature; `svg-hush` with `cdr-svg`; `hayro` with `cdr-pdf`.

### Behaviour to check when upgrading

- `malmal` and `malmald` exit with status 3 when a scan runs for six times the scan
  timeout. Run the daemon under a supervisor that restarts it, or pass `--hard-timeout 0`.

- Files that were `type.unknown` because they were HEIC, AVIF, JPEG XL or ICO are now
  analyzed and may be clean.
- PDFs with data after `%%EOF` are now at least suspicious.
- Encrypted PDFs that open without a password may now be clean, or malicious for what was
  found inside.

## 0.1.0

First release.
