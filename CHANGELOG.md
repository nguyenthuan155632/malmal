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
  is then reported at Info instead of Medium.
- `pdf.trailing_data` and `pdf.polyglot` for bytes after the last `%%EOF`. A PDF with a ZIP
  archive appended used to come back clean.
- XFA forms are searched for scripts, reported as `pdf.javascript`.
- Files embedded in a PDF are matched against the YARA rules.
- `image.compressed_metadata` (Info) for Brotli-compressed metadata in JPEG XL.
- `malmald --http`: `POST /scan`, `GET /metrics` (Prometheus), `GET /healthz`.
- `malmald --clamd`: the `INSTREAM` command of the ClamAV daemon protocol.
- `--max-size` and `--scan-timeout` for both commands; `Scanner::limits()`.
- `docs/findings.md` and `docs/integration.md`; the `survey` example.

### Changed

- `FileType`, `Report` and `Finding` are `#[non_exhaustive]`.
- `malmal::payload`, `Budget` and `LimitExceeded` are no longer public. They were internals
  that no caller needs.
- `malmald --socket` is no longer required on its own: one of `--socket`, `--http` or
  `--clamd` is.
- New dependencies: `md-5` and `aes`, for PDF decryption.

### Behaviour to check when upgrading

- Files that were `type.unknown` because they were HEIC, AVIF, JPEG XL or ICO are now
  analyzed and may be clean.
- PDFs with data after `%%EOF` are now at least suspicious.
- Encrypted PDFs that open without a password may now be clean, or malicious for what was
  found inside.

## 0.1.0

First release.
