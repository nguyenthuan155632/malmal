# Changelog

## Unreleased

### Added

- `Policy::documents()` and `--policy documents`: the default policy with XFA forms and
  attachments allowed, for services that take documents from people. What they contain
  still counts. On CIC-Evasive-PDFMal2022 it accepts 92.38% of the clean files, against
  87.32%, and refuses 99.06% of the malicious ones. `Policy::named` looks a policy up by
  name.
- `malmald --token-file <FILE>`: HTTP requests other than `GET /healthz` have to carry
  `Authorization: Bearer <token>`, or are answered `401` before their body is read. The
  daemon also warns at start-up about each endpoint that is not on loopback and that
  anyone can use.
- `Scanner::scan_within`: a scan that answers within a given time, even when a step of it
  does not end. The scan runs on a thread of its own; when it is late, the report has
  `limit.time` and the scan is left running, at most `MAX_OVERDUE` (4) of them, past which
  files are refused at once. `Scanner::overdue` counts them.

- `--max-memory` (512 MiB) for `malmal` and `malmald`, and `ScannerBuilder::memory_limit`
  with `MemoryLimit` in the library: a scan that holds more than that beyond what its
  thread held when it began is stopped with `limit.memory`. The tools count what each
  thread allocates; the limit is checked as each block of a PDF stream is decoded and
  between steps. Two files that inflate to 200 MiB peaked at 205 MiB without it and
  55 MiB with a limit of 64 MiB.
- `pdf.c2pa_manifest` (Info): attachments that are all C2PA manifests (Content
  Credentials), checked down to their JUMBF boxes, are no longer `pdf.embedded_file`. What
  the manifests carry is still scanned.
- `pdf.reference_loop` (Medium): a page tree, outline, chain of actions or chain of object
  streams that leads back to itself.
- `pdf.link_lure` (Low): a link to a web page that covers a fifth or more of a page. On
  CIC-Evasive-PDFMal2022 the default policy now refuses 98.65% of the malicious files,
  against 98.19%, and accepts as many clean ones, 87.32%.
- `image.vendor_trailer` recognizes the trailer that OPPO cameras write after a JPEG
  image.
- `malmal_scanner_set_max_memory` in the C interface and `Scanner(max_memory=…)` in
  Python, 512 MiB by default: the library counts what each thread allocates, as the
  commands do. PNG chunks, SVGZ and JPEG XL boxes are inflated in blocks against the
  limit, and a PostScript ASCII85 string is held to what is left of it.
- `pdf.signature_invalid` (Medium): a signature whose byte ranges do not fit the file or
  leave more than its value out, that has no value of its own, lies outside what it
  signs, or sits in an object stream (signature forgery and wrapping).
  `pdf.unsigned_content` (Medium): page content written after what the last signature
  signs. Usage rights signatures are not judged.
- `pdf.ambiguous_structure` (Medium): structures that readers take for different
  documents (content masking): stream lengths and keywords, keys given twice,
  cross-reference entries that point elsewhere or at a comment, objects defined again
  after the last `startxref`. On CIC-Evasive-PDFMal2022, 1,558 malicious files and no
  clean one.
- `pdf.disguised_link` (Medium): a web link through a URL shortener, to a numeric address
  or a punycode host, or to a name of made-up syllables. The default policy now refuses
  99.07% of the CIC malicious files, against 98.67%, and accepts as many clean ones.
- A rebuilt PDF keeps the text of its pages, where it was, as characters that can be
  searched and copied and do not draw; `--pdf-no-text` and `Options::pdf_text` leave it
  out.
- A rebuilt PDF draws text from the outlines of its glyphs, written anew as Type 3 fonts,
  where the page shows it in one opaque colour on a plain background with nothing over
  it; each glyph is checked against the drawing of the page before it is taken out of
  it. `--pdf-raster-text` and `Options::pdf_vector_text` keep all text in the drawing.
  On 78 clean CIC-Evasive-PDFMal2022 documents, the 47 with text came out a fifth of
  the size they did (median; at most 0.78), with a median 2.5% of the dark pixels of the
  page left in the drawing; poppler draws none of them further from the original than
  the drawing alone. The other 31 are scans and come out as before. Rebuilding took 51%
  longer.

### Changed

- The crates declare `rust-version = "1.95"`, the oldest Rust that builds them with every
  feature (`yara-x` needs it); CI builds with it.
- The features `zenavif`, `avif-decode`, `svg-hush` and `hayro` of `malmal` are gone. The
  first two did nothing; the others only pulled in a dependency that `cdr-svg` and
  `cdr-pdf` use.
- The GitHub Actions the workflows use are pinned to commits.

### Fixed

- Page content given as an array that sits in an object stream was not scanned.
- Page content that is not a stream, calculator functions that ask for more values than
  their stack holds or compute numbers past floating point on their domain, and filters
  the format does not define are `pdf.malformed`.

## 0.3.0

### Added

- `malmald --file-budget`: what the files of requests held at once may come to, as they
  arrive and while they are scanned. A file takes its share as it arrives and waits for
  room; one that finds none within `--timeout` is refused. The default, `--workers` times
  `--max-size`, is what the files could take before.
- `malmald --min-rate` (1024 bytes a second): once `--timeout` has passed, the pace a
  request and its answer have to keep, counting only the time spent waiting on the client.

### Changed

- `malmal-cli` depends on `memchr`, which `malmal` already used.
- The crate documentation says what is checked, how verdicts and the policy work, the
  limits, threads, stability and the features, with an example of a configured scanner.
- A daemon request takes its worker once its file has arrived, and gives it back before
  its answer is written. `--workers` now counts scans, not requests.

### Fixed

- Files made of one structure repeated many times were read again for each repetition,
  and some ran past the time limit, which none of them reached a check of. Measured
  before and after on a file of 1 MB: trailers whose strings never close, more than
  60 s and 0.02 s; objects that cannot be parsed, 9.1 s and 0.02 s; an object stream
  whose entries all point at one value, more than 60 s for 40 KB and 0.04 s; forms
  that draw a name listed in one large table, 7.1 s and 574 MiB, 0.04 s and 14 MiB;
  `/Encrypt` in every object, 54 s for 16 MB and 0.43 s; in SVG, `&` without `;`,
  34 s and 0.01 s, and `url(` without `)`, 18 s and 0.03 s; in PostScript,
  `%%BeginResource` comments that one keyword closes, 19 s and 0.04 s, and `(` that
  never closes, the 10 s of the time limit and 0.05 s: one pass tells which strings
  close, so ASCII85 image data, which is full of parentheses, is read once; an icon
  whose entries all name one image, 34 s for 1.3 MB and 0.01 s. Tags of server-side
  code in a raster image took 6.5 s for 16 MB and take 0.17 s. Of these, the trailers
  and the object stream now stop at `limit.complexity`, and so do PostScript strings
  that start after a backslash and never close, which that pass cannot tell of; an icon
  whose images lie over one another is `image.malformed`.
- What a damaged PDF filter produced before it gave out was not counted against
  `--max-decompressed`: 16 streams that inflate to 64 MiB each and end in a row the
  predictor rejects, 2.4 MB in all, were clean after 3 s, and 38 MB of them ran to the
  time limit. Both now stop at `limit.decompression` in 0.7 s. ASCII85 strings in
  PostScript, whose `z` is four bytes, are counted too.
- Four clients sending a byte every five seconds held the four workers of a daemon for as
  long as they went on: another request went unanswered for over a minute, and the four
  were never let go. The other request is now answered at once, and the four are let go
  after `--timeout`.
- A multipart boundary of 60,000 bytes took 7 s of a worker for a body of 4 MiB, outside
  the time limit, and takes 0.02 s. The files of one form share the time limit of one
  scan; each had its own.
- Bodies sent to a `--spool-dir` a byte at a time cost a write each: 8 MiB took 14 s over
  ICAP and 12 s over the ClamAV protocol, and take 2.7 s and 0.6 s, as without a spool.

### Behaviour to check when upgrading

- A PDF whose trailers take more than eight times the file to read, an object stream
  whose entries do, and a PostScript program whose strings that start after a backslash
  and never close take more than four times the program, are `limit.complexity`. An
  icon whose images take more than twice the file is `image.malformed`. None of the
  files of `tests/corpus` comes near these.
- A PDF whose damaged streams decode to more than `--max-decompressed` in all is
  `limit.decompression`, and so is a PostScript program whose ASCII85 strings do.
- `malmald` may hold more files at once than it has workers, up to `--file-budget`: with
  the defaults and no spool, 32 uploads of 16 MiB at once took it to 316 MB where 185 MB
  before. A request that finds no room within `--timeout` is refused (`503` over HTTP).
  A client slower than `--min-rate` past `--timeout` loses its connection. The spool
  opens a file for each MiB of the budget, up to `--connections`, where one per worker.

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
  `cdr-pdf` feature, as pictures of its pages, at `--pdf-dpi`, optionally as JPEG
  (`--pdf-jpeg`), and opened with the passwords supplied for scanning. `malmal-cli` and
  `malmal-ffi` enable `cdr-svg` by default and `cdr-pdf` on request.
  `cdr::Options::types` names the types that are rebuilt.
- `Scanner::sanitize` scans the file it has rebuilt and refuses it when that scan is not
  clean (`cdr::Error::Unclean`). Found by fuzzing: pixels that spell a PDF, hidden by the
  compression of the upload, came out of the PNG encoder as they were, and the rebuilt
  file was an image and a PDF with a script at once.
- Deeper PDF checks, for what a keyword does not show. New findings:
  `pdf.dangerous_uri` (links that run a script, start a Windows protocol handler, or open
  a local file or network share), `pdf.external_ref` (streams, forms and file
  specifications whose content is outside the file), `pdf.xml_entity` and
  `pdf.xml_external_ref` (DOCTYPE, entities and XInclude in metadata and XFA),
  `pdf.pixel_bomb`, `pdf.page_size`, `pdf.draw_recursion` (forms that draw themselves),
  `pdf.conflicting_objects` (one object defined twice in one revision), and at Info
  `pdf.risky_codec`, `pdf.print_only` and `pdf.signature_modified`. `pdf.postscript` now
  covers the `PS` operator in a form's appearance string and calculator functions that
  hold more than a calculator's operators; `pdf.rich_media` covers `Movie`, `Sound` and
  `Screen` annotations and `U3D` and `PRC` artwork; `pdf.polyglot` covers ZIP headers and
  HTML or SVG markup outside every stream; `pdf.malformed` covers a second header,
  decode parameters outside the format's ranges and names over 255 bytes.
- `malmal scan` and `malmal sanitize` map the file instead of reading it: a scan of a
  large file needs the memory the analysis keeps, not the size of the file, and a 1 GB
  PDF is scanned in a container limited to 96 MB. Files of 4 MiB and more are hashed and
  searched for payloads on threads of their own while the format is analyzed, and what is
  looked for outside the streams of a PDF is no longer looked for inside them.
- `--no-hash` and `ScannerBuilder::without_hash`: no SHA-256, which is most of the time
  of a large file on a processor without SHA instructions. `Report::sha256` is then
  empty. A blocklist brings the hash back. 1 GB: 8.0 s before, 4.4 s now, 0.42 s without
  the hash.
- The values parsed from a PDF take about half the memory they did, and the number kept
  grows with the size of the file (one for every 8 bytes, 2 million at least), so that
  a large document of many objects is less likely to stop at `limit.complexity`.
- The `evaluate` example measures refusal and false-refusal rates on files whose nature
  is known, with the findings that decided each. On CIC-Evasive-PDFMal2022 (9,107 clean
  and 21,899 malicious files) 98.19 % of the malicious files are refused and 87.32 % of
  the clean ones accepted; every clean file refused carries what it is refused for
  (scripts, XFA forms, attachments, launch actions). See the README.
- A PDF is no longer kept in memory as a tree of its values. An object is parsed where
  it stands each time a check looks at it; only the values that references lead to are
  kept. 100,000 small objects: 87 MB before, 22 MB now, and no slower. A file of 500,000
  objects, which stopped at `limit.complexity`, is analyzed to its end in 94 MB.
- Content streams are read a block at a time as they are inflated, through every filter
  of the chain. A page stream of 200 MB once inflated: 256 MB before, 12 MB now.
  Object streams, attachments, XFA packets and metadata are still decoded whole, within
  `Limits::max_decompressed`.
- `malmald --spool-dir <DIR>`: files of 1 MiB and more are written to unnamed files in
  `DIR` while they are scanned and mapped from there, so that the memory of the daemon
  does not grow with the files it is sent. The files are opened before the sandbox
  closes, one for each worker, and used again: the sandbox allows nothing more than it
  did. A 1 GB file is scanned over each of the four endpoints by a daemon limited to
  96 MB. Without the option every file is held in memory, as before.
- `--max-decompressed` and `--max-pixels` for both commands, which with `--max-size` and
  `--workers` decide what a request can cost in memory.
- `--allow <CODES>` for both commands: the finding codes named, separated by commas or
  `|`, are reported at Info and leave a file clean, as `Policy::with_override` does from
  Rust. An unknown code is an error, and so is a `limit.*` code. `malmal::report::CODES`
  lists every code the scanner reports, and `Policy::allow` checks a code against it
  (`AllowError`). `Scanner(allow=[...])` in Python and `malmal_scanner_new_with_allow` in
  C take the same list; the C function also gives the reason when it returns NULL. The README lists the codes honest files carry and
  what letting each through takes on.
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
  the `cdr` feature; `svg-hush` with `cdr-svg`; `hayro` with `cdr-pdf`; `memmap2` in
  `malmal-cli`.

### Fixed

- `pdf.javascript` and `pdf.embedded_file` were reported for name trees that list
  nothing, `pdf.embedded_file` for the packets of an XFA form and for the rights of a
  signature (`/EF` as an array). 428 of the 9,107 clean files of CIC-Evasive-PDFMal2022
  were refused for one of these.
- `sanitize` held the pixels of an image twice while writing it: a PNG at the limits
  took 494 MB and takes 250 MB.
- A PDF of thousands of streams that all run to one `endstream` was read once for each
  of them: 8 s for a file of 800 KB. The work is now cut off with `limit.complexity`,
  and the time limit is checked between streams.

### Behaviour to check when upgrading

- A link to a file on the reader's own machine that is not a program (`file:///C|/…`)
  is no longer `pdf.dangerous_uri`; a network share or a program still is.
- `limit.complexity` counts objects and the values that references lead to, one for
  every 16 bytes of the file and two million at least, and no longer every value in the
  file. Documents of many objects that were refused are now analyzed.
- The address-space limit of the sandboxed daemon grows with `--workers`, `--max-size`
  and `--max-decompressed` beyond their defaults.

- `malmal` and `malmald` exit with status 3 when a scan runs for six times the scan
  timeout. Run the daemon under a supervisor that restarts it, or pass `--hard-timeout 0`.

- PDFs that came back clean may now be suspicious or malicious for what the deeper
  checks find. Run the `survey` or `evaluate` example on your own files before deploying,
  and lower a finding with `Policy::with_override` if your users need what it reports.
- The address-space limit of the sandbox grows with `--max-size` beyond its default.
- Files that were `type.unknown` because they were HEIC, AVIF, JPEG XL or ICO are now
  analyzed and may be clean.
- PDFs with data after `%%EOF` are now at least suspicious.
- Encrypted PDFs that open without a password may now be clean, or malicious for what was
  found inside.

## 0.1.0

First release.
