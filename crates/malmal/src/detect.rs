//! Content-based file type detection. Filenames and Content-Type headers are
//! attacker-controlled, so they are only ever used as claims to check against.

use serde::Serialize;

use crate::payload::find;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    Jpeg,
    Png,
    Gif,
    Webp,
    Bmp,
    Tiff,
    /// Photoshop PSD or PSB.
    Psd,
    Svg,
    Pdf,
    PostScript,
    Zip,
    Gzip,
    Html,
    Pe,
    Elf,
    MachO,
    /// Text starting with a `#!` interpreter line.
    Script,
    Unknown,
}

impl FileType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Gif => "gif",
            Self::Webp => "webp",
            Self::Bmp => "bmp",
            Self::Tiff => "tiff",
            Self::Psd => "psd",
            Self::Svg => "svg",
            Self::Pdf => "pdf",
            Self::PostScript => "postscript",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::Html => "html",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Script => "script",
            Self::Unknown => "unknown",
        }
    }

    /// The type that [`Self::as_str`] spells as `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        const ALL: [FileType; 18] = [
            FileType::Jpeg,
            FileType::Png,
            FileType::Gif,
            FileType::Webp,
            FileType::Bmp,
            FileType::Tiff,
            FileType::Psd,
            FileType::Svg,
            FileType::Pdf,
            FileType::PostScript,
            FileType::Zip,
            FileType::Gzip,
            FileType::Html,
            FileType::Pe,
            FileType::Elf,
            FileType::MachO,
            FileType::Script,
            FileType::Unknown,
        ];
        ALL.into_iter().find(|file_type| file_type.as_str() == name)
    }

    pub fn is_executable(self) -> bool {
        matches!(self, Self::Pe | Self::Elf | Self::MachO | Self::Script)
    }

    pub fn is_raster_image(self) -> bool {
        matches!(
            self,
            Self::Jpeg | Self::Png | Self::Gif | Self::Webp | Self::Bmp | Self::Tiff | Self::Psd
        )
    }
}

const MACHO_MAGICS: [[u8; 4]; 5] = [
    [0xFE, 0xED, 0xFA, 0xCE],
    [0xFE, 0xED, 0xFA, 0xCF],
    [0xCE, 0xFA, 0xED, 0xFE],
    [0xCF, 0xFA, 0xED, 0xFE],
    // Fat binary; shared with Java class files, which are just as unwelcome.
    [0xCA, 0xFE, 0xBA, 0xBE],
];

pub fn detect(data: &[u8]) -> FileType {
    if data.starts_with(b"\xFF\xD8\xFF") {
        return FileType::Jpeg;
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return FileType::Png;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return FileType::Gif;
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return FileType::Webp;
    }
    if data.starts_with(b"II*\0")
        || data.starts_with(b"MM\0*")
        || data.starts_with(b"II+\0")
        || data.starts_with(b"MM\0+")
    {
        return FileType::Tiff;
    }
    if data.starts_with(b"8BPS\0\x01") || data.starts_with(b"8BPS\0\x02") {
        return FileType::Psd;
    }
    if data.starts_with(b"\x7fELF") {
        return FileType::Elf;
    }
    if data.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if MACHO_MAGICS.iter().any(|m| data.starts_with(m)) {
        return FileType::MachO;
    }
    if data.starts_with(b"#!") {
        return FileType::Script;
    }
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        return FileType::Zip;
    }
    if data.starts_with(b"\x1F\x8B\x08") {
        return FileType::Gzip;
    }
    // DOS EPS binary header.
    if data.starts_with(b"\xC5\xD0\xD3\xC6") {
        return FileType::PostScript;
    }
    if is_bmp(data) {
        return FileType::Bmp;
    }
    // Readers accept the PDF header anywhere in the first 1024 bytes.
    if find(&data[..data.len().min(1024)], b"%PDF-").is_some() {
        return FileType::Pdf;
    }
    let text = skip_bom_and_whitespace(data);
    if text.starts_with(b"%!") {
        return FileType::PostScript;
    }
    detect_markup(text).unwrap_or(FileType::Unknown)
}

/// "BM" alone is too weak a signature, so also require a known DIB header size.
fn is_bmp(data: &[u8]) -> bool {
    data.len() >= 18
        && data.starts_with(b"BM")
        && matches!(
            u32::from_le_bytes([data[14], data[15], data[16], data[17]]),
            12 | 16 | 40 | 52 | 56 | 64 | 108 | 124
        )
}

fn skip_bom_and_whitespace(data: &[u8]) -> &[u8] {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[start..]
}

fn detect_markup(text: &[u8]) -> Option<FileType> {
    if !text.starts_with(b"<") {
        return None;
    }
    let head = text[..text.len().min(4096)].to_ascii_lowercase();
    let has = |needle: &[u8]| find(&head, needle).is_some();
    if has(b"<!doctype html") || has(b"<html") {
        Some(FileType::Html)
    } else if has(b"<svg") {
        Some(FileType::Svg)
    } else if has(b"<script") || has(b"<body") || has(b"<head") || has(b"<iframe") {
        Some(FileType::Html)
    } else {
        None
    }
}

/// Types a file extension claims. `.ai` is PDF-based since Illustrator 9 and
/// PostScript before that, so it legitimately maps to both.
pub fn types_for_extension(ext: &str) -> Option<&'static [FileType]> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" | "jpe" | "jfif" => &[FileType::Jpeg],
        "png" => &[FileType::Png],
        "gif" => &[FileType::Gif],
        "webp" => &[FileType::Webp],
        "bmp" | "dib" => &[FileType::Bmp],
        "tif" | "tiff" => &[FileType::Tiff],
        "psd" | "psb" => &[FileType::Psd],
        // A gzip-wrapped SVG is reported as the SVG it contains.
        "svg" | "svgz" => &[FileType::Svg],
        "pdf" => &[FileType::Pdf],
        "ps" | "eps" | "epsf" => &[FileType::PostScript],
        "ai" => &[FileType::Pdf, FileType::PostScript],
        _ => return None,
    })
}

pub fn types_for_mime(content_type: &str) -> Option<&'static [FileType]> {
    let mime = content_type.split(';').next().unwrap_or("").trim();
    Some(match mime.to_ascii_lowercase().as_str() {
        "image/jpeg" | "image/pjpeg" => &[FileType::Jpeg],
        "image/png" => &[FileType::Png],
        "image/gif" => &[FileType::Gif],
        "image/webp" => &[FileType::Webp],
        "image/bmp" | "image/x-ms-bmp" => &[FileType::Bmp],
        "image/tiff" => &[FileType::Tiff],
        "image/vnd.adobe.photoshop"
        | "image/x-photoshop"
        | "image/psd"
        | "application/photoshop"
        | "application/x-photoshop"
        | "application/psd" => &[FileType::Psd],
        "image/svg+xml" => &[FileType::Svg],
        "application/pdf" => &[FileType::Pdf],
        "application/eps" | "application/x-eps" | "image/x-eps" => &[FileType::PostScript],
        // Browsers send application/postscript for .ai files of either flavour.
        "application/postscript" | "application/illustrator" => {
            &[FileType::PostScript, FileType::Pdf]
        }
        _ => return None,
    })
}

/// Final extension of the basename, if any.
pub fn extension(filename: &str) -> Option<&str> {
    let (stem, ext) = basename(filename).rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then_some(ext)
}

/// First extension anywhere in the name that a web server or OS may execute,
/// e.g. the `php` in `shell.php.jpg` or the `htaccess` in `.htaccess`.
pub fn dangerous_extension(filename: &str) -> Option<&str> {
    basename(filename).split('.').skip(1).find(|segment| {
        let segment = segment.trim().to_ascii_lowercase();
        segment.starts_with("php") || DANGEROUS_EXTENSIONS.contains(&segment.as_str())
    })
}

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "phtml", "pht", "phar", "jsp", "jspx", "asp", "aspx", "ashx", "asmx", "cer", "cgi", "pl", "py",
    "rb", "sh", "bash", "exe", "dll", "com", "scr", "msi", "bat", "cmd", "ps1", "vbs", "js", "mjs",
    "jar", "war", "htaccess", "htpasswd", "html", "htm", "xhtml", "shtml", "hta", "so",
];

fn basename(filename: &str) -> &str {
    filename.rsplit(['/', '\\']).next().unwrap_or(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_binary_signatures() {
        assert_eq!(detect(b"\xFF\xD8\xFF\xE0\0\x10JFIF"), FileType::Jpeg);
        assert_eq!(detect(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"), FileType::Png);
        assert_eq!(detect(b"GIF89a\x01\0\x01\0"), FileType::Gif);
        assert_eq!(detect(b"RIFF\x24\0\0\0WEBPVP8 "), FileType::Webp);
        assert_eq!(detect(b"II*\0\x08\0\0\0"), FileType::Tiff);
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), FileType::Elf);
        assert_eq!(detect(b"MZ\x90\0\x03"), FileType::Pe);
        assert_eq!(detect(b"\xCF\xFA\xED\xFE\x07"), FileType::MachO);
        assert_eq!(detect(b"PK\x03\x04\x14\0"), FileType::Zip);
        assert_eq!(detect(b"#!/bin/sh\nid\n"), FileType::Script);
    }

    #[test]
    fn bmp_needs_a_plausible_dib_header() {
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0; 12]);
        bmp.extend_from_slice(&40u32.to_le_bytes());
        assert_eq!(detect(&bmp), FileType::Bmp);
        assert_eq!(
            detect(b"BM is how this text file starts"),
            FileType::Unknown
        );
    }

    #[test]
    fn pdf_header_may_be_preceded_by_junk() {
        assert_eq!(detect(b"%PDF-1.7\n"), FileType::Pdf);
        let mut padded = vec![b' '; 900];
        padded.extend_from_slice(b"%PDF-1.4\n");
        assert_eq!(detect(&padded), FileType::Pdf);
        let mut too_far = vec![b' '; 2000];
        too_far.extend_from_slice(b"%PDF-1.4\n");
        assert_eq!(detect(&too_far), FileType::Unknown);
    }

    #[test]
    fn detects_postscript_variants() {
        assert_eq!(detect(b"%!PS-Adobe-3.0 EPSF-3.0\n"), FileType::PostScript);
        assert_eq!(detect(b"\xC5\xD0\xD3\xC6\x1e\0\0\0"), FileType::PostScript);
    }

    #[test]
    fn tells_svg_from_html() {
        let svg =
            b"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<SVG xmlns=\"http://www.w3.org/2000/svg\"/>";
        assert_eq!(detect(svg), FileType::Svg);
        assert_eq!(
            detect(b"  <!DOCTYPE html><html><svg/></html>"),
            FileType::Html
        );
        assert_eq!(detect(b"<ScRiPt>alert(1)</script>"), FileType::Html);
        assert_eq!(detect(b"<?xml version=\"1.0\"?><note/>"), FileType::Unknown);
    }

    #[test]
    fn empty_and_plain_text_are_unknown() {
        assert_eq!(detect(b""), FileType::Unknown);
        assert_eq!(detect(b"hello world"), FileType::Unknown);
    }

    #[test]
    fn extension_and_mime_claims() {
        assert_eq!(extension("/tmp/a/photo.JPG"), Some("JPG"));
        assert_eq!(extension("C:\\up\\x.tar.gz"), Some("gz"));
        assert_eq!(extension(".htaccess"), None);
        assert_eq!(extension("noext"), None);
        assert_eq!(types_for_extension("JPG"), Some(&[FileType::Jpeg][..]));
        assert_eq!(types_for_extension("exe"), None);
        assert_eq!(
            types_for_mime("Image/SVG+XML; charset=utf-8"),
            Some(&[FileType::Svg][..])
        );
        assert_eq!(types_for_mime("application/octet-stream"), None);
    }

    #[test]
    fn finds_dangerous_extensions_anywhere_in_the_name() {
        assert_eq!(dangerous_extension("shell.php.jpg"), Some("php"));
        assert_eq!(dangerous_extension("a.PHP5"), Some("PHP5"));
        assert_eq!(dangerous_extension("up/.htaccess"), Some("htaccess"));
        assert_eq!(dangerous_extension("x.jpg.aspx "), Some("aspx "));
        assert_eq!(dangerous_extension("php.jpg"), None);
        assert_eq!(dangerous_extension("holiday.photo.png"), None);
    }
}
