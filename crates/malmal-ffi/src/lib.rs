//! C ABI over [`malmal::Scanner`]. The contract for every function is in
//! `include/malmal.h`; no panic crosses the boundary.

use std::ffi::{CStr, CString, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use malmal::cdr::{Error, Options};
use malmal::{HashList, MemoryLimit, Policy, ScanHints, Scanner};

pub mod memory;
mod options;

use options::{DEFAULT_MAX_MEMORY, SanitizeOptions, ScannerOptions};

#[global_allocator]
static ALLOCATOR: memory::Counting = memory::Counting;

const MALMAL_CLEAN: c_int = 0;
const MALMAL_ERROR: c_int = 3;
const MALMAL_NOT_REBUILT: c_int = 4;

/// Opaque to C.
#[allow(non_camel_case_types)]
pub struct malmal_scanner {
    scanner: Scanner,
    /// When set, `malmal_scan` answers within it (`Scanner::scan_within`).
    wait: Option<Duration>,
}

impl malmal_scanner {
    fn boxed(scanner: Scanner, wait: Option<Duration>) -> *mut Self {
        Box::into_raw(Box::new(Self { scanner, wait }))
    }
}

/// The version of this library, as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn malmal_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Write `message` to `error`, if there is somewhere to write it.
///
/// # Safety
/// `error` must be null or writable.
unsafe fn report_error(error: *mut *mut c_char, message: &str) {
    if !error.is_null() {
        let message = CString::new(message.replace('\0', "")).unwrap_or_default();
        // SAFETY: the caller guarantees `error` is writable.
        unsafe { *error = message.into_raw() };
    }
}

/// # Safety
/// `options` must be null or NUL-terminated, and `error` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_new_json(
    options: *const c_char,
    error: *mut *mut c_char,
) -> *mut malmal_scanner {
    if !error.is_null() {
        // SAFETY: the caller guarantees `error` is writable.
        unsafe { *error = ptr::null_mut() };
    }
    // SAFETY: the caller guarantees null or NUL-terminated.
    let Some(json) = (unsafe { optional_utf8(options) }) else {
        // SAFETY: as above.
        unsafe { report_error(error, "the options are not UTF-8") };
        return ptr::null_mut();
    };
    let built = catch_unwind(|| ScannerOptions::parse(&json)?.build());
    match built {
        Ok(Ok(built)) => {
            let mut scanner = built.scanner;
            scanner
                .set_memory_limit((built.max_memory > 0).then(|| memory_limit(built.max_memory)));
            malmal_scanner::boxed(scanner, built.wait)
        }
        Ok(Err(message)) => {
            // SAFETY: the caller guarantees `error` is null or writable.
            unsafe { report_error(error, &message) };
            ptr::null_mut()
        }
        Err(_) => {
            // SAFETY: as above.
            unsafe { report_error(error, "the scanner could not be created") };
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `scanner` must be null or a live pointer from a `malmal_scanner_new*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_overdue(scanner: *const malmal_scanner) -> u64 {
    if scanner.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees a live scanner.
    unsafe { (*scanner).scanner.overdue() as u64 }
}

/// # Safety
/// `hashlist` must be null or point to `hashlist_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_new(
    strict: c_int,
    hashlist: *const c_char,
    hashlist_len: usize,
) -> *mut malmal_scanner {
    // SAFETY: the caller's guarantee is the one asked for there.
    unsafe { malmal_scanner_new_with_passwords(strict, hashlist, hashlist_len, ptr::null(), 0) }
}

/// # Safety
/// `hashlist` must be null or point to `hashlist_len` readable bytes, and
/// `pdf_passwords` null or to `pdf_passwords_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_new_with_passwords(
    strict: c_int,
    hashlist: *const c_char,
    hashlist_len: usize,
    pdf_passwords: *const c_char,
    pdf_passwords_len: usize,
) -> *mut malmal_scanner {
    // SAFETY: the caller's guarantees are the ones asked for there; the
    // allowed codes are null and no error is asked for.
    unsafe {
        malmal_scanner_new_with_allow(
            strict,
            hashlist,
            hashlist_len,
            pdf_passwords,
            pdf_passwords_len,
            ptr::null(),
            ptr::null_mut(),
        )
    }
}

/// # Safety
/// As for `malmal_scanner_new_with_passwords`; `allow` must be null or
/// NUL-terminated, and `error` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_new_with_allow(
    strict: c_int,
    hashlist: *const c_char,
    hashlist_len: usize,
    pdf_passwords: *const c_char,
    pdf_passwords_len: usize,
    allow: *const c_char,
    error: *mut *mut c_char,
) -> *mut malmal_scanner {
    if !error.is_null() {
        // SAFETY: the caller guarantees `error` is writable.
        unsafe { *error = ptr::null_mut() };
    }
    // SAFETY: the caller guarantees each is null or as long as it says, and
    // `allow` null or NUL-terminated.
    let (text, passwords, allow) = unsafe {
        (
            lines(hashlist, hashlist_len),
            lines(pdf_passwords, pdf_passwords_len),
            optional_str(allow),
        )
    };
    let built = catch_unwind(|| {
        let text =
            std::str::from_utf8(text).map_err(|_| "the hash list is not UTF-8".to_string())?;
        let hashlist = HashList::parse(text).map_err(|e| e.to_string())?;
        let policy = if strict != 0 {
            Policy::strict()
        } else {
            Policy::default()
        };
        // Separated as the commands' --allow is; nothing given is nothing allowed.
        let codes = allow
            .as_deref()
            .unwrap_or("")
            .split([',', '|'])
            .map(str::trim);
        let policy = codes
            .filter(|code| !code.is_empty())
            .try_fold(policy, |policy, code| policy.allow(code))
            .map_err(|e| e.to_string())?;
        // One to a line; a password is bytes, not necessarily text.
        let passwords = passwords
            .split(|&byte| byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty());
        let builder = Scanner::builder()
            .policy(policy)
            .hashlist(hashlist)
            .memory_limit(memory_limit(DEFAULT_MAX_MEMORY));
        Ok::<_, String>(builder.pdf_passwords(passwords).build())
    });
    let message = match built {
        Ok(Ok(scanner)) => return malmal_scanner::boxed(scanner, None),
        Ok(Err(message)) => message,
        Err(_) => "the scanner could not be created".to_string(),
    };
    // SAFETY: the caller guarantees `error` is null or writable.
    unsafe { report_error(error, &message) };
    ptr::null_mut()
}

/// A memory limit of `max` bytes for each scan, measured by this library's
/// allocator.
fn memory_limit(max: u64) -> MemoryLimit {
    MemoryLimit {
        max,
        measure: memory::held,
    }
}

/// # Safety
/// `scanner` must be null or a pointer from `malmal_scanner_new` that has
/// not been freed, and not in use by another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_set_max_memory(scanner: *mut malmal_scanner, max: u64) {
    if scanner.is_null() {
        return;
    }
    // SAFETY: the caller guarantees a live scanner that nothing else uses.
    let scanner = unsafe { &mut (*scanner).scanner };
    scanner.set_memory_limit((max > 0).then(|| memory_limit(max)));
}

/// # Safety
/// `scanner` must be null or a pointer from `malmal_scanner_new` that has
/// not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_free(scanner: *mut malmal_scanner) {
    if !scanner.is_null() {
        // SAFETY: the pointer came from Box::into_raw in malmal_scanner_new.
        drop(unsafe { Box::from_raw(scanner) });
    }
}

/// # Safety
/// `scanner` must be a live pointer from `malmal_scanner_new`; `data` must
/// point to `len` readable bytes (or be null with `len` 0); `filename` and
/// `content_type` must be null or NUL-terminated; `report_json` must be null
/// or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scan(
    scanner: *const malmal_scanner,
    data: *const u8,
    len: usize,
    filename: *const c_char,
    content_type: *const c_char,
    report_json: *mut *mut c_char,
) -> c_int {
    if !report_json.is_null() {
        // SAFETY: the caller guarantees `report_json` is writable.
        unsafe { *report_json = ptr::null_mut() };
    }
    // SAFETY: the caller guarantees a live scanner and `len` readable bytes.
    let Some((scanner, bytes)) = (unsafe { input(scanner, data, len) }) else {
        return MALMAL_ERROR;
    };
    // SAFETY: the caller guarantees both are null or NUL-terminated.
    let (filename, content_type) = unsafe { (optional_str(filename), optional_str(content_type)) };

    let scanned = catch_unwind(AssertUnwindSafe(|| {
        let hints = ScanHints {
            filename: filename.as_deref(),
            content_type: content_type.as_deref(),
        };
        let report = match scanner.wait {
            Some(wait) => scanner.scanner.scan_within(Arc::from(bytes), hints, wait),
            None => scanner.scanner.scan_bytes(bytes, hints),
        };
        let json = serde_json::to_string(&report).ok()?;
        Some((report.verdict as c_int, CString::new(json).ok()?))
    }));
    match scanned {
        Ok(Some((verdict, json))) => {
            if !report_json.is_null() {
                // SAFETY: the caller guarantees `report_json` is writable.
                unsafe { *report_json = json.into_raw() };
            }
            verdict
        }
        _ => MALMAL_ERROR,
    }
}

/// # Safety
/// As for `malmal_scan`; `image`, `image_len` and `info_json` must each be
/// null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_sanitize(
    scanner: *const malmal_scanner,
    data: *const u8,
    len: usize,
    filename: *const c_char,
    content_type: *const c_char,
    jpeg_quality: c_int,
    image: *mut *mut u8,
    image_len: *mut usize,
    info_json: *mut *mut c_char,
) -> c_int {
    let mut options = Options::default();
    if let Ok(quality @ 1..=100) = u8::try_from(jpeg_quality) {
        options.jpeg_quality = quality;
    }
    // SAFETY: the caller's guarantees are the ones asked for there.
    unsafe {
        sanitize_with(
            scanner,
            data,
            len,
            filename,
            content_type,
            Ok(options),
            image,
            image_len,
            info_json,
        )
    }
}

/// # Safety
/// As for `malmal_sanitize`; `options` must be null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_sanitize_json(
    scanner: *const malmal_scanner,
    data: *const u8,
    len: usize,
    filename: *const c_char,
    content_type: *const c_char,
    options: *const c_char,
    image: *mut *mut u8,
    image_len: *mut usize,
    info_json: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller guarantees null or NUL-terminated.
    let options = match unsafe { optional_utf8(options) } {
        Some(json) => SanitizeOptions::parse(&json),
        None => Err("the options are not UTF-8".to_string()),
    };
    // SAFETY: the caller's guarantees are the ones asked for there.
    unsafe {
        sanitize_with(
            scanner,
            data,
            len,
            filename,
            content_type,
            options,
            image,
            image_len,
            info_json,
        )
    }
}

/// # Safety
/// As for `malmal_sanitize`.
#[allow(clippy::too_many_arguments)]
unsafe fn sanitize_with(
    scanner: *const malmal_scanner,
    data: *const u8,
    len: usize,
    filename: *const c_char,
    content_type: *const c_char,
    options: Result<Options, String>,
    image: *mut *mut u8,
    image_len: *mut usize,
    info_json: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller guarantees each is null or writable.
    unsafe {
        if !image.is_null() {
            *image = ptr::null_mut();
        }
        if !image_len.is_null() {
            *image_len = 0;
        }
        if !info_json.is_null() {
            *info_json = ptr::null_mut();
        }
    }
    // Without somewhere to put the image there is nothing to do.
    if image.is_null() || image_len.is_null() {
        return MALMAL_ERROR;
    }
    let options = match options {
        Ok(options) => options,
        Err(message) => {
            if !info_json.is_null() {
                let info = serde_json::json!({ "error": message }).to_string();
                if let Ok(info) = CString::new(info) {
                    // SAFETY: the caller guarantees `info_json` is writable.
                    unsafe { *info_json = info.into_raw() };
                }
            }
            return MALMAL_ERROR;
        }
    };
    // SAFETY: the caller guarantees a live scanner and `len` readable bytes.
    let Some((scanner, bytes)) = (unsafe { input(scanner, data, len) }) else {
        return MALMAL_ERROR;
    };
    // SAFETY: the caller guarantees both are null or NUL-terminated.
    let (filename, content_type) = unsafe { (optional_str(filename), optional_str(content_type)) };

    let sanitized = catch_unwind(AssertUnwindSafe(|| {
        let hints = ScanHints {
            filename: filename.as_deref(),
            content_type: content_type.as_deref(),
        };
        let (status, rebuilt, info) = match scanner.scanner.sanitize(bytes, hints, &options) {
            Ok(sanitized) => {
                let info = serde_json::json!({
                    "report": sanitized.report,
                    "image": {
                        "file_type": sanitized.image.file_type.as_str(),
                        "width": sanitized.image.width,
                        "height": sanitized.image.height,
                        "frames": sanitized.image.frames,
                    },
                });
                (MALMAL_CLEAN, Some(sanitized.image.data), info)
            }
            Err(Error::Rejected(report) | Error::Unclean(report)) => {
                let info = serde_json::json!({ "report": report });
                (report.verdict as c_int, None, info)
            }
            Err(error) => {
                let info = serde_json::json!({ "error": error.to_string() });
                (MALMAL_NOT_REBUILT, None, info)
            }
        };
        Some((status, rebuilt, CString::new(info.to_string()).ok()?))
    }));
    let Ok(Some((status, rebuilt, info))) = sanitized else {
        return MALMAL_ERROR;
    };
    // SAFETY: `image` and `image_len` were checked non-null; the caller
    // guarantees all three are writable.
    unsafe {
        if let Some(rebuilt) = rebuilt {
            let rebuilt = Box::into_raw(rebuilt.into_boxed_slice());
            *image_len = rebuilt.len();
            *image = rebuilt.cast();
        }
        if !info_json.is_null() {
            *info_json = info.into_raw();
        }
    }
    status
}

/// # Safety
/// `string` must be null or a string returned by `malmal_scan` or
/// `malmal_sanitize` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_string_free(string: *mut c_char) {
    if !string.is_null() {
        // SAFETY: the pointer came from CString::into_raw in this library.
        drop(unsafe { CString::from_raw(string) });
    }
}

/// # Safety
/// `bytes` must be null or an image returned by `malmal_sanitize` that has
/// not been freed, and `len` the length returned with it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_bytes_free(bytes: *mut u8, len: usize) {
    if !bytes.is_null() {
        // SAFETY: the pointer and length are those of the boxed slice
        // leaked in malmal_sanitize.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(bytes, len)) });
    }
}

/// The text an optional argument points to; none is empty.
///
/// # Safety
/// `text` must be null or point to `len` readable bytes.
unsafe fn lines<'a>(text: *const c_char, len: usize) -> &'a [u8] {
    if text.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees `len` readable bytes.
    unsafe { std::slice::from_raw_parts(text.cast(), len) }
}

/// The scanner and the file a call was given, or `None` if they are not
/// usable.
///
/// # Safety
/// `scanner` must be null or a live pointer from `malmal_scanner_new`;
/// `data` must be null or point to `len` readable bytes.
unsafe fn input<'a>(
    scanner: *const malmal_scanner,
    data: *const u8,
    len: usize,
) -> Option<(&'a malmal_scanner, &'a [u8])> {
    if scanner.is_null() || (data.is_null() && len != 0) {
        return None;
    }
    // SAFETY: checked non-null above; the caller guarantees validity.
    let scanner = unsafe { &*scanner };
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at `data`.
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    Some((scanner, bytes))
}

/// The UTF-8 text `pointer` points to, empty when it is null; `None` when it
/// is not UTF-8.
///
/// # Safety
/// `pointer` must be null or NUL-terminated.
unsafe fn optional_utf8(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return Some(String::new());
    }
    // SAFETY: the caller guarantees a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(pointer) };
    text.to_str().ok().map(str::to_owned)
}

/// # Safety
/// `pointer` must be null or NUL-terminated.
unsafe fn optional_str(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(pointer) };
    Some(text.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(scanner: *const malmal_scanner, data: &[u8], filename: &CStr) -> (c_int, String) {
        let mut json = ptr::null_mut();
        let verdict = unsafe {
            malmal_scan(
                scanner,
                data.as_ptr(),
                data.len(),
                filename.as_ptr(),
                ptr::null(),
                &mut json,
            )
        };
        let report = unsafe { CStr::from_ptr(json) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe { malmal_string_free(json) };
        (verdict, report)
    }

    #[test]
    fn scans_through_the_c_interface() {
        let scanner = unsafe { malmal_scanner_new(0, ptr::null(), 0) };
        assert!(!scanner.is_null());

        let (verdict, report) = scan(scanner, b"\x7fELF\x02\x01\x01\0", c"photo.jpg");
        assert_eq!(verdict, 2);
        assert!(report.contains("type.executable"), "{report}");

        let (verdict, _) = scan(scanner, b"plain text", c"notes.txt");
        assert_eq!(verdict, 1);

        // Empty input with a null pointer is valid; the report is optional.
        let verdict = unsafe {
            malmal_scan(
                scanner,
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            )
        };
        assert_eq!(verdict, 1);
        unsafe { malmal_scanner_free(scanner) };
    }

    #[test]
    fn scans_stop_at_their_memory_limit() {
        // An attachment of 48 MiB of zeros, run-length encoded.
        let runs = (48 << 20) / 128;
        let data = [b"\x81\0".repeat(runs), b"\x80".to_vec()].concat();
        let mut pdf = format!(
            "%PDF-1.7\n1 0 obj << /Type /Catalog /Names << /EmbeddedFiles << /Names [(a) 3 0 R] >> >> >> endobj\n\
             2 0 obj << /Type /EmbeddedFile /Filter /RunLengthDecode /Length {} >> stream\n",
            data.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&data);
        pdf.extend_from_slice(
            b"\nendstream endobj\n3 0 obj << /Type /Filespec /F (a) /EF << /F 2 0 R >> >> endobj\n\
              trailer << /Root 1 0 R >>\n%%EOF\n",
        );
        let scanner = unsafe { malmal_scanner_new(0, ptr::null(), 0) };
        let (_, report) = scan(scanner, &pdf, c"a.pdf");
        assert!(!report.contains("limit.memory"), "{report}");
        unsafe { malmal_scanner_set_max_memory(scanner, 16 << 20) };
        let (verdict, report) = scan(scanner, &pdf, c"a.pdf");
        assert_eq!(verdict, 1);
        assert!(report.contains("limit.memory"), "{report}");
        unsafe { malmal_scanner_set_max_memory(scanner, 0) };
        let (_, report) = scan(scanner, &pdf, c"a.pdf");
        assert!(!report.contains("limit.memory"), "{report}");
        unsafe { malmal_scanner_free(scanner) };
    }

    /// One transparent pixel, with a comment a rebuilt file does not keep.
    const PNG: &[u8] =
        b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\
        \0\0\0\x18tEXtComment\0taken on holiday\xde\x76\xb6\x04\
        \0\0\0\x10IDAT\x78\x01\x01\x05\0\xfa\xff\0\0\0\0\0\0\x05\0\x01\x64\x78\x95\x38\
        \0\0\0\0IEND\xae\x42\x60\x82";

    fn sanitize(scanner: *const malmal_scanner, data: &[u8]) -> (c_int, Vec<u8>, String) {
        let (mut image, mut image_len, mut json) = (ptr::null_mut(), 0, ptr::null_mut());
        let status = unsafe {
            malmal_sanitize(
                scanner,
                data.as_ptr(),
                data.len(),
                ptr::null(),
                ptr::null(),
                0,
                &mut image,
                &mut image_len,
                &mut json,
            )
        };
        let rebuilt = if image.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(image, image_len) }.to_vec()
        };
        let info = unsafe { CStr::from_ptr(json) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe {
            malmal_bytes_free(image, image_len);
            malmal_string_free(json);
        }
        (status, rebuilt, info)
    }

    #[test]
    fn rebuilds_through_the_c_interface() {
        let scanner = unsafe { malmal_scanner_new(0, ptr::null(), 0) };

        let (status, rebuilt, info) = sanitize(scanner, PNG);
        assert_eq!(status, MALMAL_CLEAN, "{info}");
        assert!(rebuilt.starts_with(b"\x89PNG"));
        assert!(!rebuilt.windows(7).any(|window| window == b"holiday"));
        assert!(info.contains(r#""file_type":"png""#), "{info}");
        assert!(info.contains(r#""verdict":"clean""#), "{info}");

        let (status, rebuilt, info) = sanitize(scanner, b"\x7fELF\x02\x01\x01\0");
        assert_eq!(status, 2);
        assert!(rebuilt.is_empty());
        assert!(info.contains("type.executable"), "{info}");

        // Clean, as far as a scan can tell, and not an image.
        let pdf = b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF\n";
        let (status, rebuilt, info) = sanitize(scanner, pdf);
        assert_eq!(status, MALMAL_NOT_REBUILT, "{info}");
        assert!(rebuilt.is_empty());
        assert!(info.contains("error"), "{info}");

        // Nowhere to put the image.
        let mut json = ptr::dangling_mut::<c_char>();
        let status = unsafe {
            malmal_sanitize(
                scanner,
                PNG.as_ptr(),
                PNG.len(),
                ptr::null(),
                ptr::null(),
                90,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut json,
            )
        };
        assert_eq!(status, MALMAL_ERROR);
        assert!(json.is_null());
        unsafe {
            malmal_bytes_free(ptr::null_mut(), 0);
            malmal_scanner_free(scanner);
        }
    }

    #[test]
    fn rebuilds_documents_and_checks_what_it_rebuilt() {
        let scanner = unsafe { malmal_scanner_new(0, ptr::null(), 0) };

        let svg = include_bytes!("../../../tests/corpus/clean/square.svg");
        let (status, rebuilt, info) = sanitize(scanner, svg);
        assert_eq!(status, MALMAL_CLEAN, "{info}");
        assert!(rebuilt.starts_with(b"<?xml"));
        assert!(info.contains(r#""file_type":"svg""#), "{info}");

        let pdf = include_bytes!("../../../tests/corpus/clean/page.pdf");
        let (status, rebuilt, info) = sanitize(scanner, pdf);
        if cfg!(feature = "cdr-pdf") {
            assert_eq!(status, MALMAL_CLEAN, "{info}");
            assert!(rebuilt.starts_with(b"%PDF-1.7"));
            assert!(info.contains(r#""file_type":"pdf""#), "{info}");
        } else {
            assert_eq!(status, MALMAL_NOT_REBUILT, "{info}");
        }

        // A picture whose pixels are a PDF: the report is on the new file.
        let polyglot = include_bytes!("../../../tests/corpus/clean/pixels-spell-pdf.png");
        let (status, rebuilt, info) = sanitize(scanner, polyglot);
        assert_eq!(status, 2, "{info}");
        assert!(rebuilt.is_empty());
        assert!(info.contains("image.polyglot"), "{info}");
        unsafe { malmal_scanner_free(scanner) };
    }

    #[test]
    fn supplied_passwords_open_encrypted_documents() {
        // Its user password is "secret".
        let pdf = include_bytes!("../../../tests/corpus/malicious/password-javascript.pdf");
        let closed = unsafe { malmal_scanner_new(0, ptr::null(), 0) };
        let (_, report) = scan(closed, pdf, c"a.pdf");
        assert!(report.contains("cannot be inspected"), "{report}");

        let passwords = "wrong\r\n\nsecret\n";
        let opened = unsafe {
            malmal_scanner_new_with_passwords(
                0,
                ptr::null(),
                0,
                passwords.as_ptr().cast(),
                passwords.len(),
            )
        };
        let (verdict, report) = scan(opened, pdf, c"a.pdf");
        assert_eq!(verdict, 2);
        assert!(report.contains("a supplied password"), "{report}");
        unsafe {
            malmal_scanner_free(closed);
            malmal_scanner_free(opened);
        }
    }

    #[test]
    fn allowed_codes_leave_a_file_clean() {
        let form = b"%PDF-1.7\n1 0 obj << /Type /Catalog /AcroForm << /XFA 2 0 R >> >> endobj\n\
            2 0 obj << /Length 0 >> stream\n\nendstream endobj\n\
            trailer << /Root 1 0 R >>\n%%EOF\n";
        let new = |allow: &CStr, error: &mut *mut c_char| unsafe {
            malmal_scanner_new_with_allow(1, ptr::null(), 0, ptr::null(), 0, allow.as_ptr(), error)
        };
        let mut error = ptr::dangling_mut::<c_char>();
        let strict = new(c"", &mut error);
        assert!(error.is_null());
        assert_eq!(scan(strict, form, c"a.pdf").0, 2);

        let allowing = new(c" pdf.embedded_file | pdf.xfa ", &mut error);
        assert!(error.is_null());
        let (verdict, report) = scan(allowing, form, c"a.pdf");
        assert_eq!(verdict, MALMAL_CLEAN, "{report}");
        assert!(report.contains(r#""code":"pdf.xfa""#), "{report}");

        for (allow, expected) in [
            (c"pdf.embeddedfile", "unknown finding code"),
            (c"limit.time", "never"),
        ] {
            assert!(new(allow, &mut error).is_null());
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            assert!(message.contains(expected), "{message}");
            unsafe { malmal_string_free(error) };
        }
        let bad_list = c"not a digest";
        let scanner = unsafe {
            malmal_scanner_new_with_allow(
                0,
                bad_list.as_ptr(),
                bad_list.count_bytes(),
                ptr::null(),
                0,
                ptr::null(),
                &mut error,
            )
        };
        assert!(scanner.is_null() && !error.is_null());
        // Nowhere to put the message is not an error of its own.
        let scanner = unsafe {
            malmal_scanner_new_with_allow(
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                c"x".as_ptr(),
                ptr::null_mut(),
            )
        };
        assert!(scanner.is_null());
        unsafe {
            malmal_string_free(error);
            malmal_scanner_free(strict);
            malmal_scanner_free(allowing);
        }
    }

    fn new_json(options: &CStr) -> Result<*mut malmal_scanner, String> {
        let mut error = ptr::dangling_mut::<c_char>();
        let scanner = unsafe { malmal_scanner_new_json(options.as_ptr(), &mut error) };
        if scanner.is_null() {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { malmal_string_free(error) };
            return Err(message);
        }
        assert!(error.is_null());
        Ok(scanner)
    }

    #[test]
    fn json_options_reach_the_scanner() {
        let form = b"%PDF-1.7\n1 0 obj << /Type /Catalog /AcroForm << /XFA 2 0 R >> >> endobj\n\
            2 0 obj << /Length 0 >> stream\n\nendstream endobj\n\
            trailer << /Root 1 0 R >>\n%%EOF\n";
        let default = new_json(c"{}").unwrap();
        assert_eq!(scan(default, form, c"a.pdf").0, 1);
        let documents = new_json(cr#"{"policy": "documents", "wait": 60}"#).unwrap();
        let (verdict, report) = scan(documents, form, c"a.pdf");
        assert_eq!(verdict, MALMAL_CLEAN, "{report}");
        assert_eq!(unsafe { malmal_scanner_overdue(documents) }, 0);

        let images = new_json(cr#"{"types": ["png"], "without_hash": true}"#).unwrap();
        let (verdict, report) = scan(images, form, c"a.pdf");
        assert_eq!(verdict, 1, "{report}");
        assert!(report.contains("type.not_allowed"), "{report}");
        assert!(report.contains(r#""sha256":"""#), "{report}");

        let error = new_json(cr#"{"policy": "strict", "alow": []}"#).unwrap_err();
        assert!(error.contains("unknown field `alow`"), "{error}");
        // No options at all are the defaults.
        let scanner = unsafe { malmal_scanner_new_json(ptr::null(), ptr::null_mut()) };
        assert!(!scanner.is_null());
        assert_eq!(unsafe { malmal_scanner_overdue(ptr::null()) }, 0);

        let version = unsafe { CStr::from_ptr(malmal_version()) }
            .to_str()
            .unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        unsafe {
            for scanner in [default, documents, images, scanner] {
                malmal_scanner_free(scanner);
            }
        }
    }

    #[test]
    fn sanitize_takes_json_options() {
        let scanner = new_json(c"{}").unwrap();
        let run = |options: &CStr| {
            let (mut image, mut image_len, mut json) = (ptr::null_mut(), 0, ptr::null_mut());
            let status = unsafe {
                malmal_sanitize_json(
                    scanner,
                    PNG.as_ptr(),
                    PNG.len(),
                    ptr::null(),
                    ptr::null(),
                    options.as_ptr(),
                    &mut image,
                    &mut image_len,
                    &mut json,
                )
            };
            let info = unsafe { CStr::from_ptr(json) }
                .to_string_lossy()
                .into_owned();
            unsafe {
                malmal_bytes_free(image, image_len);
                malmal_string_free(json);
            }
            (status, image_len, info)
        };
        let (status, len, info) = run(cr#"{"jpeg_quality": 80, "types": ["png"]}"#);
        assert_eq!(status, MALMAL_CLEAN, "{info}");
        assert!(len > 0);
        let (status, _, info) = run(cr#"{"types": ["jpeg"]}"#);
        assert_eq!(status, MALMAL_NOT_REBUILT, "{info}");
        let (status, len, info) = run(cr#"{"pdf_dpi": 5}"#);
        assert_eq!((status, len), (MALMAL_ERROR, 0));
        assert!(info.contains("pdf_dpi"), "{info}");
        unsafe { malmal_scanner_free(scanner) };
    }

    #[test]
    fn rejects_invalid_arguments() {
        let bad_list = c"not a digest";
        let scanner = unsafe { malmal_scanner_new(1, bad_list.as_ptr(), bad_list.count_bytes()) };
        assert!(scanner.is_null());

        let mut json = ptr::dangling_mut::<c_char>();
        let verdict = unsafe {
            malmal_scan(
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                &mut json,
            )
        };
        assert_eq!(verdict, MALMAL_ERROR);
        assert!(json.is_null());
        unsafe {
            malmal_scanner_free(ptr::null_mut());
            malmal_string_free(ptr::null_mut());
        }
    }
}
