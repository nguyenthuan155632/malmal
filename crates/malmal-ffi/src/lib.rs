//! C ABI over [`malmal::Scanner`]. The contract for every function is in
//! `include/malmal.h`; no panic crosses the boundary.

use std::ffi::{CStr, CString, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use malmal::{HashList, Policy, ScanHints, Scanner};

const MALMAL_ERROR: c_int = 3;

/// Opaque to C.
#[allow(non_camel_case_types)]
pub struct malmal_scanner(Scanner);

/// # Safety
/// `hashlist` must be null or point to `hashlist_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_scanner_new(
    strict: c_int,
    hashlist: *const c_char,
    hashlist_len: usize,
) -> *mut malmal_scanner {
    let text: &[u8] = if hashlist.is_null() {
        &[]
    } else {
        // SAFETY: the caller guarantees `hashlist_len` readable bytes.
        unsafe { std::slice::from_raw_parts(hashlist.cast(), hashlist_len) }
    };
    let built = catch_unwind(|| {
        let hashlist = HashList::parse(std::str::from_utf8(text).ok()?).ok()?;
        let policy = if strict != 0 {
            Policy::strict()
        } else {
            Policy::default()
        };
        Some(Scanner::builder().policy(policy).hashlist(hashlist).build())
    });
    match built {
        Ok(Some(scanner)) => Box::into_raw(Box::new(malmal_scanner(scanner))),
        _ => ptr::null_mut(),
    }
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
    if scanner.is_null() || (data.is_null() && len != 0) {
        return MALMAL_ERROR;
    }
    // SAFETY: checked non-null above; the caller guarantees validity.
    let scanner = unsafe { &(*scanner).0 };
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at `data`.
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    // SAFETY: the caller guarantees both are null or NUL-terminated.
    let (filename, content_type) = unsafe { (optional_str(filename), optional_str(content_type)) };

    let scanned = catch_unwind(AssertUnwindSafe(|| {
        let hints = ScanHints {
            filename: filename.as_deref(),
            content_type: content_type.as_deref(),
        };
        let report = scanner.scan_bytes(bytes, hints);
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
/// `string` must be null or a report returned by `malmal_scan` that has not
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malmal_string_free(string: *mut c_char) {
    if !string.is_null() {
        // SAFETY: the pointer came from CString::into_raw in malmal_scan.
        drop(unsafe { CString::from_raw(string) });
    }
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
