//! Shared harness for the fuzz targets. Each target fixes the first bytes of
//! the input to one format's signature so the fuzzer spends its time inside
//! that format's parser. The property under test is the same everywhere: any
//! input produces a report, without panicking, hanging or exhausting memory.

use std::sync::LazyLock;
use std::time::Duration;

use malmal::cdr::{Inks, Options, Profiles, rebuild};
use malmal::{Limits, ScanHints, Scanner, Severity, Verdict};

static SCANNER: LazyLock<Scanner> = LazyLock::new(|| {
    Scanner::builder()
        .limits(Limits {
            // Small budgets keep each execution fast; the limit paths are
            // part of what gets exercised.
            max_decompressed: 4 << 20,
            max_duration: Duration::from_secs(2),
            ..Limits::default()
        })
        .build()
});

pub fn scan_with_prefix(prefix: &[u8], data: &[u8]) {
    let mut input = Vec::with_capacity(prefix.len() + data.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(data);
    let report = SCANNER.scan_bytes(&input, ScanHints::default());
    // A file the scanner could not finish must never come back clean.
    let hit_limit = report.findings.iter().any(|f| f.code.starts_with("limit."));
    assert!(!(hit_limit && report.verdict == malmal::Verdict::Clean));
}

/// What the rebuild targets are here to find; a panic would be caught on
/// the way.
fn fail(what: std::fmt::Arguments<'_>) -> ! {
    eprintln!("{what}");
    std::process::abort()
}

/// Rebuild `data` and check what comes out: a file the scanner finds
/// nothing in, apart from what the pixels themselves spell (that is for the
/// scan `sanitize` makes of the rebuilt file, which this leaves out to
/// reach further), and of the type it says it is. Inks are kept as inks,
/// and colours in their profile, when `keep_inks`.
pub fn rebuild_checked(data: &[u8], keep_inks: bool) {
    // `rebuild` catches a panic in a codec and answers with an error. The
    // fuzzer's own hook would stop at the first one, long before anything
    // that gets past that is found.
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));

    let limits = Limits {
        max_pixels: 1 << 20,
        max_decompressed: 64 << 20,
        ..Limits::default()
    };
    let mut options = Options::default();
    if keep_inks {
        options.inks = Inks::Keep;
        options.profiles = Profiles::Keep;
    }
    if let Ok(image) = rebuild(data, &limits, &options) {
        let report = Scanner::builder()
            .build()
            .scan_bytes(&image.data, ScanHints::default());
        let in_pixels = |code: &str| code == "image.polyglot" || code.starts_with("payload.");
        let clean = report.verdict == Verdict::Clean
            || report
                .findings
                .iter()
                .all(|finding| in_pixels(finding.code) || finding.severity == Severity::Info);
        if !clean {
            fail(format_args!("rebuilt file is not clean: {:?}", report.findings));
        }
        if report.detected_type != image.file_type {
            fail(format_args!(
                "rebuilt as {:?}, detected as {:?}",
                image.file_type, report.detected_type
            ));
        }
    }
}
