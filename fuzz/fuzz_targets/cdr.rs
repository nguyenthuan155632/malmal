#![no_main]

use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use malmal::cdr::{Options, rebuild};
use malmal::{Limits, ScanHints, Scanner, Severity, Verdict};

static QUIET: Once = Once::new();

/// What this target is here to find; a panic would be caught on the way.
fn fail(what: std::fmt::Arguments<'_>) -> ! {
    eprintln!("{what}");
    std::process::abort()
}

// Whatever is rebuilt must be a file the scanner finds nothing in, apart
// from what the pixels themselves spell: that is for the scan `sanitize`
// makes of the rebuilt file, which this target leaves out to reach further.
fuzz_target!(|data: &[u8]| {
    // `rebuild` catches a panic in a codec and answers with an error. The
    // fuzzer's own hook would stop at the first one, long before anything
    // that gets past that is found.
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));

    let limits = Limits {
        max_pixels: 1 << 20,
        max_decompressed: 64 << 20,
        ..Limits::default()
    };
    if let Ok(image) = rebuild(data, &limits, &Options::default()) {
        let report = Scanner::builder()
            .build()
            .scan_bytes(&image.data, ScanHints::default());
        let in_pixels = |code: &str| code == "image.polyglot" || code.starts_with("payload.");
        let clean = report.verdict == Verdict::Clean
            || report.findings.iter().all(|finding| {
                in_pixels(finding.code) || finding.severity == Severity::Info
            });
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
});
