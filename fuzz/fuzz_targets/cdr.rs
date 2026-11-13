#![no_main]

use libfuzzer_sys::fuzz_target;
use malmal::cdr::{Options, rebuild};
use malmal::{Limits, ScanHints, Scanner, Verdict};

// Whatever is rebuilt must be a file the scanner finds nothing in, apart
// from what the pixels themselves spell: that is for the scan `sanitize`
// makes of the rebuilt file, which this target leaves out to reach further.
fuzz_target!(|data: &[u8]| {
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
                in_pixels(finding.code) || finding.severity == malmal::Severity::Info
            });
        assert!(clean, "{:?}", report.findings);
        assert_eq!(report.detected_type, image.file_type);
    }
});
