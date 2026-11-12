#![no_main]

use libfuzzer_sys::fuzz_target;
use malmal::cdr::{Options, rebuild};
use malmal::{Limits, ScanHints, Scanner, Verdict};

// Whatever is rebuilt must be an image the scanner finds nothing in.
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
        assert_eq!(report.verdict, Verdict::Clean, "{:?}", report.findings);
        assert_eq!(report.detected_type, image.file_type);
    }
});
