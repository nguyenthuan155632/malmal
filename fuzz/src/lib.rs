//! Shared harness for the fuzz targets. Each target fixes the first bytes of
//! the input to one format's signature so the fuzzer spends its time inside
//! that format's parser. The property under test is the same everywhere: any
//! input produces a report, without panicking, hanging or exhausting memory.

use std::sync::LazyLock;
use std::time::Duration;

use malmal::{Limits, ScanHints, Scanner};

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
