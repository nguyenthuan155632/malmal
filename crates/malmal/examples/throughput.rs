//! Measure scan throughput on real files:
//!
//!     cargo run --release --example throughput -- FILE...
//!
//! Each file is read once and scanned repeatedly in memory, so the numbers
//! are the scanner's own cost without disk or process start-up.

use std::time::{Duration, Instant};

use malmal::{ScanHints, Scanner};

const MIN_RUN: Duration = Duration::from_millis(300);

fn main() {
    let scanner = Scanner::builder().build();
    println!(
        "{:>9} {:>9} {:>10}  type        file",
        "size", "ms/scan", "MB/s"
    );
    for path in std::env::args().skip(1) {
        let data = match std::fs::read(&path) {
            Ok(data) => data,
            Err(error) => {
                eprintln!("{path}: {error}");
                continue;
            }
        };
        let hints = ScanHints {
            filename: Some(&path),
            content_type: None,
        };
        let started = Instant::now();
        let mut runs = 0u32;
        let mut detected = "";
        while runs == 0 || started.elapsed() < MIN_RUN {
            detected = scanner.scan_bytes(&data, hints).detected_type.as_str();
            runs += 1;
        }
        let per_scan = started.elapsed().as_secs_f64() / runs as f64;
        println!(
            "{:>9} {:>9.2} {:>10.0}  {detected:<10}  {path}",
            data.len(),
            per_scan * 1e3,
            data.len() as f64 / per_scan / 1e6,
        );
    }
}
