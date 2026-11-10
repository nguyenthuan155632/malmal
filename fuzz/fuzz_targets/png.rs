#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| malmal_fuzz::scan_with_prefix(b"\x89PNG\r\n\x1a\n", data));
