#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| malmal_fuzz::scan_with_prefix(b"\0\0\x01\0", data));
