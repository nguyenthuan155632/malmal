#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| malmal_fuzz::scan_with_prefix(b"II+\0\x08\0\0\0", data));
