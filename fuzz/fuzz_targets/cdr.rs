#![no_main]

use libfuzzer_sys::fuzz_target;

// Every type the rebuild reads, from whatever the input starts with.
fuzz_target!(|data: &[u8]| malmal_fuzz::rebuild_checked(data, false));
