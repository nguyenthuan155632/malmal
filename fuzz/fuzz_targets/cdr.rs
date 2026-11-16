#![no_main]

use libfuzzer_sys::fuzz_target;

// Every type the rebuild reads, from whatever the input starts with; inks and profiles kept
// for half the inputs.
fuzz_target!(|data: &[u8]| malmal_fuzz::rebuild_checked(data, data.len() % 2 == 1));
