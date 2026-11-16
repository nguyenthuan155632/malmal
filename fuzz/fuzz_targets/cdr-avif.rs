#![no_main]

use libfuzzer_sys::fuzz_target;

// The rebuild of AVIF: HEIF items, grids, alpha, the AV1 decoder and colours kept. Starts from the seeds of
// this target, which hold files of the kind.
fuzz_target!(|data: &[u8]| malmal_fuzz::rebuild_checked(data, data.len() % 2 == 1));
