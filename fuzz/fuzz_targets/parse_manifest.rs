#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keres::fuzz_support::parse_manifest(data);
});
