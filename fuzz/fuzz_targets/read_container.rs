#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // HKDF-kind parsing skips Argon2id, so every iteration reaches the chunk
    // and trailer parsers. The seed corpus contains authenticating inputs.
    let _ = keres::fuzz_support::read_hkdf_file(data, "");
});
