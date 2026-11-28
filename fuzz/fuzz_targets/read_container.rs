#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // HKDF-kind parsing skips Argon2id, so every iteration reaches the header,
    // chunk and trailer parsers. The seed corpus contains authenticating
    // inputs. The padding header decoder is normally gated behind a valid
    // AEAD record, so exercise it directly here as well.
    let _ = keres::fuzz_support::read_hkdf_file(data, "");
    let _ = keres::fuzz_support::parse_padding_header(data);
});
