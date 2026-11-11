#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(name) = std::str::from_utf8(data) {
        let _ = keres::sanitize::sanitize_stored_name(name);
        let _ = keres::sanitize::validate_new_name(name);
    }
});
