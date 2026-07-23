#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ram_fileserver::fuzzing::digest_auth_params(data);
});
