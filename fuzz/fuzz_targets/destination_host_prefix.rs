#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ram_fileserver::fuzzing::destination_host_prefix(data);
});
