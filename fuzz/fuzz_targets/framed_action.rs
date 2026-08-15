#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sovereign_node::transport::decode_length_prefixed_action(data, 1024 * 1024);
});
