#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sovereign_node::workload::decode_signed_workload(data);
});
