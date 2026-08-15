#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sovereign_node::audit::verify_audit_segment_bytes(data);
});
