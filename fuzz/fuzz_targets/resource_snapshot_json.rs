#![no_main]

use libfuzzer_sys::fuzz_target;
use sovereign_node::resources::{ResourceSnapshotV1, SignedResourceSnapshotV1};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SignedResourceSnapshotV1>(data);
    let _ = serde_json::from_slice::<ResourceSnapshotV1>(data);
});
