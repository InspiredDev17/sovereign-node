use proptest::prelude::*;
use sovereign_node::audit::verify_audit_segment_bytes;
use sovereign_node::config::validate_public_read_path;
use sovereign_node::resources::{ResourceSnapshotV1, SignedResourceSnapshotV1};
use sovereign_node::transport::decode_length_prefixed_action;
use sovereign_node::workload::decode_signed_workload;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn framed_action_decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = decode_length_prefixed_action(&data, 4096);
    }

    #[test]
    fn workload_decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = decode_signed_workload(&data);
    }

    #[test]
    fn strict_resource_snapshot_json_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = serde_json::from_slice::<SignedResourceSnapshotV1>(&data);
        let _ = serde_json::from_slice::<ResourceSnapshotV1>(&data);
    }

    #[test]
    fn file_read_path_policy_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(value) = std::str::from_utf8(&data) {
            let _ = validate_public_read_path(value);
        }
    }

    #[test]
    fn audit_segment_verifier_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = verify_audit_segment_bytes(&data);
    }
}
