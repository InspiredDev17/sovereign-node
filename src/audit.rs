//! Bounded, local-only export of the redacted audit journal.
//!
//! Exporting does not mutate state, contact a network, or grant remote access.
//! The node device key signs a canonical page so an owner can verify origin and
//! detect changes after export. This is evidence, not remote attestation.

use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::{IdentityError, NodeIdentity};
use crate::protocol::{NodeId, PublicKeyBytes, Sha256Digest, SignatureBytes, UnixMillis};
use crate::store::{
    ActionAuditContextV1, AuditEvent, AuditKind, StateStore, StoreError, TerminalResponseMetadata,
};

const AUDIT_EXPORT_DOMAIN: &[u8] = b"sovereign-node/local-audit-export/v1\0";
pub const MAX_AUDIT_EXPORT_EVENTS: u32 = 1_000;
pub const MAX_AUDIT_EXPORT_JSON_BYTES: u64 = 32 * 1_024 * 1_024;

#[derive(Debug, Error)]
pub enum AuditExportError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("audit export encoding failed: {0}")]
    Codec(#[from] postcard::Error),
    #[error("audit export is invalid: {0}")]
    Invalid(&'static str),
    #[error("audit export signature is invalid")]
    InvalidSignature,
    #[error("audit export JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit export file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit export exceeds the bounded JSON input limit")]
    ResourceLimit,
    #[error("audit export does not match the pinned {0}")]
    PinMismatch(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditActionSnapshotV1 {
    pub context: ActionAuditContextV1,
    pub context_digest: [u8; 32],
    pub reserved_at_unix_ms: i64,
    pub execution_started_at_unix_ms: Option<i64>,
    pub terminal: Option<TerminalResponseMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportV1 {
    pub schema_version: u16,
    pub node_id: NodeId,
    pub node_key_id: Sha256Digest,
    pub generated_at: UnixMillis,
    pub after_sequence: u64,
    pub requested_limit: u32,
    pub anchor_hash: Sha256Digest,
    pub chain_event_count: u64,
    pub chain_tail_hash: Sha256Digest,
    pub has_more: bool,
    pub events: Vec<AuditEvent>,
    pub actions: Vec<AuditActionSnapshotV1>,
}

impl AuditExportV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuditExportError> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self)?;
        let mut message = Vec::with_capacity(AUDIT_EXPORT_DOMAIN.len() + encoded.len());
        message.extend_from_slice(AUDIT_EXPORT_DOMAIN);
        message.extend_from_slice(&encoded);
        Ok(message)
    }

    pub fn validate(&self) -> Result<(), AuditExportError> {
        if self.schema_version != 1 {
            return Err(AuditExportError::Invalid("unsupported schema version"));
        }
        if self.node_id.0.is_nil() {
            return Err(AuditExportError::Invalid("node ID is nil"));
        }
        if self.requested_limit == 0 || self.requested_limit > MAX_AUDIT_EXPORT_EVENTS {
            return Err(AuditExportError::Invalid("event limit is out of range"));
        }
        if self.after_sequence > self.chain_event_count
            || self.events.len() > self.requested_limit as usize
        {
            return Err(AuditExportError::Invalid("event window is inconsistent"));
        }
        if self.after_sequence == 0 && self.anchor_hash.0 != [0_u8; 32] {
            return Err(AuditExportError::Invalid(
                "genesis page anchor is not the zero hash",
            ));
        }

        let mut previous_hash = self.anchor_hash.0;
        let mut expected_sequence = self
            .after_sequence
            .checked_add(1)
            .ok_or(AuditExportError::Invalid("event sequence overflow"))?;
        let mut request_ids = BTreeSet::new();
        for event in &self.events {
            if event.sequence != expected_sequence || event.previous_hash != previous_hash {
                return Err(AuditExportError::Invalid("event page linkage is invalid"));
            }
            event.verify_hash()?;
            if let Some(request_id) = event.request_id {
                request_ids.insert(request_id);
            }
            previous_hash = event.event_hash;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(AuditExportError::Invalid("event sequence overflow"))?;
        }
        let last_sequence = self
            .events
            .last()
            .map_or(self.after_sequence, |event| event.sequence);
        if last_sequence > self.chain_event_count
            || self.has_more != (last_sequence < self.chain_event_count)
            || (self.has_more && self.events.is_empty())
        {
            return Err(AuditExportError::Invalid(
                "pagination marker is inconsistent",
            ));
        }
        if !self.has_more && previous_hash != self.chain_tail_hash.0 {
            return Err(AuditExportError::Invalid(
                "terminal page does not reach chain tail",
            ));
        }

        let mut action_ids = BTreeSet::new();
        for action in &self.actions {
            if !request_ids.contains(&action.context.request_id)
                || !action_ids.insert(action.context.request_id)
                || action.context.digest()? != action.context_digest
                || action.reserved_at_unix_ms < 0
                || action
                    .execution_started_at_unix_ms
                    .is_some_and(|started| started < action.reserved_at_unix_ms)
            {
                return Err(AuditExportError::Invalid("action context is inconsistent"));
            }
            if let Some(terminal) = &action.terminal
                && terminal.completed_at_unix_ms < action.reserved_at_unix_ms
            {
                return Err(AuditExportError::Invalid("terminal timing is inconsistent"));
            }
        }

        for event in &self.events {
            let Some(request_id) = event.request_id else {
                continue;
            };
            let Some(action) = self
                .actions
                .iter()
                .find(|action| action.context.request_id == request_id)
            else {
                continue;
            };
            if (event.kind == AuditKind::RequestReserved
                && event.context_digest != Some(action.context_digest))
                || (event.kind == AuditKind::ExecutionStarted
                    && event.subject_digest != Some(action.context_digest))
            {
                return Err(AuditExportError::Invalid(
                    "action context does not match its audit event",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditVerificationReceiptV1 {
    pub schema_version: u16,
    pub verification: &'static str,
    pub node_id: String,
    pub node_key_id_sha256: String,
    pub export_generated_at_unix_ms: u64,
    pub after_sequence: u64,
    pub anchor_sha256: String,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub event_count: u32,
    pub action_context_count: u32,
    pub chain_event_count: u64,
    pub chain_tail_sha256: String,
    pub has_more: bool,
    pub continuation_after_sequence: u64,
    pub continuation_anchor_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditExportV1 {
    pub export: AuditExportV1,
    pub node_public_key: PublicKeyBytes,
    pub node_signature: SignatureBytes,
}

impl SignedAuditExportV1 {
    pub fn verify(&self) -> Result<(), AuditExportError> {
        self.export.validate()?;
        let key = VerifyingKey::from_bytes(&self.node_public_key.0)
            .map_err(|_| AuditExportError::InvalidSignature)?;
        if key.is_weak()
            || Sha256Digest(Sha256::digest(self.node_public_key.0).into())
                != self.export.node_key_id
        {
            return Err(AuditExportError::InvalidSignature);
        }
        let signature = Signature::from_slice(self.node_signature.as_bytes())
            .map_err(|_| AuditExportError::InvalidSignature)?;
        key.verify_strict(&self.export.signing_bytes()?, &signature)
            .map_err(|_| AuditExportError::InvalidSignature)
    }
}

/// Verify a strict JSON page against owner-retained identity and chain pins.
pub fn verify_audit_export_bytes(
    input: &[u8],
    expected_node_id: NodeId,
    expected_node_key_id: Sha256Digest,
    expected_after_sequence: u64,
    expected_anchor_hash: Sha256Digest,
) -> Result<AuditVerificationReceiptV1, AuditExportError> {
    if input.len() > MAX_AUDIT_EXPORT_JSON_BYTES as usize {
        return Err(AuditExportError::ResourceLimit);
    }
    let signed: SignedAuditExportV1 = serde_json::from_slice(input)?;
    signed.verify()?;
    if signed.export.node_id != expected_node_id {
        return Err(AuditExportError::PinMismatch("NodeId"));
    }
    if signed.export.node_key_id != expected_node_key_id {
        return Err(AuditExportError::PinMismatch("node device key ID"));
    }
    if signed.export.after_sequence != expected_after_sequence {
        return Err(AuditExportError::PinMismatch("page cursor"));
    }
    if signed.export.anchor_hash != expected_anchor_hash {
        return Err(AuditExportError::PinMismatch("page anchor"));
    }

    let first_sequence = signed.export.events.first().map(|event| event.sequence);
    let last_event = signed.export.events.last();
    let last_sequence = last_event.map(|event| event.sequence);
    let continuation_after_sequence = last_sequence.unwrap_or(signed.export.after_sequence);
    let continuation_anchor_sha256 = last_event.map_or_else(
        || hex::encode(signed.export.chain_tail_hash.0),
        |event| hex::encode(event.event_hash),
    );
    Ok(AuditVerificationReceiptV1 {
        schema_version: 1,
        verification: "verified",
        node_id: signed.export.node_id.to_string(),
        node_key_id_sha256: hex::encode(signed.export.node_key_id.0),
        export_generated_at_unix_ms: signed.export.generated_at.0,
        after_sequence: signed.export.after_sequence,
        anchor_sha256: hex::encode(signed.export.anchor_hash.0),
        first_sequence,
        last_sequence,
        event_count: u32::try_from(signed.export.events.len())
            .map_err(|_| AuditExportError::ResourceLimit)?,
        action_context_count: u32::try_from(signed.export.actions.len())
            .map_err(|_| AuditExportError::ResourceLimit)?,
        chain_event_count: signed.export.chain_event_count,
        chain_tail_sha256: hex::encode(signed.export.chain_tail_hash.0),
        has_more: signed.export.has_more,
        continuation_after_sequence,
        continuation_anchor_sha256,
    })
}

/// Read and verify one untrusted export file without following a final symlink
/// or accepting devices, FIFOs, sockets, directories, or unbounded input.
pub fn verify_audit_export_file(
    path: &Path,
    expected_node_id: NodeId,
    expected_node_key_id: Sha256Digest,
    expected_after_sequence: u64,
    expected_anchor_hash: Sha256Digest,
) -> Result<AuditVerificationReceiptV1, AuditExportError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    let length = metadata.len();
    if !metadata.is_file() {
        return Err(AuditExportError::Invalid(
            "audit export input is not a regular file",
        ));
    }
    if length > MAX_AUDIT_EXPORT_JSON_BYTES {
        return Err(AuditExportError::ResourceLimit);
    }
    let capacity = usize::try_from(length).map_err(|_| AuditExportError::ResourceLimit)?;
    let mut input = Vec::with_capacity(capacity);
    file.take(MAX_AUDIT_EXPORT_JSON_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    verify_audit_export_bytes(
        &input,
        expected_node_id,
        expected_node_key_id,
        expected_after_sequence,
        expected_anchor_hash,
    )
}

pub fn export_local_audit(
    store: &StateStore,
    identity: &NodeIdentity,
    after_sequence: u64,
    limit: u32,
    generated_at: UnixMillis,
) -> Result<SignedAuditExportV1, AuditExportError> {
    if limit == 0 || limit > MAX_AUDIT_EXPORT_EVENTS {
        return Err(AuditExportError::Invalid("event limit is out of range"));
    }
    let query_limit = limit
        .checked_add(1)
        .ok_or(AuditExportError::Invalid("event limit overflow"))?;
    let snapshot = store.audit_read_snapshot(after_sequence, query_limit)?;
    let chain = snapshot.chain;
    let mut events = snapshot.events;
    if after_sequence > chain.event_count {
        return Err(AuditExportError::Invalid(
            "after sequence exceeds the current audit tail",
        ));
    }
    events.truncate(limit as usize);
    let last_sequence = events.last().map_or(after_sequence, |event| event.sequence);
    if (events.is_empty() && after_sequence < chain.event_count)
        || last_sequence > chain.event_count
    {
        return Err(AuditExportError::Invalid(
            "audit journal changed during export; retry",
        ));
    }
    let has_more = last_sequence < chain.event_count;
    let anchor_hash = events
        .first()
        .map_or(chain.tail_hash, |event| event.previous_hash);

    let included_request_ids = events
        .iter()
        .filter_map(|event| event.request_id)
        .collect::<BTreeSet<_>>();
    let actions = snapshot
        .actions
        .into_iter()
        .filter(|record| included_request_ids.contains(&record.context.request_id))
        .map(|record| AuditActionSnapshotV1 {
            context: record.context,
            context_digest: record.context_digest,
            reserved_at_unix_ms: record.reserved_at_unix_ms,
            execution_started_at_unix_ms: record.execution_started_at_unix_ms,
            terminal: record.terminal,
        })
        .collect();

    let export = AuditExportV1 {
        schema_version: 1,
        node_id: identity.node_id(),
        node_key_id: identity.key_id(),
        generated_at,
        after_sequence,
        requested_limit: limit,
        anchor_hash: Sha256Digest(anchor_hash),
        chain_event_count: chain.event_count,
        chain_tail_hash: Sha256Digest(chain.tail_hash),
        has_more,
        events,
        actions,
    };
    let node_signature = identity.sign(&export.signing_bytes()?)?;
    let signed = SignedAuditExportV1 {
        export,
        node_public_key: identity.public_key(),
        node_signature,
    };
    signed.verify()?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        AuditEventDraft, AuditOutcome, PairingApproval, PendingPairingChallenge, ReplayOutcome,
        ReplayReservation, sha256,
    };
    use uuid::Uuid;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn local_export_is_bounded_signed_paginated_and_tamper_evident() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let identity_dir = directory.path().join("identity");
        let (identity, _) = NodeIdentity::load_or_initialize(
            &identity_dir,
            "audit-export-test",
            UnixMillis(10_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        for index in 0..3_i64 {
            store.append_audit(AuditEventDraft {
                occurred_at_unix_ms: 10_001 + index,
                kind: AuditKind::AuthorizationRejected,
                outcome: AuditOutcome::Rejected,
                request_id: None,
                actor_digest: Some(sha256(b"agent")),
                subject_digest: Some(sha256(b"node")),
                context_digest: Some(sha256(b"redacted reason")),
            })?;
        }

        let first = export_local_audit(&store, &identity, 0, 2, UnixMillis(10_010))?;
        first.verify()?;
        assert_eq!(first.export.events.len(), 2);
        assert!(first.export.has_more);
        assert!(first.export.actions.is_empty());
        assert_eq!(first.export.chain_event_count, 3);

        let first_json = serde_json::to_vec_pretty(&first)?;
        let receipt = verify_audit_export_bytes(
            &first_json,
            identity.node_id(),
            identity.key_id(),
            0,
            Sha256Digest([0_u8; 32]),
        )?;
        assert_eq!(receipt.verification, "verified");
        assert_eq!(receipt.first_sequence, Some(1));
        assert_eq!(receipt.last_sequence, Some(2));
        assert_eq!(receipt.event_count, 2);
        assert_eq!(receipt.continuation_after_sequence, 2);
        assert_eq!(
            receipt.continuation_anchor_sha256,
            hex::encode(first.export.events[1].event_hash)
        );

        assert!(matches!(
            verify_audit_export_bytes(
                &first_json,
                NodeId(Uuid::new_v4()),
                identity.key_id(),
                0,
                Sha256Digest([0_u8; 32]),
            ),
            Err(AuditExportError::PinMismatch("NodeId"))
        ));
        assert!(matches!(
            verify_audit_export_bytes(
                &first_json,
                identity.node_id(),
                Sha256Digest([0x55; 32]),
                0,
                Sha256Digest([0_u8; 32]),
            ),
            Err(AuditExportError::PinMismatch("node device key ID"))
        ));
        assert!(matches!(
            verify_audit_export_bytes(
                &first_json,
                identity.node_id(),
                identity.key_id(),
                1,
                Sha256Digest([0_u8; 32]),
            ),
            Err(AuditExportError::PinMismatch("page cursor"))
        ));
        assert!(matches!(
            verify_audit_export_bytes(
                &first_json,
                identity.node_id(),
                identity.key_id(),
                0,
                Sha256Digest([0x55; 32]),
            ),
            Err(AuditExportError::PinMismatch("page anchor"))
        ));

        let second = export_local_audit(&store, &identity, 2, 2, UnixMillis(10_011))?;
        second.verify()?;
        assert_eq!(second.export.events.len(), 1);
        assert!(!second.export.has_more);
        assert_eq!(
            second.export.anchor_hash.0,
            first.export.events[1].event_hash
        );

        let mut tampered = second.clone();
        tampered.export.events[0].outcome = AuditOutcome::Accepted;
        assert!(tampered.verify().is_err());

        let mut wrong_key = first.clone();
        wrong_key.node_public_key = PublicKeyBytes([0x42; 32]);
        assert!(wrong_key.verify().is_err());

        let mut wrong_signature = first.clone();
        wrong_signature.node_signature = SignatureBytes::from_slice(&[0_u8; 64])?;
        assert!(wrong_signature.verify().is_err());

        let mut wrong_cursor = first.clone();
        wrong_cursor.export.after_sequence = 1;
        assert!(wrong_cursor.verify().is_err());

        let mut wrong_genesis_anchor = first.clone();
        wrong_genesis_anchor.export.anchor_hash = Sha256Digest([0x55; 32]);
        assert!(wrong_genesis_anchor.export.validate().is_err());

        let mut empty_progress = first.clone();
        empty_progress.export.events.clear();
        assert!(empty_progress.export.validate().is_err());

        let mut forged_json = serde_json::to_value(&first)?;
        forged_json["export"]["generated_at"] = serde_json::json!(99_999);
        assert!(
            verify_audit_export_bytes(
                &serde_json::to_vec(&forged_json)?,
                identity.node_id(),
                identity.key_id(),
                0,
                Sha256Digest([0_u8; 32]),
            )
            .is_err()
        );
        assert!(
            verify_audit_export_bytes(
                b"{malformed",
                identity.node_id(),
                identity.key_id(),
                0,
                Sha256Digest([0_u8; 32]),
            )
            .is_err()
        );
        assert!(matches!(
            verify_audit_export_bytes(
                &vec![b'x'; MAX_AUDIT_EXPORT_JSON_BYTES as usize + 1],
                identity.node_id(),
                identity.key_id(),
                0,
                Sha256Digest([0_u8; 32]),
            ),
            Err(AuditExportError::ResourceLimit)
        ));

        let mut extended = serde_json::to_value(&first)?;
        extended["export"]["events"][0]["untrusted_extra"] = serde_json::json!("misleading");
        assert!(serde_json::from_value::<SignedAuditExportV1>(extended).is_err());
        Ok(())
    }

    #[test]
    fn offline_verifier_reads_only_a_bounded_regular_nofollow_file() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let (identity, _) = NodeIdentity::load_or_initialize(
            &directory.path().join("identity"),
            "audit-verify-test",
            UnixMillis(10_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        let signed = export_local_audit(&store, &identity, 0, 10, UnixMillis(10_001))?;
        let export_path = directory.path().join("audit.json");
        std::fs::write(&export_path, serde_json::to_vec_pretty(&signed)?)?;

        let receipt = verify_audit_export_file(
            &export_path,
            identity.node_id(),
            identity.key_id(),
            0,
            Sha256Digest([0_u8; 32]),
        )?;
        assert_eq!(receipt.event_count, 0);
        assert_eq!(receipt.first_sequence, None);
        assert_eq!(receipt.last_sequence, None);
        assert!(!receipt.has_more);
        assert_eq!(receipt.continuation_after_sequence, 0);
        assert_eq!(receipt.continuation_anchor_sha256, hex::encode([0_u8; 32]));

        assert!(
            verify_audit_export_file(
                directory.path(),
                identity.node_id(),
                identity.key_id(),
                0,
                Sha256Digest([0_u8; 32]),
            )
            .is_err()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let link = directory.path().join("audit-link.json");
            symlink(&export_path, &link)?;
            assert!(
                verify_audit_export_file(
                    &link,
                    identity.node_id(),
                    identity.key_id(),
                    0,
                    Sha256Digest([0_u8; 32]),
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn local_export_rejects_invalid_bounds_and_future_cursor() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let (identity, _) = NodeIdentity::load_or_initialize(
            &directory.path().join("identity"),
            "audit-export-test",
            UnixMillis(10_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        assert!(export_local_audit(&store, &identity, 0, 0, UnixMillis(10_001)).is_err());
        assert!(
            export_local_audit(
                &store,
                &identity,
                0,
                MAX_AUDIT_EXPORT_EVENTS + 1,
                UnixMillis(10_001),
            )
            .is_err()
        );
        assert!(export_local_audit(&store, &identity, 1, 1, UnixMillis(10_001)).is_err());
        Ok(())
    }

    #[test]
    fn action_export_links_redacted_context_without_raw_request_values() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let (identity, _) = NodeIdentity::load_or_initialize(
            &directory.path().join("identity"),
            "audit-export-test",
            UnixMillis(10_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        let challenge_secret = b"0123456789abcdef0123456789abcdef";
        let pending = PendingPairingChallenge::new(
            Uuid::new_v4(),
            "raw-node-identifier".to_owned(),
            "raw-peer-identifier".to_owned(),
            "Local Broker".to_owned(),
            vec![7_u8; 32],
            vec![vec![8_u8; 32]],
            challenge_secret,
            sha256(b"node identity"),
            sha256(b"transport binding"),
            10_001,
            20_000,
        )?;
        store.put_pending_pairing(&pending)?;
        let (_, peer) = store.approve_pairing(
            &PairingApproval {
                pairing_id: pending.pairing_id,
                owner_authority_digest: sha256(b"owner authority"),
                capability_manifest_digest: sha256(b"manifest"),
                approved_at_unix_ms: 10_002,
                trust_expires_at_unix_ms: None,
            },
            challenge_secret,
        )?;
        let policy_digest = sha256(b"policy");
        store.activate_policy(1, policy_digest, 10_003)?;
        let request = ReplayReservation {
            request_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            pairing_id: peer.pairing_id,
            trust_epoch: peer.trust_epoch,
            policy_version: 1,
            policy_digest,
            replay_sequence: 1,
            replay_nonce: sha256(b"nonce"),
            agent_id: "raw-agent-identifier".to_owned(),
            node_id: "raw-node-identifier".to_owned(),
            authority_id_digest: sha256(b"raw-authority-identifier"),
            owner_id_digest: sha256(b"raw-owner-identifier"),
            capability: "SystemInfo".to_owned(),
            target_digest: sha256(b"raw-target-value"),
            arguments_digest: sha256(b"raw-argument-value"),
            authorization_digest: sha256(b"signed envelope"),
            issued_at_unix_ms: 10_003,
            not_before_unix_ms: 10_003,
            expires_at_unix_ms: 20_000,
        };
        let fingerprint = request.fingerprint()?;
        let context_digest = match store.reserve_validated_replay_at(&request, 10_004)? {
            ReplayOutcome::Reserved {
                action_context_digest,
                ..
            } => action_context_digest,
            _ => return Err("fresh audit request was not reserved".into()),
        };
        store.record_execution_started(request.request_id, fingerprint, context_digest, 10_005)?;

        let signed = export_local_audit(&store, &identity, 0, 100, UnixMillis(10_006))?;
        signed.verify()?;
        assert_eq!(signed.export.actions.len(), 1);
        assert_eq!(
            signed.export.actions[0].context.request_id,
            request.request_id
        );
        assert_eq!(
            signed.export.actions[0].execution_started_at_unix_ms,
            Some(10_005)
        );
        let json = serde_json::to_string(&signed)?;
        for excluded in [
            "raw-agent-identifier",
            "raw-node-identifier",
            "raw-peer-identifier",
            "raw-authority-identifier",
            "raw-owner-identifier",
            "raw-target-value",
            "raw-argument-value",
        ] {
            assert!(!json.contains(excluded), "export leaked {excluded}");
        }
        Ok(())
    }
}
