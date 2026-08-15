//! Bounded, local-only export of the redacted audit journal.
//!
//! Exporting does not mutate state, contact a network, or grant remote access.
//! The node device key signs a canonical page so an owner can verify origin and
//! detect changes after export. This is evidence, not remote attestation.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::Path,
};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::{IdentityError, NodeIdentity};
use crate::protocol::{NodeId, PublicKeyBytes, Sha256Digest, SignatureBytes, UnixMillis};
use crate::security::{create_private_file, ensure_private_directory, read_private_file};
use crate::store::{
    ActionAuditContextV1, AuditArchiveCandidateV1, AuditEvent, AuditKind, StateStore, StoreError,
    TerminalResponseMetadata,
};

const AUDIT_EXPORT_DOMAIN: &[u8] = b"sovereign-node/local-audit-export/v1\0";
const AUDIT_SEGMENT_DOMAIN: &[u8] = b"sovereign-node/audit-segment/v1\0";
pub const MAX_AUDIT_EXPORT_EVENTS: u32 = 1_000;
pub const MAX_AUDIT_EXPORT_JSON_BYTES: u64 = 32 * 1_024 * 1_024;
pub const MAX_AUDIT_SEGMENT_BYTES: usize = 64 * 1_024 * 1_024;

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
    #[error("audit archive filesystem policy failed: {0}")]
    SecureFile(#[from] crate::security::SecureFileError),
    #[error("injected audit archive interruption after {0}")]
    InjectedFault(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSegmentV1 {
    pub schema_version: u16,
    pub format: String,
    pub signature_algorithm: String,
    pub node_id: NodeId,
    pub node_key_id: Sha256Digest,
    pub identity_generation: u64,
    pub candidate: AuditArchiveCandidateV1,
    pub content_digest: Sha256Digest,
}

impl AuditSegmentV1 {
    fn signing_bytes(&self) -> Result<Vec<u8>, AuditExportError> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self)?;
        let mut bytes = Vec::with_capacity(AUDIT_SEGMENT_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(AUDIT_SEGMENT_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), AuditExportError> {
        if self.schema_version != 1
            || self.format != "postcard-v1"
            || self.signature_algorithm != "Ed25519"
            || self.node_id.0.is_nil()
            || self.content_digest.0 != self.candidate.digest()?
        {
            return Err(AuditExportError::Invalid(
                "audit segment metadata is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditSegmentV1 {
    pub segment: AuditSegmentV1,
    pub node_public_key: PublicKeyBytes,
    pub node_signature: SignatureBytes,
}

impl SignedAuditSegmentV1 {
    pub fn verify(&self) -> Result<(), AuditExportError> {
        self.segment.validate()?;
        let key = VerifyingKey::from_bytes(&self.node_public_key.0)
            .map_err(|_| AuditExportError::InvalidSignature)?;
        if key.is_weak()
            || Sha256Digest(Sha256::digest(self.node_public_key.0).into())
                != self.segment.node_key_id
        {
            return Err(AuditExportError::InvalidSignature);
        }
        let signature = Signature::from_slice(self.node_signature.as_bytes())
            .map_err(|_| AuditExportError::InvalidSignature)?;
        key.verify_strict(&self.segment.signing_bytes()?, &signature)
            .map_err(|_| AuditExportError::InvalidSignature)
    }

    pub fn digest(&self) -> Result<Sha256Digest, AuditExportError> {
        self.verify()?;
        Ok(Sha256Digest(
            Sha256::digest(postcard::to_allocvec(self)?).into(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditArchiveResult {
    pub segment_sequence: u64,
    pub first_audit_sequence: u64,
    pub last_audit_sequence: u64,
    pub archived_events: u64,
    pub retired_replays: u64,
    pub segment_digest_sha256: String,
    pub relative_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditArchiveVerification {
    pub verification: &'static str,
    pub segment_count: u64,
    pub archived_event_count: u64,
    pub final_segment_digest_sha256: String,
    pub final_audit_hash_sha256: String,
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

/// Seal one eligible audit prefix into the owner-private archive. This is an
/// owner-local maintenance operation and never accepts a remote output path.
pub fn seal_eligible_audit_segment(
    store: &StateStore,
    identity: &NodeIdentity,
    archive_root: &Path,
    eligible_before_unix_ms: i64,
    maximum_events: u32,
    created_at: UnixMillis,
) -> Result<Option<AuditArchiveResult>, AuditExportError> {
    seal_eligible_audit_segment_inner(
        store,
        identity,
        archive_root,
        eligible_before_unix_ms,
        maximum_events,
        created_at,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_eligible_audit_segment_inner(
    store: &StateStore,
    identity: &NodeIdentity,
    archive_root: &Path,
    eligible_before_unix_ms: i64,
    maximum_events: u32,
    created_at: UnixMillis,
    injected_fault_at: Option<&'static str>,
) -> Result<Option<AuditArchiveResult>, AuditExportError> {
    ensure_private_directory(archive_root)?;
    let created_at_i64 = i64::try_from(created_at.0)
        .map_err(|_| AuditExportError::Invalid("archive time is outside supported range"))?;
    let Some(candidate) =
        store.prepare_audit_archive(eligible_before_unix_ms, maximum_events, created_at_i64)?
    else {
        return Ok(None);
    };
    if injected_fault_at == Some("pending-state") {
        return Err(AuditExportError::InjectedFault("pending-state"));
    }
    let segment = AuditSegmentV1 {
        schema_version: 1,
        format: "postcard-v1".to_owned(),
        signature_algorithm: "Ed25519".to_owned(),
        node_id: identity.node_id(),
        node_key_id: identity.key_id(),
        identity_generation: identity.cryptographic_identity().rotation_counter,
        content_digest: Sha256Digest(candidate.digest()?),
        candidate,
    };
    let signed = SignedAuditSegmentV1 {
        node_signature: identity.sign(&segment.signing_bytes()?)?,
        node_public_key: identity.public_key(),
        segment,
    };
    signed.verify()?;
    let encoded = postcard::to_allocvec(&signed)?;
    if encoded.len() > MAX_AUDIT_SEGMENT_BYTES {
        return Err(AuditExportError::ResourceLimit);
    }
    let relative_name = format!(
        "audit-segment-{:020}.postcard",
        signed.segment.candidate.segment_sequence
    );
    let final_path = archive_root.join(&relative_name);
    let temporary_path = archive_root.join(format!(".{relative_name}.pending"));
    if final_path.exists() {
        if read_private_file(&final_path)? != encoded {
            return Err(AuditExportError::Invalid(
                "existing archive segment conflicts with pending candidate",
            ));
        }
    } else {
        if temporary_path.exists() {
            if read_private_file(&temporary_path)? != encoded {
                return Err(AuditExportError::Invalid(
                    "pending archive file conflicts with durable candidate",
                ));
            }
        } else {
            if injected_fault_at == Some("temporary-write-failure") {
                return Err(AuditExportError::InjectedFault("temporary-write-failure"));
            }
            create_private_file(&temporary_path, &encoded)?;
        }
        if injected_fault_at == Some("temporary-write") {
            return Err(AuditExportError::InjectedFault("temporary-write"));
        }
        verify_audit_segment_file(&temporary_path)?;
        if injected_fault_at == Some("rename-failure") {
            return Err(AuditExportError::InjectedFault("rename-failure"));
        }
        fs::rename(&temporary_path, &final_path)?;
        if injected_fault_at == Some("directory-sync-failure") {
            return Err(AuditExportError::InjectedFault("directory-sync-failure"));
        }
        File::open(archive_root)?.sync_all()?;
        if injected_fault_at == Some("rename") {
            return Err(AuditExportError::InjectedFault("rename"));
        }
    }
    let verified = verify_audit_segment_file(&final_path)?;
    if verified != signed {
        return Err(AuditExportError::Invalid(
            "sealed archive bytes changed during publication",
        ));
    }
    let segment_digest = signed.digest()?;
    store.record_sealed_audit_segment(
        &signed.segment.candidate,
        segment_digest.0,
        &relative_name,
    )?;
    if injected_fault_at == Some("database-commit") {
        return Err(AuditExportError::InjectedFault("database-commit"));
    }
    let (archived_events, retired_replays) =
        store.prune_sealed_audit_segment(signed.segment.candidate.candidate_id)?;
    Ok(Some(AuditArchiveResult {
        segment_sequence: signed.segment.candidate.segment_sequence,
        first_audit_sequence: signed.segment.candidate.first_audit_sequence,
        last_audit_sequence: signed.segment.candidate.last_audit_sequence,
        archived_events,
        retired_replays,
        segment_digest_sha256: hex::encode(segment_digest.0),
        relative_name,
    }))
}

pub fn verify_audit_segment_file(path: &Path) -> Result<SignedAuditSegmentV1, AuditExportError> {
    let bytes = read_private_file(path)?;
    verify_audit_segment_bytes(&bytes)
}

pub fn verify_audit_segment_bytes(bytes: &[u8]) -> Result<SignedAuditSegmentV1, AuditExportError> {
    if bytes.len() > MAX_AUDIT_SEGMENT_BYTES {
        return Err(AuditExportError::ResourceLimit);
    }
    let (segment, remainder): (SignedAuditSegmentV1, &[u8]) = postcard::take_from_bytes(bytes)?;
    if !remainder.is_empty() {
        return Err(AuditExportError::Invalid(
            "audit segment contains trailing bytes",
        ));
    }
    segment.verify()?;
    Ok(segment)
}

/// Verify every sealed file against its durable database manifest and both the
/// segment-digest chain and audit-event chain. This does not mutate the store.
pub fn verify_complete_audit_archive(
    store: &StateStore,
    archive_root: &Path,
) -> Result<AuditArchiveVerification, AuditExportError> {
    let metadata = store.sealed_audit_segments()?;
    let checkpoint = store.audit_archive_checkpoint()?;
    let mut expected_segment = 1_u64;
    let mut expected_audit_sequence = 1_u64;
    let mut previous_segment_digest = [0_u8; 32];
    let mut previous_audit_hash = [0_u8; 32];
    for item in &metadata {
        if item.segment_sequence != expected_segment
            || item.first_audit_sequence != expected_audit_sequence
        {
            return Err(AuditExportError::Invalid(
                "archive manifest sequence is discontinuous",
            ));
        }
        let path = archive_root.join(&item.relative_name);
        let signed = verify_audit_segment_file(&path)?;
        let candidate = &signed.segment.candidate;
        if candidate.segment_sequence != item.segment_sequence
            || candidate.first_audit_sequence != item.first_audit_sequence
            || candidate.last_audit_sequence != item.last_audit_sequence
            || candidate.previous_segment_digest != previous_segment_digest
            || candidate.previous_audit_hash != previous_audit_hash
            || signed.digest()?.0 != item.segment_digest
        {
            return Err(AuditExportError::Invalid(
                "archive file does not match its manifest chain",
            ));
        }
        previous_segment_digest = item.segment_digest;
        previous_audit_hash = candidate.last_audit_hash;
        expected_segment = expected_segment
            .checked_add(1)
            .ok_or(AuditExportError::Invalid(
                "archive segment sequence overflow",
            ))?;
        expected_audit_sequence = candidate
            .last_audit_sequence
            .checked_add(1)
            .ok_or(AuditExportError::Invalid("archive audit sequence overflow"))?;
    }
    if checkpoint.segment_sequence != metadata.len() as u64
        || checkpoint.archived_sequence != expected_audit_sequence.saturating_sub(1)
        || checkpoint.segment_digest != previous_segment_digest
        || checkpoint.archived_audit_hash != previous_audit_hash
    {
        return Err(AuditExportError::Invalid(
            "archive checkpoint does not match verified files",
        ));
    }
    Ok(AuditArchiveVerification {
        verification: "verified",
        segment_count: checkpoint.segment_sequence,
        archived_event_count: checkpoint.archived_sequence,
        final_segment_digest_sha256: hex::encode(checkpoint.segment_digest),
        final_audit_hash_sha256: hex::encode(checkpoint.archived_audit_hash),
    })
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

    #[test]
    fn signed_segments_bound_the_archive_chain_and_active_tail() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let identity_root = directory.path().join("identity");
        let archive_root = directory.path().join("archive");
        let (identity, _) = NodeIdentity::load_or_initialize(
            &identity_root,
            "audit-segment-test",
            UnixMillis(1_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        for time in 1_001..=1_003 {
            store.append_audit(AuditEventDraft {
                occurred_at_unix_ms: time,
                kind: AuditKind::AuthorizationRejected,
                outcome: AuditOutcome::Rejected,
                request_id: None,
                actor_digest: Some(sha256(b"peer")),
                subject_digest: None,
                context_digest: Some(sha256(b"bounded-rejection-class")),
            })?;
        }

        let first = seal_eligible_audit_segment(
            &store,
            &identity,
            &archive_root,
            2_000,
            2,
            UnixMillis(2_001),
        )?
        .ok_or("expected first audit segment")?;
        assert_eq!(first.archived_events, 2);
        let first_segment = verify_audit_segment_file(&archive_root.join(&first.relative_name))?;
        assert_eq!(
            first_segment.segment.candidate.previous_segment_digest,
            [0; 32]
        );
        assert_eq!(store.verify_audit_chain()?.event_count, 3);

        let second = seal_eligible_audit_segment(
            &store,
            &identity,
            &archive_root,
            2_000,
            2,
            UnixMillis(2_002),
        )?
        .ok_or("expected second audit segment")?;
        let second_segment = verify_audit_segment_file(&archive_root.join(&second.relative_name))?;
        assert_eq!(
            second_segment.segment.candidate.previous_segment_digest,
            first_segment.digest()?.0
        );
        assert_eq!(store.audit_archive_checkpoint()?.archived_sequence, 3);
        assert_eq!(store.verify_audit_chain()?.event_count, 3);
        let verification = verify_complete_audit_archive(&store, &archive_root)?;
        assert_eq!(verification.segment_count, 2);
        assert_eq!(verification.archived_event_count, 3);
        Ok(())
    }

    #[test]
    fn archive_restart_reconciliation_finishes_every_durable_boundary() -> TestResult {
        for fault in [
            "pending-state",
            "temporary-write-failure",
            "temporary-write",
            "rename-failure",
            "directory-sync-failure",
            "rename",
            "database-commit",
        ] {
            let directory = tempfile::TempDir::new()?;
            let archive_root = directory.path().join("archive");
            let (identity, _) = NodeIdentity::load_or_initialize(
                &directory.path().join("identity"),
                "archive-reconcile-test",
                UnixMillis(1_000),
            )?;
            let store = StateStore::open(directory.path().join("state.sqlite3"))?;
            store.append_audit(AuditEventDraft {
                occurred_at_unix_ms: 1_001,
                kind: AuditKind::AuthorizationRejected,
                outcome: AuditOutcome::Rejected,
                request_id: None,
                actor_digest: None,
                subject_digest: None,
                context_digest: Some(sha256(b"bounded-class")),
            })?;
            assert!(matches!(
                seal_eligible_audit_segment_inner(
                    &store,
                    &identity,
                    &archive_root,
                    2_000,
                    10,
                    UnixMillis(2_001),
                    Some(fault),
                ),
                Err(AuditExportError::InjectedFault(_))
            ));
            drop(store);

            let reopened = StateStore::open(directory.path().join("state.sqlite3"))?;
            let completed = seal_eligible_audit_segment(
                &reopened,
                &identity,
                &archive_root,
                2_000,
                10,
                UnixMillis(2_002),
            )?
            .ok_or("reconciliation did not complete pending segment")?;
            assert_eq!(completed.archived_events, 1);
            assert_eq!(reopened.verify_audit_chain()?.event_count, 1);
            assert_eq!(
                verify_complete_audit_archive(&reopened, &archive_root)?.segment_count,
                1
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn archive_root_symlink_is_rejected() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = tempfile::TempDir::new()?;
        let real = directory.path().join("real-archive");
        std::fs::create_dir(&real)?;
        let link = directory.path().join("archive-link");
        symlink(&real, &link)?;
        let (identity, _) = NodeIdentity::load_or_initialize(
            &directory.path().join("identity"),
            "archive-symlink-test",
            UnixMillis(1_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        store.append_audit(AuditEventDraft {
            occurred_at_unix_ms: 1_001,
            kind: AuditKind::AuthorizationRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest: None,
            subject_digest: None,
            context_digest: None,
        })?;
        assert!(
            seal_eligible_audit_segment(&store, &identity, &link, 2_000, 10, UnixMillis(2_001),)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn corrupted_or_trailing_archive_bytes_are_rejected() -> TestResult {
        let directory = tempfile::TempDir::new()?;
        let identity_root = directory.path().join("identity");
        let archive_root = directory.path().join("archive");
        let (identity, _) = NodeIdentity::load_or_initialize(
            &identity_root,
            "audit-corruption-test",
            UnixMillis(1_000),
        )?;
        let store = StateStore::open(directory.path().join("state.sqlite3"))?;
        store.append_audit(AuditEventDraft {
            occurred_at_unix_ms: 1_001,
            kind: AuditKind::AuthorizationRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest: None,
            subject_digest: None,
            context_digest: Some(sha256(b"reason")),
        })?;
        let sealed = seal_eligible_audit_segment(
            &store,
            &identity,
            &archive_root,
            2_000,
            10,
            UnixMillis(2_001),
        )?
        .ok_or("expected audit segment")?;
        let original = read_private_file(&archive_root.join(&sealed.relative_name))?;
        let corrupt = archive_root.join("corrupt.postcard");
        let mut changed = original.clone();
        let midpoint = changed.len() / 2;
        changed[midpoint] ^= 0x01;
        create_private_file(&corrupt, &changed)?;
        assert!(verify_audit_segment_file(&corrupt).is_err());
        let trailing = archive_root.join("trailing.postcard");
        let mut extended = original;
        extended.push(0);
        create_private_file(&trailing, &extended)?;
        assert!(verify_audit_segment_file(&trailing).is_err());
        Ok(())
    }
}
