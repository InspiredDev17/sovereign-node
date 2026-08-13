//! Durable, fail-closed state for pairing, trust, replay protection, and audit.
//!
//! This module deliberately stores authorization and response *digests*, never
//! bearer credentials, raw action arguments, or response bodies.  Signature
//! validation remains the authorization layer's responsibility.  Callers use
//! [`StateStore::reserve_replay_after_validation`] so an invalid authorization is
//! audited but never consumes a replay identifier.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use postcard::to_stdvec;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::lifecycle::{LeaseKind, LifecycleLease};

/// SHA-256 digests are used to bind data that must not be stored in plaintext.
pub type Sha256Digest = [u8; 32];

const SCHEMA_VERSION: i64 = 8;
const PEER_RATE_WINDOW_MS: i64 = 60_000;
const ZERO_HASH: Sha256Digest = [0_u8; 32];
const MAX_ID_BYTES: usize = 255;
const MAX_LABEL_BYTES: usize = 255;
const MAX_CAPABILITY_BYTES: usize = 128;
// The opaque pairing material may include two public keys and a DER client CA certificate.
const MAX_PUBLIC_KEY_BYTES: usize = 131_072;
const MAX_CERTIFICATE_CHAIN_COUNT: usize = 8;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 262_144;
const MIN_PAIRING_CHALLENGE_BYTES: usize = 16;
const MAX_UPDATE_TEXT_BYTES: usize = 1024;

/// Capacity limits intentionally fail closed instead of allowing unbounded
/// unauthenticated state growth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub max_pending_pairings: u64,
    pub max_trusted_peers: u64,
    pub max_open_replays: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_pending_pairings: 64,
            max_trusted_peers: 1024,
            max_open_replays: 4096,
        }
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("state database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("state serialization error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("state filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state database mutex was poisoned")]
    LockPoisoned,
    #[error("database schema {found} is newer than supported schema {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("invalid state input: {0}")]
    InvalidInput(&'static str),
    #[error("stored state is corrupt: {0}")]
    CorruptData(&'static str),
    #[error("resource limit reached: {0}")]
    ResourceLimit(&'static str),
    #[error("pairing challenge was not found")]
    PairingNotFound,
    #[error("pairing challenge has expired")]
    PairingExpired,
    #[error("pairing challenge proof did not match")]
    PairingChallengeMismatch,
    #[error("peer is already trusted")]
    PeerAlreadyTrusted,
    #[error("peer is revoked and requires an explicit new identity or recovery flow")]
    PeerRevoked,
    #[error("request authorization was rejected")]
    AuthorizationRejected,
    #[error("request authorization has expired")]
    AuthorizationExpired,
    #[error("request replay reservation does not exist")]
    ReplayNotFound,
    #[error("request fingerprint does not match its replay reservation")]
    ReplayFingerprintMismatch,
    #[error("terminal response metadata conflicts with the immutable stored result")]
    TerminalResponseConflict,
    #[error("credential rotation does not match the currently trusted key")]
    CredentialRotationMismatch,
    #[error("credential rotation challenge was not found")]
    CredentialRotationNotFound,
    #[error("credential rotation challenge has expired")]
    CredentialRotationExpired,
    #[error("credential rotation challenge proof did not match")]
    CredentialRotationChallengeMismatch,
    #[error("pairing recovery challenge was not found")]
    RecoveryNotFound,
    #[error("pairing recovery challenge has expired")]
    RecoveryExpired,
    #[error("pairing recovery state or proof did not match")]
    RecoveryMismatch,
    #[error("update release counter rollback or replay was rejected")]
    UpdateCounterRollback,
    #[error("update release counter already binds different staged content")]
    UpdateCounterCollision,
    #[error("update authority keys do not match the durable pinned authorities")]
    UpdateAuthorityMismatch,
    #[error("audit chain is invalid at sequence {sequence}")]
    AuditChainInvalid { sequence: u64 },
    #[error("policy version rollback was rejected")]
    PolicyRollback,
    #[error("policy content changed without increasing its version")]
    PolicyVersionReuse,
    #[error("system clock moved backwards beyond the locally permitted tolerance")]
    ClockRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestLimitScope {
    Peer,
    Global,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteRequestAdmission {
    Admitted {
        peer_remaining: u32,
        global_remaining: u32,
    },
    Limited {
        scope: RequestLimitScope,
        retry_after_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RateWindow {
    started_at_unix_ms: i64,
    request_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RateWindowDecision {
    Admit { next: RateWindow, remaining: u32 },
    Limit { retry_after_ms: u64 },
}

/// A pending, locally displayed pairing challenge.  Only a digest of the
/// challenge secret is persisted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingPairingChallenge {
    pub pairing_id: Uuid,
    pub node_id: String,
    pub peer_id: String,
    pub device_label: String,
    pub peer_public_key: Vec<u8>,
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    /// Device-key digest displayed locally and bound into the signed transcript.
    pub node_identity_digest: Sha256Digest,
    pub challenge_digest: Sha256Digest,
    pub transport_binding_digest: Sha256Digest,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl PendingPairingChallenge {
    /// Construct a record while hashing the randomly generated challenge.  A
    /// challenge must carry at least 128 bits of entropy; short display codes
    /// should be backed by an independent high-entropy transcript secret.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pairing_id: Uuid,
        node_id: String,
        peer_id: String,
        device_label: String,
        peer_public_key: Vec<u8>,
        client_certificate_chain_der: Vec<Vec<u8>>,
        challenge_secret: &[u8],
        node_identity_digest: Sha256Digest,
        transport_binding_digest: Sha256Digest,
        requested_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, StoreError> {
        if challenge_secret.len() < MIN_PAIRING_CHALLENGE_BYTES {
            return Err(StoreError::InvalidInput(
                "pairing challenge must contain at least 128 bits",
            ));
        }
        let value = Self {
            pairing_id,
            node_id,
            peer_id,
            device_label,
            peer_public_key,
            client_certificate_chain_der,
            challenge_digest: sha256(challenge_secret),
            node_identity_digest,
            transport_binding_digest,
            requested_at_unix_ms,
            expires_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier(&self.node_id)?;
        validate_identifier(&self.peer_id)?;
        if self.pairing_id.is_nil() {
            return Err(StoreError::InvalidInput(
                "pairing identifier must be non-nil",
            ));
        }
        validate_bounded_text(&self.device_label, MAX_LABEL_BYTES, "device label")?;
        if self.peer_public_key.is_empty() || self.peer_public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(StoreError::InvalidInput("invalid peer public key length"));
        }
        validate_certificate_chain(&self.client_certificate_chain_der)?;
        if self.expires_at_unix_ms <= self.requested_at_unix_ms {
            return Err(StoreError::InvalidInput(
                "pairing expiry must follow creation time",
            ));
        }
        Ok(())
    }
}

/// Explicit owner approval used to turn a pending challenge into trust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairingApproval {
    pub pairing_id: Uuid,
    pub owner_authority_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub approved_at_unix_ms: i64,
    pub trust_expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Pairing {
    pub pairing_id: Uuid,
    pub node_id: String,
    pub peer_id: String,
    pub device_label: String,
    pub peer_public_key: Vec<u8>,
    pub transport_binding_digest: Sha256Digest,
    pub owner_authority_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub requested_at_unix_ms: i64,
    pub approved_at_unix_ms: i64,
}

/// A short-lived, node-bound request to rotate one existing peer credential.
/// Only the challenge digest is durable; the clear challenge is displayed once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingCredentialRotation {
    pub rotation_id: Uuid,
    pub pairing_id: Uuid,
    pub node_id: String,
    pub peer_id: String,
    pub current_public_key_digest: Sha256Digest,
    pub current_trust_epoch: u64,
    pub new_public_key: Vec<u8>,
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    pub new_identity_digest: Sha256Digest,
    pub node_identity_digest: Sha256Digest,
    pub challenge_digest: Sha256Digest,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl PendingCredentialRotation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rotation_id: Uuid,
        pairing_id: Uuid,
        node_id: String,
        peer_id: String,
        current_public_key_digest: Sha256Digest,
        current_trust_epoch: u64,
        new_public_key: Vec<u8>,
        client_certificate_chain_der: Vec<Vec<u8>>,
        node_identity_digest: Sha256Digest,
        challenge_secret: &[u8],
        requested_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, StoreError> {
        if challenge_secret.len() < MIN_PAIRING_CHALLENGE_BYTES {
            return Err(StoreError::InvalidInput(
                "credential rotation challenge must contain at least 128 bits",
            ));
        }
        let value = Self {
            rotation_id,
            pairing_id,
            node_id,
            peer_id: peer_id.clone(),
            current_public_key_digest,
            current_trust_epoch,
            new_identity_digest: peer_identity_digest(&peer_id, &new_public_key),
            new_public_key,
            client_certificate_chain_der,
            node_identity_digest,
            challenge_digest: sha256(challenge_secret),
            requested_at_unix_ms,
            expires_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier(&self.node_id)?;
        validate_identifier(&self.peer_id)?;
        if self.rotation_id.is_nil() || self.pairing_id.is_nil() {
            return Err(StoreError::InvalidInput(
                "credential rotation identifiers must be non-nil",
            ));
        }
        if self.current_trust_epoch == 0 {
            return Err(StoreError::InvalidInput(
                "credential rotation trust epoch must be non-zero",
            ));
        }
        if self.new_public_key.is_empty() || self.new_public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(StoreError::InvalidInput("invalid peer public key length"));
        }
        validate_certificate_chain(&self.client_certificate_chain_der)?;
        if !constant_time_digest_eq(
            &self.new_identity_digest,
            &peer_identity_digest(&self.peer_id, &self.new_public_key),
        ) {
            return Err(StoreError::CorruptData(
                "credential rotation identity digest is inconsistent",
            ));
        }
        if self.expires_at_unix_ms <= self.requested_at_unix_ms {
            return Err(StoreError::InvalidInput(
                "credential rotation expiry must follow creation time",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialRotationApproval {
    pub rotation_id: Uuid,
    pub owner_authority_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub approved_at_unix_ms: i64,
    pub trust_expires_at_unix_ms: Option<i64>,
}

/// A short-lived local recovery ceremony for an explicitly revoked peer.
/// The original revocation and trust generation are immutable transcript inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingPairingRecovery {
    pub recovery_id: Uuid,
    pub pairing_id: Uuid,
    pub node_id: String,
    pub peer_id: String,
    pub device_label: String,
    pub revoked_identity_digest: Sha256Digest,
    pub revoked_trust_epoch: u64,
    pub revocation_digest: Sha256Digest,
    pub new_public_key: Vec<u8>,
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    pub new_identity_digest: Sha256Digest,
    pub node_identity_digest: Sha256Digest,
    pub challenge_digest: Sha256Digest,
    pub transport_binding_digest: Sha256Digest,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl PendingPairingRecovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recovery_id: Uuid,
        revoked_peer: &TrustedPeer,
        revocation_digest: Sha256Digest,
        new_public_key: Vec<u8>,
        client_certificate_chain_der: Vec<Vec<u8>>,
        node_identity_digest: Sha256Digest,
        challenge_secret: &[u8],
        transport_binding_digest: Sha256Digest,
        requested_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, StoreError> {
        if challenge_secret.len() < MIN_PAIRING_CHALLENGE_BYTES {
            return Err(StoreError::InvalidInput(
                "pairing recovery challenge must contain at least 128 bits",
            ));
        }
        let value = Self {
            recovery_id,
            pairing_id: revoked_peer.pairing_id,
            node_id: revoked_peer.node_id.clone(),
            peer_id: revoked_peer.peer_id.clone(),
            device_label: revoked_peer.device_label.clone(),
            revoked_identity_digest: revoked_peer.identity_digest,
            revoked_trust_epoch: revoked_peer.trust_epoch,
            revocation_digest,
            new_identity_digest: peer_identity_digest(&revoked_peer.peer_id, &new_public_key),
            new_public_key,
            client_certificate_chain_der,
            node_identity_digest,
            challenge_digest: sha256(challenge_secret),
            transport_binding_digest,
            requested_at_unix_ms,
            expires_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier(&self.node_id)?;
        validate_identifier(&self.peer_id)?;
        validate_bounded_text(&self.device_label, MAX_LABEL_BYTES, "device label")?;
        if self.recovery_id.is_nil() || self.pairing_id.is_nil() || self.revoked_trust_epoch == 0 {
            return Err(StoreError::InvalidInput(
                "pairing recovery identifiers and epoch must be non-zero",
            ));
        }
        if self.new_public_key.is_empty() || self.new_public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(StoreError::InvalidInput("invalid peer public key length"));
        }
        validate_certificate_chain(&self.client_certificate_chain_der)?;
        if !constant_time_digest_eq(
            &self.new_identity_digest,
            &peer_identity_digest(&self.peer_id, &self.new_public_key),
        ) {
            return Err(StoreError::CorruptData(
                "pairing recovery identity digest is inconsistent",
            ));
        }
        if self.expires_at_unix_ms <= self.requested_at_unix_ms {
            return Err(StoreError::InvalidInput(
                "pairing recovery expiry must follow creation time",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairingRecoveryApproval {
    pub recovery_id: Uuid,
    pub owner_authority_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub approved_at_unix_ms: i64,
    pub trust_expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PairingRecoveryRecord {
    pub recovery_id: Uuid,
    pub pairing_id: Uuid,
    pub peer_id: String,
    pub previous_identity_digest: Sha256Digest,
    pub next_identity_digest: Sha256Digest,
    pub previous_trust_epoch: u64,
    pub next_trust_epoch: u64,
    pub revocation: RevocationRecord,
    pub owner_authority_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub recovered_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingRecoveryOutcome {
    pub trusted_peer: TrustedPeer,
    pub recovery: PairingRecoveryRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateStageRecord {
    pub stage_id: Uuid,
    pub software_version: String,
    pub previous_version: String,
    pub rollback_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub release_counter: u64,
    pub manifest_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub release_key_digest: Sha256Digest,
    pub owner_key_digest: Sha256Digest,
    /// Owner-private path relative to the node data directory.
    pub staged_artifact_relative_path: String,
    pub staged_at_unix_ms: i64,
}

impl UpdateStageRecord {
    fn validate(&self) -> Result<(), StoreError> {
        if self.stage_id.is_nil() || self.release_counter == 0 || self.staged_at_unix_ms < 0 {
            return Err(StoreError::InvalidInput(
                "update stage identifiers, counter, and time are invalid",
            ));
        }
        for value in [
            &self.software_version,
            &self.previous_version,
            &self.rollback_version,
            &self.target_os,
            &self.target_arch,
            &self.staged_artifact_relative_path,
        ] {
            validate_bounded_text(value, MAX_UPDATE_TEXT_BYTES, "update field")?;
            if value.chars().any(char::is_control) {
                return Err(StoreError::InvalidInput(
                    "update field contains control characters",
                ));
            }
        }
        if self.software_version == self.previous_version
            || self.rollback_version != self.previous_version
            || self.release_key_digest == self.owner_key_digest
            || self.manifest_digest == ZERO_HASH
            || self.artifact_digest == ZERO_HASH
            || self.release_key_digest == ZERO_HASH
            || self.owner_key_digest == ZERO_HASH
        {
            return Err(StoreError::InvalidInput(
                "update stage record is inconsistent",
            ));
        }
        let relative = Path::new(&self.staged_artifact_relative_path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(StoreError::InvalidInput(
                "staged update path must be a contained relative path",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UpdateStageOutcome {
    Staged(UpdateStageRecord),
    AlreadyStaged(UpdateStageRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub peer_id: String,
    pub pairing_id: Uuid,
    pub node_id: String,
    pub device_label: String,
    pub public_key: Vec<u8>,
    pub identity_digest: Sha256Digest,
    pub capability_manifest_digest: Sha256Digest,
    pub status: TrustStatus,
    /// Monotonically increases when the peer credential is rotated. Signed
    /// authorizations bind this value as their trust epoch.
    pub trust_epoch: u64,
    pub paired_at_unix_ms: i64,
    pub trust_expires_at_unix_ms: Option<i64>,
    pub last_key_rotation_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
}

impl TrustedPeer {
    #[must_use]
    pub fn is_currently_trusted(&self, now_unix_ms: i64) -> bool {
        self.status == TrustStatus::Active
            && self
                .trust_expires_at_unix_ms
                .is_none_or(|expires_at| expires_at > now_unix_ms)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub peer_id: String,
    pub pairing_id: Uuid,
    pub revoked_at_unix_ms: i64,
    pub owner_authority_digest: Sha256Digest,
    pub reason_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationOutcome {
    Revoked(RevocationRecord),
    AlreadyRevoked(RevocationRecord),
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialRotationOutcome {
    Rotated(TrustedPeer),
    AlreadyCurrent(TrustedPeer),
}

/// Security-relevant request fields used for durable replay binding.  Raw
/// arguments, raw targets, and authorization tokens are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayReservation {
    pub request_id: Uuid,
    pub task_id: Uuid,
    pub pairing_id: Uuid,
    pub trust_epoch: u64,
    pub policy_version: u64,
    pub policy_digest: Sha256Digest,
    pub replay_sequence: u64,
    pub replay_nonce: Sha256Digest,
    pub agent_id: String,
    pub node_id: String,
    pub capability: String,
    pub target_digest: Sha256Digest,
    pub arguments_digest: Sha256Digest,
    pub authorization_digest: Sha256Digest,
    pub expires_at_unix_ms: i64,
}

impl ReplayReservation {
    pub fn fingerprint(&self) -> Result<Sha256Digest, StoreError> {
        self.validate()?;
        Ok(sha256(&encode(self)?))
    }

    fn validate(&self) -> Result<(), StoreError> {
        validate_identifier(&self.agent_id)?;
        validate_identifier(&self.node_id)?;
        validate_bounded_text(&self.capability, MAX_CAPABILITY_BYTES, "capability")?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TerminalStatus {
    Succeeded,
    Rejected,
    Failed,
    Cancelled,
    Expired,
    Indeterminate,
}

/// Immutable metadata for a terminal action response.  The response itself is
/// returned to the caller by the runtime and is not retained here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalResponseMetadata {
    pub status: TerminalStatus,
    pub response_digest: Sha256Digest,
    pub redacted_error_digest: Option<Sha256Digest>,
    pub response_size_bytes: u64,
    pub completed_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    Reserved {
        fingerprint: Sha256Digest,
    },
    DuplicateSame {
        fingerprint: Sha256Digest,
        terminal: Option<TerminalResponseMetadata>,
    },
    Collision {
        existing_fingerprint: Sha256Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalRecordOutcome {
    Recorded,
    AlreadyRecordedSame,
}

/// Audit entries have a closed vocabulary and digest-only context.  This keeps
/// secrets, action arguments, raw targets, and credential material out of the
/// audit database by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditKind {
    PairingChallengeCreated,
    PairingApproved,
    PairingRejected,
    PeerRevoked,
    CredentialRotated,
    NodeIdentityRotationStarted,
    NodeIdentityRotated,
    PolicyActivated,
    AuthorizationRejected,
    RequestReserved,
    ReplayDuplicate,
    ReplayCollision,
    TerminalResponseRecorded,
    // New variants are appended to preserve postcard discriminants in existing
    // audit chains across schema migrations.
    CredentialRotationChallengeCreated,
    CredentialRotationRejected,
    PairingRecoveryChallengeCreated,
    PairingRecoveryRejected,
    PairingRecovered,
    UpdateRejected,
    UpdateStaged,
    ClockRollbackRejected,
    ClockRollbackAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Accepted,
    Rejected,
    Observed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEventDraft {
    pub occurred_at_unix_ms: i64,
    pub kind: AuditKind,
    pub outcome: AuditOutcome,
    pub request_id: Option<Uuid>,
    pub actor_digest: Option<Sha256Digest>,
    pub subject_digest: Option<Sha256Digest>,
    pub context_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_id: Uuid,
    pub occurred_at_unix_ms: i64,
    pub kind: AuditKind,
    pub outcome: AuditOutcome,
    pub request_id: Option<Uuid>,
    pub actor_digest: Option<Sha256Digest>,
    pub subject_digest: Option<Sha256Digest>,
    pub context_digest: Option<Sha256Digest>,
    pub previous_hash: Sha256Digest,
    pub event_hash: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditChainState {
    pub event_count: u64,
    pub tail_hash: Sha256Digest,
}

#[derive(Debug)]
pub struct StateStore {
    connection: Mutex<Connection>,
    path: PathBuf,
    limits: StoreLimits,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_limits(path, StoreLimits::default())
    }

    pub fn open_with_limits(
        path: impl AsRef<Path>,
        limits: StoreLimits,
    ) -> Result<Self, StoreError> {
        if !cfg!(unix) {
            return Err(StoreError::InvalidInput(
                "v0.1 state storage requires Unix ownership and mode checks",
            ));
        }
        validate_limits(limits)?;
        let path = path.as_ref().to_path_buf();
        prepare_private_database_file(&path)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(&path, flags)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        configure_connection(&connection)?;
        migrate(&mut connection)?;
        tighten_private_permissions(&path)?;

        Ok(Self {
            connection: Mutex::new(connection),
            path,
            limits,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically admit an authenticated request against both its durable per-peer window and the
    /// durable node-global window. Neither counter advances unless both limits admit the request.
    /// Reconnecting or reopening the store does not reset either allowance. A backwards wall-clock
    /// step fails closed.
    pub fn admit_remote_request(
        &self,
        peer_id: &str,
        peer_maximum_per_minute: u32,
        global_maximum_per_minute: u32,
    ) -> Result<RemoteRequestAdmission, StoreError> {
        self.admit_remote_request_at(
            peer_id,
            peer_maximum_per_minute,
            global_maximum_per_minute,
            unix_time_ms()?,
        )
    }

    pub fn admit_remote_request_with_clock_policy(
        &self,
        peer_id: &str,
        peer_maximum_per_minute: u32,
        global_maximum_per_minute: u32,
        maximum_rollback_ms: i64,
    ) -> Result<RemoteRequestAdmission, StoreError> {
        self.admit_remote_request_with_clock_policy_at(
            peer_id,
            peer_maximum_per_minute,
            global_maximum_per_minute,
            unix_time_ms()?,
            maximum_rollback_ms,
        )
    }

    pub fn admit_remote_request_at(
        &self,
        peer_id: &str,
        peer_maximum_per_minute: u32,
        global_maximum_per_minute: u32,
        now_unix_ms: i64,
    ) -> Result<RemoteRequestAdmission, StoreError> {
        self.admit_remote_request_with_clock_policy_at(
            peer_id,
            peer_maximum_per_minute,
            global_maximum_per_minute,
            now_unix_ms,
            0,
        )
    }

    pub fn admit_remote_request_with_clock_policy_at(
        &self,
        peer_id: &str,
        peer_maximum_per_minute: u32,
        global_maximum_per_minute: u32,
        now_unix_ms: i64,
        maximum_rollback_ms: i64,
    ) -> Result<RemoteRequestAdmission, StoreError> {
        validate_identifier(peer_id)?;
        validate_clock_policy(now_unix_ms, maximum_rollback_ms)?;
        if peer_maximum_per_minute == 0 || global_maximum_per_minute < peer_maximum_per_minute {
            return Err(StoreError::InvalidInput(
                "request limits must be non-zero and global must cover per-peer",
            ));
        }
        if now_unix_ms < 0 {
            return Err(StoreError::InvalidInput(
                "peer request time must not predate the Unix epoch",
            ));
        }

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match advance_trusted_clock_in_transaction(&transaction, now_unix_ms, maximum_rollback_ms) {
            Ok(()) => {}
            Err(StoreError::ClockRollback) => {
                append_clock_rollback_audit_once(
                    &transaction,
                    AuditEventDraft {
                        occurred_at_unix_ms: now_unix_ms,
                        kind: AuditKind::ClockRollbackRejected,
                        outcome: AuditOutcome::Rejected,
                        request_id: None,
                        actor_digest: Some(sha256(peer_id.as_bytes())),
                        subject_digest: Some(sha256(b"trusted-clock")),
                        context_digest: Some(sha256(b"rollback-beyond-policy")),
                    },
                )?;
                transaction.commit()?;
                return Err(StoreError::ClockRollback);
            }
            Err(error) => return Err(error),
        }
        let peer_window = transaction
            .query_row(
                "SELECT window_started_at_unix_ms, request_count
                 FROM peer_rate_limits WHERE peer_id = ?1",
                [peer_id],
                decode_rate_window,
            )
            .optional()?;
        let global_window = transaction
            .query_row(
                "SELECT window_started_at_unix_ms, request_count
                 FROM global_rate_limit WHERE singleton = 1",
                [],
                decode_rate_window,
            )
            .optional()?;

        let peer_decision = evaluate_rate_window(
            peer_window,
            peer_maximum_per_minute,
            now_unix_ms,
            maximum_rollback_ms,
        )?;
        let global_decision = evaluate_rate_window(
            global_window,
            global_maximum_per_minute,
            now_unix_ms,
            maximum_rollback_ms,
        )?;
        if let RateWindowDecision::Limit { retry_after_ms } = peer_decision {
            transaction.commit()?;
            return Ok(RemoteRequestAdmission::Limited {
                scope: RequestLimitScope::Peer,
                retry_after_ms,
            });
        }
        if let RateWindowDecision::Limit { retry_after_ms } = global_decision {
            transaction.commit()?;
            return Ok(RemoteRequestAdmission::Limited {
                scope: RequestLimitScope::Global,
                retry_after_ms,
            });
        }
        let RateWindowDecision::Admit {
            next: peer_next,
            remaining: peer_remaining,
        } = peer_decision
        else {
            return Err(StoreError::CorruptData("invalid peer admission decision"));
        };
        let RateWindowDecision::Admit {
            next: global_next,
            remaining: global_remaining,
        } = global_decision
        else {
            return Err(StoreError::CorruptData("invalid global admission decision"));
        };

        transaction.execute(
            "INSERT INTO peer_rate_limits(peer_id, window_started_at_unix_ms, request_count)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET
                 window_started_at_unix_ms = excluded.window_started_at_unix_ms,
                 request_count = excluded.request_count",
            params![
                peer_id,
                peer_next.started_at_unix_ms,
                i64::from(peer_next.request_count)
            ],
        )?;
        transaction.execute(
            "INSERT INTO global_rate_limit(singleton, window_started_at_unix_ms, request_count)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
                 window_started_at_unix_ms = excluded.window_started_at_unix_ms,
                 request_count = excluded.request_count",
            params![
                global_next.started_at_unix_ms,
                i64::from(global_next.request_count)
            ],
        )?;
        transaction.commit()?;
        Ok(RemoteRequestAdmission::Admitted {
            peer_remaining,
            global_remaining,
        })
    }

    /// Persist the canonical local policy binding and reject rollback or same-version remapping.
    pub fn activate_policy(
        &self,
        version: u64,
        digest: Sha256Digest,
        now_unix_ms: i64,
    ) -> Result<(), StoreError> {
        if version == 0 {
            return Err(StoreError::InvalidInput("policy version must be non-zero"));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT policy_version, policy_digest FROM policy_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_version, stored_digest)) = existing {
            let stored_version = u64::from_be_bytes(
                stored_version
                    .try_into()
                    .map_err(|_| StoreError::CorruptData("policy version has invalid length"))?,
            );
            let stored_digest = digest_from_blob(stored_digest)?;
            if version < stored_version {
                return Err(StoreError::PolicyRollback);
            }
            if version == stored_version {
                if !constant_time_digest_eq(&digest, &stored_digest) {
                    return Err(StoreError::PolicyVersionReuse);
                }
                transaction.commit()?;
                return Ok(());
            }
        }
        transaction.execute(
            "INSERT INTO policy_state(singleton, policy_version, policy_digest)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
                 policy_version = excluded.policy_version,
                 policy_digest = excluded.policy_digest",
            params![&u64_blob(version)[..], &digest[..]],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: now_unix_ms,
                kind: AuditKind::PolicyActivated,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: None,
                subject_digest: Some(sha256(&u64_blob(version))),
                context_digest: Some(digest),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Return the durable wall-clock high-water mark used for remote authorization.
    pub fn trusted_clock_high_water(&self) -> Result<Option<i64>, StoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT high_water_unix_ms FROM trusted_clock_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Check and advance the durable wall-clock checkpoint. A backwards step beyond the
    /// configured tolerance is audited and rejected without lowering the checkpoint.
    pub fn observe_trusted_clock_at(
        &self,
        now_unix_ms: i64,
        maximum_rollback_ms: i64,
    ) -> Result<(), StoreError> {
        validate_clock_policy(now_unix_ms, maximum_rollback_ms)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match advance_trusted_clock_in_transaction(&transaction, now_unix_ms, maximum_rollback_ms) {
            Ok(()) => {}
            Err(StoreError::ClockRollback) => {
                append_clock_rollback_audit_once(
                    &transaction,
                    AuditEventDraft {
                        occurred_at_unix_ms: now_unix_ms,
                        kind: AuditKind::ClockRollbackRejected,
                        outcome: AuditOutcome::Rejected,
                        request_id: None,
                        actor_digest: None,
                        subject_digest: Some(sha256(b"trusted-clock")),
                        context_digest: Some(sha256(b"rollback-beyond-policy")),
                    },
                )?;
                transaction.commit()?;
                return Err(StoreError::ClockRollback);
            }
            Err(error) => return Err(error),
        }
        transaction.commit()?;
        Ok(())
    }

    /// Replace the clock checkpoint only during an explicit owner-local maintenance window.
    /// Both leases prove that the daemon is stopped and another state mutation is not racing.
    pub fn acknowledge_trusted_clock(
        &self,
        admin_lease: &LifecycleLease,
        daemon_lease: &LifecycleLease,
        now_unix_ms: i64,
    ) -> Result<Option<i64>, StoreError> {
        if admin_lease.kind() != LeaseKind::AdminMutation
            || daemon_lease.kind() != LeaseKind::Daemon
        {
            return Err(StoreError::InvalidInput(
                "clock acknowledgement requires admin and daemon leases",
            ));
        }
        validate_clock_policy(now_unix_ms, 0)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT high_water_unix_ms FROM trusted_clock_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        transaction.execute(
            "INSERT INTO trusted_clock_state
                (singleton, high_water_unix_ms, rollback_rejection_latched)
             VALUES (1, ?1, 0)
             ON CONFLICT(singleton) DO UPDATE SET
                 high_water_unix_ms = excluded.high_water_unix_ms,
                 rollback_rejection_latched = 0",
            [now_unix_ms],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: now_unix_ms,
                kind: AuditKind::ClockRollbackAcknowledged,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(sha256(b"local-owner-confirmed-clock-acknowledgement-v1")),
                subject_digest: Some(sha256(b"trusted-clock")),
                context_digest: Some(sha256(&previous.unwrap_or_default().to_be_bytes())),
            },
        )?;
        transaction.commit()?;
        Ok(previous)
    }

    pub fn latest_staged_update(&self) -> Result<Option<UpdateStageRecord>, StoreError> {
        let connection = self.lock()?;
        let state: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT state.highest_release_counter, state.latest_manifest_digest, stages.record
                 FROM update_state AS state
                 JOIN update_stages AS stages ON stages.stage_id = state.latest_stage_id
                 WHERE state.singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((counter, manifest_digest, record)) = state else {
            return Ok(None);
        };
        let counter = u64::from_be_bytes(
            counter
                .try_into()
                .map_err(|_| StoreError::CorruptData("update counter has invalid length"))?,
        );
        let manifest_digest = digest_from_blob(manifest_digest)?;
        let record: UpdateStageRecord = decode(&record)?;
        record.validate()?;
        if record.release_counter != counter || record.manifest_digest != manifest_digest {
            return Err(StoreError::CorruptData(
                "update state does not match its latest stage record",
            ));
        }
        Ok(Some(record))
    }

    /// Atomically advances the durable update counter and audit chain after an
    /// already-local artifact has passed cryptographic and content validation.
    /// This records staging only; it does not install or execute the artifact.
    pub(crate) fn stage_verified_update(
        &self,
        record: &UpdateStageRecord,
    ) -> Result<UpdateStageOutcome, StoreError> {
        record.validate()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_state: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT highest_release_counter, latest_manifest_digest
                 FROM update_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((current_counter, latest_manifest_digest)) = current_state {
            let current_counter = u64::from_be_bytes(current_counter.try_into().map_err(|_| {
                StoreError::CorruptData("update release counter has invalid length")
            })?);
            let pinned_record: Vec<u8> = transaction.query_row(
                "SELECT stages.record
                 FROM update_state AS state
                 JOIN update_stages AS stages ON stages.stage_id = state.latest_stage_id
                 WHERE state.singleton = 1",
                [],
                |row| row.get(0),
            )?;
            let pinned_record: UpdateStageRecord = decode(&pinned_record)?;
            let latest_manifest_digest = digest_from_blob(latest_manifest_digest)?;
            pinned_record.validate()?;
            if pinned_record.release_counter != current_counter
                || pinned_record.manifest_digest != latest_manifest_digest
            {
                return Err(StoreError::CorruptData(
                    "update state does not match its pinned stage record",
                ));
            }
            if pinned_record.release_key_digest != record.release_key_digest
                || pinned_record.owner_key_digest != record.owner_key_digest
            {
                return Err(StoreError::UpdateAuthorityMismatch);
            }
            if record.release_counter < current_counter {
                return Err(StoreError::UpdateCounterRollback);
            }
            if record.release_counter == current_counter {
                let existing: Vec<u8> = transaction.query_row(
                    "SELECT record FROM update_stages WHERE release_counter = ?1",
                    [&u64_blob(record.release_counter)[..]],
                    |row| row.get(0),
                )?;
                let existing: UpdateStageRecord = decode(&existing)?;
                if existing.manifest_digest == record.manifest_digest
                    && existing.artifact_digest == record.artifact_digest
                    && existing.release_key_digest == record.release_key_digest
                    && existing.owner_key_digest == record.owner_key_digest
                {
                    transaction.commit()?;
                    return Ok(UpdateStageOutcome::AlreadyStaged(existing));
                }
                return Err(StoreError::UpdateCounterCollision);
            }
        }

        transaction.execute(
            "INSERT INTO update_stages
                (stage_id, release_counter, staged_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.stage_id.to_string(),
                &u64_blob(record.release_counter)[..],
                record.staged_at_unix_ms,
                encode(record)?
            ],
        )?;
        transaction.execute(
            "INSERT INTO update_state
                (singleton, highest_release_counter, latest_stage_id, latest_manifest_digest)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
                 highest_release_counter = excluded.highest_release_counter,
                 latest_stage_id = excluded.latest_stage_id,
                 latest_manifest_digest = excluded.latest_manifest_digest",
            params![
                &u64_blob(record.release_counter)[..],
                record.stage_id.to_string(),
                &record.manifest_digest[..]
            ],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: record.staged_at_unix_ms,
                kind: AuditKind::UpdateStaged,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(record.owner_key_digest),
                subject_digest: Some(record.manifest_digest),
                context_digest: Some(record.artifact_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(UpdateStageOutcome::Staged(record.clone()))
    }

    pub(crate) fn audit_update_rejection(
        &self,
        occurred_at_unix_ms: i64,
        actor_digest: Option<Sha256Digest>,
        subject_digest: Sha256Digest,
        reason: &[u8],
    ) -> Result<(), StoreError> {
        self.append_audit(AuditEventDraft {
            occurred_at_unix_ms,
            kind: AuditKind::UpdateRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest,
            subject_digest: Some(subject_digest),
            context_digest: Some(sha256(reason)),
        })?;
        Ok(())
    }

    pub fn put_pending_pairing(
        &self,
        challenge: &PendingPairingChallenge,
    ) -> Result<(), StoreError> {
        challenge.validate()?;
        let record = encode(challenge)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        transaction.execute(
            "DELETE FROM pending_pairings WHERE expires_at_unix_ms <= ?1",
            [challenge.requested_at_unix_ms],
        )?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairings WHERE pairing_id = ?1",
                [challenge.pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: PendingPairingChallenge = decode(&existing)?;
            if existing == *challenge {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::InvalidInput(
                "pairing identifier already binds different challenge data",
            ));
        }

        enforce_count_limit(
            &transaction,
            "SELECT COUNT(*) FROM pending_pairings",
            self.limits.max_pending_pairings,
            "pending pairing capacity",
        )?;

        transaction.execute(
            "INSERT INTO pending_pairings
                (pairing_id, peer_id, node_id, expires_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                challenge.pairing_id.to_string(),
                challenge.peer_id,
                challenge.node_id,
                challenge.expires_at_unix_ms,
                record
            ],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: challenge.requested_at_unix_ms,
                kind: AuditKind::PairingChallengeCreated,
                outcome: AuditOutcome::Observed,
                request_id: None,
                actor_digest: None,
                subject_digest: Some(sha256(challenge.peer_id.as_bytes())),
                context_digest: Some(sha256(challenge.node_id.as_bytes())),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()
    }

    pub fn pending_pairing(
        &self,
        pairing_id: Uuid,
    ) -> Result<Option<PendingPairingChallenge>, StoreError> {
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM pending_pairings WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn put_pending_credential_rotation(
        &self,
        challenge: &PendingCredentialRotation,
    ) -> Result<(), StoreError> {
        challenge.validate()?;
        let record = encode(challenge)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM pending_credential_rotations WHERE expires_at_unix_ms <= ?1",
            [challenge.requested_at_unix_ms],
        )?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_credential_rotations WHERE rotation_id = ?1",
                [challenge.rotation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: PendingCredentialRotation = decode(&existing)?;
            if existing == *challenge {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::InvalidInput(
                "rotation identifier already binds different challenge data",
            ));
        }
        enforce_count_limit(
            &transaction,
            "SELECT COUNT(*) FROM pending_credential_rotations",
            self.limits.max_pending_pairings,
            "pending credential rotation capacity",
        )?;
        transaction.execute(
            "INSERT INTO pending_credential_rotations
                (rotation_id, peer_id, pairing_id, expires_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                challenge.rotation_id.to_string(),
                challenge.peer_id,
                challenge.pairing_id.to_string(),
                challenge.expires_at_unix_ms,
                record
            ],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: challenge.requested_at_unix_ms,
                kind: AuditKind::CredentialRotationChallengeCreated,
                outcome: AuditOutcome::Observed,
                request_id: None,
                actor_digest: None,
                subject_digest: Some(sha256(challenge.peer_id.as_bytes())),
                context_digest: Some(challenge.new_identity_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()
    }

    pub fn pending_credential_rotation(
        &self,
        rotation_id: Uuid,
    ) -> Result<Option<PendingCredentialRotation>, StoreError> {
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM pending_credential_rotations WHERE rotation_id = ?1",
                [rotation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn audit_credential_rotation_rejection(
        &self,
        rotation_id: Uuid,
        occurred_at_unix_ms: i64,
        reason: &[u8],
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_credential_rotations WHERE rotation_id = ?1",
                [rotation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Err(StoreError::CredentialRotationNotFound);
        };
        let pending: PendingCredentialRotation = decode(&record)?;
        append_credential_rotation_rejection_audit(
            &transaction,
            &pending,
            occurred_at_unix_ms,
            reason,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn revoked_peer_for_recovery(
        &self,
        peer_id: &str,
    ) -> Result<Option<(TrustedPeer, RevocationRecord)>, StoreError> {
        validate_identifier(peer_id)?;
        let connection = self.lock()?;
        let peer_record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM trusted_peers WHERE peer_id = ?1 AND trust_status = 2",
                [peer_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(peer_record) = peer_record else {
            return Ok(None);
        };
        let peer: TrustedPeer = decode(&peer_record)?;
        let revocation = revocation_in_connection(&connection, peer_id)?.ok_or(
            StoreError::CorruptData("revoked peer lacks revocation record"),
        )?;
        if peer.status != TrustStatus::Revoked
            || peer.pairing_id != revocation.pairing_id
            || peer.revoked_at_unix_ms != Some(revocation.revoked_at_unix_ms)
        {
            return Err(StoreError::CorruptData(
                "revoked peer and revocation record disagree",
            ));
        }
        Ok(Some((peer, revocation)))
    }

    pub fn put_pending_pairing_recovery(
        &self,
        recovery: &PendingPairingRecovery,
    ) -> Result<(), StoreError> {
        recovery.validate()?;
        let record = encode(recovery)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM pending_pairing_recoveries WHERE expires_at_unix_ms <= ?1",
            [recovery.requested_at_unix_ms],
        )?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairing_recoveries WHERE recovery_id = ?1",
                [recovery.recovery_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let existing: PendingPairingRecovery = decode(&existing)?;
            if existing == *recovery {
                transaction.commit()?;
                return Ok(());
            }
            return Err(StoreError::InvalidInput(
                "recovery identifier already binds different challenge data",
            ));
        }
        let peer_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers
                 WHERE peer_id = ?1 AND pairing_id = ?2 AND trust_status = 2",
                params![recovery.peer_id, recovery.pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(peer_record) = peer_record else {
            return Err(StoreError::RecoveryMismatch);
        };
        let peer: TrustedPeer = decode(&peer_record)?;
        let revocation = revocation_in_transaction(&transaction, &recovery.peer_id)?
            .ok_or(StoreError::RecoveryMismatch)?;
        let revocation_digest = sha256(&encode(&revocation)?);
        if peer.status != TrustStatus::Revoked
            || peer.node_id != recovery.node_id
            || peer.pairing_id != recovery.pairing_id
            || peer.identity_digest != recovery.revoked_identity_digest
            || peer.trust_epoch != recovery.revoked_trust_epoch
            || peer.revoked_at_unix_ms != Some(revocation.revoked_at_unix_ms)
            || !constant_time_digest_eq(&revocation_digest, &recovery.revocation_digest)
        {
            return Err(StoreError::RecoveryMismatch);
        }
        let other_for_peer: Option<String> = transaction
            .query_row(
                "SELECT recovery_id FROM pending_pairing_recoveries WHERE peer_id = ?1",
                [&recovery.peer_id],
                |row| row.get(0),
            )
            .optional()?;
        if other_for_peer.is_some() {
            return Err(StoreError::InvalidInput(
                "peer already has a pending recovery ceremony",
            ));
        }
        enforce_count_limit(
            &transaction,
            "SELECT COUNT(*) FROM pending_pairing_recoveries",
            self.limits.max_pending_pairings,
            "pending pairing recovery capacity",
        )?;
        transaction.execute(
            "INSERT INTO pending_pairing_recoveries
                (recovery_id, peer_id, pairing_id, expires_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                recovery.recovery_id.to_string(),
                recovery.peer_id,
                recovery.pairing_id.to_string(),
                recovery.expires_at_unix_ms,
                record
            ],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: recovery.requested_at_unix_ms,
                kind: AuditKind::PairingRecoveryChallengeCreated,
                outcome: AuditOutcome::Observed,
                request_id: None,
                actor_digest: None,
                subject_digest: Some(recovery.revoked_identity_digest),
                context_digest: Some(recovery.new_identity_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()
    }

    pub fn pending_pairing_recovery(
        &self,
        recovery_id: Uuid,
    ) -> Result<Option<PendingPairingRecovery>, StoreError> {
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM pending_pairing_recoveries WHERE recovery_id = ?1",
                [recovery_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn audit_pairing_recovery_rejection(
        &self,
        recovery_id: Uuid,
        occurred_at_unix_ms: i64,
        reason: &[u8],
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairing_recoveries WHERE recovery_id = ?1",
                [recovery_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Err(StoreError::RecoveryNotFound);
        };
        let pending: PendingPairingRecovery = decode(&record)?;
        append_pairing_recovery_rejection_audit(
            &transaction,
            &pending,
            occurred_at_unix_ms,
            reason,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn audit_pairing_rejection(
        &self,
        pairing_id: Uuid,
        occurred_at_unix_ms: i64,
        reason: &[u8],
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairings WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Err(StoreError::PairingNotFound);
        };
        let pending: PendingPairingChallenge = decode(&record)?;
        append_pairing_rejection_audit(&transaction, &pending, occurred_at_unix_ms, reason)?;
        transaction.commit()?;
        Ok(())
    }

    /// Establish trust only after the owner approval and pairing proof have
    /// both been supplied.  Approval, trust insertion, challenge consumption,
    /// and audit append commit atomically.
    pub fn approve_pairing(
        &self,
        approval: &PairingApproval,
        presented_challenge: &[u8],
    ) -> Result<(Pairing, TrustedPeer), StoreError> {
        if presented_challenge.len() < MIN_PAIRING_CHALLENGE_BYTES {
            return Err(StoreError::PairingChallengeMismatch);
        }
        if approval
            .trust_expires_at_unix_ms
            .is_some_and(|expires_at| expires_at <= approval.approved_at_unix_ms)
        {
            return Err(StoreError::InvalidInput(
                "trust expiry must follow approval time",
            ));
        }

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairings WHERE pairing_id = ?1",
                [approval.pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(pending_record) = pending_record else {
            return Err(StoreError::PairingNotFound);
        };
        let pending: PendingPairingChallenge = decode(&pending_record)?;

        if pending.expires_at_unix_ms <= approval.approved_at_unix_ms {
            transaction.execute(
                "DELETE FROM pending_pairings WHERE pairing_id = ?1",
                [approval.pairing_id.to_string()],
            )?;
            append_pairing_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"expired",
            )?;
            transaction.commit()?;
            return Err(StoreError::PairingExpired);
        }

        let presented_digest = sha256(presented_challenge);
        if !constant_time_digest_eq(&pending.challenge_digest, &presented_digest) {
            append_pairing_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"challenge-mismatch",
            )?;
            transaction.commit()?;
            return Err(StoreError::PairingChallengeMismatch);
        }

        if transaction
            .query_row(
                "SELECT 1 FROM revocations WHERE peer_id = ?1",
                [&pending.peer_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            append_pairing_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"peer-revoked",
            )?;
            transaction.commit()?;
            return Err(StoreError::PeerRevoked);
        }

        if transaction
            .query_row(
                "SELECT 1 FROM trusted_peers WHERE peer_id = ?1",
                [&pending.peer_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::PeerAlreadyTrusted);
        }
        enforce_count_limit(
            &transaction,
            "SELECT COUNT(*) FROM trusted_peers",
            self.limits.max_trusted_peers,
            "trusted peer capacity",
        )?;

        let pairing = Pairing {
            pairing_id: pending.pairing_id,
            node_id: pending.node_id.clone(),
            peer_id: pending.peer_id.clone(),
            device_label: pending.device_label.clone(),
            peer_public_key: pending.peer_public_key.clone(),
            transport_binding_digest: pending.transport_binding_digest,
            owner_authority_digest: approval.owner_authority_digest,
            capability_manifest_digest: approval.capability_manifest_digest,
            requested_at_unix_ms: pending.requested_at_unix_ms,
            approved_at_unix_ms: approval.approved_at_unix_ms,
        };
        let trusted_peer = TrustedPeer {
            peer_id: pending.peer_id.clone(),
            pairing_id: pending.pairing_id,
            node_id: pending.node_id.clone(),
            device_label: pending.device_label.clone(),
            public_key: pending.peer_public_key.clone(),
            identity_digest: peer_identity_digest(&pending.peer_id, &pending.peer_public_key),
            capability_manifest_digest: approval.capability_manifest_digest,
            status: TrustStatus::Active,
            trust_epoch: 1,
            paired_at_unix_ms: approval.approved_at_unix_ms,
            trust_expires_at_unix_ms: approval.trust_expires_at_unix_ms,
            last_key_rotation_at_unix_ms: None,
            revoked_at_unix_ms: None,
        };

        transaction.execute(
            "INSERT INTO pairings (pairing_id, peer_id, node_id, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                pairing.pairing_id.to_string(),
                pairing.peer_id,
                pairing.node_id,
                encode(&pairing)?
            ],
        )?;
        transaction.execute(
            "INSERT INTO trusted_peers
                (peer_id, pairing_id, trust_status, trust_expires_at_unix_ms, record)
             VALUES (?1, ?2, 1, ?3, ?4)",
            params![
                trusted_peer.peer_id,
                trusted_peer.pairing_id.to_string(),
                trusted_peer.trust_expires_at_unix_ms,
                encode(&trusted_peer)?
            ],
        )?;
        transaction.execute(
            "DELETE FROM pending_pairings WHERE pairing_id = ?1",
            [pending.pairing_id.to_string()],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: approval.approved_at_unix_ms,
                kind: AuditKind::PairingApproved,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(approval.owner_authority_digest),
                subject_digest: Some(trusted_peer.identity_digest),
                context_digest: Some(approval.capability_manifest_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok((pairing, trusted_peer))
    }

    pub fn pairing(&self, pairing_id: Uuid) -> Result<Option<Pairing>, StoreError> {
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM pairings WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    /// Returns only active, non-expired trust.  Revoked and expired peers are
    /// indistinguishable from untrusted peers at this authorization boundary.
    pub fn currently_trusted_peer(
        &self,
        peer_id: &str,
        now_unix_ms: i64,
    ) -> Result<Option<TrustedPeer>, StoreError> {
        validate_identifier(peer_id)?;
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM trusted_peers
                 WHERE peer_id = ?1
                   AND trust_status = 1
                   AND (trust_expires_at_unix_ms IS NULL OR trust_expires_at_unix_ms > ?2)",
                params![peer_id, now_unix_ms],
                |row| row.get(0),
            )
            .optional()?;
        let peer = record
            .map(|bytes| decode::<TrustedPeer>(&bytes))
            .transpose()?;
        if peer
            .as_ref()
            .is_some_and(|value| !value.is_currently_trusted(now_unix_ms))
        {
            return Err(StoreError::CorruptData("trust index disagrees with record"));
        }
        Ok(peer)
    }

    pub fn peer_record(&self, peer_id: &str) -> Result<Option<TrustedPeer>, StoreError> {
        validate_identifier(peer_id)?;
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT record FROM trusted_peers WHERE peer_id = ?1",
                [peer_id],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn currently_trusted_peers(
        &self,
        now_unix_ms: i64,
    ) -> Result<Vec<TrustedPeer>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT record FROM trusted_peers
             WHERE trust_status = 1
               AND (trust_expires_at_unix_ms IS NULL OR trust_expires_at_unix_ms > ?1)
             ORDER BY peer_id ASC",
        )?;
        let rows = statement.query_map([now_unix_ms], |row| row.get::<_, Vec<u8>>(0))?;
        let mut peers = Vec::new();
        for row in rows {
            let peer: TrustedPeer = decode(&row?)?;
            if !peer.is_currently_trusted(now_unix_ms) {
                return Err(StoreError::CorruptData("trust index disagrees with record"));
            }
            peers.push(peer);
        }
        Ok(peers)
    }

    pub fn revoke_peer(
        &self,
        peer_id: &str,
        revoked_at_unix_ms: i64,
        owner_authority_digest: Sha256Digest,
        reason_digest: Sha256Digest,
    ) -> Result<RevocationOutcome, StoreError> {
        validate_identifier(peer_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(record) = revocation_in_transaction(&transaction, peer_id)? {
            transaction.commit()?;
            return Ok(RevocationOutcome::AlreadyRevoked(record));
        }
        let trusted_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers WHERE peer_id = ?1",
                [peer_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(trusted_record) = trusted_record else {
            transaction.commit()?;
            return Ok(RevocationOutcome::NotFound);
        };
        let mut peer: TrustedPeer = decode(&trusted_record)?;
        peer.status = TrustStatus::Revoked;
        peer.revoked_at_unix_ms = Some(revoked_at_unix_ms);
        let revocation = RevocationRecord {
            peer_id: peer.peer_id.clone(),
            pairing_id: peer.pairing_id,
            revoked_at_unix_ms,
            owner_authority_digest,
            reason_digest,
        };

        transaction.execute(
            "UPDATE trusted_peers
             SET trust_status = 2, record = ?2
             WHERE peer_id = ?1 AND trust_status = 1",
            params![peer_id, encode(&peer)?],
        )?;
        transaction.execute(
            "INSERT INTO revocations
                (peer_id, pairing_id, revoked_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                peer_id,
                peer.pairing_id.to_string(),
                revoked_at_unix_ms,
                encode(&revocation)?
            ],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: revoked_at_unix_ms,
                kind: AuditKind::PeerRevoked,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(owner_authority_digest),
                subject_digest: Some(peer.identity_digest),
                context_digest: Some(reason_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(RevocationOutcome::Revoked(revocation))
    }

    pub fn revocation_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Option<RevocationRecord>, StoreError> {
        validate_identifier(peer_id)?;
        let connection = self.lock()?;
        revocation_in_connection(&connection, peer_id)
    }

    pub fn is_peer_revoked(&self, peer_id: &str) -> Result<bool, StoreError> {
        Ok(self.revocation_for_peer(peer_id)?.is_some())
    }

    /// Commit an owner-present recovery after both replacement authorities
    /// prove possession. The transaction serializes revocation state, epoch
    /// advancement, credential replacement, and immutable recovery history.
    pub(crate) fn approve_pairing_recovery(
        &self,
        approval: &PairingRecoveryApproval,
        presented_challenge: &[u8],
    ) -> Result<PairingRecoveryOutcome, StoreError> {
        if approval
            .trust_expires_at_unix_ms
            .is_some_and(|expiry| expiry <= approval.approved_at_unix_ms)
        {
            return Err(StoreError::InvalidInput(
                "trust expiry must follow recovery approval",
            ));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_pairing_recoveries WHERE recovery_id = ?1",
                [approval.recovery_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(pending_record) = pending_record else {
            return Err(StoreError::RecoveryNotFound);
        };
        let pending: PendingPairingRecovery = decode(&pending_record)?;
        if pending.expires_at_unix_ms <= approval.approved_at_unix_ms {
            transaction.execute(
                "DELETE FROM pending_pairing_recoveries WHERE recovery_id = ?1",
                [approval.recovery_id.to_string()],
            )?;
            append_pairing_recovery_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"expired",
            )?;
            transaction.commit()?;
            return Err(StoreError::RecoveryExpired);
        }
        if !constant_time_digest_eq(&pending.challenge_digest, &sha256(presented_challenge)) {
            append_pairing_recovery_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"challenge-mismatch",
            )?;
            transaction.commit()?;
            return Err(StoreError::RecoveryMismatch);
        }
        let peer_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers
                 WHERE peer_id = ?1 AND pairing_id = ?2 AND trust_status = 2",
                params![pending.peer_id, pending.pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(peer_record) = peer_record else {
            append_pairing_recovery_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"peer-not-revoked",
            )?;
            transaction.commit()?;
            return Err(StoreError::RecoveryMismatch);
        };
        let mut peer: TrustedPeer = decode(&peer_record)?;
        let revocation = revocation_in_transaction(&transaction, &pending.peer_id)?.ok_or(
            StoreError::CorruptData("revoked peer lacks revocation record"),
        )?;
        let revocation_digest = sha256(&encode(&revocation)?);
        if peer.status != TrustStatus::Revoked
            || peer.node_id != pending.node_id
            || peer.pairing_id != pending.pairing_id
            || peer.identity_digest != pending.revoked_identity_digest
            || peer.trust_epoch != pending.revoked_trust_epoch
            || peer.revoked_at_unix_ms != Some(revocation.revoked_at_unix_ms)
            || revocation.pairing_id != pending.pairing_id
            || !constant_time_digest_eq(&revocation_digest, &pending.revocation_digest)
            || peer.public_key == pending.new_public_key
        {
            append_pairing_recovery_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"revocation-state-changed",
            )?;
            transaction.commit()?;
            return Err(StoreError::RecoveryMismatch);
        }
        let previous_identity_digest = peer.identity_digest;
        let previous_trust_epoch = peer.trust_epoch;
        let next_trust_epoch = previous_trust_epoch
            .checked_add(1)
            .ok_or(StoreError::CorruptData("credential epoch overflow"))?;
        peer.public_key.clone_from(&pending.new_public_key);
        peer.identity_digest = pending.new_identity_digest;
        peer.capability_manifest_digest = approval.capability_manifest_digest;
        peer.status = TrustStatus::Active;
        peer.trust_epoch = next_trust_epoch;
        peer.trust_expires_at_unix_ms = approval.trust_expires_at_unix_ms;
        peer.last_key_rotation_at_unix_ms = Some(approval.approved_at_unix_ms);
        peer.revoked_at_unix_ms = None;

        let recovery = PairingRecoveryRecord {
            recovery_id: pending.recovery_id,
            pairing_id: pending.pairing_id,
            peer_id: pending.peer_id.clone(),
            previous_identity_digest,
            next_identity_digest: peer.identity_digest,
            previous_trust_epoch,
            next_trust_epoch,
            revocation,
            owner_authority_digest: approval.owner_authority_digest,
            capability_manifest_digest: approval.capability_manifest_digest,
            recovered_at_unix_ms: approval.approved_at_unix_ms,
        };
        let updated = transaction.execute(
            "UPDATE trusted_peers
             SET trust_status = 1, trust_expires_at_unix_ms = ?2, record = ?3
             WHERE peer_id = ?1 AND trust_status = 2",
            params![peer.peer_id, peer.trust_expires_at_unix_ms, encode(&peer)?],
        )?;
        if updated != 1 {
            return Err(StoreError::CorruptData(
                "pairing recovery did not update exactly one revoked peer",
            ));
        }
        transaction.execute(
            "INSERT INTO pairing_recoveries
                (recovery_id, peer_id, pairing_id, recovered_at_unix_ms, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                recovery.recovery_id.to_string(),
                recovery.peer_id,
                recovery.pairing_id.to_string(),
                recovery.recovered_at_unix_ms,
                encode(&recovery)?
            ],
        )?;
        let removed_revocation = transaction.execute(
            "DELETE FROM revocations WHERE peer_id = ?1",
            [&peer.peer_id],
        )?;
        if removed_revocation != 1 {
            return Err(StoreError::CorruptData(
                "pairing recovery did not consume exactly one revocation",
            ));
        }
        let removed_pending = transaction.execute(
            "DELETE FROM pending_pairing_recoveries WHERE recovery_id = ?1",
            [pending.recovery_id.to_string()],
        )?;
        if removed_pending != 1 {
            return Err(StoreError::CorruptData(
                "pairing recovery did not consume exactly one challenge",
            ));
        }
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: approval.approved_at_unix_ms,
                kind: AuditKind::PairingRecovered,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(approval.owner_authority_digest),
                subject_digest: Some(peer.identity_digest),
                context_digest: Some(previous_identity_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(PairingRecoveryOutcome {
            trusted_peer: peer,
            recovery,
        })
    }

    pub fn pairing_recoveries_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Vec<PairingRecoveryRecord>, StoreError> {
        validate_identifier(peer_id)?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT record FROM pairing_recoveries
             WHERE peer_id = ?1 ORDER BY recovered_at_unix_ms ASC, recovery_id ASC",
        )?;
        let rows = statement.query_map([peer_id], |row| row.get::<_, Vec<u8>>(0))?;
        let mut recoveries = Vec::new();
        for row in rows {
            recoveries.push(decode(&row?)?);
        }
        Ok(recoveries)
    }

    /// Commit a locally approved credential-rotation challenge. Signature and
    /// owner-presence checks are performed by `PairingManager`; this transaction
    /// rechecks challenge, expiry, current credential, and epoch atomically.
    pub(crate) fn approve_credential_rotation(
        &self,
        approval: &CredentialRotationApproval,
        presented_challenge: &[u8],
    ) -> Result<CredentialRotationOutcome, StoreError> {
        if approval
            .trust_expires_at_unix_ms
            .is_some_and(|expiry| expiry <= approval.approved_at_unix_ms)
        {
            return Err(StoreError::InvalidInput(
                "trust expiry must follow rotation approval",
            ));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM pending_credential_rotations WHERE rotation_id = ?1",
                [approval.rotation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(pending_record) = pending_record else {
            return Err(StoreError::CredentialRotationNotFound);
        };
        let pending: PendingCredentialRotation = decode(&pending_record)?;
        if pending.expires_at_unix_ms <= approval.approved_at_unix_ms {
            transaction.execute(
                "DELETE FROM pending_credential_rotations WHERE rotation_id = ?1",
                [approval.rotation_id.to_string()],
            )?;
            append_credential_rotation_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"expired",
            )?;
            transaction.commit()?;
            return Err(StoreError::CredentialRotationExpired);
        }
        if !constant_time_digest_eq(&pending.challenge_digest, &sha256(presented_challenge)) {
            append_credential_rotation_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"challenge-mismatch",
            )?;
            transaction.commit()?;
            return Err(StoreError::CredentialRotationChallengeMismatch);
        }
        let record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers
                 WHERE peer_id = ?1 AND pairing_id = ?2 AND trust_status = 1
                   AND (trust_expires_at_unix_ms IS NULL OR trust_expires_at_unix_ms > ?3)",
                params![
                    pending.peer_id,
                    pending.pairing_id.to_string(),
                    approval.approved_at_unix_ms
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            append_credential_rotation_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"peer-inactive",
            )?;
            transaction.commit()?;
            return Err(StoreError::PeerRevoked);
        };
        let mut peer: TrustedPeer = decode(&record)?;
        let current_digest = sha256(&peer.public_key);
        if peer.node_id != pending.node_id
            || peer.trust_epoch != pending.current_trust_epoch
            || !constant_time_digest_eq(&current_digest, &pending.current_public_key_digest)
        {
            append_credential_rotation_rejection_audit(
                &transaction,
                &pending,
                approval.approved_at_unix_ms,
                b"current-credential-changed",
            )?;
            transaction.commit()?;
            return Err(StoreError::CredentialRotationMismatch);
        }
        if peer.public_key == pending.new_public_key {
            transaction.execute(
                "DELETE FROM pending_credential_rotations WHERE rotation_id = ?1",
                [approval.rotation_id.to_string()],
            )?;
            transaction.commit()?;
            return Ok(CredentialRotationOutcome::AlreadyCurrent(peer));
        }
        peer.public_key = pending.new_public_key;
        peer.identity_digest = pending.new_identity_digest;
        peer.capability_manifest_digest = approval.capability_manifest_digest;
        peer.trust_epoch = peer
            .trust_epoch
            .checked_add(1)
            .ok_or(StoreError::CorruptData("credential epoch overflow"))?;
        peer.trust_expires_at_unix_ms = approval.trust_expires_at_unix_ms;
        peer.last_key_rotation_at_unix_ms = Some(approval.approved_at_unix_ms);
        transaction.execute(
            "UPDATE trusted_peers
             SET trust_expires_at_unix_ms = ?2, record = ?3
             WHERE peer_id = ?1 AND trust_status = 1",
            params![peer.peer_id, peer.trust_expires_at_unix_ms, encode(&peer)?],
        )?;
        transaction.execute(
            "DELETE FROM pending_credential_rotations WHERE rotation_id = ?1",
            [approval.rotation_id.to_string()],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: approval.approved_at_unix_ms,
                kind: AuditKind::CredentialRotated,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(approval.owner_authority_digest),
                subject_digest: Some(peer.identity_digest),
                context_digest: Some(current_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(CredentialRotationOutcome::Rotated(peer))
    }

    /// Internal test helper for transport epoch tests. Production callers must
    /// use the owner-approved `PairingManager` ceremony.
    #[cfg(test)]
    pub(crate) fn rotate_peer_credential(
        &self,
        peer_id: &str,
        expected_public_key_digest: Sha256Digest,
        new_public_key: Vec<u8>,
        owner_authority_digest: Sha256Digest,
        rotated_at_unix_ms: i64,
    ) -> Result<CredentialRotationOutcome, StoreError> {
        validate_identifier(peer_id)?;
        if new_public_key.is_empty() || new_public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(StoreError::InvalidInput("invalid peer public key length"));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers WHERE peer_id = ?1 AND trust_status = 1",
                [peer_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return if revocation_in_transaction(&transaction, peer_id)?.is_some() {
                Err(StoreError::PeerRevoked)
            } else {
                Err(StoreError::PairingNotFound)
            };
        };
        let mut peer: TrustedPeer = decode(&record)?;
        let current_digest = sha256(&peer.public_key);
        if !constant_time_digest_eq(&current_digest, &expected_public_key_digest) {
            return Err(StoreError::CredentialRotationMismatch);
        }
        if peer.public_key == new_public_key {
            transaction.commit()?;
            return Ok(CredentialRotationOutcome::AlreadyCurrent(peer));
        }
        peer.public_key = new_public_key;
        peer.identity_digest = peer_identity_digest(&peer.peer_id, &peer.public_key);
        peer.trust_epoch = peer
            .trust_epoch
            .checked_add(1)
            .ok_or(StoreError::CorruptData("credential epoch overflow"))?;
        peer.last_key_rotation_at_unix_ms = Some(rotated_at_unix_ms);
        transaction.execute(
            "UPDATE trusted_peers SET record = ?2 WHERE peer_id = ?1 AND trust_status = 1",
            params![peer_id, encode(&peer)?],
        )?;
        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: rotated_at_unix_ms,
                kind: AuditKind::CredentialRotated,
                outcome: AuditOutcome::Accepted,
                request_id: None,
                actor_digest: Some(owner_authority_digest),
                subject_digest: Some(peer.identity_digest),
                context_digest: Some(current_digest),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(CredentialRotationOutcome::Rotated(peer))
    }

    /// Validate the authorization first, then atomically reserve the request
    /// identifier.  If validation fails, the denial is audit-chained and no
    /// replay row is inserted.
    pub fn reserve_replay_after_validation<F, E>(
        &self,
        reservation: &ReplayReservation,
        validate_authorization: F,
    ) -> Result<ReplayOutcome, StoreError>
    where
        F: FnOnce() -> Result<(), E>,
        E: fmt::Display,
    {
        reservation.validate()?;
        let now_unix_ms = unix_time_ms()?;
        if let Err(error) = validate_authorization() {
            self.append_audit(AuditEventDraft {
                occurred_at_unix_ms: now_unix_ms,
                kind: AuditKind::AuthorizationRejected,
                outcome: AuditOutcome::Rejected,
                request_id: Some(reservation.request_id),
                actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                subject_digest: Some(sha256(reservation.node_id.as_bytes())),
                context_digest: Some(sha256(error.to_string().as_bytes())),
            })?;
            return Err(StoreError::AuthorizationRejected);
        }
        self.reserve_validated_replay_at(reservation, now_unix_ms)
    }

    pub fn reserve_validated_replay_at(
        &self,
        reservation: &ReplayReservation,
        now_unix_ms: i64,
    ) -> Result<ReplayOutcome, StoreError> {
        self.reserve_validated_replay_with_clock_at(reservation, now_unix_ms, 0)
    }

    pub fn reserve_validated_replay_with_clock_at(
        &self,
        reservation: &ReplayReservation,
        now_unix_ms: i64,
        maximum_rollback_ms: i64,
    ) -> Result<ReplayOutcome, StoreError> {
        validate_clock_policy(now_unix_ms, maximum_rollback_ms)?;
        if reservation.expires_at_unix_ms <= now_unix_ms {
            return Err(StoreError::AuthorizationExpired);
        }
        let fingerprint = reservation.fingerprint()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        match advance_trusted_clock_in_transaction(&transaction, now_unix_ms, maximum_rollback_ms) {
            Ok(()) => {}
            Err(StoreError::ClockRollback) => {
                append_clock_rollback_audit_once(
                    &transaction,
                    AuditEventDraft {
                        occurred_at_unix_ms: now_unix_ms,
                        kind: AuditKind::ClockRollbackRejected,
                        outcome: AuditOutcome::Rejected,
                        request_id: Some(reservation.request_id),
                        actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                        subject_digest: Some(sha256(reservation.node_id.as_bytes())),
                        context_digest: Some(sha256(b"rollback-beyond-policy")),
                    },
                )?;
                transaction.commit()?;
                return Err(StoreError::ClockRollback);
            }
            Err(error) => return Err(error),
        }

        // Defense in depth: even a caller that accidentally treats a stale
        // authorization as valid cannot reserve work for a revoked pairing.
        if transaction
            .query_row(
                "SELECT 1 FROM revocations WHERE pairing_id = ?1",
                [reservation.pairing_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            append_audit_in_transaction(
                &transaction,
                AuditEventDraft {
                    occurred_at_unix_ms: now_unix_ms,
                    kind: AuditKind::AuthorizationRejected,
                    outcome: AuditOutcome::Rejected,
                    request_id: Some(reservation.request_id),
                    actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                    subject_digest: Some(sha256(reservation.pairing_id.as_bytes())),
                    context_digest: Some(sha256(b"revoked-pairing")),
                },
            )?;
            transaction.commit()?;
            return Err(StoreError::PeerRevoked);
        }

        // Serialize replay reservation with revocation and credential rotation. Re-check the
        // durable peer record inside this IMMEDIATE transaction so an old epoch cannot slip
        // through after a key rotation between signature verification and reservation.
        let peer_record: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record FROM trusted_peers
                 WHERE pairing_id = ?1 AND trust_status = 1
                   AND (trust_expires_at_unix_ms IS NULL OR trust_expires_at_unix_ms > ?2)",
                params![reservation.pairing_id.to_string(), now_unix_ms],
                |row| row.get(0),
            )
            .optional()?;
        let Some(peer_record) = peer_record else {
            append_audit_in_transaction(
                &transaction,
                AuditEventDraft {
                    occurred_at_unix_ms: now_unix_ms,
                    kind: AuditKind::AuthorizationRejected,
                    outcome: AuditOutcome::Rejected,
                    request_id: Some(reservation.request_id),
                    actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                    subject_digest: Some(sha256(reservation.pairing_id.as_bytes())),
                    context_digest: Some(sha256(b"inactive-or-expired-pairing")),
                },
            )?;
            transaction.commit()?;
            return Err(StoreError::PeerRevoked);
        };
        let current_peer: TrustedPeer = decode(&peer_record)?;
        if current_peer.trust_epoch != reservation.trust_epoch {
            append_audit_in_transaction(
                &transaction,
                AuditEventDraft {
                    occurred_at_unix_ms: now_unix_ms,
                    kind: AuditKind::AuthorizationRejected,
                    outcome: AuditOutcome::Rejected,
                    request_id: Some(reservation.request_id),
                    actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                    subject_digest: Some(sha256(reservation.pairing_id.as_bytes())),
                    context_digest: Some(sha256(b"stale-trust-epoch")),
                },
            )?;
            transaction.commit()?;
            return Err(StoreError::PeerRevoked);
        }

        let active_policy: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT policy_version, policy_digest FROM policy_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((policy_version, policy_digest)) = active_policy else {
            return Err(StoreError::PolicyRollback);
        };
        let policy_version = u64::from_be_bytes(
            policy_version
                .try_into()
                .map_err(|_| StoreError::CorruptData("policy version has invalid length"))?,
        );
        let policy_digest = digest_from_blob(policy_digest)?;
        if policy_version != reservation.policy_version
            || !constant_time_digest_eq(&policy_digest, &reservation.policy_digest)
        {
            return Err(StoreError::PolicyVersionReuse);
        }

        let existing: Option<(Vec<u8>, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT request_fingerprint, terminal_record
                 FROM request_replays
                 WHERE request_id = ?1
                    OR (pairing_id = ?2 AND trust_epoch = ?3
                        AND (replay_sequence = ?4 OR replay_nonce = ?5))
                 ORDER BY CASE WHEN request_id = ?1 THEN 0 ELSE 1 END
                 LIMIT 1",
                params![
                    reservation.request_id.to_string(),
                    reservation.pairing_id.to_string(),
                    &u64_blob(reservation.trust_epoch)[..],
                    &u64_blob(reservation.replay_sequence)[..],
                    &reservation.replay_nonce[..]
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (outcome, audit_kind, audit_outcome) = if let Some((existing, terminal)) = existing {
            let existing_fingerprint = digest_from_blob(existing)?;
            if constant_time_digest_eq(&existing_fingerprint, &fingerprint) {
                let terminal = terminal
                    .map(|bytes| decode::<TerminalResponseMetadata>(&bytes))
                    .transpose()?;
                (
                    ReplayOutcome::DuplicateSame {
                        fingerprint,
                        terminal,
                    },
                    AuditKind::ReplayDuplicate,
                    AuditOutcome::Observed,
                )
            } else {
                (
                    ReplayOutcome::Collision {
                        existing_fingerprint,
                    },
                    AuditKind::ReplayCollision,
                    AuditOutcome::Rejected,
                )
            }
        } else {
            enforce_count_limit(
                &transaction,
                "SELECT COUNT(*) FROM request_replays WHERE terminal_record IS NULL",
                self.limits.max_open_replays,
                "open replay reservation capacity",
            )?;
            transaction.execute(
                "INSERT INTO request_replays
                    (request_id, pairing_id, trust_epoch, replay_sequence,
                     replay_nonce, request_fingerprint, reserved_at_unix_ms,
                     expires_at_unix_ms, terminal_record)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    reservation.request_id.to_string(),
                    reservation.pairing_id.to_string(),
                    &u64_blob(reservation.trust_epoch)[..],
                    &u64_blob(reservation.replay_sequence)[..],
                    &reservation.replay_nonce[..],
                    &fingerprint[..],
                    now_unix_ms,
                    reservation.expires_at_unix_ms
                ],
            )?;
            (
                ReplayOutcome::Reserved { fingerprint },
                AuditKind::RequestReserved,
                AuditOutcome::Accepted,
            )
        };

        append_audit_in_transaction(
            &transaction,
            AuditEventDraft {
                occurred_at_unix_ms: now_unix_ms,
                kind: audit_kind,
                outcome: audit_outcome,
                request_id: Some(reservation.request_id),
                actor_digest: Some(sha256(reservation.agent_id.as_bytes())),
                subject_digest: Some(sha256(reservation.node_id.as_bytes())),
                context_digest: Some(fingerprint),
            },
        )?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(outcome)
    }

    pub fn replay_outcome(
        &self,
        reservation: &ReplayReservation,
    ) -> Result<Option<ReplayOutcome>, StoreError> {
        let fingerprint = reservation.fingerprint()?;
        let connection = self.lock()?;
        let existing: Option<(Vec<u8>, Option<Vec<u8>>)> = connection
            .query_row(
                "SELECT request_fingerprint, terminal_record
                 FROM request_replays WHERE request_id = ?1",
                [reservation.request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((existing, terminal)) = existing else {
            return Ok(None);
        };
        let existing_fingerprint = digest_from_blob(existing)?;
        if constant_time_digest_eq(&existing_fingerprint, &fingerprint) {
            Ok(Some(ReplayOutcome::DuplicateSame {
                fingerprint,
                terminal: terminal
                    .map(|bytes| decode::<TerminalResponseMetadata>(&bytes))
                    .transpose()?,
            }))
        } else {
            Ok(Some(ReplayOutcome::Collision {
                existing_fingerprint,
            }))
        }
    }

    /// Record terminal metadata exactly once.  A retry with identical metadata
    /// is idempotent; any different terminal result fails closed.
    pub fn record_terminal_response(
        &self,
        request_id: Uuid,
        expected_fingerprint: Sha256Digest,
        terminal: &TerminalResponseMetadata,
    ) -> Result<TerminalRecordOutcome, StoreError> {
        let terminal_record = encode(terminal)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(Vec<u8>, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT request_fingerprint, terminal_record
                 FROM request_replays WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_fingerprint, stored_terminal)) = existing else {
            return Err(StoreError::ReplayNotFound);
        };
        let stored_fingerprint = digest_from_blob(stored_fingerprint)?;
        if !constant_time_digest_eq(&stored_fingerprint, &expected_fingerprint) {
            return Err(StoreError::ReplayFingerprintMismatch);
        }

        let outcome = if let Some(stored_terminal) = stored_terminal {
            let stored_terminal: TerminalResponseMetadata = decode(&stored_terminal)?;
            if stored_terminal != *terminal {
                return Err(StoreError::TerminalResponseConflict);
            }
            TerminalRecordOutcome::AlreadyRecordedSame
        } else {
            transaction.execute(
                "UPDATE request_replays SET terminal_record = ?2
                 WHERE request_id = ?1 AND terminal_record IS NULL",
                params![request_id.to_string(), terminal_record],
            )?;
            append_audit_in_transaction(
                &transaction,
                AuditEventDraft {
                    occurred_at_unix_ms: terminal.completed_at_unix_ms,
                    kind: AuditKind::TerminalResponseRecorded,
                    outcome: AuditOutcome::Observed,
                    request_id: Some(request_id),
                    actor_digest: None,
                    subject_digest: Some(expected_fingerprint),
                    context_digest: Some(terminal.response_digest),
                },
            )?;
            TerminalRecordOutcome::Recorded
        };
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(outcome)
    }

    /// Mark reservations from a prior daemon process as spent and indeterminate.
    /// The daemon lease makes this safe against a concurrently executing runtime.
    pub fn reconcile_open_replays(
        &self,
        daemon_lease: &LifecycleLease,
        now_unix_ms: i64,
    ) -> Result<u64, StoreError> {
        if daemon_lease.kind() != LeaseKind::Daemon {
            return Err(StoreError::InvalidInput(
                "open replay reconciliation requires the daemon lease",
            ));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = transaction.prepare(
            "SELECT request_id, request_fingerprint FROM request_replays
             WHERE terminal_record IS NULL ORDER BY reserved_at_unix_ms",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let reconciled = u64::try_from(rows.len())
            .map_err(|_| StoreError::CorruptData("replay reconciliation count overflow"))?;
        for (request_id, fingerprint) in rows {
            let request_id = Uuid::parse_str(&request_id)
                .map_err(|_| StoreError::CorruptData("replay request ID is invalid"))?;
            let fingerprint = digest_from_blob(fingerprint)?;
            let terminal = TerminalResponseMetadata {
                status: TerminalStatus::Indeterminate,
                response_digest: sha256(b"indeterminate-after-daemon-restart"),
                redacted_error_digest: Some(sha256(b"prior-runtime-ended-before-terminal-record")),
                response_size_bytes: 0,
                completed_at_unix_ms: now_unix_ms,
            };
            transaction.execute(
                "UPDATE request_replays SET terminal_record = ?2
                 WHERE request_id = ?1 AND terminal_record IS NULL",
                params![request_id.to_string(), encode(&terminal)?],
            )?;
            append_audit_in_transaction(
                &transaction,
                AuditEventDraft {
                    occurred_at_unix_ms: now_unix_ms,
                    kind: AuditKind::TerminalResponseRecorded,
                    outcome: AuditOutcome::Observed,
                    request_id: Some(request_id),
                    actor_digest: None,
                    subject_digest: Some(fingerprint),
                    context_digest: Some(terminal.response_digest),
                },
            )?;
        }
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(reconciled)
    }

    pub fn terminal_response(
        &self,
        request_id: Uuid,
    ) -> Result<Option<TerminalResponseMetadata>, StoreError> {
        let connection = self.lock()?;
        let record: Option<Vec<u8>> = connection
            .query_row(
                "SELECT terminal_record FROM request_replays
                 WHERE request_id = ?1 AND terminal_record IS NOT NULL",
                [request_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        record.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn append_audit(&self, draft: AuditEventDraft) -> Result<AuditEvent, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = append_audit_in_transaction(&transaction, draft)?;
        transaction.commit()?;
        drop(connection);
        self.tighten_permissions()?;
        Ok(event)
    }

    pub fn audit_events_after(
        &self,
        sequence: u64,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        if limit == 0 || limit > 10_000 {
            return Err(StoreError::InvalidInput(
                "audit query limit is out of range",
            ));
        }
        let sequence = i64::try_from(sequence)
            .map_err(|_| StoreError::InvalidInput("audit sequence is too large"))?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT record FROM audit_events
             WHERE sequence > ?1 ORDER BY sequence ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![sequence, limit], |row| row.get::<_, Vec<u8>>(0))?;
        let mut events = Vec::new();
        for row in rows {
            events.push(decode(&row?)?);
        }
        Ok(events)
    }

    /// Verify every link and the durable tail marker.  This is suitable for
    /// startup checks and Agent Green monitoring.
    pub fn verify_audit_chain(&self) -> Result<AuditChainState, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT sequence, previous_hash, event_hash, record
             FROM audit_events ORDER BY sequence ASC",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_sequence = 1_u64;
        let mut previous_hash = ZERO_HASH;
        while let Some(row) = rows.next()? {
            let stored_sequence: i64 = row.get(0)?;
            let stored_previous = digest_from_blob(row.get(1)?)?;
            let stored_hash = digest_from_blob(row.get(2)?)?;
            let record: Vec<u8> = row.get(3)?;
            let event: AuditEvent = decode(&record)?;
            let sequence = u64::try_from(stored_sequence)
                .map_err(|_| StoreError::CorruptData("negative audit sequence"))?;
            if sequence != expected_sequence
                || event.sequence != sequence
                || event.previous_hash != stored_previous
                || event.event_hash != stored_hash
                || !constant_time_digest_eq(&stored_previous, &previous_hash)
                || !constant_time_digest_eq(&audit_event_hash(&event)?, &stored_hash)
            {
                return Err(StoreError::AuditChainInvalid { sequence });
            }
            previous_hash = stored_hash;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(StoreError::CorruptData("audit sequence overflow"))?;
        }
        drop(rows);
        drop(statement);

        let (tail_sequence, tail_hash): (i64, Vec<u8>) = connection.query_row(
            "SELECT tail_sequence, tail_hash FROM audit_chain_tail WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let tail_sequence = u64::try_from(tail_sequence)
            .map_err(|_| StoreError::CorruptData("negative audit tail sequence"))?;
        let tail_hash = digest_from_blob(tail_hash)?;
        let event_count = expected_sequence - 1;
        if tail_sequence != event_count || !constant_time_digest_eq(&tail_hash, &previous_hash) {
            return Err(StoreError::AuditChainInvalid {
                sequence: event_count.saturating_add(1),
            });
        }
        Ok(AuditChainState {
            event_count,
            tail_hash,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::LockPoisoned)
    }

    fn tighten_permissions(&self) -> Result<(), StoreError> {
        tighten_private_permissions(&self.path)
    }
}

fn configure_connection(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA temp_store = MEMORY;
         PRAGMA secure_delete = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA wal_autocheckpoint = 1000;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let current: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_pairings (
             pairing_id TEXT PRIMARY KEY NOT NULL,
             peer_id TEXT NOT NULL,
             node_id TEXT NOT NULL,
             expires_at_unix_ms INTEGER NOT NULL,
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS pending_pairings_expiry_idx
             ON pending_pairings(expires_at_unix_ms);
         CREATE INDEX IF NOT EXISTS pending_pairings_peer_idx
             ON pending_pairings(peer_id);

         CREATE TABLE IF NOT EXISTS pending_credential_rotations (
             rotation_id TEXT PRIMARY KEY NOT NULL,
             peer_id TEXT NOT NULL,
             pairing_id TEXT NOT NULL,
             expires_at_unix_ms INTEGER NOT NULL,
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS pending_credential_rotations_expiry_idx
             ON pending_credential_rotations(expires_at_unix_ms);
         CREATE INDEX IF NOT EXISTS pending_credential_rotations_peer_idx
             ON pending_credential_rotations(peer_id);

         CREATE TABLE IF NOT EXISTS pending_pairing_recoveries (
             recovery_id TEXT PRIMARY KEY NOT NULL,
             peer_id TEXT NOT NULL,
             pairing_id TEXT NOT NULL,
             expires_at_unix_ms INTEGER NOT NULL,
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS pending_pairing_recoveries_expiry_idx
             ON pending_pairing_recoveries(expires_at_unix_ms);
         CREATE UNIQUE INDEX IF NOT EXISTS pending_pairing_recoveries_peer_idx
             ON pending_pairing_recoveries(peer_id);

         CREATE TABLE IF NOT EXISTS pairing_recoveries (
             recovery_id TEXT PRIMARY KEY NOT NULL,
             peer_id TEXT NOT NULL,
             pairing_id TEXT NOT NULL,
             recovered_at_unix_ms INTEGER NOT NULL,
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS pairing_recoveries_peer_idx
             ON pairing_recoveries(peer_id, recovered_at_unix_ms);
         CREATE INDEX IF NOT EXISTS pairing_recoveries_pairing_idx
             ON pairing_recoveries(pairing_id, recovered_at_unix_ms);

         CREATE TABLE IF NOT EXISTS pairings (
             pairing_id TEXT PRIMARY KEY NOT NULL,
             peer_id TEXT NOT NULL UNIQUE,
             node_id TEXT NOT NULL,
             record BLOB NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS trusted_peers (
             peer_id TEXT PRIMARY KEY NOT NULL,
             pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(pairing_id),
             trust_status INTEGER NOT NULL CHECK (trust_status IN (1, 2)),
             trust_expires_at_unix_ms INTEGER,
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS trusted_peers_current_idx
             ON trusted_peers(trust_status, trust_expires_at_unix_ms);

         CREATE TABLE IF NOT EXISTS revocations (
             peer_id TEXT PRIMARY KEY NOT NULL REFERENCES trusted_peers(peer_id),
             pairing_id TEXT NOT NULL REFERENCES pairings(pairing_id),
             revoked_at_unix_ms INTEGER NOT NULL,
             record BLOB NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS request_replays (
             request_id TEXT PRIMARY KEY NOT NULL,
             pairing_id TEXT NOT NULL,
             trust_epoch BLOB NOT NULL CHECK (length(trust_epoch) = 8),
             replay_sequence BLOB NOT NULL CHECK (length(replay_sequence) = 8),
             replay_nonce BLOB NOT NULL CHECK (length(replay_nonce) = 32),
             request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
             reserved_at_unix_ms INTEGER NOT NULL,
             expires_at_unix_ms INTEGER NOT NULL,
             terminal_record BLOB
         ) STRICT;
         CREATE INDEX IF NOT EXISTS request_replays_open_idx
             ON request_replays(reserved_at_unix_ms) WHERE terminal_record IS NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS request_replays_sequence_idx
             ON request_replays(pairing_id, trust_epoch, replay_sequence);
         CREATE UNIQUE INDEX IF NOT EXISTS request_replays_nonce_idx
             ON request_replays(pairing_id, trust_epoch, replay_nonce);

         CREATE TABLE IF NOT EXISTS policy_state (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
             policy_version BLOB NOT NULL CHECK (length(policy_version) = 8),
             policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS trusted_clock_state (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
             high_water_unix_ms INTEGER NOT NULL CHECK (high_water_unix_ms >= 0),
             rollback_rejection_latched INTEGER NOT NULL DEFAULT 0
                 CHECK (rollback_rejection_latched IN (0, 1))
         ) STRICT;

         CREATE TABLE IF NOT EXISTS peer_rate_limits (
             peer_id TEXT PRIMARY KEY NOT NULL REFERENCES trusted_peers(peer_id),
             window_started_at_unix_ms INTEGER NOT NULL CHECK (window_started_at_unix_ms >= 0),
             request_count INTEGER NOT NULL CHECK (request_count > 0)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS global_rate_limit (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
             window_started_at_unix_ms INTEGER NOT NULL CHECK (window_started_at_unix_ms >= 0),
             request_count INTEGER NOT NULL CHECK (request_count > 0)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS update_stages (
             stage_id TEXT PRIMARY KEY NOT NULL,
             release_counter BLOB NOT NULL UNIQUE CHECK (length(release_counter) = 8),
             staged_at_unix_ms INTEGER NOT NULL CHECK (staged_at_unix_ms >= 0),
             record BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS update_stages_time_idx
             ON update_stages(staged_at_unix_ms);

         CREATE TABLE IF NOT EXISTS update_state (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
             highest_release_counter BLOB NOT NULL CHECK (length(highest_release_counter) = 8),
             latest_stage_id TEXT NOT NULL REFERENCES update_stages(stage_id),
             latest_manifest_digest BLOB NOT NULL CHECK (length(latest_manifest_digest) = 32)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS audit_events (
             sequence INTEGER PRIMARY KEY NOT NULL,
             event_id TEXT NOT NULL UNIQUE,
             previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
             event_hash BLOB NOT NULL UNIQUE CHECK (length(event_hash) = 32),
             record BLOB NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS audit_chain_tail (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
             tail_sequence INTEGER NOT NULL CHECK (tail_sequence >= 0),
             tail_hash BLOB NOT NULL CHECK (length(tail_hash) = 32)
         ) STRICT;
         INSERT INTO audit_chain_tail(singleton, tail_sequence, tail_hash)
             VALUES (1, 0, zeroblob(32))
             ON CONFLICT(singleton) DO NOTHING;
         PRAGMA user_version = 8;",
    )?;
    // Pending ceremonies are authorization-free, short-lived bootstrap state.
    // Schema 5 adds the certificate chain needed to revalidate X.509 at local
    // approval, so pre-v5 invitations are invalidated rather than guessed or
    // silently upgraded without their original leaf/intermediates.
    if current < 5 {
        transaction.execute("DELETE FROM pending_pairings", [])?;
        transaction.execute("DELETE FROM pending_credential_rotations", [])?;
    }
    // Schema 6 adds recovery-only tables. Existing trust, revocations, replay,
    // policy state, and audit records remain byte-for-byte unchanged.
    // Schema 7 adds offline update staging and a monotonic release-counter
    // high-water mark. No executable content is stored in SQLite.
    // Schema 8 adds the durable trusted-clock high-water mark. It is initialized
    // only from a live local observation, never guessed during migration.
    transaction.commit()?;
    Ok(())
}

fn append_pairing_rejection_audit(
    transaction: &Transaction<'_>,
    pending: &PendingPairingChallenge,
    occurred_at_unix_ms: i64,
    reason: &[u8],
) -> Result<(), StoreError> {
    append_audit_in_transaction(
        transaction,
        AuditEventDraft {
            occurred_at_unix_ms,
            kind: AuditKind::PairingRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest: None,
            subject_digest: Some(sha256(pending.peer_id.as_bytes())),
            context_digest: Some(sha256(reason)),
        },
    )?;
    Ok(())
}

fn append_credential_rotation_rejection_audit(
    transaction: &Transaction<'_>,
    pending: &PendingCredentialRotation,
    occurred_at_unix_ms: i64,
    reason: &[u8],
) -> Result<(), StoreError> {
    append_audit_in_transaction(
        transaction,
        AuditEventDraft {
            occurred_at_unix_ms,
            kind: AuditKind::CredentialRotationRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest: None,
            subject_digest: Some(pending.new_identity_digest),
            context_digest: Some(sha256(reason)),
        },
    )?;
    Ok(())
}

fn append_pairing_recovery_rejection_audit(
    transaction: &Transaction<'_>,
    pending: &PendingPairingRecovery,
    occurred_at_unix_ms: i64,
    reason: &[u8],
) -> Result<(), StoreError> {
    append_audit_in_transaction(
        transaction,
        AuditEventDraft {
            occurred_at_unix_ms,
            kind: AuditKind::PairingRecoveryRejected,
            outcome: AuditOutcome::Rejected,
            request_id: None,
            actor_digest: None,
            subject_digest: Some(pending.new_identity_digest),
            context_digest: Some(sha256(reason)),
        },
    )?;
    Ok(())
}

fn append_audit_in_transaction(
    transaction: &Transaction<'_>,
    draft: AuditEventDraft,
) -> Result<AuditEvent, StoreError> {
    let (tail_sequence, tail_hash): (i64, Vec<u8>) = transaction.query_row(
        "SELECT tail_sequence, tail_hash FROM audit_chain_tail WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let tail_sequence = u64::try_from(tail_sequence)
        .map_err(|_| StoreError::CorruptData("negative audit tail sequence"))?;
    let previous_hash = digest_from_blob(tail_hash)?;
    let sequence = tail_sequence
        .checked_add(1)
        .ok_or(StoreError::CorruptData("audit sequence overflow"))?;
    let mut event = AuditEvent {
        sequence,
        event_id: Uuid::new_v4(),
        occurred_at_unix_ms: draft.occurred_at_unix_ms,
        kind: draft.kind,
        outcome: draft.outcome,
        request_id: draft.request_id,
        actor_digest: draft.actor_digest,
        subject_digest: draft.subject_digest,
        context_digest: draft.context_digest,
        previous_hash,
        event_hash: ZERO_HASH,
    };
    event.event_hash = audit_event_hash(&event)?;
    let sequence_i64 = i64::try_from(sequence)
        .map_err(|_| StoreError::CorruptData("audit sequence exceeds SQLite integer"))?;
    transaction.execute(
        "INSERT INTO audit_events
            (sequence, event_id, previous_hash, event_hash, record)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            sequence_i64,
            event.event_id.to_string(),
            &event.previous_hash[..],
            &event.event_hash[..],
            encode(&event)?
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE audit_chain_tail SET tail_sequence = ?1, tail_hash = ?2
         WHERE singleton = 1 AND tail_sequence = ?3 AND tail_hash = ?4",
        params![
            sequence_i64,
            &event.event_hash[..],
            i64::try_from(tail_sequence)
                .map_err(|_| StoreError::CorruptData("audit sequence overflow"))?,
            &event.previous_hash[..]
        ],
    )?;
    if updated != 1 {
        return Err(StoreError::CorruptData("audit tail changed unexpectedly"));
    }
    Ok(event)
}

fn audit_event_hash(event: &AuditEvent) -> Result<Sha256Digest, StoreError> {
    #[derive(Serialize)]
    struct AuditHashMaterial<'a> {
        format_version: u8,
        sequence: u64,
        event_id: Uuid,
        occurred_at_unix_ms: i64,
        kind: AuditKind,
        outcome: AuditOutcome,
        request_id: Option<Uuid>,
        actor_digest: &'a Option<Sha256Digest>,
        subject_digest: &'a Option<Sha256Digest>,
        context_digest: &'a Option<Sha256Digest>,
        previous_hash: Sha256Digest,
    }

    let material = AuditHashMaterial {
        format_version: 1,
        sequence: event.sequence,
        event_id: event.event_id,
        occurred_at_unix_ms: event.occurred_at_unix_ms,
        kind: event.kind,
        outcome: event.outcome,
        request_id: event.request_id,
        actor_digest: &event.actor_digest,
        subject_digest: &event.subject_digest,
        context_digest: &event.context_digest,
        previous_hash: event.previous_hash,
    };
    Ok(sha256(&encode(&material)?))
}

fn revocation_in_connection(
    connection: &Connection,
    peer_id: &str,
) -> Result<Option<RevocationRecord>, StoreError> {
    let record: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record FROM revocations WHERE peer_id = ?1",
            [peer_id],
            |row| row.get(0),
        )
        .optional()?;
    record.map(|bytes| decode(&bytes)).transpose()
}

fn revocation_in_transaction(
    transaction: &Transaction<'_>,
    peer_id: &str,
) -> Result<Option<RevocationRecord>, StoreError> {
    let record: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT record FROM revocations WHERE peer_id = ?1",
            [peer_id],
            |row| row.get(0),
        )
        .optional()?;
    record.map(|bytes| decode(&bytes)).transpose()
}

fn enforce_count_limit(
    transaction: &Transaction<'_>,
    query: &str,
    maximum: u64,
    label: &'static str,
) -> Result<(), StoreError> {
    let count: i64 = transaction.query_row(query, [], |row| row.get(0))?;
    let count = u64::try_from(count).map_err(|_| StoreError::CorruptData("negative row count"))?;
    if count >= maximum {
        return Err(StoreError::ResourceLimit(label));
    }
    Ok(())
}

fn validate_certificate_chain(chain: &[Vec<u8>]) -> Result<(), StoreError> {
    if chain.is_empty() || chain.len() > MAX_CERTIFICATE_CHAIN_COUNT {
        return Err(StoreError::InvalidInput(
            "client certificate chain count is out of range",
        ));
    }
    let mut total = 0_usize;
    for certificate in chain {
        if certificate.is_empty() {
            return Err(StoreError::InvalidInput(
                "client certificate chain contains an empty certificate",
            ));
        }
        total = total
            .checked_add(certificate.len())
            .ok_or(StoreError::InvalidInput(
                "client certificate chain is too large",
            ))?;
        if total > MAX_CERTIFICATE_CHAIN_BYTES {
            return Err(StoreError::InvalidInput(
                "client certificate chain is too large",
            ));
        }
    }
    Ok(())
}

fn decode_rate_window(row: &rusqlite::Row<'_>) -> rusqlite::Result<RateWindow> {
    let request_count: i64 = row.get(1)?;
    let request_count = u32::try_from(request_count).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(RateWindow {
        started_at_unix_ms: row.get(0)?,
        request_count,
    })
}

fn evaluate_rate_window(
    existing: Option<RateWindow>,
    maximum_per_minute: u32,
    now_unix_ms: i64,
    maximum_rollback_ms: i64,
) -> Result<RateWindowDecision, StoreError> {
    let Some(existing) = existing else {
        return Ok(RateWindowDecision::Admit {
            next: RateWindow {
                started_at_unix_ms: now_unix_ms,
                request_count: 1,
            },
            remaining: maximum_per_minute - 1,
        });
    };
    if now_unix_ms
        < existing
            .started_at_unix_ms
            .saturating_sub(maximum_rollback_ms)
    {
        return Err(StoreError::ClockRollback);
    }
    let elapsed = now_unix_ms
        .saturating_sub(existing.started_at_unix_ms)
        .max(0);
    if elapsed >= PEER_RATE_WINDOW_MS {
        return Ok(RateWindowDecision::Admit {
            next: RateWindow {
                started_at_unix_ms: now_unix_ms,
                request_count: 1,
            },
            remaining: maximum_per_minute - 1,
        });
    }
    if existing.request_count >= maximum_per_minute {
        let retry_after_ms = u64::try_from(PEER_RATE_WINDOW_MS - elapsed)
            .map_err(|_| StoreError::CorruptData("invalid request-rate window"))?;
        return Ok(RateWindowDecision::Limit { retry_after_ms });
    }
    let next_count = existing
        .request_count
        .checked_add(1)
        .ok_or(StoreError::CorruptData("request-rate count overflow"))?;
    Ok(RateWindowDecision::Admit {
        next: RateWindow {
            started_at_unix_ms: existing.started_at_unix_ms,
            request_count: next_count,
        },
        remaining: maximum_per_minute - next_count,
    })
}

fn validate_clock_policy(now_unix_ms: i64, maximum_rollback_ms: i64) -> Result<(), StoreError> {
    if now_unix_ms < 0 || maximum_rollback_ms < 0 {
        return Err(StoreError::InvalidInput(
            "clock values must not predate the Unix epoch",
        ));
    }
    Ok(())
}

fn advance_trusted_clock_in_transaction(
    transaction: &Transaction<'_>,
    now_unix_ms: i64,
    maximum_rollback_ms: i64,
) -> Result<(), StoreError> {
    validate_clock_policy(now_unix_ms, maximum_rollback_ms)?;
    let high_water: Option<i64> = transaction
        .query_row(
            "SELECT high_water_unix_ms FROM trusted_clock_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(high_water) = high_water {
        let earliest_permitted = high_water.saturating_sub(maximum_rollback_ms);
        if now_unix_ms < earliest_permitted {
            return Err(StoreError::ClockRollback);
        }
        if now_unix_ms <= high_water {
            transaction.execute(
                "UPDATE trusted_clock_state SET rollback_rejection_latched = 0
                 WHERE singleton = 1 AND rollback_rejection_latched != 0",
                [],
            )?;
            return Ok(());
        }
    }
    transaction.execute(
        "INSERT INTO trusted_clock_state
            (singleton, high_water_unix_ms, rollback_rejection_latched)
         VALUES (1, ?1, 0)
         ON CONFLICT(singleton) DO UPDATE SET
             high_water_unix_ms = excluded.high_water_unix_ms,
             rollback_rejection_latched = 0",
        [now_unix_ms],
    )?;
    Ok(())
}

fn append_clock_rollback_audit_once(
    transaction: &Transaction<'_>,
    draft: AuditEventDraft,
) -> Result<(), StoreError> {
    let latched: i64 = transaction.query_row(
        "SELECT rollback_rejection_latched FROM trusted_clock_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if latched == 0 {
        append_audit_in_transaction(transaction, draft)?;
        transaction.execute(
            "UPDATE trusted_clock_state SET rollback_rejection_latched = 1 WHERE singleton = 1",
            [],
        )?;
    }
    Ok(())
}

fn validate_limits(limits: StoreLimits) -> Result<(), StoreError> {
    if limits.max_pending_pairings == 0
        || limits.max_trusted_peers == 0
        || limits.max_open_replays == 0
    {
        return Err(StoreError::InvalidInput("store limits must be non-zero"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), StoreError> {
    validate_bounded_text(value, MAX_ID_BYTES, "identifier")?;
    if value.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput(
            "identifier contains control characters",
        ));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    maximum: usize,
    _label: &'static str,
) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > maximum {
        return Err(StoreError::InvalidInput(
            "text field length is out of range",
        ));
    }
    Ok(())
}

fn peer_identity_digest(peer_id: &str, public_key: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"sovereign-node-peer-identity-v1\0");
    hasher.update((peer_id.len() as u64).to_be_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.update((public_key.len() as u64).to_be_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

#[must_use]
pub fn sha256(value: &[u8]) -> Sha256Digest {
    Sha256::digest(value).into()
}

fn constant_time_digest_eq(left: &Sha256Digest, right: &Sha256Digest) -> bool {
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn digest_from_blob(value: Vec<u8>) -> Result<Sha256Digest, StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::CorruptData("digest has invalid length"))
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, StoreError> {
    Ok(to_stdvec(value)?)
}

fn decode<T: DeserializeOwned>(value: &[u8]) -> Result<T, StoreError> {
    let (decoded, remainder) = postcard::take_from_bytes(value)?;
    if !remainder.is_empty() {
        return Err(StoreError::CorruptData("stored record has trailing bytes"));
    }
    Ok(decoded)
}

fn unix_time_ms() -> Result<i64, StoreError> {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000)
        .map_err(|_| StoreError::CorruptData("system time is out of range"))
}

fn prepare_private_database_file(path: &Path) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or(StoreError::InvalidInput("database path has no parent"))?;
    if !parent.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }

    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(StoreError::InvalidInput(
            "database parent must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if parent_metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(StoreError::InvalidInput(
                "database parent must be owned by the daemon account",
            ));
        }
    }

    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StoreError::InvalidInput(
                "database path must be a real regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(StoreError::InvalidInput(
                    "database file must be owned by the daemon account",
                ));
            }
        }
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    tighten_private_permissions(path)
}

fn tighten_private_permissions(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        for candidate in sqlite_files(path) {
            if candidate.exists() {
                fs::set_permissions(candidate, fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sqlite_files(path: &Path) -> [PathBuf; 3] {
    let path_text = path.as_os_str().to_string_lossy();
    [
        path.to_path_buf(),
        PathBuf::from(format!("{path_text}-wal")),
        PathBuf::from(format!("{path_text}-shm")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NOW: i64 = 2_000_000_000_000;

    fn test_store() -> Result<(TempDir, PathBuf, StateStore), StoreError> {
        let directory = TempDir::new()?;
        let path = directory.path().join("state.sqlite3");
        let store = StateStore::open(&path)?;
        Ok((directory, path, store))
    }

    fn pending(challenge_secret: &[u8]) -> Result<PendingPairingChallenge, StoreError> {
        pending_for("broker-01", challenge_secret)
    }

    fn pending_for(
        peer_id: &str,
        challenge_secret: &[u8],
    ) -> Result<PendingPairingChallenge, StoreError> {
        PendingPairingChallenge::new(
            Uuid::new_v4(),
            "node-01".to_owned(),
            peer_id.to_owned(),
            format!("Owner Action Broker {peer_id}"),
            vec![7_u8; 32],
            vec![vec![8_u8; 32]],
            challenge_secret,
            sha256(b"node-identity"),
            sha256(b"channel-binding"),
            NOW,
            NOW + 60_000,
        )
    }

    fn replay(store: &StateStore, request_id: Uuid) -> Result<ReplayReservation, StoreError> {
        let (_, peer) = pair_peer(store, b"0123456789abcdef0123456789abcdef")?;
        let policy_digest = sha256(b"test-policy");
        store.activate_policy(1, policy_digest, NOW - 1)?;
        Ok(ReplayReservation {
            request_id,
            task_id: Uuid::new_v4(),
            pairing_id: peer.pairing_id,
            trust_epoch: peer.trust_epoch,
            policy_version: 1,
            policy_digest,
            replay_sequence: 1,
            replay_nonce: sha256(request_id.as_bytes()),
            agent_id: "agent-green".to_owned(),
            node_id: "node-01".to_owned(),
            capability: "SystemInfo".to_owned(),
            target_digest: sha256(b"local"),
            arguments_digest: sha256(b"empty-map"),
            authorization_digest: sha256(b"signed-envelope"),
            expires_at_unix_ms: i64::MAX,
        })
    }

    fn pair_peer(
        store: &StateStore,
        challenge_secret: &[u8],
    ) -> Result<(Pairing, TrustedPeer), StoreError> {
        pair_peer_for(store, "broker-01", challenge_secret)
    }

    fn pair_peer_for(
        store: &StateStore,
        peer_id: &str,
        challenge_secret: &[u8],
    ) -> Result<(Pairing, TrustedPeer), StoreError> {
        let challenge = pending_for(peer_id, challenge_secret)?;
        store.put_pending_pairing(&challenge)?;
        store.approve_pairing(
            &PairingApproval {
                pairing_id: challenge.pairing_id,
                owner_authority_digest: sha256(b"owner"),
                capability_manifest_digest: sha256(b"manifest"),
                approved_at_unix_ms: NOW + 1,
                trust_expires_at_unix_ms: None,
            },
            challenge_secret,
        )
    }

    fn update_record(counter: u64, digest_seed: u8) -> UpdateStageRecord {
        UpdateStageRecord {
            stage_id: Uuid::new_v4(),
            software_version: format!("1.{counter}.0"),
            previous_version: "0.1.0".to_owned(),
            rollback_version: "0.1.0".to_owned(),
            target_os: "test-os".to_owned(),
            target_arch: "test-arch".to_owned(),
            release_counter: counter,
            manifest_digest: [digest_seed; 32],
            artifact_digest: [digest_seed.wrapping_add(1); 32],
            release_key_digest: [0x71; 32],
            owner_key_digest: [0x72; 32],
            staged_artifact_relative_path: format!("updates/staged/{counter}/artifact.bin"),
            staged_at_unix_ms: NOW + i64::try_from(counter).unwrap_or_default(),
        }
    }

    #[test]
    fn pairing_requires_correct_proof_and_survives_restart() -> Result<(), StoreError> {
        let (directory, path, store) = test_store()?;
        let secret = b"0123456789abcdef0123456789abcdef";
        let challenge = pending(secret)?;
        let pairing_id = challenge.pairing_id;
        store.put_pending_pairing(&challenge)?;
        let wrong = store.approve_pairing(
            &PairingApproval {
                pairing_id,
                owner_authority_digest: sha256(b"owner"),
                capability_manifest_digest: sha256(b"manifest"),
                approved_at_unix_ms: NOW + 1,
                trust_expires_at_unix_ms: None,
            },
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        );
        assert!(matches!(wrong, Err(StoreError::PairingChallengeMismatch)));
        assert!(
            store
                .currently_trusted_peer("broker-01", NOW + 2)?
                .is_none()
        );

        let (_, peer) = store.approve_pairing(
            &PairingApproval {
                pairing_id,
                owner_authority_digest: sha256(b"owner"),
                capability_manifest_digest: sha256(b"manifest"),
                approved_at_unix_ms: NOW + 2,
                trust_expires_at_unix_ms: None,
            },
            secret,
        )?;
        assert_eq!(peer.status, TrustStatus::Active);
        drop(store);

        let reopened = StateStore::open(&path)?;
        assert_eq!(
            reopened
                .currently_trusted_peer("broker-01", NOW + 3)?
                .map(|value| value.pairing_id),
            Some(pairing_id)
        );
        drop(reopened);
        drop(directory);
        Ok(())
    }

    #[test]
    fn revocation_is_current_idempotent_and_durable() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let first = store.revoke_peer(
            &peer.peer_id,
            NOW + 10,
            sha256(b"owner"),
            sha256(b"lost-device"),
        )?;
        assert!(matches!(first, RevocationOutcome::Revoked(_)));
        assert!(
            store
                .currently_trusted_peer(&peer.peer_id, NOW + 11)?
                .is_none()
        );
        let second = store.revoke_peer(
            &peer.peer_id,
            NOW + 12,
            sha256(b"owner"),
            sha256(b"different-reason"),
        )?;
        assert!(matches!(second, RevocationOutcome::AlreadyRevoked(_)));
        drop(store);

        let reopened = StateStore::open(path)?;
        assert!(reopened.is_peer_revoked(&peer.peer_id)?);
        assert!(
            reopened
                .currently_trusted_peer(&peer.peer_id, NOW + 20)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn request_limits_survive_reconnect_and_store_reopen() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        assert_eq!(
            store.admit_remote_request_at(&peer.peer_id, 2, 10, NOW)?,
            RemoteRequestAdmission::Admitted {
                peer_remaining: 1,
                global_remaining: 9
            }
        );
        assert_eq!(
            store.admit_remote_request_at(&peer.peer_id, 2, 10, NOW + 1)?,
            RemoteRequestAdmission::Admitted {
                peer_remaining: 0,
                global_remaining: 8
            }
        );
        drop(store);

        let reopened = StateStore::open(path)?;
        assert_eq!(
            reopened.admit_remote_request_at(&peer.peer_id, 2, 10, NOW + 2)?,
            RemoteRequestAdmission::Limited {
                scope: RequestLimitScope::Peer,
                retry_after_ms: 59_998
            }
        );
        assert_eq!(
            reopened.admit_remote_request_at(&peer.peer_id, 2, 10, NOW + 60_000)?,
            RemoteRequestAdmission::Admitted {
                peer_remaining: 1,
                global_remaining: 9
            }
        );
        assert!(matches!(
            reopened.admit_remote_request_at(&peer.peer_id, 2, 10, NOW + 59_999),
            Err(StoreError::ClockRollback)
        ));
        Ok(())
    }

    #[test]
    fn trusted_clock_rollback_is_durable_tolerated_only_within_policy_and_audited()
    -> Result<(), StoreError> {
        let (directory, path, store) = test_store()?;
        store.observe_trusted_clock_at(NOW, 5_000)?;
        store.observe_trusted_clock_at(NOW - 5_000, 5_000)?;
        assert_eq!(store.trusted_clock_high_water()?, Some(NOW));
        assert!(matches!(
            store.observe_trusted_clock_at(NOW - 5_001, 5_000),
            Err(StoreError::ClockRollback)
        ));
        assert!(matches!(
            store.observe_trusted_clock_at(NOW - 6_000, 5_000),
            Err(StoreError::ClockRollback)
        ));
        assert_eq!(store.trusted_clock_high_water()?, Some(NOW));
        assert_eq!(
            store
                .audit_events_after(0, 100)?
                .iter()
                .filter(|event| event.kind == AuditKind::ClockRollbackRejected)
                .count(),
            1
        );

        drop(store);
        let reopened = StateStore::open(path)?;
        assert_eq!(reopened.trusted_clock_high_water()?, Some(NOW));
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let admin_lease = LifecycleLease::acquire(directory.path(), LeaseKind::AdminMutation)
            .map_err(|_| StoreError::InvalidInput("could not acquire test admin lease"))?;
        let daemon_lease = LifecycleLease::acquire(directory.path(), LeaseKind::Daemon)
            .map_err(|_| StoreError::InvalidInput("could not acquire test daemon lease"))?;
        assert_eq!(
            reopened.acknowledge_trusted_clock(&admin_lease, &daemon_lease, NOW - 60_000)?,
            Some(NOW)
        );
        assert_eq!(reopened.trusted_clock_high_water()?, Some(NOW - 60_000));
        assert!(
            reopened
                .audit_events_after(0, 100)?
                .iter()
                .any(|event| event.kind == AuditKind::ClockRollbackAcknowledged)
        );
        reopened.verify_audit_chain()?;
        Ok(())
    }

    #[test]
    fn authenticated_admission_uses_the_configured_clock_tolerance() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        assert!(matches!(
            store.admit_remote_request_with_clock_policy_at(&peer.peer_id, 3, 10, NOW, 5_000)?,
            RemoteRequestAdmission::Admitted { .. }
        ));
        assert!(matches!(
            store.admit_remote_request_with_clock_policy_at(
                &peer.peer_id,
                3,
                10,
                NOW - 5_000,
                5_000
            )?,
            RemoteRequestAdmission::Admitted { .. }
        ));
        assert!(matches!(
            store.admit_remote_request_with_clock_policy_at(
                &peer.peer_id,
                3,
                10,
                NOW - 5_001,
                5_000
            ),
            Err(StoreError::ClockRollback)
        ));
        Ok(())
    }

    #[test]
    fn replay_reservation_rechecks_trusted_clock_before_consuming_request_id()
    -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        store.observe_trusted_clock_at(NOW + 10_000, 5_000)?;
        assert!(matches!(
            store.reserve_validated_replay_with_clock_at(&request, NOW, 5_000),
            Err(StoreError::ClockRollback)
        ));
        assert!(store.replay_outcome(&request)?.is_none());
        assert!(
            store
                .audit_events_after(0, 100)?
                .iter()
                .any(|event| event.kind == AuditKind::ClockRollbackRejected
                    && event.request_id == Some(request.request_id))
        );
        Ok(())
    }

    #[test]
    fn schema_one_store_migrates_to_durable_request_admission() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch(
            "DROP TABLE peer_rate_limits;
             DROP TABLE global_rate_limit;
             PRAGMA user_version = 1;",
        )?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert_eq!(
            migrated.admit_remote_request_at(&peer.peer_id, 1, 1, NOW)?,
            RemoteRequestAdmission::Admitted {
                peer_remaining: 0,
                global_remaining: 0
            }
        );
        assert_eq!(
            migrated.admit_remote_request_at(&peer.peer_id, 1, 1, NOW + 1)?,
            RemoteRequestAdmission::Limited {
                scope: RequestLimitScope::Peer,
                retry_after_ms: 59_999
            }
        );
        Ok(())
    }

    #[test]
    fn schema_two_store_migrates_to_global_request_admission() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch("DROP TABLE global_rate_limit; PRAGMA user_version = 2;")?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert!(matches!(
            migrated.admit_remote_request_at(&peer.peer_id, 2, 2, NOW)?,
            RemoteRequestAdmission::Admitted { .. }
        ));
        Ok(())
    }

    #[test]
    fn schema_four_migration_invalidates_pending_but_preserves_trust_and_audit()
    -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, trusted) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let pending = pending_for("pending-broker", b"fedcba9876543210fedcba9876543210")?;
        let pending_id = pending.pairing_id;
        store.put_pending_pairing(&pending)?;
        let before = store.verify_audit_chain()?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch("PRAGMA user_version = 4;")?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert!(migrated.pending_pairing(pending_id)?.is_none());
        assert_eq!(
            migrated
                .currently_trusted_peer(&trusted.peer_id, NOW + 10)?
                .map(|peer| peer.pairing_id),
            Some(trusted.pairing_id)
        );
        assert_eq!(migrated.verify_audit_chain()?, before);
        Ok(())
    }

    #[test]
    fn schema_five_migration_adds_recovery_tables_without_rewriting_trust() -> Result<(), StoreError>
    {
        let (_directory, path, store) = test_store()?;
        let (_, trusted) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let before = store.verify_audit_chain()?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch(
            "DROP TABLE pending_pairing_recoveries;
             DROP TABLE pairing_recoveries;
             PRAGMA user_version = 5;",
        )?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert_eq!(
            migrated
                .peer_record(&trusted.peer_id)?
                .map(|peer| peer.pairing_id),
            Some(trusted.pairing_id)
        );
        assert_eq!(migrated.verify_audit_chain()?, before);
        let connection = migrated.lock()?;
        for table in ["pending_pairing_recoveries", "pairing_recoveries"] {
            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )?;
            assert_eq!(exists, 1);
        }
        Ok(())
    }

    #[test]
    fn update_counter_is_monotonic_idempotent_and_audited() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let first = update_record(2, 0x20);
        assert_eq!(
            store.stage_verified_update(&first)?,
            UpdateStageOutcome::Staged(first.clone())
        );
        let same_content = UpdateStageRecord {
            stage_id: Uuid::new_v4(),
            staged_at_unix_ms: NOW + 99,
            ..first.clone()
        };
        assert_eq!(
            store.stage_verified_update(&same_content)?,
            UpdateStageOutcome::AlreadyStaged(first.clone())
        );
        assert!(matches!(
            store.stage_verified_update(&update_record(2, 0x21)),
            Err(StoreError::UpdateCounterCollision)
        ));
        assert!(matches!(
            store.stage_verified_update(&update_record(1, 0x10)),
            Err(StoreError::UpdateCounterRollback)
        ));
        let mut wrong_authority = update_record(3, 0x31);
        wrong_authority.release_key_digest = [0x73; 32];
        assert!(matches!(
            store.stage_verified_update(&wrong_authority),
            Err(StoreError::UpdateAuthorityMismatch)
        ));
        let second = update_record(3, 0x30);
        assert!(matches!(
            store.stage_verified_update(&second)?,
            UpdateStageOutcome::Staged(_)
        ));
        assert_eq!(store.latest_staged_update()?, Some(second.clone()));
        let audit = store.verify_audit_chain()?;
        assert_eq!(audit.event_count, 2);
        drop(store);

        let reopened = StateStore::open(path)?;
        assert_eq!(reopened.latest_staged_update()?, Some(second));
        assert_eq!(reopened.verify_audit_chain()?, audit);
        Ok(())
    }

    #[test]
    fn schema_six_migration_adds_update_state_without_rewriting_audit() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, trusted) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let before = store.verify_audit_chain()?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch(
            "DROP TABLE update_state;
             DROP TABLE update_stages;
             PRAGMA user_version = 6;",
        )?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert!(migrated.latest_staged_update()?.is_none());
        assert_eq!(migrated.verify_audit_chain()?, before);
        assert_eq!(
            migrated
                .peer_record(&trusted.peer_id)?
                .map(|peer| peer.pairing_id),
            Some(trusted.pairing_id)
        );
        assert!(matches!(
            migrated.stage_verified_update(&update_record(2, 0x20))?,
            UpdateStageOutcome::Staged(_)
        ));
        Ok(())
    }

    #[test]
    fn schema_seven_migration_adds_uninitialized_trusted_clock_without_rewriting_audit()
    -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, trusted) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let before = store.verify_audit_chain()?;
        drop(store);

        let legacy = Connection::open(&path)?;
        legacy.execute_batch(
            "DROP TABLE trusted_clock_state;
             PRAGMA user_version = 7;",
        )?;
        drop(legacy);

        let migrated = StateStore::open(path)?;
        assert_eq!(migrated.trusted_clock_high_water()?, None);
        assert_eq!(migrated.verify_audit_chain()?, before);
        assert_eq!(
            migrated
                .peer_record(&trusted.peer_id)?
                .map(|peer| peer.pairing_id),
            Some(trusted.pairing_id)
        );
        migrated.observe_trusted_clock_at(NOW, 5_000)?;
        assert_eq!(migrated.trusted_clock_high_water()?, Some(NOW));
        Ok(())
    }

    #[test]
    fn global_limit_is_atomic_with_peer_limit() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let (_, first_peer) =
            pair_peer_for(&store, "broker-01", b"0123456789abcdef0123456789abcdef")?;
        let (_, second_peer) =
            pair_peer_for(&store, "broker-02", b"fedcba9876543210fedcba9876543210")?;
        assert!(matches!(
            store.admit_remote_request_at(&first_peer.peer_id, 2, 2, NOW)?,
            RemoteRequestAdmission::Admitted { .. }
        ));
        assert!(matches!(
            store.admit_remote_request_at(&second_peer.peer_id, 2, 2, NOW + 1)?,
            RemoteRequestAdmission::Admitted { .. }
        ));
        drop(store);

        let store = StateStore::open(path)?;
        assert_eq!(
            store.admit_remote_request_at(&first_peer.peer_id, 2, 2, NOW + 2)?,
            RemoteRequestAdmission::Limited {
                scope: RequestLimitScope::Global,
                retry_after_ms: 59_998
            }
        );
        let connection = store.lock()?;
        let peer_count: i64 = connection.query_row(
            "SELECT request_count FROM peer_rate_limits WHERE peer_id = ?1",
            [&first_peer.peer_id],
            |row| row.get(0),
        )?;
        let global_count: i64 = connection.query_row(
            "SELECT request_count FROM global_rate_limit WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!((peer_count, global_count), (1, 2));
        Ok(())
    }

    #[test]
    fn concurrent_request_admission_never_exceeds_either_limit() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        let store = std::sync::Arc::new(store);
        let mut workers = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let peer_id = peer.peer_id.clone();
            workers.push(std::thread::spawn(move || {
                store.admit_remote_request_at(&peer_id, 3, 3, NOW)
            }));
        }

        let mut admitted = 0;
        let mut limited = 0;
        for worker in workers {
            match worker
                .join()
                .map_err(|_| StoreError::CorruptData("peer admission worker panicked"))??
            {
                RemoteRequestAdmission::Admitted { .. } => admitted += 1,
                RemoteRequestAdmission::Limited { .. } => limited += 1,
            }
        }
        assert_eq!(admitted, 3);
        assert_eq!(limited, 13);
        Ok(())
    }

    #[test]
    fn replay_reservation_distinguishes_duplicate_and_collision_across_restart()
    -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let request_id = Uuid::new_v4();
        let request = replay(&store, request_id)?;
        store.activate_policy(request.policy_version, request.policy_digest, NOW - 1)?;
        let fingerprint = request.fingerprint()?;
        assert!(matches!(
            store.reserve_validated_replay_at(&request, NOW)?,
            ReplayOutcome::Reserved { .. }
        ));
        drop(store);

        let reopened = StateStore::open(path)?;
        assert!(matches!(
            reopened.reserve_validated_replay_at(&request, NOW + 1)?,
            ReplayOutcome::DuplicateSame { terminal: None, .. }
        ));
        let mut collision = request;
        collision.arguments_digest = sha256(b"different arguments");
        assert!(matches!(
            reopened.reserve_validated_replay_at(&collision, NOW + 2)?,
            ReplayOutcome::Collision { existing_fingerprint } if existing_fingerprint == fingerprint
        ));
        Ok(())
    }

    #[test]
    fn exclusive_daemon_lease_reconciles_open_replay_without_retry() -> Result<(), StoreError> {
        let (directory, path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        store.reserve_validated_replay_at(&request, NOW)?;
        drop(store);

        let reopened = StateStore::open(path)?;
        assert!(matches!(
            reopened.replay_outcome(&request)?,
            Some(ReplayOutcome::DuplicateSame { terminal: None, .. })
        ));
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let admin_lease = LifecycleLease::acquire(directory.path(), LeaseKind::AdminMutation)
            .map_err(|_| StoreError::InvalidInput("could not acquire test admin lease"))?;
        assert!(matches!(
            reopened.reconcile_open_replays(&admin_lease, NOW + 1),
            Err(StoreError::InvalidInput(_))
        ));
        let daemon_lease = LifecycleLease::acquire(directory.path(), LeaseKind::Daemon)
            .map_err(|_| StoreError::InvalidInput("could not acquire test daemon lease"))?;
        assert_eq!(reopened.reconcile_open_replays(&daemon_lease, NOW + 2)?, 1);
        assert_eq!(reopened.reconcile_open_replays(&daemon_lease, NOW + 3)?, 0);
        assert!(matches!(
            reopened.terminal_response(request.request_id)?,
            Some(TerminalResponseMetadata {
                status: TerminalStatus::Indeterminate,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejected_authorization_never_reserves_request_id() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        let rejected =
            store.reserve_replay_after_validation(&request, || Err::<(), _>("forged signature"));
        assert!(matches!(rejected, Err(StoreError::AuthorizationRejected)));
        assert!(store.replay_outcome(&request)?.is_none());
        assert!(matches!(
            store.reserve_validated_replay_at(&request, NOW)?,
            ReplayOutcome::Reserved { .. }
        ));
        Ok(())
    }

    #[test]
    fn terminal_response_is_immutable_and_returned_to_duplicate() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        let fingerprint = request.fingerprint()?;
        store.reserve_validated_replay_at(&request, NOW)?;
        let terminal = TerminalResponseMetadata {
            status: TerminalStatus::Succeeded,
            response_digest: sha256(b"redacted response"),
            redacted_error_digest: None,
            response_size_bytes: 17,
            completed_at_unix_ms: NOW + 1,
        };
        assert_eq!(
            store.record_terminal_response(request.request_id, fingerprint, &terminal)?,
            TerminalRecordOutcome::Recorded
        );
        assert_eq!(
            store.record_terminal_response(request.request_id, fingerprint, &terminal)?,
            TerminalRecordOutcome::AlreadyRecordedSame
        );
        let mut conflicting = terminal.clone();
        conflicting.status = TerminalStatus::Failed;
        assert!(matches!(
            store.record_terminal_response(request.request_id, fingerprint, &conflicting),
            Err(StoreError::TerminalResponseConflict)
        ));
        assert!(matches!(
            store.reserve_validated_replay_at(&request, NOW + 2)?,
            ReplayOutcome::DuplicateSame { terminal: Some(value), .. } if value == terminal
        ));
        Ok(())
    }

    #[test]
    fn credential_rotation_uses_expected_key_and_increments_epoch() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let (_, peer) = pair_peer(&store, b"0123456789abcdef0123456789abcdef")?;
        assert!(matches!(
            store.rotate_peer_credential(
                &peer.peer_id,
                sha256(b"wrong key"),
                vec![8_u8; 32],
                sha256(b"owner"),
                NOW + 5,
            ),
            Err(StoreError::CredentialRotationMismatch)
        ));
        let rotated = store.rotate_peer_credential(
            &peer.peer_id,
            sha256(&peer.public_key),
            vec![8_u8; 32],
            sha256(b"owner"),
            NOW + 6,
        )?;
        let CredentialRotationOutcome::Rotated(rotated) = rotated else {
            return Err(StoreError::CorruptData("rotation did not update the key"));
        };
        assert_eq!(rotated.trust_epoch, 2);
        assert_eq!(rotated.public_key, vec![8_u8; 32]);
        Ok(())
    }

    #[test]
    fn policy_binding_is_monotonic_and_rejects_same_version_remapping() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let first = sha256(b"policy-one");
        store.activate_policy(1, first, NOW)?;
        store.activate_policy(1, first, NOW + 1)?;
        assert!(matches!(
            store.activate_policy(1, sha256(b"changed"), NOW + 2),
            Err(StoreError::PolicyVersionReuse)
        ));
        store.activate_policy(2, sha256(b"policy-two"), NOW + 3)?;
        assert!(matches!(
            store.activate_policy(1, first, NOW + 4),
            Err(StoreError::PolicyRollback)
        ));
        Ok(())
    }

    #[test]
    fn audit_chain_detects_record_tampering() -> Result<(), StoreError> {
        let (_directory, _path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        store.reserve_validated_replay_at(&request, NOW)?;
        let state = store.verify_audit_chain()?;
        assert_eq!(state.event_count, 4);
        {
            let connection = store.lock()?;
            connection.execute(
                "UPDATE audit_events SET record = X'00' WHERE sequence = 1",
                [],
            )?;
        }
        assert!(store.verify_audit_chain().is_err());
        Ok(())
    }

    #[test]
    fn pending_pairing_limit_fails_closed() -> Result<(), StoreError> {
        let directory = TempDir::new()?;
        let store = StateStore::open_with_limits(
            directory.path().join("state.sqlite3"),
            StoreLimits {
                max_pending_pairings: 1,
                max_trusted_peers: 1,
                max_open_replays: 1,
            },
        )?;
        store.put_pending_pairing(&pending(b"0123456789abcdef0123456789abcdef")?)?;
        let second = store.put_pending_pairing(&pending(b"fedcba9876543210fedcba9876543210")?);
        assert!(matches!(
            second,
            Err(StoreError::ResourceLimit("pending pairing capacity"))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_files_are_owner_only() -> Result<(), StoreError> {
        let (_directory, path, store) = test_store()?;
        let request = replay(&store, Uuid::new_v4())?;
        store.reserve_validated_replay_at(&request, NOW)?;
        for candidate in sqlite_files(&path) {
            if candidate.exists() {
                let mode = fs::metadata(candidate)?.permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
        Ok(())
    }
}
