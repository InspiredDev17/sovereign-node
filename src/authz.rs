use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::PolicyConfig;
use crate::pairing::{PairingError, PairingKeyMaterialV1, decode_key_material};
use crate::protocol::{
    ActionErrorCode, ActionRequestV1, Capability, NodeId, Sha256Digest, SignedActionV1, UnixMillis,
    ValidationError,
};
use crate::store::{
    AuditEventDraft, AuditKind, AuditOutcome, ReplayOutcome, ReplayReservation, StateStore,
    StoreError, TrustedPeer, sha256,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportPeer {
    pub peer_id: String,
    pub certificate_sha256: Sha256Digest,
    pub trust_epoch: u64,
}

pub trait Clock: fmt::Debug + Send + Sync {
    fn now(&self) -> Result<UnixMillis, AuthorizationError>;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<UnixMillis, AuthorizationError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthorizationError::Clock)?;
        let millis = u64::try_from(duration.as_millis()).map_err(|_| AuthorizationError::Clock)?;
        Ok(UnixMillis(millis))
    }
}

#[derive(Debug)]
pub struct VerifiedAction {
    signed: SignedActionV1,
    replay_fingerprint: [u8; 32],
    peer_id: String,
}

impl VerifiedAction {
    #[must_use]
    pub fn request(&self) -> &ActionRequestV1 {
        &self.signed.request
    }

    #[must_use]
    pub(crate) const fn replay_fingerprint(&self) -> [u8; 32] {
        self.replay_fingerprint
    }

    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

#[derive(Debug)]
pub enum AuthorizationOutcome {
    Fresh(Box<VerifiedAction>),
    Duplicate,
}

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("authorization state is unavailable")]
    Store(#[from] StoreError),
    #[error("authorization clock is unavailable or invalid")]
    Clock,
    #[error("transport peer is not currently trusted")]
    UntrustedPeer,
    #[error("transport certificate does not match the paired certificate")]
    TransportBinding,
    #[error("authorization signature is invalid")]
    Forged,
    #[error("authorization does not apply to this node")]
    WrongNode,
    #[error("authorization has expired")]
    Expired,
    #[error("authorization is not yet valid")]
    NotYetValid,
    #[error("authorization time-to-live exceeds local policy")]
    TtlExceeded,
    #[error("authorization trust generation does not match")]
    TrustEpoch,
    #[error("authorization capability is not advertised")]
    CapabilityNotAdvertised,
    #[error("authorization capability is outside the paired scope")]
    CapabilityNotPaired,
    #[error("authorization target or arguments do not match")]
    CapabilityMismatch,
    #[error("authorization owner identity does not match pairing")]
    OwnerMismatch,
    #[error("authorization policy version is unsupported")]
    PolicyVersion,
    #[error("authorization uses a duplicate request")]
    Duplicate,
    #[error("authorization replay identifier collides with prior work")]
    ReplayCollision,
    #[error("authorization encoding is invalid")]
    Encoding,
    #[error("paired key material is invalid")]
    PairingMaterial,
}

impl AuthorizationError {
    #[must_use]
    pub const fn code(&self) -> ActionErrorCode {
        match self {
            Self::WrongNode => ActionErrorCode::WrongNode,
            Self::Expired => ActionErrorCode::ExpiredAuthorization,
            Self::NotYetValid => ActionErrorCode::NotYetValid,
            Self::CapabilityNotAdvertised => ActionErrorCode::CapabilityNotAdvertised,
            Self::CapabilityNotPaired | Self::CapabilityMismatch => {
                ActionErrorCode::CapabilityMismatch
            }
            Self::Duplicate => ActionErrorCode::DuplicateRequest,
            Self::ReplayCollision => ActionErrorCode::ReplayDetected,
            Self::UntrustedPeer | Self::TrustEpoch | Self::Store(StoreError::PeerRevoked) => {
                ActionErrorCode::RevokedPairing
            }
            Self::Store(StoreError::ResourceLimit(_)) => ActionErrorCode::ResourceExhausted,
            Self::Store(_) | Self::Clock => ActionErrorCode::Internal,
            Self::Forged | Self::OwnerMismatch | Self::TransportBinding => {
                ActionErrorCode::ForgedAuthorization
            }
            Self::TtlExceeded | Self::PolicyVersion | Self::Encoding | Self::PairingMaterial => {
                ActionErrorCode::InvalidRequest
            }
        }
    }
}

#[derive(Debug)]
pub struct AuthorizationEngine {
    node_id: NodeId,
    store: Arc<StateStore>,
    clock: Arc<dyn Clock>,
    advertised_capabilities: BTreeSet<Capability>,
    max_action_ttl_millis: u64,
    policy_version: u64,
    policy_digest: Sha256Digest,
}

impl AuthorizationEngine {
    #[must_use]
    pub fn new(
        node_id: NodeId,
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        policy: &PolicyConfig,
        policy_version: u64,
        policy_digest: Sha256Digest,
    ) -> Self {
        Self {
            node_id,
            store,
            clock,
            advertised_capabilities: policy.enabled_capabilities.iter().copied().collect(),
            max_action_ttl_millis: u64::try_from(policy.max_action_ttl_secs)
                .unwrap_or(0)
                .saturating_mul(1_000),
            policy_version,
            policy_digest,
        }
    }

    pub fn verify_and_reserve(
        &self,
        action: SignedActionV1,
        transport_peer: &TransportPeer,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        let now = self.clock.now()?;
        let request = &action.request;
        let reservation = reservation_for(&action, self.policy_digest)?;

        let trusted = self
            .store
            .currently_trusted_peer(
                &transport_peer.peer_id,
                i64::try_from(now.0).map_err(|_| AuthorizationError::Clock)?,
            )?
            .ok_or(AuthorizationError::UntrustedPeer);
        let trusted = match trusted {
            Ok(trusted) => trusted,
            Err(error) => {
                self.audit_rejection(request, &error, now)?;
                return Err(error);
            }
        };
        let material = decode_key_material(&trusted.public_key)
            .map_err(|_: PairingError| AuthorizationError::PairingMaterial);
        let material = match material {
            Ok(material) => material,
            Err(error) => {
                self.audit_rejection(request, &error, now)?;
                return Err(error);
            }
        };
        if let Err(error) =
            self.validate(request, &action, transport_peer, &trusted, &material, now)
        {
            self.audit_rejection(request, &error, now)?;
            return Err(error);
        }

        let outcome = self.store.reserve_validated_replay_at(
            &reservation,
            i64::try_from(now.0).map_err(|_| AuthorizationError::Clock)?,
        )?;
        match outcome {
            ReplayOutcome::Reserved { fingerprint } => {
                Ok(AuthorizationOutcome::Fresh(Box::new(VerifiedAction {
                    signed: action,
                    replay_fingerprint: fingerprint,
                    peer_id: transport_peer.peer_id.clone(),
                })))
            }
            ReplayOutcome::DuplicateSame { .. } => Ok(AuthorizationOutcome::Duplicate),
            ReplayOutcome::Collision { .. } => Err(AuthorizationError::ReplayCollision),
        }
    }

    fn validate(
        &self,
        request: &ActionRequestV1,
        action: &SignedActionV1,
        transport_peer: &TransportPeer,
        trusted: &TrustedPeer,
        material: &PairingKeyMaterialV1,
        now: UnixMillis,
    ) -> Result<(), AuthorizationError> {
        if transport_peer.trust_epoch != trusted.trust_epoch {
            return Err(AuthorizationError::TrustEpoch);
        }
        request
            .validate_for_node(self.node_id, now, trusted.trust_epoch)
            .map_err(map_validation)?;
        let ttl = request
            .expires_at
            .0
            .checked_sub(request.issued_at.0)
            .ok_or(AuthorizationError::TtlExceeded)?;
        if ttl > self.max_action_ttl_millis {
            return Err(AuthorizationError::TtlExceeded);
        }
        if request.authorization.pairing_id.0 != trusted.pairing_id {
            return Err(AuthorizationError::TrustEpoch);
        }
        if request.authorization.policy_version != self.policy_version {
            return Err(AuthorizationError::PolicyVersion);
        }
        if transport_peer.certificate_sha256 != material.client_certificate_sha256 {
            return Err(AuthorizationError::TransportBinding);
        }
        if request.user_authority.owner_id != material.owner_id {
            return Err(AuthorizationError::OwnerMismatch);
        }
        if !self.advertised_capabilities.contains(&request.capability) {
            return Err(AuthorizationError::CapabilityNotAdvertised);
        }
        if !material.allowed_capabilities.contains(&request.capability) {
            return Err(AuthorizationError::CapabilityNotPaired);
        }

        let owner_key = VerifyingKey::from_bytes(&material.owner_public_key.0)
            .map_err(|_| AuthorizationError::PairingMaterial)?;
        let broker_key = VerifyingKey::from_bytes(&material.broker_public_key.0)
            .map_err(|_| AuthorizationError::PairingMaterial)?;
        if owner_key.is_weak() || broker_key.is_weak() {
            return Err(AuthorizationError::PairingMaterial);
        }
        if request.authorization.owner_key_id != crate::identity::key_id(&owner_key)
            || request.authorization.broker_key_id != crate::identity::key_id(&broker_key)
        {
            return Err(AuthorizationError::Forged);
        }

        let owner_message = request
            .owner_signing_bytes()
            .map_err(|_| AuthorizationError::Encoding)?;
        verify_signature(
            &owner_key,
            &owner_message,
            action.owner_signature.as_bytes(),
        )?;
        let broker_message = action
            .broker_signing_bytes()
            .map_err(|_| AuthorizationError::Encoding)?;
        verify_signature(
            &broker_key,
            &broker_message,
            action.broker_signature.as_bytes(),
        )?;
        Ok(())
    }

    fn audit_rejection(
        &self,
        request: &ActionRequestV1,
        error: &AuthorizationError,
        now: UnixMillis,
    ) -> Result<(), AuthorizationError> {
        self.store.append_audit(AuditEventDraft {
            occurred_at_unix_ms: i64::try_from(now.0).map_err(|_| AuthorizationError::Clock)?,
            kind: AuditKind::AuthorizationRejected,
            outcome: AuditOutcome::Rejected,
            request_id: Some(request.request_id.0),
            actor_digest: Some(sha256(request.agent_id.to_string().as_bytes())),
            subject_digest: Some(sha256(request.node_id.to_string().as_bytes())),
            context_digest: Some(sha256(format!("{:?}", error.code()).as_bytes())),
        })?;
        Ok(())
    }
}

fn reservation_for(
    action: &SignedActionV1,
    policy_digest: Sha256Digest,
) -> Result<ReplayReservation, AuthorizationError> {
    let request = &action.request;
    let target_digest = request
        .target
        .digest()
        .map_err(|_| AuthorizationError::Encoding)?;
    let encoded = postcard::to_allocvec(action).map_err(|_| AuthorizationError::Encoding)?;
    let authorization_digest: [u8; 32] = Sha256::digest(encoded).into();
    Ok(ReplayReservation {
        request_id: request.request_id.0,
        task_id: request.task_id.0,
        pairing_id: request.authorization.pairing_id.0,
        trust_epoch: request.authorization.trust_epoch,
        policy_version: request.authorization.policy_version,
        policy_digest: policy_digest.0,
        replay_sequence: request.replay_protection.sequence,
        replay_nonce: request.replay_protection.nonce.0,
        agent_id: request.agent_id.to_string(),
        node_id: request.node_id.to_string(),
        capability: format!("{:?}", request.capability),
        target_digest: target_digest.0,
        arguments_digest: request.arguments_digest.0,
        authorization_digest,
        expires_at_unix_ms: i64::try_from(request.expires_at.0)
            .map_err(|_| AuthorizationError::Clock)?,
    })
}

fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), AuthorizationError> {
    let signature = Signature::from_slice(signature).map_err(|_| AuthorizationError::Forged)?;
    key.verify_strict(message, &signature)
        .map_err(|_| AuthorizationError::Forged)
}

fn map_validation(error: ValidationError) -> AuthorizationError {
    match error {
        ValidationError::WrongNode { .. } => AuthorizationError::WrongNode,
        ValidationError::Expired => AuthorizationError::Expired,
        ValidationError::NotYetValid => AuthorizationError::NotYetValid,
        ValidationError::TrustEpochMismatch => AuthorizationError::TrustEpoch,
        ValidationError::CapabilityMismatch
        | ValidationError::TargetMismatch
        | ValidationError::ArgumentsDigestMismatch
        | ValidationError::AuthorizationCapabilityMismatch
        | ValidationError::AuthorizationTargetMismatch => AuthorizationError::CapabilityMismatch,
        _ => AuthorizationError::Encoding,
    }
}
