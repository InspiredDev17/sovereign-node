use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use x509_parser::{parse_x509_certificate, time::ASN1Time};

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;

use crate::identity::{NodeIdentity, key_id};
use crate::protocol::{
    Capability, PairingId, PublicKeyBytes, Sha256Digest, SignatureBytes, UnixMillis,
};
use crate::store::{
    CredentialRotationApproval, CredentialRotationOutcome, PairingApproval,
    PairingRecoveryApproval, PairingRecoveryOutcome, PendingCredentialRotation,
    PendingPairingChallenge, PendingPairingRecovery, RevocationOutcome, StateStore, StoreError,
    TrustedPeer, sha256,
};

const PAIRING_PROOF_DOMAIN: &[u8] = b"sovereign-node/pairing-proof/v1\0";
const CREDENTIAL_ROTATION_PROOF_DOMAIN: &[u8] = b"sovereign-node/credential-rotation-proof/v1\0";
const PAIRING_RECOVERY_PROOF_DOMAIN: &[u8] = b"sovereign-node/pairing-recovery-proof/v1\0";
const TRUST_RECEIPT_DOMAIN: &[u8] = b"sovereign-node/trust-receipt/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingKeyMaterialV1 {
    pub schema_version: u16,
    pub owner_id: String,
    pub owner_public_key: PublicKeyBytes,
    pub broker_public_key: PublicKeyBytes,
    /// DER-encoded CA certificate used only to authenticate this peer's TLS certificate.
    pub client_ca_der: Vec<u8>,
    /// Exact SHA-256 fingerprint of the expected TLS leaf certificate.
    pub client_certificate_sha256: Sha256Digest,
    pub allowed_capabilities: Vec<Capability>,
    /// Exact cached-trust expiry displayed locally and signed by both pairing roles.
    pub trust_expires_at: Option<UnixMillis>,
}

#[derive(Clone, Debug)]
pub struct PairingRequest {
    pub peer_id: String,
    pub device_label: String,
    pub key_material: PairingKeyMaterialV1,
    /// Leaf first, followed by any intermediates. This is validated at request
    /// and approval time but only its exact leaf digest is retained as trust.
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    pub ttl_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PairingDisplay {
    pub pairing_id: PairingId,
    pub node_id: String,
    pub node_identity_fingerprint: String,
    pub node_public_key_hex: String,
    pub node_signature_hex: String,
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub software_version: &'static str,
    pub peer_id: String,
    pub device_label: String,
    pub owner_key_fingerprint: String,
    pub broker_key_fingerprint: String,
    pub client_certificate_fingerprint: String,
    pub challenge_hex: String,
    pub proof_payload_hex: String,
    pub expires_at: UnixMillis,
    pub allowed_capabilities: Vec<Capability>,
    pub trust_expires_at: Option<UnixMillis>,
}

#[derive(Clone, Debug)]
pub struct PairingProof {
    pub pairing_id: PairingId,
    pub challenge_secret: [u8; 32],
    pub owner_signature: SignatureBytes,
    pub broker_signature: SignatureBytes,
    pub approved_at: UnixMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustReceiptKind {
    InitialPairing,
    CredentialRotation,
    RecoveryPairing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustReceiptV1 {
    pub schema_version: u16,
    pub kind: TrustReceiptKind,
    pub node_id: String,
    pub node_key_id: Sha256Digest,
    pub node_public_key: PublicKeyBytes,
    pub pairing_id: PairingId,
    pub peer_id: String,
    pub peer_identity_digest: Sha256Digest,
    pub previous_peer_identity_digest: Option<Sha256Digest>,
    pub capability_manifest_digest: Sha256Digest,
    pub transport_binding_digest: Sha256Digest,
    pub trust_epoch: u64,
    pub issued_at: UnixMillis,
    pub trust_expires_at: Option<UnixMillis>,
}

impl TrustReceiptV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PairingError> {
        #[derive(Serialize)]
        struct SignedReceipt<'a> {
            domain: &'a [u8],
            receipt: &'a TrustReceiptV1,
        }
        postcard::to_allocvec(&SignedReceipt {
            domain: TRUST_RECEIPT_DOMAIN,
            receipt: self,
        })
        .map_err(|_| PairingError::Encoding)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustReceiptV1 {
    pub receipt: TrustReceiptV1,
    pub node_signature: SignatureBytes,
}

impl SignedTrustReceiptV1 {
    pub fn verify(&self) -> Result<(), PairingError> {
        let transition_shape_is_valid = match self.receipt.kind {
            TrustReceiptKind::InitialPairing => {
                self.receipt.previous_peer_identity_digest.is_none()
            }
            TrustReceiptKind::CredentialRotation | TrustReceiptKind::RecoveryPairing => self
                .receipt
                .previous_peer_identity_digest
                .is_some_and(|previous| previous != self.receipt.peer_identity_digest),
        };
        if self.receipt.schema_version != 1
            || self.receipt.trust_epoch == 0
            || self.receipt.pairing_id.0.is_nil()
            || self.receipt.node_id.is_empty()
            || self.receipt.peer_id.is_empty()
            || !transition_shape_is_valid
            || self
                .receipt
                .trust_expires_at
                .is_some_and(|expiry| expiry.0 <= self.receipt.issued_at.0)
        {
            return Err(PairingError::InvalidProof);
        }
        Uuid::parse_str(&self.receipt.node_id).map_err(|_| PairingError::InvalidProof)?;
        if key_id_from_bytes(self.receipt.node_public_key)? != self.receipt.node_key_id {
            return Err(PairingError::InvalidProof);
        }
        verify(
            self.receipt.node_public_key,
            &self.receipt.signing_bytes()?,
            &self.node_signature,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PairingApprovalResult {
    pub trusted_peer: TrustedPeer,
    pub receipt: SignedTrustReceiptV1,
}

#[derive(Clone, Debug)]
pub struct CredentialRotationRequest {
    pub peer_id: String,
    pub key_material: PairingKeyMaterialV1,
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    pub ttl_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialRotationDisplay {
    pub rotation_id: Uuid,
    pub pairing_id: PairingId,
    pub node_id: String,
    pub node_identity_fingerprint: String,
    pub node_public_key_hex: String,
    pub node_signature_hex: String,
    pub peer_id: String,
    pub device_label: String,
    pub current_trust_epoch: u64,
    pub current_owner_key_fingerprint: String,
    pub current_broker_key_fingerprint: String,
    pub current_client_certificate_fingerprint: String,
    pub next_owner_key_fingerprint: String,
    pub next_broker_key_fingerprint: String,
    pub next_client_certificate_fingerprint: String,
    pub challenge_hex: String,
    pub proof_payload_hex: String,
    pub expires_at: UnixMillis,
    pub allowed_capabilities: Vec<Capability>,
    pub trust_expires_at: Option<UnixMillis>,
}

#[derive(Clone, Debug)]
pub struct CredentialRotationProof {
    pub rotation_id: Uuid,
    pub challenge_secret: [u8; 32],
    pub current_owner_signature: SignatureBytes,
    pub current_broker_signature: SignatureBytes,
    pub next_owner_signature: SignatureBytes,
    pub next_broker_signature: SignatureBytes,
    pub approved_at: UnixMillis,
}

#[derive(Clone, Debug)]
pub struct PairingRecoveryRequest {
    pub peer_id: String,
    pub key_material: PairingKeyMaterialV1,
    pub client_certificate_chain_der: Vec<Vec<u8>>,
    pub ttl_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PairingRecoveryDisplay {
    pub recovery_id: Uuid,
    pub pairing_id: PairingId,
    pub node_id: String,
    pub node_identity_fingerprint: String,
    pub node_public_key_hex: String,
    pub node_signature_hex: String,
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub software_version: &'static str,
    pub peer_id: String,
    pub device_label: String,
    pub revoked_trust_epoch: u64,
    pub revoked_identity_fingerprint: String,
    pub revoked_owner_key_fingerprint: String,
    pub revoked_broker_key_fingerprint: String,
    pub revoked_client_certificate_fingerprint: String,
    pub next_owner_key_fingerprint: String,
    pub next_broker_key_fingerprint: String,
    pub next_client_certificate_fingerprint: String,
    pub revocation_digest: String,
    pub challenge_hex: String,
    pub proof_payload_hex: String,
    pub expires_at: UnixMillis,
    pub allowed_capabilities: Vec<Capability>,
    pub trust_expires_at: Option<UnixMillis>,
}

#[derive(Clone, Debug)]
pub struct PairingRecoveryProof {
    pub recovery_id: Uuid,
    pub challenge_secret: [u8; 32],
    pub next_owner_signature: SignatureBytes,
    pub next_broker_signature: SignatureBytes,
    pub approved_at: UnixMillis,
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("pairing material is invalid: {0}")]
    Invalid(String),
    #[error("pairing proof is invalid")]
    InvalidProof,
    #[error("local owner confirmation is required")]
    OwnerConfirmationRequired,
    #[error("pairing data could not be encoded")]
    Encoding,
    #[error("pairing time is out of range")]
    TimeRange,
}

#[derive(Debug)]
pub struct PairingManager {
    identity: Arc<NodeIdentity>,
    store: Arc<StateStore>,
    local_capabilities: BTreeSet<Capability>,
}

impl PairingManager {
    #[must_use]
    pub fn new(
        identity: Arc<NodeIdentity>,
        store: Arc<StateStore>,
        local_capabilities: impl IntoIterator<Item = Capability>,
    ) -> Self {
        Self {
            identity,
            store,
            local_capabilities: local_capabilities.into_iter().collect(),
        }
    }

    pub fn begin(
        &self,
        request: PairingRequest,
        now: UnixMillis,
    ) -> Result<PairingDisplay, PairingError> {
        validate_pairing_request(&request, &self.local_capabilities, now)?;
        let pairing_id = PairingId(Uuid::new_v4());
        let expires_at = now
            .0
            .checked_add(request.ttl_millis)
            .ok_or(PairingError::TimeRange)
            .map(UnixMillis)?;
        let mut challenge_secret = [0_u8; 32];
        OsRng.fill_bytes(&mut challenge_secret);
        let material =
            postcard::to_allocvec(&request.key_material).map_err(|_| PairingError::Encoding)?;
        let pending = PendingPairingChallenge::new(
            pairing_id.0,
            self.identity.node_id().to_string(),
            request.peer_id.clone(),
            request.device_label.clone(),
            material,
            request.client_certificate_chain_der.clone(),
            &challenge_secret,
            self.identity.key_id().0,
            request.key_material.client_certificate_sha256.0,
            millis_to_i64(now)?,
            millis_to_i64(expires_at)?,
        )?;
        self.store.put_pending_pairing(&pending)?;

        let proof_payload =
            pairing_proof_bytes(&pending, &challenge_secret, &request.key_material)?;
        let node_signature = self
            .identity
            .sign(&proof_payload)
            .map_err(|_| PairingError::Encoding)?;
        Ok(PairingDisplay {
            pairing_id,
            node_id: self.identity.node_id().to_string(),
            node_identity_fingerprint: self.identity.fingerprint(),
            node_public_key_hex: hex::encode(self.identity.public_key().0),
            node_signature_hex: hex::encode(node_signature.as_bytes()),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            software_version: env!("CARGO_PKG_VERSION"),
            peer_id: request.peer_id,
            device_label: request.device_label,
            owner_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.owner_public_key)?.0,
            ),
            broker_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.broker_public_key)?.0,
            ),
            client_certificate_fingerprint: hex::encode(
                request.key_material.client_certificate_sha256.0,
            ),
            challenge_hex: hex::encode(challenge_secret),
            proof_payload_hex: hex::encode(proof_payload),
            expires_at,
            allowed_capabilities: request.key_material.allowed_capabilities,
            trust_expires_at: request.key_material.trust_expires_at,
        })
    }

    /// Completes pairing only after proof of both keys and a local owner confirmation.
    /// This method is intentionally not reachable from the LAN action protocol.
    pub fn approve_local(
        &self,
        proof: &PairingProof,
        owner_confirmed: bool,
    ) -> Result<PairingApprovalResult, PairingError> {
        if !owner_confirmed {
            return Err(PairingError::OwnerConfirmationRequired);
        }
        let pending = self
            .store
            .pending_pairing(proof.pairing_id.0)?
            .ok_or(StoreError::PairingNotFound)?;
        if pending.node_identity_digest != self.identity.key_id().0 {
            self.store.audit_pairing_rejection(
                proof.pairing_id.0,
                millis_to_i64(proof.approved_at)?,
                b"node-identity-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        let material = decode_key_material(&pending.peer_public_key)?;
        if let Err(error) = validate_client_certificate_binding(
            &material,
            &pending.client_certificate_chain_der,
            proof.approved_at,
        ) {
            self.store.audit_pairing_rejection(
                proof.pairing_id.0,
                millis_to_i64(proof.approved_at)?,
                b"client-certificate-invalid",
            )?;
            return Err(error);
        }
        let proof_payload = pairing_proof_bytes(&pending, &proof.challenge_secret, &material)?;
        if verify(
            material.owner_public_key,
            &proof_payload,
            &proof.owner_signature,
        )
        .is_err()
        {
            self.store.audit_pairing_rejection(
                proof.pairing_id.0,
                millis_to_i64(proof.approved_at)?,
                b"owner-proof-invalid",
            )?;
            return Err(PairingError::InvalidProof);
        }
        if verify(
            material.broker_public_key,
            &proof_payload,
            &proof.broker_signature,
        )
        .is_err()
        {
            self.store.audit_pairing_rejection(
                proof.pairing_id.0,
                millis_to_i64(proof.approved_at)?,
                b"broker-proof-invalid",
            )?;
            return Err(PairingError::InvalidProof);
        }

        let manifest_digest = Sha256::digest(
            postcard::to_allocvec(&material.allowed_capabilities)
                .map_err(|_| PairingError::Encoding)?,
        );
        let (_, trusted) = self.store.approve_pairing(
            &PairingApproval {
                pairing_id: proof.pairing_id.0,
                owner_authority_digest: key_id_from_bytes(material.owner_public_key)?.0,
                capability_manifest_digest: manifest_digest.into(),
                approved_at_unix_ms: millis_to_i64(proof.approved_at)?,
                trust_expires_at_unix_ms: material
                    .trust_expires_at
                    .map(millis_to_i64)
                    .transpose()?,
            },
            &proof.challenge_secret,
        )?;
        let receipt = self.sign_receipt(
            TrustReceiptKind::InitialPairing,
            &trusted,
            &material,
            None,
            proof.approved_at,
        )?;
        Ok(PairingApprovalResult {
            trusted_peer: trusted,
            receipt,
        })
    }

    pub fn begin_credential_rotation(
        &self,
        request: CredentialRotationRequest,
        now: UnixMillis,
    ) -> Result<CredentialRotationDisplay, PairingError> {
        if !(60_000..=900_000).contains(&request.ttl_millis) {
            return Err(PairingError::Invalid(
                "rotation TTL must be between one and fifteen minutes".to_owned(),
            ));
        }
        validate_key_material(&request.key_material)?;
        validate_client_certificate_binding(
            &request.key_material,
            &request.client_certificate_chain_der,
            now,
        )?;
        if request
            .key_material
            .allowed_capabilities
            .iter()
            .any(|capability| !self.local_capabilities.contains(capability))
        {
            return Err(PairingError::Invalid(
                "requested capability is not locally advertised".to_owned(),
            ));
        }
        if request
            .key_material
            .trust_expires_at
            .is_some_and(|expiry| expiry.0 <= now.0)
        {
            return Err(PairingError::Invalid(
                "trust lease is already expired".to_owned(),
            ));
        }
        let trusted = self
            .store
            .currently_trusted_peer(&request.peer_id, millis_to_i64(now)?)?
            .ok_or(StoreError::PairingNotFound)?;
        if trusted.node_id != self.identity.node_id().to_string() {
            return Err(PairingError::Invalid(
                "trusted peer belongs to a different node".to_owned(),
            ));
        }
        let current_material = decode_key_material(&trusted.public_key)?;
        let next_encoded =
            postcard::to_allocvec(&request.key_material).map_err(|_| PairingError::Encoding)?;
        if next_encoded == trusted.public_key {
            return Err(PairingError::Invalid(
                "new credential is identical to the current credential".to_owned(),
            ));
        }
        let expires_at = now
            .0
            .checked_add(request.ttl_millis)
            .ok_or(PairingError::TimeRange)
            .map(UnixMillis)?;
        let rotation_id = Uuid::new_v4();
        let mut challenge_secret = [0_u8; 32];
        OsRng.fill_bytes(&mut challenge_secret);
        let pending = PendingCredentialRotation::new(
            rotation_id,
            trusted.pairing_id,
            trusted.node_id.clone(),
            trusted.peer_id.clone(),
            sha256(&trusted.public_key),
            trusted.trust_epoch,
            next_encoded,
            request.client_certificate_chain_der.clone(),
            self.identity.key_id().0,
            &challenge_secret,
            millis_to_i64(now)?,
            millis_to_i64(expires_at)?,
        )?;
        self.store.put_pending_credential_rotation(&pending)?;
        let proof_payload = credential_rotation_proof_bytes(
            &pending,
            &challenge_secret,
            &current_material,
            &request.key_material,
        )?;
        let node_signature = self
            .identity
            .sign(&proof_payload)
            .map_err(|_| PairingError::Encoding)?;
        Ok(CredentialRotationDisplay {
            rotation_id,
            pairing_id: PairingId(trusted.pairing_id),
            node_id: trusted.node_id,
            node_identity_fingerprint: self.identity.fingerprint(),
            node_public_key_hex: hex::encode(self.identity.public_key().0),
            node_signature_hex: hex::encode(node_signature.as_bytes()),
            peer_id: trusted.peer_id,
            device_label: trusted.device_label,
            current_trust_epoch: trusted.trust_epoch,
            current_owner_key_fingerprint: hex::encode(
                key_id_from_bytes(current_material.owner_public_key)?.0,
            ),
            current_broker_key_fingerprint: hex::encode(
                key_id_from_bytes(current_material.broker_public_key)?.0,
            ),
            current_client_certificate_fingerprint: hex::encode(
                current_material.client_certificate_sha256.0,
            ),
            next_owner_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.owner_public_key)?.0,
            ),
            next_broker_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.broker_public_key)?.0,
            ),
            next_client_certificate_fingerprint: hex::encode(
                request.key_material.client_certificate_sha256.0,
            ),
            challenge_hex: hex::encode(challenge_secret),
            proof_payload_hex: hex::encode(proof_payload),
            expires_at,
            allowed_capabilities: request.key_material.allowed_capabilities,
            trust_expires_at: request.key_material.trust_expires_at,
        })
    }

    pub fn approve_credential_rotation_local(
        &self,
        proof: &CredentialRotationProof,
        owner_confirmed: bool,
    ) -> Result<PairingApprovalResult, PairingError> {
        if !owner_confirmed {
            return Err(PairingError::OwnerConfirmationRequired);
        }
        let pending = self
            .store
            .pending_credential_rotation(proof.rotation_id)?
            .ok_or(StoreError::CredentialRotationNotFound)?;
        if pending.node_identity_digest != self.identity.key_id().0 {
            self.store.audit_credential_rotation_rejection(
                proof.rotation_id,
                millis_to_i64(proof.approved_at)?,
                b"node-identity-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        let current = self
            .store
            .currently_trusted_peer(&pending.peer_id, millis_to_i64(proof.approved_at)?)?
            .ok_or(StoreError::PairingNotFound)?;
        if current.pairing_id != pending.pairing_id
            || current.trust_epoch != pending.current_trust_epoch
            || sha256(&current.public_key) != pending.current_public_key_digest
        {
            self.store.audit_credential_rotation_rejection(
                proof.rotation_id,
                millis_to_i64(proof.approved_at)?,
                b"current-credential-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        let current_material = decode_key_material(&current.public_key)?;
        let next_material = decode_key_material(&pending.new_public_key)?;
        if let Err(error) = validate_client_certificate_binding(
            &next_material,
            &pending.client_certificate_chain_der,
            proof.approved_at,
        ) {
            self.store.audit_credential_rotation_rejection(
                proof.rotation_id,
                millis_to_i64(proof.approved_at)?,
                b"client-certificate-invalid",
            )?;
            return Err(error);
        }
        let payload = credential_rotation_proof_bytes(
            &pending,
            &proof.challenge_secret,
            &current_material,
            &next_material,
        )?;
        let proofs = [
            (
                current_material.owner_public_key,
                &proof.current_owner_signature,
                b"current-owner".as_slice(),
            ),
            (
                current_material.broker_public_key,
                &proof.current_broker_signature,
                b"current-broker".as_slice(),
            ),
            (
                next_material.owner_public_key,
                &proof.next_owner_signature,
                b"next-owner".as_slice(),
            ),
            (
                next_material.broker_public_key,
                &proof.next_broker_signature,
                b"next-broker".as_slice(),
            ),
        ];
        for (key, signature, reason) in proofs {
            if verify(key, &payload, signature).is_err() {
                self.store.audit_credential_rotation_rejection(
                    proof.rotation_id,
                    millis_to_i64(proof.approved_at)?,
                    reason,
                )?;
                return Err(PairingError::InvalidProof);
            }
        }
        let manifest_digest: [u8; 32] = Sha256::digest(
            postcard::to_allocvec(&next_material.allowed_capabilities)
                .map_err(|_| PairingError::Encoding)?,
        )
        .into();
        let previous_identity_digest = current.identity_digest;
        let outcome = self.store.approve_credential_rotation(
            &CredentialRotationApproval {
                rotation_id: proof.rotation_id,
                owner_authority_digest: key_id_from_bytes(current_material.owner_public_key)?.0,
                capability_manifest_digest: manifest_digest,
                approved_at_unix_ms: millis_to_i64(proof.approved_at)?,
                trust_expires_at_unix_ms: next_material
                    .trust_expires_at
                    .map(millis_to_i64)
                    .transpose()?,
            },
            &proof.challenge_secret,
        )?;
        let trusted = match outcome {
            CredentialRotationOutcome::Rotated(peer)
            | CredentialRotationOutcome::AlreadyCurrent(peer) => peer,
        };
        let receipt = self.sign_receipt(
            TrustReceiptKind::CredentialRotation,
            &trusted,
            &next_material,
            Some(Sha256Digest(previous_identity_digest)),
            proof.approved_at,
        )?;
        Ok(PairingApprovalResult {
            trusted_peer: trusted,
            receipt,
        })
    }

    /// Starts a separate recovery ceremony for a peer that is already durably
    /// revoked. Old keys are not accepted as recovery authority; the exact
    /// revocation, old epoch, replacement material, and local node identity are
    /// bound into a short-lived node-signed transcript.
    pub fn begin_pairing_recovery(
        &self,
        request: PairingRecoveryRequest,
        now: UnixMillis,
    ) -> Result<PairingRecoveryDisplay, PairingError> {
        if !(60_000..=900_000).contains(&request.ttl_millis) {
            return Err(PairingError::Invalid(
                "recovery TTL must be between one and fifteen minutes".to_owned(),
            ));
        }
        validate_key_material(&request.key_material)?;
        validate_client_certificate_binding(
            &request.key_material,
            &request.client_certificate_chain_der,
            now,
        )?;
        if request
            .key_material
            .allowed_capabilities
            .iter()
            .any(|capability| !self.local_capabilities.contains(capability))
        {
            return Err(PairingError::Invalid(
                "requested capability is not locally advertised".to_owned(),
            ));
        }
        if request
            .key_material
            .trust_expires_at
            .is_some_and(|expiry| expiry.0 <= now.0)
        {
            return Err(PairingError::Invalid(
                "trust lease is already expired".to_owned(),
            ));
        }
        let (revoked, revocation) = self
            .store
            .revoked_peer_for_recovery(&request.peer_id)?
            .ok_or(StoreError::PairingNotFound)?;
        if revoked.node_id != self.identity.node_id().to_string() {
            return Err(PairingError::Invalid(
                "revoked peer belongs to a different node".to_owned(),
            ));
        }
        let revoked_material = decode_key_material(&revoked.public_key)?;
        let next_encoded =
            postcard::to_allocvec(&request.key_material).map_err(|_| PairingError::Encoding)?;
        if next_encoded == revoked.public_key {
            return Err(PairingError::Invalid(
                "recovery credential must differ from the revoked credential".to_owned(),
            ));
        }
        let expires_at = now
            .0
            .checked_add(request.ttl_millis)
            .ok_or(PairingError::TimeRange)
            .map(UnixMillis)?;
        let recovery_id = Uuid::new_v4();
        let mut challenge_secret = [0_u8; 32];
        OsRng.fill_bytes(&mut challenge_secret);
        let revocation_digest =
            sha256(&postcard::to_allocvec(&revocation).map_err(|_| PairingError::Encoding)?);
        let pending = PendingPairingRecovery::new(
            recovery_id,
            &revoked,
            revocation_digest,
            next_encoded,
            request.client_certificate_chain_der.clone(),
            self.identity.key_id().0,
            &challenge_secret,
            request.key_material.client_certificate_sha256.0,
            millis_to_i64(now)?,
            millis_to_i64(expires_at)?,
        )?;
        self.store.put_pending_pairing_recovery(&pending)?;
        let proof_payload =
            pairing_recovery_proof_bytes(&pending, &challenge_secret, &request.key_material)?;
        let node_signature = self
            .identity
            .sign(&proof_payload)
            .map_err(|_| PairingError::Encoding)?;
        Ok(PairingRecoveryDisplay {
            recovery_id,
            pairing_id: PairingId(revoked.pairing_id),
            node_id: revoked.node_id,
            node_identity_fingerprint: self.identity.fingerprint(),
            node_public_key_hex: hex::encode(self.identity.public_key().0),
            node_signature_hex: hex::encode(node_signature.as_bytes()),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            software_version: env!("CARGO_PKG_VERSION"),
            peer_id: revoked.peer_id,
            device_label: revoked.device_label,
            revoked_trust_epoch: revoked.trust_epoch,
            revoked_identity_fingerprint: hex::encode(revoked.identity_digest),
            revoked_owner_key_fingerprint: hex::encode(
                key_id_from_bytes(revoked_material.owner_public_key)?.0,
            ),
            revoked_broker_key_fingerprint: hex::encode(
                key_id_from_bytes(revoked_material.broker_public_key)?.0,
            ),
            revoked_client_certificate_fingerprint: hex::encode(
                revoked_material.client_certificate_sha256.0,
            ),
            next_owner_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.owner_public_key)?.0,
            ),
            next_broker_key_fingerprint: hex::encode(
                key_id_from_bytes(request.key_material.broker_public_key)?.0,
            ),
            next_client_certificate_fingerprint: hex::encode(
                request.key_material.client_certificate_sha256.0,
            ),
            revocation_digest: hex::encode(revocation_digest),
            challenge_hex: hex::encode(challenge_secret),
            proof_payload_hex: hex::encode(proof_payload),
            expires_at,
            allowed_capabilities: request.key_material.allowed_capabilities,
            trust_expires_at: request.key_material.trust_expires_at,
        })
    }

    /// Completes recovery only from the local administrative path after the
    /// replacement owner and broker have signed the exact recovery transcript.
    pub fn approve_pairing_recovery_local(
        &self,
        proof: &PairingRecoveryProof,
        owner_confirmed: bool,
    ) -> Result<PairingApprovalResult, PairingError> {
        if !owner_confirmed {
            return Err(PairingError::OwnerConfirmationRequired);
        }
        let approved_at = millis_to_i64(proof.approved_at)?;
        let pending = self
            .store
            .pending_pairing_recovery(proof.recovery_id)?
            .ok_or(StoreError::RecoveryNotFound)?;
        if pending.node_identity_digest != self.identity.key_id().0 {
            self.store.audit_pairing_recovery_rejection(
                proof.recovery_id,
                approved_at,
                b"node-identity-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        let (revoked, revocation) = self
            .store
            .revoked_peer_for_recovery(&pending.peer_id)?
            .ok_or(StoreError::RecoveryMismatch)?;
        let revocation_digest =
            sha256(&postcard::to_allocvec(&revocation).map_err(|_| PairingError::Encoding)?);
        if revoked.pairing_id != pending.pairing_id
            || revoked.identity_digest != pending.revoked_identity_digest
            || revoked.trust_epoch != pending.revoked_trust_epoch
            || revocation_digest != pending.revocation_digest
        {
            self.store.audit_pairing_recovery_rejection(
                proof.recovery_id,
                approved_at,
                b"revocation-state-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        let next_material = decode_key_material(&pending.new_public_key)?;
        if pending.transport_binding_digest != next_material.client_certificate_sha256.0 {
            self.store.audit_pairing_recovery_rejection(
                proof.recovery_id,
                approved_at,
                b"transport-binding-changed",
            )?;
            return Err(PairingError::InvalidProof);
        }
        if let Err(error) = validate_client_certificate_binding(
            &next_material,
            &pending.client_certificate_chain_der,
            proof.approved_at,
        ) {
            self.store.audit_pairing_recovery_rejection(
                proof.recovery_id,
                approved_at,
                b"client-certificate-invalid",
            )?;
            return Err(error);
        }
        let payload =
            pairing_recovery_proof_bytes(&pending, &proof.challenge_secret, &next_material)?;
        for (key, signature, reason) in [
            (
                next_material.owner_public_key,
                &proof.next_owner_signature,
                b"next-owner".as_slice(),
            ),
            (
                next_material.broker_public_key,
                &proof.next_broker_signature,
                b"next-broker".as_slice(),
            ),
        ] {
            if verify(key, &payload, signature).is_err() {
                self.store.audit_pairing_recovery_rejection(
                    proof.recovery_id,
                    approved_at,
                    reason,
                )?;
                return Err(PairingError::InvalidProof);
            }
        }
        let manifest_digest: [u8; 32] = Sha256::digest(
            postcard::to_allocvec(&next_material.allowed_capabilities)
                .map_err(|_| PairingError::Encoding)?,
        )
        .into();
        let outcome: PairingRecoveryOutcome = self.store.approve_pairing_recovery(
            &PairingRecoveryApproval {
                recovery_id: proof.recovery_id,
                owner_authority_digest: key_id_from_bytes(next_material.owner_public_key)?.0,
                capability_manifest_digest: manifest_digest,
                approved_at_unix_ms: approved_at,
                trust_expires_at_unix_ms: next_material
                    .trust_expires_at
                    .map(millis_to_i64)
                    .transpose()?,
            },
            &proof.challenge_secret,
        )?;
        let receipt = self.sign_receipt(
            TrustReceiptKind::RecoveryPairing,
            &outcome.trusted_peer,
            &next_material,
            Some(Sha256Digest(outcome.recovery.previous_identity_digest)),
            proof.approved_at,
        )?;
        Ok(PairingApprovalResult {
            trusted_peer: outcome.trusted_peer,
            receipt,
        })
    }

    fn sign_receipt(
        &self,
        kind: TrustReceiptKind,
        trusted: &TrustedPeer,
        material: &PairingKeyMaterialV1,
        previous_peer_identity_digest: Option<Sha256Digest>,
        issued_at: UnixMillis,
    ) -> Result<SignedTrustReceiptV1, PairingError> {
        let receipt = TrustReceiptV1 {
            schema_version: 1,
            kind,
            node_id: trusted.node_id.clone(),
            node_key_id: self.identity.key_id(),
            node_public_key: self.identity.public_key(),
            pairing_id: PairingId(trusted.pairing_id),
            peer_id: trusted.peer_id.clone(),
            peer_identity_digest: Sha256Digest(trusted.identity_digest),
            previous_peer_identity_digest,
            capability_manifest_digest: Sha256Digest(trusted.capability_manifest_digest),
            transport_binding_digest: material.client_certificate_sha256,
            trust_epoch: trusted.trust_epoch,
            issued_at,
            trust_expires_at: trusted
                .trust_expires_at_unix_ms
                .map(i64_to_millis)
                .transpose()?,
        };
        let node_signature = self
            .identity
            .sign(&receipt.signing_bytes()?)
            .map_err(|_| PairingError::Encoding)?;
        Ok(SignedTrustReceiptV1 {
            receipt,
            node_signature,
        })
    }

    pub fn revoke_local(
        &self,
        peer_id: &str,
        reason: &str,
        now: UnixMillis,
        owner_confirmed: bool,
    ) -> Result<RevocationOutcome, PairingError> {
        if !owner_confirmed {
            return Err(PairingError::OwnerConfirmationRequired);
        }
        if reason.is_empty() || reason.len() > 512 || reason.contains('\0') {
            return Err(PairingError::Invalid(
                "revocation reason is invalid".to_owned(),
            ));
        }
        self.store
            .revoke_peer(
                peer_id,
                millis_to_i64(now)?,
                sha256(b"local-owner-confirmed-revocation-v1"),
                sha256(reason.as_bytes()),
            )
            .map_err(Into::into)
    }
}

pub fn decode_key_material(encoded: &[u8]) -> Result<PairingKeyMaterialV1, PairingError> {
    let (material, remainder): (PairingKeyMaterialV1, &[u8]) =
        postcard::take_from_bytes(encoded).map_err(|_| PairingError::Encoding)?;
    if !remainder.is_empty() {
        return Err(PairingError::Encoding);
    }
    validate_key_material(&material)?;
    Ok(material)
}

fn validate_pairing_request(
    request: &PairingRequest,
    local_capabilities: &BTreeSet<Capability>,
    now: UnixMillis,
) -> Result<(), PairingError> {
    if request.peer_id.is_empty()
        || request.peer_id.len() > 128
        || request.peer_id.chars().any(char::is_control)
    {
        return Err(PairingError::Invalid("peer ID is invalid".to_owned()));
    }
    if request.device_label.is_empty()
        || request.device_label.len() > 128
        || request.device_label.contains('\0')
    {
        return Err(PairingError::Invalid("device label is invalid".to_owned()));
    }
    if !(60_000..=900_000).contains(&request.ttl_millis) {
        return Err(PairingError::Invalid(
            "pairing TTL must be between one and fifteen minutes".to_owned(),
        ));
    }
    if request
        .key_material
        .trust_expires_at
        .is_some_and(|expiry| expiry.0 <= now.0)
    {
        return Err(PairingError::Invalid(
            "trust lease is already expired".to_owned(),
        ));
    }
    validate_key_material(&request.key_material)?;
    validate_client_certificate_binding(
        &request.key_material,
        &request.client_certificate_chain_der,
        now,
    )?;
    if request
        .key_material
        .allowed_capabilities
        .iter()
        .any(|capability| !local_capabilities.contains(capability))
    {
        return Err(PairingError::Invalid(
            "requested capability is not locally advertised".to_owned(),
        ));
    }
    Ok(())
}

fn validate_key_material(material: &PairingKeyMaterialV1) -> Result<(), PairingError> {
    if material.schema_version != 1 {
        return Err(PairingError::Invalid(
            "unsupported key material version".to_owned(),
        ));
    }
    if material.owner_id.is_empty()
        || material.owner_id.len() > 256
        || material.owner_id.chars().any(char::is_control)
    {
        return Err(PairingError::Invalid("owner ID is invalid".to_owned()));
    }
    let owner = VerifyingKey::from_bytes(&material.owner_public_key.0)
        .map_err(|_| PairingError::Invalid("owner public key is invalid".to_owned()))?;
    let broker = VerifyingKey::from_bytes(&material.broker_public_key.0)
        .map_err(|_| PairingError::Invalid("broker public key is invalid".to_owned()))?;
    if owner.is_weak() || broker.is_weak() {
        return Err(PairingError::Invalid(
            "weak Ed25519 public keys are not accepted".to_owned(),
        ));
    }
    if owner == broker {
        return Err(PairingError::Invalid(
            "owner and broker keys must be role-separated".to_owned(),
        ));
    }
    if material.client_ca_der.is_empty() || material.client_ca_der.len() > 131_072 {
        return Err(PairingError::Invalid(
            "client CA is missing or too large".to_owned(),
        ));
    }
    validate_ca_certificate(&material.client_ca_der)?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            material.client_ca_der.clone(),
        ))
        .map_err(|_| PairingError::Invalid("client CA certificate is invalid".to_owned()))?;
    if material.allowed_capabilities.is_empty() || material.allowed_capabilities.len() > 64 {
        return Err(PairingError::Invalid(
            "pairing capability scope is empty or too large".to_owned(),
        ));
    }
    let unique: BTreeSet<_> = material.allowed_capabilities.iter().copied().collect();
    if unique.len() != material.allowed_capabilities.len() {
        return Err(PairingError::Invalid(
            "pairing capability scope contains duplicates".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ca_certificate(certificate_der: &[u8]) -> Result<(), PairingError> {
    let (remainder, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| PairingError::Invalid("client CA certificate is invalid".to_owned()))?;
    if !remainder.is_empty() {
        return Err(PairingError::Invalid(
            "client CA certificate has trailing data".to_owned(),
        ));
    }
    let constraints = certificate
        .basic_constraints()
        .map_err(|_| PairingError::Invalid("client CA constraints are invalid".to_owned()))?
        .ok_or_else(|| PairingError::Invalid("client CA lacks basic constraints".to_owned()))?;
    if !constraints.value.ca {
        return Err(PairingError::Invalid(
            "client CA basic constraints do not permit certificate signing".to_owned(),
        ));
    }
    if certificate
        .key_usage()
        .map_err(|_| PairingError::Invalid("client CA key usage is invalid".to_owned()))?
        .is_some_and(|usage| !usage.value.key_cert_sign())
    {
        return Err(PairingError::Invalid(
            "client CA key usage does not permit certificate signing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_client_certificate_binding(
    material: &PairingKeyMaterialV1,
    chain_der: &[Vec<u8>],
    now: UnixMillis,
) -> Result<(), PairingError> {
    let now_seconds = i64::try_from(now.0 / 1_000).map_err(|_| PairingError::TimeRange)?;
    let validation_time = ASN1Time::from_timestamp(now_seconds)
        .map_err(|_| PairingError::Invalid("certificate validation time is invalid".to_owned()))?;
    let (_, ca) = parse_x509_certificate(&material.client_ca_der)
        .map_err(|_| PairingError::Invalid("client CA certificate is invalid".to_owned()))?;
    if !ca.validity().is_valid_at(validation_time) {
        return Err(PairingError::Invalid(
            "client CA certificate is not currently valid".to_owned(),
        ));
    }
    if chain_der.is_empty() || chain_der.len() > 8 {
        return Err(PairingError::Invalid(
            "client certificate chain count is out of range".to_owned(),
        ));
    }
    let total = chain_der.iter().try_fold(0_usize, |total, certificate| {
        if certificate.is_empty() {
            return Err(PairingError::Invalid(
                "client certificate chain contains an empty certificate".to_owned(),
            ));
        }
        total.checked_add(certificate.len()).ok_or_else(|| {
            PairingError::Invalid("client certificate chain is too large".to_owned())
        })
    })?;
    if total > 262_144 {
        return Err(PairingError::Invalid(
            "client certificate chain is too large".to_owned(),
        ));
    }
    let leaf_der = &chain_der[0];
    if Sha256::digest(leaf_der).as_slice() != material.client_certificate_sha256.0 {
        return Err(PairingError::Invalid(
            "client certificate does not match its signed fingerprint".to_owned(),
        ));
    }
    if leaf_der == &material.client_ca_der {
        return Err(PairingError::Invalid(
            "client certificate must not be the CA certificate".to_owned(),
        ));
    }
    let (remainder, leaf) = parse_x509_certificate(leaf_der)
        .map_err(|_| PairingError::Invalid("client certificate is invalid".to_owned()))?;
    if !remainder.is_empty() {
        return Err(PairingError::Invalid(
            "client certificate has trailing data".to_owned(),
        ));
    }
    if leaf
        .basic_constraints()
        .map_err(|_| {
            PairingError::Invalid("client certificate constraints are invalid".to_owned())
        })?
        .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(PairingError::Invalid(
            "client certificate must be an end-entity certificate".to_owned(),
        ));
    }
    let extended_usage = leaf
        .extended_key_usage()
        .map_err(|_| PairingError::Invalid("client certificate purpose is invalid".to_owned()))?
        .ok_or_else(|| {
            PairingError::Invalid("client certificate lacks clientAuth purpose".to_owned())
        })?;
    if !extended_usage.value.client_auth {
        return Err(PairingError::Invalid(
            "client certificate is not valid for clientAuth".to_owned(),
        ));
    }
    let key_usage = leaf
        .key_usage()
        .map_err(|_| PairingError::Invalid("client certificate key usage is invalid".to_owned()))?
        .ok_or_else(|| {
            PairingError::Invalid("client certificate lacks TLS signing key usage".to_owned())
        })?;
    if !key_usage.value.digital_signature() {
        return Err(PairingError::Invalid(
            "client certificate cannot create TLS signatures".to_owned(),
        ));
    }
    for intermediate in &chain_der[1..] {
        let (remainder, _) = parse_x509_certificate(intermediate)
            .map_err(|_| PairingError::Invalid("client intermediate is invalid".to_owned()))?;
        if !remainder.is_empty() {
            return Err(PairingError::Invalid(
                "client intermediate has trailing data".to_owned(),
            ));
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(material.client_ca_der.clone()))
        .map_err(|_| PairingError::Invalid("client CA certificate is invalid".to_owned()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|_| PairingError::Invalid("client certificate verifier is invalid".to_owned()))?;
    let leaf = CertificateDer::from_slice(leaf_der);
    let intermediates = chain_der[1..]
        .iter()
        .map(|certificate| CertificateDer::from_slice(certificate))
        .collect::<Vec<_>>();
    verifier
        .verify_client_cert(
            &leaf,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(
                u64::try_from(now_seconds).map_err(|_| PairingError::TimeRange)?,
            )),
        )
        .map_err(|_| {
            PairingError::Invalid(
                "client certificate chain, validity, or clientAuth purpose is invalid".to_owned(),
            )
        })?;
    Ok(())
}

fn pairing_proof_bytes(
    pending: &PendingPairingChallenge,
    challenge_secret: &[u8; 32],
    material: &PairingKeyMaterialV1,
) -> Result<Vec<u8>, PairingError> {
    #[derive(Serialize)]
    struct PairingTranscript<'a> {
        domain: &'a [u8],
        pairing_id: Uuid,
        node_id: &'a str,
        peer_id: &'a str,
        device_label: &'a str,
        challenge_secret: &'a [u8; 32],
        key_material_digest: [u8; 32],
        transport_binding_digest: [u8; 32],
        node_identity_digest: [u8; 32],
        expires_at_unix_ms: i64,
    }
    let material_bytes = postcard::to_allocvec(material).map_err(|_| PairingError::Encoding)?;
    postcard::to_allocvec(&PairingTranscript {
        domain: PAIRING_PROOF_DOMAIN,
        pairing_id: pending.pairing_id,
        node_id: &pending.node_id,
        peer_id: &pending.peer_id,
        device_label: &pending.device_label,
        challenge_secret,
        key_material_digest: Sha256::digest(material_bytes).into(),
        transport_binding_digest: pending.transport_binding_digest,
        node_identity_digest: pending.node_identity_digest,
        expires_at_unix_ms: pending.expires_at_unix_ms,
    })
    .map_err(|_| PairingError::Encoding)
}

fn credential_rotation_proof_bytes(
    pending: &PendingCredentialRotation,
    challenge_secret: &[u8; 32],
    current_material: &PairingKeyMaterialV1,
    next_material: &PairingKeyMaterialV1,
) -> Result<Vec<u8>, PairingError> {
    #[derive(Serialize)]
    struct CredentialRotationTranscript<'a> {
        domain: &'a [u8],
        rotation_id: Uuid,
        pairing_id: Uuid,
        node_id: &'a str,
        peer_id: &'a str,
        current_trust_epoch: u64,
        challenge_secret: &'a [u8; 32],
        current_material_digest: [u8; 32],
        next_material_digest: [u8; 32],
        next_transport_binding_digest: [u8; 32],
        node_identity_digest: [u8; 32],
        expires_at_unix_ms: i64,
    }
    let current_bytes =
        postcard::to_allocvec(current_material).map_err(|_| PairingError::Encoding)?;
    let next_bytes = postcard::to_allocvec(next_material).map_err(|_| PairingError::Encoding)?;
    postcard::to_allocvec(&CredentialRotationTranscript {
        domain: CREDENTIAL_ROTATION_PROOF_DOMAIN,
        rotation_id: pending.rotation_id,
        pairing_id: pending.pairing_id,
        node_id: &pending.node_id,
        peer_id: &pending.peer_id,
        current_trust_epoch: pending.current_trust_epoch,
        challenge_secret,
        current_material_digest: Sha256::digest(current_bytes).into(),
        next_material_digest: Sha256::digest(next_bytes).into(),
        next_transport_binding_digest: next_material.client_certificate_sha256.0,
        node_identity_digest: pending.node_identity_digest,
        expires_at_unix_ms: pending.expires_at_unix_ms,
    })
    .map_err(|_| PairingError::Encoding)
}

fn pairing_recovery_proof_bytes(
    pending: &PendingPairingRecovery,
    challenge_secret: &[u8; 32],
    next_material: &PairingKeyMaterialV1,
) -> Result<Vec<u8>, PairingError> {
    #[derive(Serialize)]
    struct PairingRecoveryTranscript<'a> {
        domain: &'a [u8],
        recovery_id: Uuid,
        pairing_id: Uuid,
        node_id: &'a str,
        peer_id: &'a str,
        device_label: &'a str,
        revoked_identity_digest: [u8; 32],
        revoked_trust_epoch: u64,
        revocation_digest: [u8; 32],
        challenge_secret: &'a [u8; 32],
        next_material_digest: [u8; 32],
        next_transport_binding_digest: [u8; 32],
        node_identity_digest: [u8; 32],
        expires_at_unix_ms: i64,
    }
    let next_bytes = postcard::to_allocvec(next_material).map_err(|_| PairingError::Encoding)?;
    postcard::to_allocvec(&PairingRecoveryTranscript {
        domain: PAIRING_RECOVERY_PROOF_DOMAIN,
        recovery_id: pending.recovery_id,
        pairing_id: pending.pairing_id,
        node_id: &pending.node_id,
        peer_id: &pending.peer_id,
        device_label: &pending.device_label,
        revoked_identity_digest: pending.revoked_identity_digest,
        revoked_trust_epoch: pending.revoked_trust_epoch,
        revocation_digest: pending.revocation_digest,
        challenge_secret,
        next_material_digest: Sha256::digest(next_bytes).into(),
        next_transport_binding_digest: pending.transport_binding_digest,
        node_identity_digest: pending.node_identity_digest,
        expires_at_unix_ms: pending.expires_at_unix_ms,
    })
    .map_err(|_| PairingError::Encoding)
}

fn verify(
    key: PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), PairingError> {
    let key = VerifyingKey::from_bytes(&key.0).map_err(|_| PairingError::InvalidProof)?;
    if key.is_weak() {
        return Err(PairingError::InvalidProof);
    }
    let signature =
        Signature::from_slice(signature.as_bytes()).map_err(|_| PairingError::InvalidProof)?;
    key.verify_strict(message, &signature)
        .map_err(|_| PairingError::InvalidProof)
}

/// Verify a node signature over a displayed pairing or rotation proof payload.
/// This uses strict Ed25519 verification and is suitable for owner tooling.
pub fn verify_node_proof(
    node_public_key: PublicKeyBytes,
    payload: &[u8],
    signature: &SignatureBytes,
) -> Result<(), PairingError> {
    verify(node_public_key, payload, signature)
}

fn key_id_from_bytes(key: PublicKeyBytes) -> Result<Sha256Digest, PairingError> {
    let key = VerifyingKey::from_bytes(&key.0)
        .map_err(|_| PairingError::Invalid("public key is invalid".to_owned()))?;
    Ok(key_id(&key))
}

fn millis_to_i64(value: UnixMillis) -> Result<i64, PairingError> {
    i64::try_from(value.0).map_err(|_| PairingError::TimeRange)
}

fn i64_to_millis(value: i64) -> Result<UnixMillis, PairingError> {
    u64::try_from(value)
        .map(UnixMillis)
        .map_err(|_| PairingError::TimeRange)
}
