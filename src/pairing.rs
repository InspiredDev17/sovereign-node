use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::{NodeIdentity, key_id};
use crate::protocol::{
    Capability, PairingId, PublicKeyBytes, Sha256Digest, SignatureBytes, UnixMillis,
};
use crate::store::{
    PairingApproval, PendingPairingChallenge, RevocationOutcome, StateStore, StoreError,
    TrustedPeer, sha256,
};

const PAIRING_PROOF_DOMAIN: &[u8] = b"sovereign-node/pairing-proof/v1\0";

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
    pub ttl_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PairingDisplay {
    pub pairing_id: PairingId,
    pub node_id: String,
    pub node_identity_fingerprint: String,
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
            &challenge_secret,
            self.identity.key_id().0,
            request.key_material.client_certificate_sha256.0,
            millis_to_i64(now)?,
            millis_to_i64(expires_at)?,
        )?;
        self.store.put_pending_pairing(&pending)?;

        let proof_payload =
            pairing_proof_bytes(&pending, &challenge_secret, &request.key_material)?;
        Ok(PairingDisplay {
            pairing_id,
            node_id: self.identity.node_id().to_string(),
            node_identity_fingerprint: self.identity.fingerprint(),
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
    ) -> Result<TrustedPeer, PairingError> {
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
        Ok(trusted)
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

fn verify(
    key: PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), PairingError> {
    let key = VerifyingKey::from_bytes(&key.0).map_err(|_| PairingError::InvalidProof)?;
    let signature =
        Signature::from_slice(signature.as_bytes()).map_err(|_| PairingError::InvalidProof)?;
    key.verify_strict(message, &signature)
        .map_err(|_| PairingError::InvalidProof)
}

fn key_id_from_bytes(key: PublicKeyBytes) -> Result<Sha256Digest, PairingError> {
    let key = VerifyingKey::from_bytes(&key.0)
        .map_err(|_| PairingError::Invalid("public key is invalid".to_owned()))?;
    Ok(key_id(&key))
}

fn millis_to_i64(value: UnixMillis) -> Result<i64, PairingError> {
    i64::try_from(value.0).map_err(|_| PairingError::TimeRange)
}
