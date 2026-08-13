use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::protocol::{
    ActiveTrustSummaryV1, CapabilityManifestV1, CryptographicIdentityV1, DeviceIdentityV1,
    KeyAlgorithm, NodeId, NodeIdentityProofV2, NodeRegistrationV1, Nonce, PROTOCOL_VERSION_V1,
    PublicKeyBytes, SCHEMA_VERSION_V1, Sha256Digest, SignatureBytes, SignedNodeIdentityProofV2,
    TrustStatus, UnixMillis, ValidationError,
};
use crate::resources::ResourceReporter;
use crate::security::{
    SecureFileError, create_private_file, ensure_private_directory, read_private_file,
};
use crate::store::{ActivePolicyBinding, StoreError, TrustedPeer};

const IDENTITY_FILENAME: &str = "identity.json";
const IDENTITY_ROTATION_DOMAIN: &[u8] = b"sovereign-node/device-identity-rotation/v1\0";
const ACTIVE_TRUST_SET_DOMAIN: &[u8] = b"sovereign-node/active-trust-set/v1\0";
pub const MAX_IDENTITY_PROOF_JSON_BYTES: u64 = 1_048_576;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDocument {
    schema_version: u16,
    node_id: NodeId,
    installation_id: Uuid,
    display_name: String,
    created_at: UnixMillis,
    rotation_counter: u64,
    signing_key: [u8; 32],
}

#[derive(Clone)]
pub struct NodeIdentity {
    node_id: NodeId,
    device: DeviceIdentityV1,
    created_at: UnixMillis,
    rotation_counter: u64,
    signing_key: SigningKey,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("device", &self.device)
            .field("created_at", &self.created_at)
            .field("rotation_counter", &self.rotation_counter)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error(transparent)]
    SecureFile(#[from] SecureFileError),
    #[error("identity document could not be encoded: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("identity document is invalid: {0}")]
    Invalid(String),
    #[error("identity filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity signature could not be encoded")]
    SignatureEncoding,
}

#[derive(Debug, Error)]
pub enum IdentityProofError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("identity proof is invalid: {0}")]
    Validation(#[from] ValidationError),
    #[error("identity proof canonical encoding failed: {0}")]
    Codec(#[from] postcard::Error),
    #[error("identity proof JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity proof file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity proof exceeds the bounded JSON input limit")]
    ResourceLimit,
    #[error("identity proof signature is invalid")]
    InvalidSignature,
    #[error("identity proof does not match the pinned {0}")]
    PinMismatch(&'static str),
    #[error("active trust snapshot is inconsistent")]
    InvalidTrustSnapshot,
    #[error("identity proof input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("identity proof requires a durably activated local policy")]
    PolicyInactive,
    #[error("configured policy does not match the durable active policy")]
    PolicyMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityProofVerificationReceiptV1 {
    pub schema_version: u16,
    pub verification: &'static str,
    pub node_id: String,
    pub node_key_id_sha256: String,
    pub challenge_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub capability_manifest_version: u64,
    pub capability_manifest_sha256: String,
    pub local_policy_sha256: String,
    pub trust_status: TrustStatus,
    pub active_peer_count: u32,
    pub maximum_peer_trust_epoch: u64,
    pub active_trust_set_sha256: String,
    pub device_rotation_counter: u64,
}

#[derive(Debug)]
pub struct IdentityProofRequest<'a> {
    pub manifest: CapabilityManifestV1,
    pub local_policy_digest: Sha256Digest,
    pub active_peers: &'a [TrustedPeer],
    pub trust_observed_at_unix_ms: i64,
    pub requester_challenge: Nonce,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

#[derive(Serialize)]
struct ActiveTrustDigestV1 {
    schema_version: u16,
    node_id: NodeId,
    peers: Vec<ActiveTrustDigestEntryV1>,
}

#[derive(Serialize)]
struct ActiveTrustDigestEntryV1 {
    pairing_id: Uuid,
    identity_digest: Sha256Digest,
    capability_manifest_digest: Sha256Digest,
    trust_epoch: u64,
    trust_expires_at_unix_ms: Option<i64>,
}

impl NodeIdentity {
    pub fn load_or_initialize(
        data_dir: &Path,
        display_name: &str,
        now: UnixMillis,
    ) -> Result<(Self, bool), IdentityError> {
        if !cfg!(unix) {
            return Err(IdentityError::Invalid(
                "v0.1 identity storage requires Unix ownership and mode checks".to_owned(),
            ));
        }
        validate_display_name(display_name)?;
        ensure_private_directory(data_dir)?;
        let path = identity_path(data_dir);
        if path.exists() {
            return Ok((Self::load(data_dir)?, false));
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let identity = Self {
            node_id: NodeId(Uuid::new_v4()),
            device: DeviceIdentityV1 {
                display_name: display_name.to_owned(),
                installation_id: Uuid::new_v4(),
            },
            created_at: now,
            rotation_counter: 0,
            signing_key,
        };
        identity.persist_new(&path)?;
        Ok((identity, true))
    }

    pub fn load(data_dir: &Path) -> Result<Self, IdentityError> {
        if !cfg!(unix) {
            return Err(IdentityError::Invalid(
                "v0.1 identity storage requires Unix ownership and mode checks".to_owned(),
            ));
        }
        ensure_private_directory(data_dir)?;
        let path = identity_path(data_dir);
        let mut raw = read_private_file(&path)?;
        let parsed = serde_json::from_slice::<IdentityDocument>(&raw);
        raw.zeroize();
        let mut document = parsed?;
        let result = validate_document(&document).map(|()| Self {
            node_id: document.node_id,
            device: DeviceIdentityV1 {
                display_name: document.display_name.clone(),
                installation_id: document.installation_id,
            },
            created_at: document.created_at,
            rotation_counter: document.rotation_counter,
            signing_key: SigningKey::from_bytes(&document.signing_key),
        });
        document.signing_key.zeroize();
        result
    }

    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub fn device(&self) -> &DeviceIdentityV1 {
        &self.device
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    #[must_use]
    pub fn key_id(&self) -> Sha256Digest {
        key_id(&self.verifying_key())
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex::encode(self.key_id().0)
    }

    pub fn sign(&self, message: &[u8]) -> Result<SignatureBytes, IdentityError> {
        SignatureBytes::from_slice(&self.signing_key.sign(message).to_bytes())
            .map_err(|_| IdentityError::SignatureEncoding)
    }

    #[must_use]
    pub fn cryptographic_identity(&self) -> CryptographicIdentityV1 {
        CryptographicIdentityV1 {
            algorithm: KeyAlgorithm::Ed25519,
            key_id: self.key_id(),
            public_key: self.public_key(),
            created_at: self.created_at,
            rotation_counter: self.rotation_counter,
        }
    }

    pub fn registration(
        &self,
        manifest: CapabilityManifestV1,
        trust_status: TrustStatus,
        generated_at: UnixMillis,
    ) -> NodeRegistrationV1 {
        let system =
            ResourceReporter::new(self.node_id, self.device.clone()).system_info(trust_status);
        NodeRegistrationV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: PROTOCOL_VERSION_V1,
            node_id: self.node_id,
            device: self.device.clone(),
            cryptographic_identity: self.cryptographic_identity(),
            capability_manifest: manifest,
            platform: system.platform,
            hardware: system.hardware,
            trust_status,
            software: system.software,
            generated_at,
        }
    }

    pub fn fresh_identity_proof(
        &self,
        request: IdentityProofRequest<'_>,
    ) -> Result<SignedNodeIdentityProofV2, IdentityProofError> {
        let active_trust = active_trust_summary(
            self.node_id(),
            request.active_peers,
            request.trust_observed_at_unix_ms,
        )?;
        let trust_status = if active_trust.active_peer_count == 0 {
            TrustStatus::Unpaired
        } else {
            TrustStatus::Trusted
        };
        let capability_manifest_digest = request.manifest.digest()?;
        let proof = NodeIdentityProofV2 {
            schema_version: 2,
            registration: self.registration(request.manifest, trust_status, request.issued_at),
            capability_manifest_digest,
            local_policy_digest: request.local_policy_digest,
            active_trust,
            requester_challenge: request.requester_challenge,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
        };
        proof.validate()?;
        let node_signature = self.sign(&proof.signing_bytes()?)?;
        let signed = SignedNodeIdentityProofV2 {
            proof,
            node_signature,
        };
        verify_identity_proof(
            &signed,
            self.node_id(),
            self.key_id(),
            request.requester_challenge,
            request.issued_at,
        )?;
        Ok(signed)
    }

    /// Rotates only the device identity key. It preserves the stable NodeId and installation ID.
    /// The returned binding is signed by both the old and new keys for audit/proof of possession.
    pub fn rotate_locally(
        &self,
        data_dir: &Path,
        now: UnixMillis,
        owner_confirmed: bool,
    ) -> Result<(Self, RotationBindingV1), IdentityError> {
        if !owner_confirmed {
            return Err(IdentityError::Invalid(
                "local owner confirmation is required for credential rotation".to_owned(),
            ));
        }
        let next_counter = self
            .rotation_counter
            .checked_add(1)
            .ok_or_else(|| IdentityError::Invalid("rotation counter overflow".to_owned()))?;
        let next_key = SigningKey::generate(&mut OsRng);
        let mut binding = RotationBindingV1 {
            schema_version: 1,
            node_id: self.node_id,
            previous_key_id: self.key_id(),
            next_key_id: key_id(&next_key.verifying_key()),
            rotation_counter: next_counter,
            approved_at: now,
            previous_key_signature: Vec::new(),
            next_key_signature: Vec::new(),
        };
        let bytes = binding.signing_bytes()?;
        binding.previous_key_signature = self.signing_key.sign(&bytes).to_bytes().to_vec();
        binding.next_key_signature = next_key.sign(&bytes).to_bytes().to_vec();

        let rotated = Self {
            node_id: self.node_id,
            device: self.device.clone(),
            created_at: now,
            rotation_counter: next_counter,
            signing_key: next_key,
        };
        rotated.persist_atomic(&identity_path(data_dir))?;
        Ok((rotated, binding))
    }

    fn persist_new(&self, path: &Path) -> Result<(), IdentityError> {
        let mut serialized = serde_json::to_vec_pretty(&self.document())?;
        let result = create_private_file(path, &serialized);
        serialized.zeroize();
        result?;
        Ok(())
    }

    fn persist_atomic(&self, path: &Path) -> Result<(), IdentityError> {
        let next_path = path.with_extension(format!("next-{}", Uuid::new_v4()));
        self.persist_new(&next_path)?;
        if let Err(error) = fs::rename(&next_path, path) {
            let _ = fs::remove_file(&next_path);
            return Err(error.into());
        }
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn document(&self) -> IdentityDocument {
        IdentityDocument {
            schema_version: 1,
            node_id: self.node_id,
            installation_id: self.device.installation_id,
            display_name: self.device.display_name.clone(),
            created_at: self.created_at,
            rotation_counter: self.rotation_counter,
            signing_key: self.signing_key.to_bytes(),
        }
    }
}

pub fn active_trust_summary(
    node_id: NodeId,
    peers: &[TrustedPeer],
    now_unix_ms: i64,
) -> Result<ActiveTrustSummaryV1, IdentityProofError> {
    let mut ordered = peers.to_vec();
    ordered.sort_by(|left, right| left.peer_id.cmp(&right.peer_id));
    if ordered
        .windows(2)
        .any(|pair| pair[0].peer_id == pair[1].peer_id)
        || ordered.iter().any(|peer| {
            peer.node_id != node_id.to_string()
                || peer.trust_epoch == 0
                || !peer.is_currently_trusted(now_unix_ms)
        })
    {
        return Err(IdentityProofError::InvalidTrustSnapshot);
    }
    let maximum_peer_trust_epoch = ordered
        .iter()
        .map(|peer| peer.trust_epoch)
        .max()
        .unwrap_or(0);
    let active_peer_count =
        u32::try_from(ordered.len()).map_err(|_| IdentityProofError::ResourceLimit)?;
    let digest_record = ActiveTrustDigestV1 {
        schema_version: 1,
        node_id,
        peers: ordered
            .into_iter()
            .map(|peer| ActiveTrustDigestEntryV1 {
                pairing_id: peer.pairing_id,
                identity_digest: Sha256Digest(peer.identity_digest),
                capability_manifest_digest: Sha256Digest(peer.capability_manifest_digest),
                trust_epoch: peer.trust_epoch,
                trust_expires_at_unix_ms: peer.trust_expires_at_unix_ms,
            })
            .collect(),
    };
    let encoded = postcard::to_allocvec(&digest_record)?;
    let mut hasher = Sha256::new();
    hasher.update(ACTIVE_TRUST_SET_DOMAIN);
    hasher.update(encoded);
    Ok(ActiveTrustSummaryV1 {
        active_peer_count,
        maximum_peer_trust_epoch,
        active_trust_set_digest: Sha256Digest(hasher.finalize().into()),
    })
}

pub fn require_active_policy(
    active: Option<ActivePolicyBinding>,
    expected_version: u64,
    expected_digest: Sha256Digest,
) -> Result<(), IdentityProofError> {
    let active = active.ok_or(IdentityProofError::PolicyInactive)?;
    if active.version != expected_version || active.digest != expected_digest.0 {
        return Err(IdentityProofError::PolicyMismatch);
    }
    Ok(())
}

pub fn verify_identity_proof(
    signed: &SignedNodeIdentityProofV2,
    expected_node_id: NodeId,
    expected_node_key_id: Sha256Digest,
    expected_challenge: Nonce,
    now: UnixMillis,
) -> Result<IdentityProofVerificationReceiptV1, IdentityProofError> {
    signed.proof.validate_freshness(now, expected_challenge)?;
    if signed.proof.registration.node_id != expected_node_id {
        return Err(IdentityProofError::PinMismatch("NodeId"));
    }
    if signed.proof.registration.cryptographic_identity.key_id != expected_node_key_id {
        return Err(IdentityProofError::PinMismatch("node device key ID"));
    }
    let public_key = signed.proof.registration.cryptographic_identity.public_key;
    let key = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|_| IdentityProofError::InvalidSignature)?;
    if key.is_weak() {
        return Err(IdentityProofError::InvalidSignature);
    }
    let signature = Signature::from_slice(signed.node_signature.as_bytes())
        .map_err(|_| IdentityProofError::InvalidSignature)?;
    key.verify_strict(&signed.proof.signing_bytes()?, &signature)
        .map_err(|_| IdentityProofError::InvalidSignature)?;
    Ok(IdentityProofVerificationReceiptV1 {
        schema_version: 1,
        verification: "verified",
        node_id: signed.proof.registration.node_id.to_string(),
        node_key_id_sha256: hex::encode(expected_node_key_id.0),
        challenge_sha256: hex::encode(Sha256::digest(expected_challenge.0)),
        issued_at_unix_ms: signed.proof.issued_at.0,
        expires_at_unix_ms: signed.proof.expires_at.0,
        capability_manifest_version: signed
            .proof
            .registration
            .capability_manifest
            .manifest_version,
        capability_manifest_sha256: hex::encode(signed.proof.capability_manifest_digest.0),
        local_policy_sha256: hex::encode(signed.proof.local_policy_digest.0),
        trust_status: signed.proof.registration.trust_status,
        active_peer_count: signed.proof.active_trust.active_peer_count,
        maximum_peer_trust_epoch: signed.proof.active_trust.maximum_peer_trust_epoch,
        active_trust_set_sha256: hex::encode(signed.proof.active_trust.active_trust_set_digest.0),
        device_rotation_counter: signed
            .proof
            .registration
            .cryptographic_identity
            .rotation_counter,
    })
}

pub fn verify_identity_proof_bytes(
    input: &[u8],
    expected_node_id: NodeId,
    expected_node_key_id: Sha256Digest,
    expected_challenge: Nonce,
    now: UnixMillis,
) -> Result<IdentityProofVerificationReceiptV1, IdentityProofError> {
    if input.len() > MAX_IDENTITY_PROOF_JSON_BYTES as usize {
        return Err(IdentityProofError::ResourceLimit);
    }
    let signed: SignedNodeIdentityProofV2 = serde_json::from_slice(input)?;
    verify_identity_proof(
        &signed,
        expected_node_id,
        expected_node_key_id,
        expected_challenge,
        now,
    )
}

pub fn verify_identity_proof_file(
    path: &Path,
    expected_node_id: NodeId,
    expected_node_key_id: Sha256Digest,
    expected_challenge: Nonce,
    now: UnixMillis,
) -> Result<IdentityProofVerificationReceiptV1, IdentityProofError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(IdentityProofError::InvalidInput(
            "identity proof input is not a regular file",
        ));
    }
    if metadata.len() > MAX_IDENTITY_PROOF_JSON_BYTES {
        return Err(IdentityProofError::ResourceLimit);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| IdentityProofError::ResourceLimit)?;
    let mut input = Vec::with_capacity(capacity);
    file.take(MAX_IDENTITY_PROOF_JSON_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    verify_identity_proof_bytes(
        &input,
        expected_node_id,
        expected_node_key_id,
        expected_challenge,
        now,
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationBindingV1 {
    pub schema_version: u16,
    pub node_id: NodeId,
    pub previous_key_id: Sha256Digest,
    pub next_key_id: Sha256Digest,
    pub rotation_counter: u64,
    pub approved_at: UnixMillis,
    pub previous_key_signature: Vec<u8>,
    pub next_key_signature: Vec<u8>,
}

impl RotationBindingV1 {
    fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        #[derive(Serialize)]
        struct UnsignedBinding<'a> {
            schema_version: u16,
            node_id: NodeId,
            previous_key_id: Sha256Digest,
            next_key_id: Sha256Digest,
            rotation_counter: u64,
            approved_at: UnixMillis,
            domain: &'a [u8],
        }
        postcard::to_allocvec(&UnsignedBinding {
            schema_version: self.schema_version,
            node_id: self.node_id,
            previous_key_id: self.previous_key_id,
            next_key_id: self.next_key_id,
            rotation_counter: self.rotation_counter,
            approved_at: self.approved_at,
            domain: IDENTITY_ROTATION_DOMAIN,
        })
        .map_err(|_| IdentityError::SignatureEncoding)
    }
}

#[must_use]
pub fn key_id(key: &VerifyingKey) -> Sha256Digest {
    Sha256Digest(Sha256::digest(key.as_bytes()).into())
}

fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_FILENAME)
}

fn validate_display_name(display_name: &str) -> Result<(), IdentityError> {
    if display_name.is_empty() || display_name.len() > 128 || display_name.contains('\0') {
        return Err(IdentityError::Invalid(
            "display name must contain between 1 and 128 bytes without NUL".to_owned(),
        ));
    }
    Ok(())
}

fn validate_document(document: &IdentityDocument) -> Result<(), IdentityError> {
    if document.schema_version != 1 {
        return Err(IdentityError::Invalid(
            "unsupported identity schema version".to_owned(),
        ));
    }
    validate_display_name(&document.display_name)?;
    if document.node_id.0.is_nil() || document.installation_id.is_nil() {
        return Err(IdentityError::Invalid(
            "identity contains a nil identifier".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::protocol::Capability;
    use crate::store::TrustStatus as StoreTrustStatus;

    fn manifest(generated_at: UnixMillis) -> CapabilityManifestV1 {
        CapabilityManifestV1 {
            manifest_version: 7,
            capabilities: vec![Capability::SystemInfo, Capability::ResourceStatus],
            generated_at,
        }
    }

    fn trusted_peer(node_id: NodeId, peer_id: &str, epoch: u64) -> TrustedPeer {
        TrustedPeer {
            peer_id: peer_id.to_owned(),
            pairing_id: Uuid::new_v4(),
            node_id: node_id.to_string(),
            device_label: "redacted-in-proof".to_owned(),
            public_key: vec![0x42; 32],
            identity_digest: Sha256::digest(format!("identity:{peer_id}")).into(),
            capability_manifest_digest: Sha256::digest(format!("manifest:{peer_id}")).into(),
            status: StoreTrustStatus::Active,
            trust_epoch: epoch,
            paired_at_unix_ms: 900,
            trust_expires_at_unix_ms: Some(2_000),
            last_key_rotation_at_unix_ms: None,
            revoked_at_unix_ms: None,
        }
    }

    #[test]
    fn node_identity_is_stable_across_restart() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (created, was_created) =
            NodeIdentity::load_or_initialize(temp.path(), "test-node", UnixMillis(1_000))?;
        let loaded = NodeIdentity::load(temp.path())?;
        assert!(was_created);
        assert_eq!(created.node_id(), loaded.node_id());
        assert_eq!(created.public_key(), loaded.public_key());
        Ok(())
    }

    #[test]
    fn credential_rotation_preserves_node_id_and_replaces_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (identity, _) =
            NodeIdentity::load_or_initialize(temp.path(), "test-node", UnixMillis(1_000))?;
        let old_key = identity.public_key();
        let (rotated, binding) = identity.rotate_locally(temp.path(), UnixMillis(2_000), true)?;
        let reloaded = NodeIdentity::load(temp.path())?;
        assert_eq!(rotated.node_id(), identity.node_id());
        assert_ne!(rotated.public_key(), old_key);
        assert_eq!(reloaded.public_key(), rotated.public_key());
        assert_eq!(binding.rotation_counter, 1);
        Ok(())
    }

    #[test]
    fn rotation_requires_local_owner_confirmation() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (identity, _) =
            NodeIdentity::load_or_initialize(temp.path(), "test-node", UnixMillis(1_000))?;
        assert!(
            identity
                .rotate_locally(temp.path(), UnixMillis(2_000), false)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn fresh_identity_proof_is_challenge_bound_expiring_and_strict()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (identity, _) =
            NodeIdentity::load_or_initialize(temp.path(), "test-node", UnixMillis(1_000))?;
        let challenge = Nonce([0x11; 32]);
        let signed = identity.fresh_identity_proof(IdentityProofRequest {
            manifest: manifest(UnixMillis(1_000)),
            local_policy_digest: Sha256Digest([0x22; 32]),
            active_peers: &[],
            trust_observed_at_unix_ms: 1_000,
            requester_challenge: challenge,
            issued_at: UnixMillis(1_000),
            expires_at: UnixMillis(1_100),
        })?;

        let receipt = verify_identity_proof(
            &signed,
            identity.node_id(),
            identity.key_id(),
            challenge,
            UnixMillis(1_050),
        )?;
        assert_eq!(receipt.verification, "verified");
        assert_eq!(receipt.trust_status, TrustStatus::Unpaired);
        assert_eq!(receipt.active_peer_count, 0);
        assert_eq!(receipt.capability_manifest_version, 7);
        assert_eq!(
            receipt.challenge_sha256,
            hex::encode(Sha256::digest(challenge.0))
        );

        assert!(
            verify_identity_proof(
                &signed,
                identity.node_id(),
                identity.key_id(),
                Nonce([0x12; 32]),
                UnixMillis(1_050),
            )
            .is_err()
        );
        assert!(
            verify_identity_proof(
                &signed,
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_100),
            )
            .is_err()
        );
        assert!(
            verify_identity_proof(
                &signed,
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(999),
            )
            .is_err()
        );
        assert!(matches!(
            verify_identity_proof(
                &signed,
                NodeId(Uuid::new_v4()),
                identity.key_id(),
                challenge,
                UnixMillis(1_050),
            ),
            Err(IdentityProofError::PinMismatch("NodeId"))
        ));
        assert!(matches!(
            verify_identity_proof(
                &signed,
                identity.node_id(),
                Sha256Digest([0x33; 32]),
                challenge,
                UnixMillis(1_050),
            ),
            Err(IdentityProofError::PinMismatch("node device key ID"))
        ));

        let mut forged_policy = signed.clone();
        forged_policy.proof.local_policy_digest = Sha256Digest([0x44; 32]);
        assert!(
            verify_identity_proof(
                &forged_policy,
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_050),
            )
            .is_err()
        );

        let mut forged_manifest = signed.clone();
        forged_manifest
            .proof
            .registration
            .capability_manifest
            .capabilities
            .clear();
        assert!(
            verify_identity_proof(
                &forged_manifest,
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_050),
            )
            .is_err()
        );

        let mut wrong_signature = signed.clone();
        wrong_signature.node_signature = SignatureBytes::from_slice(&[0_u8; 64])?;
        assert!(
            verify_identity_proof(
                &wrong_signature,
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_050),
            )
            .is_err()
        );

        let mut extended = serde_json::to_value(&signed)?;
        extended["proof"]["registration"]["device"]["untrusted_extra"] =
            serde_json::json!("misleading");
        assert!(serde_json::from_value::<SignedNodeIdentityProofV2>(extended).is_err());

        assert!(
            identity
                .fresh_identity_proof(IdentityProofRequest {
                    manifest: manifest(UnixMillis(1_000)),
                    local_policy_digest: Sha256Digest([0x22; 32]),
                    active_peers: &[],
                    trust_observed_at_unix_ms: 1_000,
                    requester_challenge: challenge,
                    issued_at: UnixMillis(1_000),
                    expires_at: UnixMillis(
                        1_000 + crate::protocol::MAX_IDENTITY_PROOF_TTL_MILLIS + 1,
                    ),
                })
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn identity_proof_requires_exact_durable_active_policy() {
        let digest = Sha256Digest([0x71; 32]);
        assert!(matches!(
            require_active_policy(None, 7, digest),
            Err(IdentityProofError::PolicyInactive)
        ));
        assert!(matches!(
            require_active_policy(
                Some(ActivePolicyBinding {
                    version: 6,
                    digest: digest.0,
                }),
                7,
                digest,
            ),
            Err(IdentityProofError::PolicyMismatch)
        ));
        assert!(matches!(
            require_active_policy(
                Some(ActivePolicyBinding {
                    version: 7,
                    digest: [0x72; 32],
                }),
                7,
                digest,
            ),
            Err(IdentityProofError::PolicyMismatch)
        ));
        assert!(
            require_active_policy(
                Some(ActivePolicyBinding {
                    version: 7,
                    digest: digest.0,
                }),
                7,
                digest,
            )
            .is_ok()
        );
    }

    #[test]
    fn active_trust_digest_is_ordered_private_and_epoch_sensitive()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (identity, _) =
            NodeIdentity::load_or_initialize(temp.path(), "test-node", UnixMillis(1_000))?;
        let node_id = identity.node_id();
        let alpha = trusted_peer(node_id, "alpha-peer", 2);
        let bravo = trusted_peer(node_id, "bravo-peer", 5);
        let first = active_trust_summary(node_id, &[alpha.clone(), bravo.clone()], 1_000)?;
        let reordered = active_trust_summary(node_id, &[bravo.clone(), alpha.clone()], 1_000)?;
        assert_eq!(first, reordered);
        assert_eq!(first.active_peer_count, 2);
        assert_eq!(first.maximum_peer_trust_epoch, 5);

        let challenge = Nonce([0x61; 32]);
        let signed = identity.fresh_identity_proof(IdentityProofRequest {
            manifest: manifest(UnixMillis(1_000)),
            local_policy_digest: Sha256Digest([0x62; 32]),
            active_peers: &[alpha.clone(), bravo.clone()],
            trust_observed_at_unix_ms: 1_000,
            requester_challenge: challenge,
            issued_at: UnixMillis(1_000),
            expires_at: UnixMillis(2_000),
        })?;
        let receipt = verify_identity_proof(
            &signed,
            node_id,
            identity.key_id(),
            challenge,
            UnixMillis(1_500),
        )?;
        assert_eq!(receipt.trust_status, TrustStatus::Trusted);
        assert_eq!(receipt.active_peer_count, 2);
        assert_eq!(receipt.maximum_peer_trust_epoch, 5);
        let json = serde_json::to_string(&signed)?;
        for excluded in ["alpha-peer", "bravo-peer", "redacted-in-proof"] {
            assert!(!json.contains(excluded), "identity proof leaked {excluded}");
        }

        let mut rotated = bravo.clone();
        rotated.trust_epoch = 6;
        let changed = active_trust_summary(node_id, &[alpha.clone(), rotated], 1_000)?;
        assert_ne!(
            first.active_trust_set_digest,
            changed.active_trust_set_digest
        );
        assert_eq!(changed.maximum_peer_trust_epoch, 6);

        let mut expired = alpha.clone();
        expired.trust_expires_at_unix_ms = Some(1_000);
        assert!(active_trust_summary(node_id, &[expired], 1_000).is_err());

        let mut revoked = alpha.clone();
        revoked.status = StoreTrustStatus::Revoked;
        assert!(active_trust_summary(node_id, &[revoked], 1_000).is_err());

        let mut wrong_node = alpha.clone();
        wrong_node.node_id = Uuid::new_v4().to_string();
        assert!(active_trust_summary(node_id, &[wrong_node], 1_000).is_err());
        assert!(active_trust_summary(node_id, &[alpha.clone(), alpha], 1_000).is_err());
        Ok(())
    }

    #[test]
    fn identity_proof_verifier_reads_only_bounded_regular_nofollow_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let (identity, _) = NodeIdentity::load_or_initialize(
            &temp.path().join("identity"),
            "test-node",
            UnixMillis(1_000),
        )?;
        let challenge = Nonce([0x51; 32]);
        let signed = identity.fresh_identity_proof(IdentityProofRequest {
            manifest: manifest(UnixMillis(1_000)),
            local_policy_digest: Sha256Digest([0x52; 32]),
            active_peers: &[],
            trust_observed_at_unix_ms: 1_000,
            requester_challenge: challenge,
            issued_at: UnixMillis(1_000),
            expires_at: UnixMillis(2_000),
        })?;
        let path = temp.path().join("proof.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&signed)?)?;
        verify_identity_proof_file(
            &path,
            identity.node_id(),
            identity.key_id(),
            challenge,
            UnixMillis(1_500),
        )?;
        assert!(
            verify_identity_proof_file(
                temp.path(),
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_500),
            )
            .is_err()
        );
        assert!(matches!(
            verify_identity_proof_bytes(
                &vec![b'x'; MAX_IDENTITY_PROOF_JSON_BYTES as usize + 1],
                identity.node_id(),
                identity.key_id(),
                challenge,
                UnixMillis(1_500),
            ),
            Err(IdentityProofError::ResourceLimit)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let link = temp.path().join("proof-link.json");
            symlink(&path, &link)?;
            assert!(
                verify_identity_proof_file(
                    &link,
                    identity.node_id(),
                    identity.key_id(),
                    challenge,
                    UnixMillis(1_500),
                )
                .is_err()
            );
        }
        Ok(())
    }
}
