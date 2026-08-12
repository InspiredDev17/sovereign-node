use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::protocol::{
    CapabilityManifestV1, CryptographicIdentityV1, DeviceIdentityV1, KeyAlgorithm, NodeId,
    NodeRegistrationV1, PROTOCOL_VERSION_V1, PublicKeyBytes, SCHEMA_VERSION_V1, Sha256Digest,
    SignatureBytes, TrustStatus, UnixMillis,
};
use crate::resources::ResourceReporter;
use crate::security::{
    SecureFileError, create_private_file, ensure_private_directory, read_private_file,
};

const IDENTITY_FILENAME: &str = "identity.json";
const IDENTITY_ROTATION_DOMAIN: &[u8] = b"sovereign-node/device-identity-rotation/v1\0";

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
}
