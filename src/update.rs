//! Offline update-bundle verification.
//!
//! This module deliberately has no downloader, installer, privilege elevation, or self-replacement
//! behavior. It verifies an already-local artifact so an owner-operated updater can stage it.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const UPDATE_DOMAIN: &[u8] = b"sovereign-node/offline-update/v1\0";
const OWNER_APPROVAL_DOMAIN: &[u8] = b"sovereign-node/offline-update-owner-approval/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifestV1 {
    pub schema_version: u16,
    pub software_version: String,
    pub previous_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub artifact_sha256: [u8; 32],
    pub release_counter: u64,
    pub rollback_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdateV1 {
    pub manifest: UpdateManifestV1,
    pub release_signature: Vec<u8>,
    pub owner_approval_signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct UpdatePolicy {
    pub current_version: String,
    pub current_release_counter: u64,
    pub target_os: String,
    pub target_arch: String,
}

#[derive(Debug)]
pub struct VerifiedUpdate<'a> {
    manifest: &'a UpdateManifestV1,
}

impl VerifiedUpdate<'_> {
    #[must_use]
    pub fn manifest(&self) -> &UpdateManifestV1 {
        self.manifest
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UpdateError {
    #[error("unsupported update schema version")]
    Version,
    #[error("update does not apply to the running version")]
    PreviousVersion,
    #[error("update release counter is not monotonic")]
    Counter,
    #[error("update version or rollback metadata is invalid")]
    Rollback,
    #[error("update target does not match this operating system and architecture")]
    Target,
    #[error("artifact digest does not match the signed manifest")]
    ArtifactDigest,
    #[error("release signature is invalid")]
    ReleaseSignature,
    #[error("owner approval is invalid")]
    OwnerApproval,
    #[error("could not encode the update manifest")]
    Encoding,
}

pub fn verify_update<'a>(
    bundle: &'a SignedUpdateV1,
    artifact: &[u8],
    policy: &UpdatePolicy,
    release_key: &VerifyingKey,
    owner_key: &VerifyingKey,
) -> Result<VerifiedUpdate<'a>, UpdateError> {
    if release_key.is_weak() {
        return Err(UpdateError::ReleaseSignature);
    }
    if owner_key.is_weak() {
        return Err(UpdateError::OwnerApproval);
    }
    if bundle.manifest.schema_version != 1 {
        return Err(UpdateError::Version);
    }
    if bundle.manifest.previous_version != policy.current_version {
        return Err(UpdateError::PreviousVersion);
    }
    if bundle.manifest.software_version.is_empty()
        || bundle.manifest.software_version == bundle.manifest.previous_version
        || bundle.manifest.rollback_version != bundle.manifest.previous_version
    {
        return Err(UpdateError::Rollback);
    }
    if bundle.manifest.release_counter <= policy.current_release_counter {
        return Err(UpdateError::Counter);
    }
    if bundle.manifest.target_os != policy.target_os
        || bundle.manifest.target_arch != policy.target_arch
    {
        return Err(UpdateError::Target);
    }

    let actual_digest: [u8; 32] = Sha256::digest(artifact).into();
    if actual_digest != bundle.manifest.artifact_sha256 {
        return Err(UpdateError::ArtifactDigest);
    }

    let manifest_bytes =
        postcard::to_allocvec(&bundle.manifest).map_err(|_| UpdateError::Encoding)?;
    let release_message = domain_message(UPDATE_DOMAIN, &manifest_bytes);
    verify_signature(
        release_key,
        &release_message,
        &bundle.release_signature,
        UpdateError::ReleaseSignature,
    )?;

    let owner_message = domain_message(OWNER_APPROVAL_DOMAIN, &manifest_bytes);
    verify_signature(
        owner_key,
        &owner_message,
        &bundle.owner_approval_signature,
        UpdateError::OwnerApproval,
    )?;

    Ok(VerifiedUpdate {
        manifest: &bundle.manifest,
    })
}

fn domain_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature: &[u8],
    error: UpdateError,
) -> Result<(), UpdateError> {
    let signature = Signature::from_slice(signature).map_err(|_| error.clone())?;
    key.verify_strict(message, &signature).map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn fixture(artifact: &[u8]) -> (SignedUpdateV1, SigningKey, SigningKey, UpdatePolicy) {
        let release = SigningKey::from_bytes(&[7; 32]);
        let owner = SigningKey::from_bytes(&[9; 32]);
        let manifest = UpdateManifestV1 {
            schema_version: 1,
            software_version: "0.2.0".to_owned(),
            previous_version: "0.1.0".to_owned(),
            target_os: "test-os".to_owned(),
            target_arch: "test-arch".to_owned(),
            artifact_sha256: Sha256::digest(artifact).into(),
            release_counter: 2,
            rollback_version: "0.1.0".to_owned(),
        };
        let bytes = postcard::to_allocvec(&manifest).unwrap_or_default();
        let release_signature = release
            .sign(&domain_message(UPDATE_DOMAIN, &bytes))
            .to_bytes();
        let owner_signature = owner
            .sign(&domain_message(OWNER_APPROVAL_DOMAIN, &bytes))
            .to_bytes();
        let bundle = SignedUpdateV1 {
            manifest,
            release_signature: release_signature.to_vec(),
            owner_approval_signature: owner_signature.to_vec(),
        };
        let policy = UpdatePolicy {
            current_version: "0.1.0".to_owned(),
            current_release_counter: 1,
            target_os: "test-os".to_owned(),
            target_arch: "test-arch".to_owned(),
        };
        (bundle, release, owner, policy)
    }

    #[test]
    fn signed_owner_approved_offline_update_is_accepted() {
        let artifact = b"signed release artifact";
        let (bundle, release, owner, policy) = fixture(artifact);
        let verified = verify_update(
            &bundle,
            artifact,
            &policy,
            &release.verifying_key(),
            &owner.verifying_key(),
        );
        assert!(verified.is_ok());
    }

    #[test]
    fn tampered_artifact_is_rejected() {
        let (bundle, release, owner, policy) = fixture(b"expected");
        let verified = verify_update(
            &bundle,
            b"tampered",
            &policy,
            &release.verifying_key(),
            &owner.verifying_key(),
        );
        assert_eq!(verified.map(|_| ()), Err(UpdateError::ArtifactDigest));
    }

    #[test]
    fn replayed_or_downgrade_counter_is_rejected() {
        let artifact = b"expected";
        let (bundle, release, owner, mut policy) = fixture(artifact);
        policy.current_release_counter = 2;
        let verified = verify_update(
            &bundle,
            artifact,
            &policy,
            &release.verifying_key(),
            &owner.verifying_key(),
        );
        assert_eq!(verified.map(|_| ()), Err(UpdateError::Counter));
    }

    #[test]
    fn rollback_metadata_must_name_the_current_version() {
        let artifact = b"release artifact";
        let (mut bundle, release, owner, policy) = fixture(artifact);
        bundle.manifest.rollback_version = "0.0.1".to_owned();
        assert!(matches!(
            verify_update(
                &bundle,
                artifact,
                &policy,
                &release.verifying_key(),
                &owner.verifying_key(),
            ),
            Err(UpdateError::Rollback)
        ));
    }
}
