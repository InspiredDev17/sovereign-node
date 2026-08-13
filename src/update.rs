//! Offline update-bundle verification.
//!
//! This module deliberately has no downloader, installer, privilege elevation, or self-replacement
//! behavior. It verifies and copies an already-local artifact into owner-private staging so a
//! separate owner-operated installer can act later.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::security::{
    SecureFileError, create_private_file, ensure_private_directory, read_private_file,
};
use crate::store::{StateStore, StoreError, UpdateStageOutcome, UpdateStageRecord, sha256};

const UPDATE_DOMAIN: &[u8] = b"sovereign-node/offline-update/v1\0";
const OWNER_APPROVAL_DOMAIN: &[u8] = b"sovereign-node/offline-update-owner-approval/v1\0";
const MAX_BUNDLE_BYTES: u64 = 1_048_576;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

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

impl UpdateManifestV1 {
    pub fn release_signing_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        self.domain_signing_bytes(UPDATE_DOMAIN)
    }

    pub fn owner_approval_signing_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        self.domain_signing_bytes(OWNER_APPROVAL_DOMAIN)
    }

    fn domain_signing_bytes(&self, domain: &[u8]) -> Result<Vec<u8>, UpdateError> {
        let manifest_bytes = postcard::to_allocvec(self).map_err(|_| UpdateError::Encoding)?;
        Ok(domain_message(domain, &manifest_bytes))
    }
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

#[derive(Debug)]
pub struct LocalUpdateStageRequest<'a> {
    pub bundle_json_path: &'a Path,
    pub artifact_path: &'a Path,
    pub data_dir: &'a Path,
    pub store: &'a StateStore,
    pub policy: UpdatePolicy,
    pub release_key: &'a VerifyingKey,
    pub owner_key: &'a VerifyingKey,
    pub max_artifact_bytes: u64,
    pub owner_confirmed: bool,
    pub staged_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalUpdateStageResult {
    pub record: UpdateStageRecord,
    pub staged_artifact_path: PathBuf,
    pub already_staged: bool,
    pub installation_performed: bool,
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

#[derive(Debug, Error)]
pub enum UpdateStageError {
    #[error(transparent)]
    Verification(#[from] UpdateError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    SecureFile(#[from] SecureFileError),
    #[error("update staging filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("update bundle is not strict valid JSON: {0}")]
    BundleJson(#[from] serde_json::Error),
    #[error("explicit local owner confirmation is required to stage an update")]
    OwnerConfirmationRequired,
    #[error("update bundle or artifact exceeds the configured bound")]
    ResourceLimit,
    #[error("existing staged content conflicts with the signed update")]
    StageConflict,
}

pub fn verify_update<'a>(
    bundle: &'a SignedUpdateV1,
    artifact: &[u8],
    policy: &UpdatePolicy,
    release_key: &VerifyingKey,
    owner_key: &VerifyingKey,
) -> Result<VerifiedUpdate<'a>, UpdateError> {
    let actual_digest: [u8; 32] = Sha256::digest(artifact).into();
    verify_update_digest(bundle, actual_digest, policy, release_key, owner_key)
}

pub fn verify_update_digest<'a>(
    bundle: &'a SignedUpdateV1,
    actual_digest: [u8; 32],
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
    if release_key == owner_key {
        return Err(UpdateError::OwnerApproval);
    }
    if bundle.manifest.schema_version != 1 {
        return Err(UpdateError::Version);
    }
    if bundle.manifest.previous_version != policy.current_version {
        return Err(UpdateError::PreviousVersion);
    }
    if !valid_version_label(&bundle.manifest.software_version)
        || !valid_version_label(&bundle.manifest.previous_version)
        || !valid_version_label(&bundle.manifest.rollback_version)
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

    if actual_digest != bundle.manifest.artifact_sha256 {
        return Err(UpdateError::ArtifactDigest);
    }

    let release_message = bundle.manifest.release_signing_bytes()?;
    verify_signature(
        release_key,
        &release_message,
        &bundle.release_signature,
        UpdateError::ReleaseSignature,
    )?;

    let owner_message = bundle.manifest.owner_approval_signing_bytes()?;
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

fn valid_version_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

pub fn stage_local_update(
    request: &LocalUpdateStageRequest<'_>,
) -> Result<LocalUpdateStageResult, UpdateStageError> {
    let bundle_bytes = match read_bounded_regular(request.bundle_json_path, MAX_BUNDLE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            audit_rejection(
                request,
                sha256(b"unreadable-update-bundle"),
                error.audit_code(),
            )?;
            return Err(error);
        }
    };
    let bundle_digest = sha256(&bundle_bytes);
    if !request.owner_confirmed {
        audit_rejection(request, bundle_digest, b"owner-confirmation-required")?;
        return Err(UpdateStageError::OwnerConfirmationRequired);
    }
    let bundle: SignedUpdateV1 = match serde_json::from_slice(&bundle_bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            audit_rejection(request, bundle_digest, b"bundle-json-invalid")?;
            return Err(UpdateStageError::BundleJson(error));
        }
    };
    let manifest_bytes = postcard::to_allocvec(&bundle.manifest)
        .map_err(|_| UpdateStageError::Verification(UpdateError::Encoding))?;
    let signed_bundle_bytes = postcard::to_allocvec(&bundle)
        .map_err(|_| UpdateStageError::Verification(UpdateError::Encoding))?;
    let manifest_digest = sha256(&manifest_bytes);
    if let Err(error) = verify_update_digest(
        &bundle,
        bundle.manifest.artifact_sha256,
        &request.policy,
        request.release_key,
        request.owner_key,
    ) {
        audit_rejection(request, manifest_digest, update_error_code(&error))?;
        return Err(UpdateStageError::Verification(error));
    }

    let stage_relative_dir = PathBuf::from("updates").join("staged").join(format!(
        "{}-{}",
        bundle.manifest.release_counter,
        hex::encode(manifest_digest)
    ));
    let stage_dir = request.data_dir.join(&stage_relative_dir);
    ensure_private_directory(&request.data_dir.join("updates"))?;
    ensure_private_directory(&request.data_dir.join("updates/staged"))?;
    ensure_private_directory(&stage_dir)?;
    let staged_artifact_path = stage_dir.join("artifact.bin");
    if let Err(error) = stage_artifact(
        request.artifact_path,
        &staged_artifact_path,
        request.max_artifact_bytes,
        bundle.manifest.artifact_sha256,
    ) {
        audit_rejection(request, manifest_digest, error.audit_code())?;
        return Err(error);
    }
    let staged_bundle_path = stage_dir.join("bundle.postcard");
    if staged_bundle_path.exists() {
        if read_private_file(&staged_bundle_path)? != signed_bundle_bytes {
            audit_rejection(request, manifest_digest, b"staged-bundle-conflict")?;
            return Err(UpdateStageError::StageConflict);
        }
    } else {
        create_private_file(&staged_bundle_path, &signed_bundle_bytes)?;
    }

    let record = UpdateStageRecord {
        stage_id: Uuid::new_v4(),
        software_version: bundle.manifest.software_version,
        previous_version: bundle.manifest.previous_version,
        rollback_version: bundle.manifest.rollback_version,
        target_os: bundle.manifest.target_os,
        target_arch: bundle.manifest.target_arch,
        release_counter: bundle.manifest.release_counter,
        manifest_digest,
        artifact_digest: bundle.manifest.artifact_sha256,
        release_key_digest: sha256(request.release_key.as_bytes()),
        owner_key_digest: sha256(request.owner_key.as_bytes()),
        staged_artifact_relative_path: stage_relative_dir
            .join("artifact.bin")
            .to_string_lossy()
            .into_owned(),
        staged_at_unix_ms: request.staged_at_unix_ms,
    };
    let (record, already_staged) = match request.store.stage_verified_update(&record) {
        Ok(UpdateStageOutcome::Staged(record)) => (record, false),
        Ok(UpdateStageOutcome::AlreadyStaged(record)) => (record, true),
        Err(error) => {
            audit_rejection(request, manifest_digest, store_error_code(&error))?;
            return Err(UpdateStageError::Store(error));
        }
    };
    Ok(LocalUpdateStageResult {
        staged_artifact_path: request.data_dir.join(&record.staged_artifact_relative_path),
        record,
        already_staged,
        installation_performed: false,
    })
}

fn stage_artifact(
    source: &Path,
    destination: &Path,
    maximum_bytes: u64,
    expected_digest: [u8; 32],
) -> Result<(), UpdateStageError> {
    if maximum_bytes == 0 {
        return Err(UpdateStageError::ResourceLimit);
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(UpdateStageError::StageConflict);
            }
            validate_staged_private_metadata(destination, &metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if fs::symlink_metadata(destination).is_ok() {
        let existing = hash_regular_file(destination, maximum_bytes)?;
        return if existing == expected_digest {
            Ok(())
        } else {
            Err(UpdateStageError::StageConflict)
        };
    }
    let mut source = open_regular_nofollow(source)?;
    if source.metadata()?.len() > maximum_bytes {
        return Err(UpdateStageError::ResourceLimit);
    }
    let temporary = destination.with_file_name(format!(".artifact-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&temporary)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let copy_result = (|| -> Result<(), UpdateStageError> {
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(count).map_err(|_| UpdateStageError::ResourceLimit)?)
                .ok_or(UpdateStageError::ResourceLimit)?;
            if total > maximum_bytes {
                return Err(UpdateStageError::ResourceLimit);
            }
            hasher.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        output.sync_all()?;
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_digest {
            return Err(UpdateStageError::Verification(UpdateError::ArtifactDigest));
        }
        fs::rename(&temporary, destination)?;
        File::open(
            destination
                .parent()
                .ok_or(UpdateStageError::StageConflict)?,
        )?
        .sync_all()?;
        Ok(())
    })();
    if copy_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copy_result
}

fn validate_staged_private_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), UpdateStageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(UpdateStageError::SecureFile(SecureFileError::Permissions(
                path.display().to_string(),
            )));
        }
    }
    Ok(())
}

fn hash_regular_file(path: &Path, maximum_bytes: u64) -> Result<[u8; 32], UpdateStageError> {
    let mut file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > maximum_bytes {
        return Err(UpdateStageError::ResourceLimit);
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| UpdateStageError::ResourceLimit)?)
            .ok_or(UpdateStageError::ResourceLimit)?;
        if total > maximum_bytes {
            return Err(UpdateStageError::ResourceLimit);
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn read_bounded_regular(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, UpdateStageError> {
    let file = open_regular_nofollow(path)?;
    let length = file.metadata()?.len();
    if length > maximum_bytes {
        return Err(UpdateStageError::ResourceLimit);
    }
    let capacity = usize::try_from(length).map_err(|_| UpdateStageError::ResourceLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| UpdateStageError::ResourceLimit)? > maximum_bytes {
        return Err(UpdateStageError::ResourceLimit);
    }
    Ok(bytes)
}

fn open_regular_nofollow(path: &Path) -> Result<File, UpdateStageError> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(UpdateStageError::StageConflict);
    }
    Ok(file)
}

fn audit_rejection(
    request: &LocalUpdateStageRequest<'_>,
    subject_digest: [u8; 32],
    reason: &[u8],
) -> Result<(), UpdateStageError> {
    request.store.audit_update_rejection(
        request.staged_at_unix_ms,
        None,
        subject_digest,
        reason,
    )?;
    Ok(())
}

impl UpdateStageError {
    fn audit_code(&self) -> &'static [u8] {
        match self {
            Self::Verification(error) => update_error_code(error),
            Self::Store(error) => store_error_code(error),
            Self::SecureFile(_) => b"secure-file-invalid",
            Self::Io(_) => b"filesystem-error",
            Self::BundleJson(_) => b"bundle-json-invalid",
            Self::OwnerConfirmationRequired => b"owner-confirmation-required",
            Self::ResourceLimit => b"resource-limit",
            Self::StageConflict => b"stage-conflict",
        }
    }
}

fn update_error_code(error: &UpdateError) -> &'static [u8] {
    match error {
        UpdateError::Version => b"schema-version",
        UpdateError::PreviousVersion => b"previous-version",
        UpdateError::Counter => b"release-counter",
        UpdateError::Rollback => b"rollback-metadata",
        UpdateError::Target => b"target-mismatch",
        UpdateError::ArtifactDigest => b"artifact-digest",
        UpdateError::ReleaseSignature => b"release-signature",
        UpdateError::OwnerApproval => b"owner-approval",
        UpdateError::Encoding => b"encoding",
    }
}

fn store_error_code(error: &StoreError) -> &'static [u8] {
    match error {
        StoreError::UpdateCounterRollback => b"counter-rollback",
        StoreError::UpdateCounterCollision => b"counter-collision",
        StoreError::UpdateAuthorityMismatch => b"authority-mismatch",
        _ => b"store-error",
    }
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
    use tempfile::TempDir;

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

    #[test]
    fn update_roles_cannot_share_one_key() {
        let artifact = b"release artifact";
        let (bundle, release, _owner, policy) = fixture(artifact);
        assert!(matches!(
            verify_update(
                &bundle,
                artifact,
                &policy,
                &release.verifying_key(),
                &release.verifying_key(),
            ),
            Err(UpdateError::OwnerApproval)
        ));
    }

    #[test]
    fn local_stage_requires_confirmation_and_persists_audited_checkpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let data_dir = directory.path().join("node-state");
        let store_path = data_dir.join("state.sqlite3");
        let store = StateStore::open(&store_path)?;
        let artifact = b"signed release artifact";
        let artifact_path = directory.path().join("release.bin");
        fs::write(&artifact_path, artifact)?;
        let (bundle, release, owner, policy) = fixture(artifact);
        let release_key = release.verifying_key();
        let owner_key = owner.verifying_key();
        let bundle_path = directory.path().join("bundle.json");
        fs::write(&bundle_path, serde_json::to_vec(&bundle)?)?;
        let request = |confirmed| LocalUpdateStageRequest {
            bundle_json_path: &bundle_path,
            artifact_path: &artifact_path,
            data_dir: &data_dir,
            store: &store,
            policy: policy.clone(),
            release_key: &release_key,
            owner_key: &owner_key,
            max_artifact_bytes: 1_048_576,
            owner_confirmed: confirmed,
            staged_at_unix_ms: 2_000_000_000_000,
        };

        assert!(matches!(
            stage_local_update(&request(false)),
            Err(UpdateStageError::OwnerConfirmationRequired)
        ));
        assert!(store.latest_staged_update()?.is_none());
        let rejected_audit = store.verify_audit_chain()?.event_count;

        let result = stage_local_update(&request(true))?;
        assert!(!result.already_staged);
        assert!(!result.installation_performed);
        assert_eq!(fs::read(&result.staged_artifact_path)?, artifact);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&result.staged_artifact_path)?
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        assert_eq!(result.record.rollback_version, "0.1.0");
        assert_eq!(result.record.release_counter, 2);
        assert_eq!(store.latest_staged_update()?.as_ref(), Some(&result.record));
        assert_eq!(store.verify_audit_chain()?.event_count, rejected_audit + 1);
        drop(store);

        let reopened = StateStore::open(store_path)?;
        assert_eq!(reopened.latest_staged_update()?, Some(result.record));
        reopened.verify_audit_chain()?;
        Ok(())
    }

    #[test]
    fn forged_oversized_and_replayed_updates_fail_without_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let data_dir = directory.path().join("node-state");
        let store = StateStore::open(data_dir.join("state.sqlite3"))?;
        let artifact = b"bounded artifact";
        let artifact_path = directory.path().join("release.bin");
        fs::write(&artifact_path, artifact)?;
        let (mut bundle, release, owner, policy) = fixture(artifact);
        let release_key = release.verifying_key();
        let owner_key = owner.verifying_key();
        bundle.release_signature[0] ^= 1;
        let bundle_path = directory.path().join("bundle.json");
        fs::write(&bundle_path, serde_json::to_vec(&bundle)?)?;

        let stage = |maximum, policy: UpdatePolicy| LocalUpdateStageRequest {
            bundle_json_path: &bundle_path,
            artifact_path: &artifact_path,
            data_dir: &data_dir,
            store: &store,
            policy,
            release_key: &release_key,
            owner_key: &owner_key,
            max_artifact_bytes: maximum,
            owner_confirmed: true,
            staged_at_unix_ms: 2_000_000_000_000,
        };
        assert!(matches!(
            stage_local_update(&stage(1_048_576, policy.clone())),
            Err(UpdateStageError::Verification(
                UpdateError::ReleaseSignature
            ))
        ));
        assert!(store.latest_staged_update()?.is_none());

        let (mut owner_forged, _, _, _) = fixture(artifact);
        owner_forged.owner_approval_signature[0] ^= 1;
        fs::write(&bundle_path, serde_json::to_vec(&owner_forged)?)?;
        assert!(matches!(
            stage_local_update(&stage(1_048_576, policy.clone())),
            Err(UpdateStageError::Verification(UpdateError::OwnerApproval))
        ));
        assert!(store.latest_staged_update()?.is_none());

        let (valid, _, _, _) = fixture(artifact);
        fs::write(&bundle_path, serde_json::to_vec(&valid)?)?;
        let mut wrong_target = policy.clone();
        wrong_target.target_arch = "wrong-arch".to_owned();
        assert!(matches!(
            stage_local_update(&stage(1_048_576, wrong_target)),
            Err(UpdateStageError::Verification(UpdateError::Target))
        ));
        assert!(matches!(
            stage_local_update(&stage(1, policy.clone())),
            Err(UpdateStageError::ResourceLimit)
        ));
        assert!(store.latest_staged_update()?.is_none());

        let staged = stage_local_update(&stage(1_048_576, policy))?;
        let mut replay_policy = fixture(artifact).3;
        replay_policy.current_release_counter = staged.record.release_counter;
        assert!(matches!(
            stage_local_update(&stage(1_048_576, replay_policy)),
            Err(UpdateStageError::Verification(UpdateError::Counter))
        ));
        assert_eq!(
            store.latest_staged_update()?.map(|record| record.stage_id),
            Some(staged.record.stage_id)
        );
        store.verify_audit_chain()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn update_artifact_symlink_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        let data_dir = directory.path().join("node-state");
        let store = StateStore::open(data_dir.join("state.sqlite3"))?;
        let real_artifact = directory.path().join("real.bin");
        fs::write(&real_artifact, b"signed release artifact")?;
        let artifact_path = directory.path().join("artifact-link.bin");
        symlink(&real_artifact, &artifact_path)?;
        let (bundle, release, owner, policy) = fixture(b"signed release artifact");
        let release_key = release.verifying_key();
        let owner_key = owner.verifying_key();
        let bundle_path = directory.path().join("bundle.json");
        fs::write(&bundle_path, serde_json::to_vec(&bundle)?)?;
        let result = stage_local_update(&LocalUpdateStageRequest {
            bundle_json_path: &bundle_path,
            artifact_path: &artifact_path,
            data_dir: &data_dir,
            store: &store,
            policy,
            release_key: &release_key,
            owner_key: &owner_key,
            max_artifact_bytes: 1_048_576,
            owner_confirmed: true,
            staged_at_unix_ms: 2_000_000_000_000,
        });
        assert!(matches!(result, Err(UpdateStageError::Io(_))));
        assert!(store.latest_staged_update()?.is_none());
        Ok(())
    }
}
