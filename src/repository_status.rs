//! Privacy-minimized, signed local repository-status reporting.
//!
//! The node consumes an owner-produced logical snapshot. It never opens a repository, invokes
//! Git, reads diffs or files, contacts a remote, runs hooks, or mutates repository state.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::RepositorySnapshotConfig;
use crate::protocol::{RepositoryStatusV1, UnixMillis};
use crate::resources::read_bounded_regular_nofollow;

const REPOSITORY_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] =
    b"sovereign-node/local-repository-status-snapshot/v1\0";
const MAX_REPOSITORY_SNAPSHOT_BYTES: u64 = 64 * 1_024;
const MAX_REPOSITORY_ENTRIES: usize = 128;
const MAX_REPOSITORY_ID_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryStatusEntryV1 {
    pub repository_id: String,
    pub status: RepositoryStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryStatusSnapshotV1 {
    pub schema_version: u16,
    pub observed_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub repositories: Vec<RepositoryStatusEntryV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRepositoryStatusSnapshotV1 {
    /// Exact UTF-8 JSON bytes of `RepositoryStatusSnapshotV1`, encoded as hexadecimal.
    pub payload_hex: String,
    /// Ed25519 signature over `repository_status_snapshot_signing_bytes(payload)`.
    pub signature_hex: String,
}

#[must_use]
pub fn repository_status_snapshot_signing_bytes(payload_json: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(REPOSITORY_SNAPSHOT_SIGNATURE_DOMAIN.len() + payload_json.len());
    bytes.extend_from_slice(REPOSITORY_SNAPSHOT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(payload_json);
    bytes
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryStatusError {
    #[error("repository status snapshot is unavailable or unverifiable")]
    SnapshotUnavailable,
    #[error("logical repository target is not present in the signed snapshot")]
    TargetNotFound,
}

#[derive(Debug)]
pub struct RepositoryStatusReporter {
    adapter: Option<RepositoryStatusAdapter>,
}

#[derive(Debug)]
struct RepositoryStatusAdapter {
    snapshot_path: PathBuf,
    public_key: VerifyingKey,
    maximum_age_millis: u64,
}

impl RepositoryStatusReporter {
    #[must_use]
    pub fn new(config: Option<&RepositorySnapshotConfig>) -> Self {
        Self {
            adapter: config.and_then(RepositoryStatusAdapter::from_config),
        }
    }

    pub fn status(
        &self,
        now: UnixMillis,
        repository_id: &str,
        include_untracked_summary: bool,
    ) -> Result<RepositoryStatusV1, RepositoryStatusError> {
        let adapter = self
            .adapter
            .as_ref()
            .ok_or(RepositoryStatusError::SnapshotUnavailable)?;
        let snapshot = adapter
            .read_verified(now)
            .ok_or(RepositoryStatusError::SnapshotUnavailable)?;
        let mut status = snapshot
            .repositories
            .into_iter()
            .find(|repository| repository.repository_id == repository_id)
            .map(|repository| repository.status)
            .ok_or(RepositoryStatusError::TargetNotFound)?;
        if !include_untracked_summary {
            status.untracked_count = None;
        }
        Ok(status)
    }
}

impl RepositoryStatusAdapter {
    fn from_config(config: &RepositorySnapshotConfig) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(&config.public_key_hex).ok()?.try_into().ok()?;
        let public_key = VerifyingKey::from_bytes(&bytes).ok()?;
        if public_key.is_weak() {
            return None;
        }
        Some(Self {
            snapshot_path: config.snapshot_path.clone(),
            public_key,
            maximum_age_millis: config.max_age_secs.checked_mul(1_000)?,
        })
    }

    fn read_verified(&self, now: UnixMillis) -> Option<RepositoryStatusSnapshotV1> {
        let raw = read_bounded_regular_nofollow(&self.snapshot_path, MAX_REPOSITORY_SNAPSHOT_BYTES)
            .ok()?;
        let signed: SignedRepositoryStatusSnapshotV1 = serde_json::from_slice(&raw).ok()?;
        let payload = hex::decode(&signed.payload_hex).ok()?;
        if payload.len() > MAX_REPOSITORY_SNAPSHOT_BYTES as usize / 2 {
            return None;
        }
        let signature_bytes: [u8; 64] = hex::decode(&signed.signature_hex).ok()?.try_into().ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.public_key
            .verify_strict(
                &repository_status_snapshot_signing_bytes(&payload),
                &signature,
            )
            .ok()?;
        let snapshot: RepositoryStatusSnapshotV1 = serde_json::from_slice(&payload).ok()?;
        snapshot_valid(&snapshot, now, self.maximum_age_millis).then_some(snapshot)
    }
}

fn snapshot_valid(
    snapshot: &RepositoryStatusSnapshotV1,
    now: UnixMillis,
    maximum_age_millis: u64,
) -> bool {
    if snapshot.schema_version != 1
        || snapshot.observed_at_unix_ms > now.0
        || snapshot.valid_until_unix_ms <= now.0
        || snapshot.valid_until_unix_ms < snapshot.observed_at_unix_ms
        || snapshot
            .valid_until_unix_ms
            .saturating_sub(snapshot.observed_at_unix_ms)
            > maximum_age_millis
        || now.0.saturating_sub(snapshot.observed_at_unix_ms) > maximum_age_millis
        || snapshot.repositories.is_empty()
        || snapshot.repositories.len() > MAX_REPOSITORY_ENTRIES
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    snapshot.repositories.iter().all(|repository| {
        valid_identifier(&repository.repository_id)
            && identifiers.insert(repository.repository_id.as_str())
            && repository.status.validate().is_ok()
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    use super::*;

    const NOW: u64 = 2_000_000_000_000;

    fn snapshot() -> RepositoryStatusSnapshotV1 {
        RepositoryStatusSnapshotV1 {
            schema_version: 1,
            observed_at_unix_ms: NOW - 1_000,
            valid_until_unix_ms: NOW + 10_000,
            repositories: vec![RepositoryStatusEntryV1 {
                repository_id: "primary".to_owned(),
                status: RepositoryStatusV1 {
                    head: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
                    branch: Some("main".to_owned()),
                    clean: false,
                    ahead: 1,
                    behind: 0,
                    untracked_count: Some(2),
                },
            }],
        }
    }

    fn write_snapshot(
        directory: &TempDir,
        name: &str,
        signing_key: &SigningKey,
        snapshot: &RepositoryStatusSnapshotV1,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(snapshot)?;
        let signature = signing_key.sign(&repository_status_snapshot_signing_bytes(&payload));
        let signed = SignedRepositoryStatusSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let path = directory.path().join(name);
        fs::write(&path, serde_json::to_vec(&signed)?)?;
        Ok(path)
    }

    fn config(path: PathBuf, key: &SigningKey) -> RepositorySnapshotConfig {
        RepositorySnapshotConfig {
            snapshot_path: path,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            max_age_secs: 30,
        }
    }

    #[test]
    fn fresh_snapshot_returns_only_bounded_status_and_honors_untracked_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let path = write_snapshot(&directory, "repositories.json", &key, &snapshot())?;
        let reporter = RepositoryStatusReporter::new(Some(&config(path, &key)));
        let minimized = reporter.status(UnixMillis(NOW), "primary", false)?;
        assert_eq!(minimized.branch.as_deref(), Some("main"));
        assert_eq!(minimized.untracked_count, None);
        let expanded = reporter.status(UnixMillis(NOW), "primary", true)?;
        assert_eq!(expanded.untracked_count, Some(2));
        let encoded = serde_json::to_string(&expanded)?;
        for forbidden in [
            "repository_id",
            "path",
            "remote",
            "url",
            "diff",
            "credential",
            "file",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn forged_stale_duplicate_and_unknown_repositories_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let trusted = SigningKey::from_bytes(&[0x52; 32]);
        let attacker = SigningKey::from_bytes(&[0x53; 32]);
        let forged_path = write_snapshot(&directory, "forged.json", &attacker, &snapshot())?;
        let forged = RepositoryStatusReporter::new(Some(&config(forged_path, &trusted)));
        assert_eq!(
            forged.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );

        let mut stale = snapshot();
        stale.observed_at_unix_ms = NOW - 31_000;
        stale.valid_until_unix_ms = NOW + 1;
        let stale_path = write_snapshot(&directory, "stale.json", &trusted, &stale)?;
        let stale = RepositoryStatusReporter::new(Some(&config(stale_path, &trusted)));
        assert_eq!(
            stale.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );

        let mut duplicate = snapshot();
        duplicate
            .repositories
            .push(duplicate.repositories[0].clone());
        let duplicate_path = write_snapshot(&directory, "duplicate.json", &trusted, &duplicate)?;
        let duplicate = RepositoryStatusReporter::new(Some(&config(duplicate_path, &trusted)));
        assert_eq!(
            duplicate.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );

        let valid_path = write_snapshot(&directory, "valid.json", &trusted, &snapshot())?;
        let valid = RepositoryStatusReporter::new(Some(&config(valid_path, &trusted)));
        assert_eq!(
            valid.status(UnixMillis(NOW), "unknown", false),
            Err(RepositoryStatusError::TargetNotFound)
        );
        Ok(())
    }

    #[test]
    fn oversized_extended_or_inconsistent_snapshot_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let oversized_path = directory.path().join("oversized.json");
        fs::write(
            &oversized_path,
            vec![b'x'; usize::try_from(MAX_REPOSITORY_SNAPSHOT_BYTES)? + 1],
        )?;
        let oversized = RepositoryStatusReporter::new(Some(&config(oversized_path, &key)));
        assert_eq!(
            oversized.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );

        let mut inconsistent = snapshot();
        inconsistent.repositories[0].status.clean = true;
        let inconsistent_path =
            write_snapshot(&directory, "inconsistent.json", &key, &inconsistent)?;
        let inconsistent = RepositoryStatusReporter::new(Some(&config(inconsistent_path, &key)));
        assert_eq!(
            inconsistent.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );

        let mut extended = serde_json::to_value(snapshot())?;
        let repositories = extended
            .get_mut("repositories")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| std::io::Error::other("repository test payload is malformed"))?;
        let first = repositories
            .first_mut()
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| std::io::Error::other("repository test entry is malformed"))?;
        first.insert(
            "repository_path".to_owned(),
            serde_json::json!("/private/repo"),
        );
        let payload = serde_json::to_vec(&extended)?;
        let signature = key.sign(&repository_status_snapshot_signing_bytes(&payload));
        let signed = SignedRepositoryStatusSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let extended_path = directory.path().join("extended.json");
        fs::write(&extended_path, serde_json::to_vec(&signed)?)?;
        let extended = RepositoryStatusReporter::new(Some(&config(extended_path, &key)));
        assert_eq!(
            extended.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x54; 32]);
        let target = write_snapshot(&directory, "target.json", &key, &snapshot())?;
        let link = directory.path().join("link.json");
        symlink(target, &link)?;
        let reporter = RepositoryStatusReporter::new(Some(&config(link, &key)));
        assert_eq!(
            reporter.status(UnixMillis(NOW), "primary", false),
            Err(RepositoryStatusError::SnapshotUnavailable)
        );
        Ok(())
    }
}
