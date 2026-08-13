//! Privacy-minimized, signed local service-status reporting.
//!
//! The adapter accepts only owner-defined logical identifiers. Service-manager commands,
//! unit files, environments, credentials, process identifiers, and control operations are
//! deliberately absent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::ServiceSnapshotConfig;
use crate::protocol::{EntityStatusV1, UnixMillis};
use crate::resources::read_bounded_regular_nofollow;

const SERVICE_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] =
    b"sovereign-node/local-service-status-snapshot/v1\0";
const MAX_SERVICE_SNAPSHOT_BYTES: u64 = 64 * 1_024;
const MAX_SERVICE_ENTRIES: usize = 128;
const MAX_SERVICE_ID_BYTES: usize = 64;
const MAX_DETAIL_CODE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceStateV1 {
    Running,
    Starting,
    Stopping,
    Stopped,
    Degraded,
    Failed,
    Unknown,
}

impl ServiceStateV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Starting => "starting",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusEntryV1 {
    pub service_id: String,
    pub state: ServiceStateV1,
    pub detail_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusSnapshotV1 {
    pub schema_version: u16,
    pub observed_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub services: Vec<ServiceStatusEntryV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceStatusSnapshotV1 {
    /// Exact UTF-8 JSON bytes of `ServiceStatusSnapshotV1`, encoded as hexadecimal.
    pub payload_hex: String,
    /// Ed25519 signature over `service_status_snapshot_signing_bytes(payload)`, as hexadecimal.
    pub signature_hex: String,
}

#[must_use]
pub fn service_status_snapshot_signing_bytes(payload_json: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(SERVICE_SNAPSHOT_SIGNATURE_DOMAIN.len() + payload_json.len());
    bytes.extend_from_slice(SERVICE_SNAPSHOT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(payload_json);
    bytes
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceStatusError {
    #[error("service status snapshot is unavailable or unverifiable")]
    SnapshotUnavailable,
    #[error("logical service target is not present in the signed snapshot")]
    TargetNotFound,
}

#[derive(Debug)]
pub struct ServiceStatusReporter {
    adapter: Option<ServiceStatusAdapter>,
}

#[derive(Debug)]
struct ServiceStatusAdapter {
    snapshot_path: PathBuf,
    public_key: VerifyingKey,
    maximum_age_millis: u64,
}

impl ServiceStatusReporter {
    #[must_use]
    pub fn new(config: Option<&ServiceSnapshotConfig>) -> Self {
        Self {
            adapter: config.and_then(ServiceStatusAdapter::from_config),
        }
    }

    pub fn status(
        &self,
        now: UnixMillis,
        service_id: &str,
    ) -> Result<EntityStatusV1, ServiceStatusError> {
        let adapter = self
            .adapter
            .as_ref()
            .ok_or(ServiceStatusError::SnapshotUnavailable)?;
        let snapshot = adapter
            .read_verified(now)
            .ok_or(ServiceStatusError::SnapshotUnavailable)?;
        let service = snapshot
            .services
            .into_iter()
            .find(|service| service.service_id == service_id)
            .ok_or(ServiceStatusError::TargetNotFound)?;
        let mut attributes = BTreeMap::new();
        attributes.insert("logical_service_id".to_owned(), service.service_id);
        attributes.insert(
            "observed_at_unix_ms".to_owned(),
            snapshot.observed_at_unix_ms.to_string(),
        );
        Ok(EntityStatusV1 {
            state: service.state.as_str().to_owned(),
            detail: service
                .detail_code
                .map(|code| format!("authenticated-local-snapshot:{code}")),
            attributes,
        })
    }
}

impl ServiceStatusAdapter {
    fn from_config(config: &ServiceSnapshotConfig) -> Option<Self> {
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

    fn read_verified(&self, now: UnixMillis) -> Option<ServiceStatusSnapshotV1> {
        let raw =
            read_bounded_regular_nofollow(&self.snapshot_path, MAX_SERVICE_SNAPSHOT_BYTES).ok()?;
        let signed: SignedServiceStatusSnapshotV1 = serde_json::from_slice(&raw).ok()?;
        let payload = hex::decode(&signed.payload_hex).ok()?;
        if payload.len() > MAX_SERVICE_SNAPSHOT_BYTES as usize / 2 {
            return None;
        }
        let signature_bytes: [u8; 64] = hex::decode(&signed.signature_hex).ok()?.try_into().ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.public_key
            .verify_strict(&service_status_snapshot_signing_bytes(&payload), &signature)
            .ok()?;
        let snapshot: ServiceStatusSnapshotV1 = serde_json::from_slice(&payload).ok()?;
        snapshot_valid(&snapshot, now, self.maximum_age_millis).then_some(snapshot)
    }
}

fn snapshot_valid(
    snapshot: &ServiceStatusSnapshotV1,
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
        || snapshot.services.is_empty()
        || snapshot.services.len() > MAX_SERVICE_ENTRIES
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    snapshot.services.iter().all(|service| {
        valid_identifier(&service.service_id)
            && identifiers.insert(service.service_id.as_str())
            && valid_detail_code(service.detail_code.as_deref())
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SERVICE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_detail_code(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_DETAIL_CODE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    use super::*;

    const NOW: u64 = 2_000_000_000_000;

    fn snapshot() -> ServiceStatusSnapshotV1 {
        ServiceStatusSnapshotV1 {
            schema_version: 1,
            observed_at_unix_ms: NOW - 1_000,
            valid_until_unix_ms: NOW + 10_000,
            services: vec![ServiceStatusEntryV1 {
                service_id: "model-engine.service".to_owned(),
                state: ServiceStateV1::Running,
                detail_code: Some("ready".to_owned()),
            }],
        }
    }

    fn write_snapshot(
        directory: &TempDir,
        name: &str,
        signing_key: &SigningKey,
        snapshot: &ServiceStatusSnapshotV1,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(snapshot)?;
        let signature = signing_key.sign(&service_status_snapshot_signing_bytes(&payload));
        let signed = SignedServiceStatusSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let path = directory.path().join(name);
        fs::write(&path, serde_json::to_vec(&signed)?)?;
        Ok(path)
    }

    fn config(path: PathBuf, key: &SigningKey) -> ServiceSnapshotConfig {
        ServiceSnapshotConfig {
            snapshot_path: path,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            max_age_secs: 30,
        }
    }

    #[test]
    fn fresh_signed_snapshot_returns_only_logical_bounded_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let path = write_snapshot(&directory, "services.json", &key, &snapshot())?;
        let reporter = ServiceStatusReporter::new(Some(&config(path, &key)));
        let status = reporter.status(UnixMillis(NOW), "model-engine.service")?;
        assert_eq!(status.state, "running");
        assert_eq!(
            status.detail.as_deref(),
            Some("authenticated-local-snapshot:ready")
        );
        assert_eq!(
            status
                .attributes
                .get("logical_service_id")
                .map(String::as_str),
            Some("model-engine.service")
        );
        assert_eq!(status.attributes.len(), 2);
        let encoded = serde_json::to_string(&status)?;
        for forbidden in ["unit_path", "environment", "credential", "pid", "command"] {
            assert!(!encoded.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn forged_stale_duplicate_and_unknown_services_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let trusted = SigningKey::from_bytes(&[0x42; 32]);
        let attacker = SigningKey::from_bytes(&[0x43; 32]);
        let forged_path = write_snapshot(&directory, "forged.json", &attacker, &snapshot())?;
        let forged = ServiceStatusReporter::new(Some(&config(forged_path, &trusted)));
        assert_eq!(
            forged.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );

        let mut stale = snapshot();
        stale.observed_at_unix_ms = NOW - 31_000;
        stale.valid_until_unix_ms = NOW + 1;
        let stale_path = write_snapshot(&directory, "stale.json", &trusted, &stale)?;
        let stale = ServiceStatusReporter::new(Some(&config(stale_path, &trusted)));
        assert_eq!(
            stale.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );

        let mut duplicate = snapshot();
        duplicate.services.push(duplicate.services[0].clone());
        let duplicate_path = write_snapshot(&directory, "duplicate.json", &trusted, &duplicate)?;
        let duplicate = ServiceStatusReporter::new(Some(&config(duplicate_path, &trusted)));
        assert_eq!(
            duplicate.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );

        let valid_path = write_snapshot(&directory, "valid.json", &trusted, &snapshot())?;
        let valid = ServiceStatusReporter::new(Some(&config(valid_path, &trusted)));
        assert_eq!(
            valid.status(UnixMillis(NOW), "unknown.service"),
            Err(ServiceStatusError::TargetNotFound)
        );
        Ok(())
    }

    #[test]
    fn oversized_or_schema_extended_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x45; 32]);
        let oversized_path = directory.path().join("oversized.json");
        fs::write(
            &oversized_path,
            vec![b'x'; usize::try_from(MAX_SERVICE_SNAPSHOT_BYTES)? + 1],
        )?;
        let oversized = ServiceStatusReporter::new(Some(&config(oversized_path, &key)));
        assert_eq!(
            oversized.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );

        let mut extended = serde_json::to_value(snapshot())?;
        let services = extended
            .get_mut("services")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| std::io::Error::other("service test payload is malformed"))?;
        let first = services
            .first_mut()
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| std::io::Error::other("service test entry is malformed"))?;
        first.insert(
            "unit_path".to_owned(),
            serde_json::json!("/etc/private.service"),
        );
        let payload = serde_json::to_vec(&extended)?;
        let signature = key.sign(&service_status_snapshot_signing_bytes(&payload));
        let signed = SignedServiceStatusSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let extended_path = directory.path().join("extended.json");
        fs::write(&extended_path, serde_json::to_vec(&signed)?)?;
        let extended = ServiceStatusReporter::new(Some(&config(extended_path, &key)));
        assert_eq!(
            extended.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let target = write_snapshot(&directory, "target.json", &key, &snapshot())?;
        let link = directory.path().join("link.json");
        symlink(target, &link)?;
        let reporter = ServiceStatusReporter::new(Some(&config(link, &key)));
        assert_eq!(
            reporter.status(UnixMillis(NOW), "model-engine.service"),
            Err(ServiceStatusError::SnapshotUnavailable)
        );
        Ok(())
    }
}
