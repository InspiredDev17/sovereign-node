use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protocol::Capability;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_CONCURRENT_ACTIONS: usize = 4;
pub const DEFAULT_QUEUE_CAPACITY: usize = 32;
pub const DEFAULT_MAX_ACTION_TTL_SECS: i64 = 300;
pub const DEFAULT_MAX_CLOCK_ROLLBACK_SECS: u64 = 5;
pub const DEFAULT_MAX_REQUESTS_PER_PEER_PER_MINUTE: u32 = 120;
pub const DEFAULT_MAX_REQUESTS_GLOBAL_PER_MINUTE: u32 = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    /// Owner-controlled monotonic revision. Increment for every policy/target mapping change.
    pub policy_version: u64,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub file_roots: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub approved_actions: BTreeMap<String, ApprovedActionConfig>,
    #[serde(default)]
    pub health: HealthConfig,
    /// Optional signed local accelerator/model measurements. Absence remains Unknown.
    #[serde(default)]
    pub resource_reporting: ResourceReportingConfig,
    /// Optional pinned offline-update authorities. Absence disables staging.
    #[serde(default)]
    pub updates: Option<UpdateConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub enabled_capabilities: Vec<Capability>,
    pub max_frame_bytes: usize,
    pub max_concurrent_actions: usize,
    pub queue_capacity: usize,
    /// Durable fixed-window admission limit applied to each authenticated peer before authz.
    pub max_requests_per_peer_per_minute: u32,
    /// Durable fixed-window limit shared by all authenticated peers before authz.
    pub max_requests_global_per_minute: u32,
    pub max_action_ttl_secs: i64,
    /// Maximum tolerated backwards wall-clock movement before remote work fails closed.
    pub max_clock_rollback_secs: u64,
    pub require_owner_signature_for_all_actions: bool,
    pub max_file_read_bytes: usize,
    pub max_file_write_bytes: usize,
    pub max_action_output_bytes: usize,
    pub max_action_runtime_secs: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled_capabilities: vec![Capability::SystemInfo, Capability::ResourceStatus],
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_concurrent_actions: DEFAULT_MAX_CONCURRENT_ACTIONS,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            max_requests_per_peer_per_minute: DEFAULT_MAX_REQUESTS_PER_PEER_PER_MINUTE,
            max_requests_global_per_minute: DEFAULT_MAX_REQUESTS_GLOBAL_PER_MINUTE,
            max_action_ttl_secs: DEFAULT_MAX_ACTION_TTL_SECS,
            max_clock_rollback_secs: DEFAULT_MAX_CLOCK_ROLLBACK_SECS,
            require_owner_signature_for_all_actions: true,
            max_file_read_bytes: 524_288,
            max_file_write_bytes: 524_288,
            max_action_output_bytes: 262_144,
            max_action_runtime_secs: 30,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedActionConfig {
    pub executable: PathBuf,
    #[serde(default)]
    pub fixed_arguments: Vec<String>,
    pub working_directory: PathBuf,
    #[serde(default)]
    pub executable_sha256: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    /// Optional signed, sanitized Agent Green health snapshot. Never treated as attestation.
    pub agent_green: Option<HealthSnapshotConfig>,
    /// Optional signed, sanitized Action Broker health snapshot. Network polling is never implicit.
    pub action_broker: Option<HealthSnapshotConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSnapshotConfig {
    pub snapshot_path: PathBuf,
    /// Pinned Ed25519 public key for this health producer, encoded as 64 hex characters.
    pub public_key_hex: String,
    /// Maximum producer-declared validity window and observation age.
    pub max_age_secs: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceReportingConfig {
    pub snapshot: Option<ResourceSnapshotConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSnapshotConfig {
    pub snapshot_path: PathBuf,
    /// Pinned Ed25519 public key for the local measurement producer.
    pub public_key_hex: String,
    /// Maximum producer-declared validity window and observation age.
    pub max_age_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// Pinned Ed25519 release-role public key, encoded as 64 hexadecimal characters.
    pub release_public_key_hex: String,
    /// Separate pinned Ed25519 key used for exact owner approval of a manifest.
    pub owner_approval_public_key_hex: String,
    #[serde(default = "default_max_update_artifact_bytes")]
    pub max_artifact_bytes: u64,
}

const fn default_max_update_artifact_bytes() -> u64 {
    1_073_741_824
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("configuration is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl NodeConfig {
    pub fn policy_digest(&self) -> Result<[u8; 32], ConfigError> {
        let encoded = postcard::to_allocvec(self)
            .map_err(|_| ConfigError::Invalid("configuration cannot be encoded".to_owned()))?;
        Ok(Sha256::digest(encoded).into())
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        require_absolute("data_dir", &self.data_dir)?;
        if self.policy_version == 0 {
            return Err(ConfigError::Invalid(
                "policy_version must be non-zero and incremented for each policy change".to_owned(),
            ));
        }

        match (self.listen, &self.tls) {
            (Some(address), Some(tls)) => {
                if !is_private_or_loopback(address.ip()) {
                    return Err(ConfigError::Invalid(format!(
                        "listen address {address} is not loopback, link-local, or private LAN"
                    )));
                }
                if address.port() == 0 {
                    return Err(ConfigError::Invalid(
                        "listen port must be explicitly assigned".to_owned(),
                    ));
                }
                require_absolute("tls.certificate_pem", &tls.certificate_pem)?;
                require_absolute("tls.private_key_pem", &tls.private_key_pem)?;
            }
            (Some(_), None) => {
                return Err(ConfigError::Invalid(
                    "a TLS configuration is mandatory when the LAN listener is enabled".to_owned(),
                ));
            }
            (None, Some(_) | None) => {}
        }

        let policy = &self.policy;
        for capability in &policy.enabled_capabilities {
            match capability {
                Capability::SystemInfo | Capability::ResourceStatus => {}
                Capability::GpuStatus | Capability::EngineStatus | Capability::ModelStatus
                    if self.resource_reporting.snapshot.is_some() => {}
                Capability::AgentGreenHealth if self.health.agent_green.is_some() => {}
                Capability::ActionBrokerHealth if self.health.action_broker.is_some() => {}
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "capability {capability:?} is unavailable without its hardened local adapter"
                    )));
                }
            }
        }
        if policy.max_frame_bytes == 0 || policy.max_frame_bytes > 16 * 1_048_576 {
            return Err(ConfigError::Invalid(
                "max_frame_bytes must be between 1 and 16777216".to_owned(),
            ));
        }
        if policy.max_concurrent_actions == 0 || policy.max_concurrent_actions > 256 {
            return Err(ConfigError::Invalid(
                "max_concurrent_actions must be between 1 and 256".to_owned(),
            ));
        }
        if policy.queue_capacity < policy.max_concurrent_actions || policy.queue_capacity > 4096 {
            return Err(ConfigError::Invalid(
                "queue_capacity must cover concurrency and be at most 4096".to_owned(),
            ));
        }
        if policy.max_requests_per_peer_per_minute == 0
            || policy.max_requests_per_peer_per_minute > 60_000
        {
            return Err(ConfigError::Invalid(
                "max_requests_per_peer_per_minute must be between 1 and 60000".to_owned(),
            ));
        }
        if policy.max_requests_global_per_minute < policy.max_requests_per_peer_per_minute
            || policy.max_requests_global_per_minute > 1_000_000
        {
            return Err(ConfigError::Invalid(
                "max_requests_global_per_minute must cover the per-peer limit and be at most 1000000"
                    .to_owned(),
            ));
        }
        if policy.max_action_ttl_secs <= 0 || policy.max_action_ttl_secs > 3600 {
            return Err(ConfigError::Invalid(
                "max_action_ttl_secs must be between 1 and 3600".to_owned(),
            ));
        }
        if policy.max_clock_rollback_secs > 60 {
            return Err(ConfigError::Invalid(
                "max_clock_rollback_secs must be between 0 and 60".to_owned(),
            ));
        }
        if !policy.require_owner_signature_for_all_actions {
            return Err(ConfigError::Invalid(
                "v1 requires an exact owner signature for every remote action".to_owned(),
            ));
        }
        let agent_green_health_key = self
            .health
            .agent_green
            .as_ref()
            .map(|adapter| validate_health_adapter("health.agent_green", adapter))
            .transpose()?;
        let action_broker_health_key = self
            .health
            .action_broker
            .as_ref()
            .map(|adapter| validate_health_adapter("health.action_broker", adapter))
            .transpose()?;
        let resource_snapshot_key = self
            .resource_reporting
            .snapshot
            .as_ref()
            .map(|adapter| validate_resource_adapter("resource_reporting.snapshot", adapter))
            .transpose()?;
        if agent_green_health_key.is_some() && agent_green_health_key == action_broker_health_key {
            return Err(ConfigError::Invalid(
                "Agent Green and Action Broker health keys must be role-separated".to_owned(),
            ));
        }
        if let (Some(agent_green), Some(action_broker)) =
            (&self.health.agent_green, &self.health.action_broker)
            && agent_green.snapshot_path == action_broker.snapshot_path
        {
            return Err(ConfigError::Invalid(
                "Agent Green and Action Broker health snapshots must use separate paths".to_owned(),
            ));
        }
        if resource_snapshot_key.is_some()
            && (resource_snapshot_key == agent_green_health_key
                || resource_snapshot_key == action_broker_health_key)
        {
            return Err(ConfigError::Invalid(
                "resource, Agent Green, and Action Broker snapshot keys must be role-separated"
                    .to_owned(),
            ));
        }
        if let Some(resource) = &self.resource_reporting.snapshot
            && [
                self.health.agent_green.as_ref(),
                self.health.action_broker.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|health| health.snapshot_path == resource.snapshot_path)
        {
            return Err(ConfigError::Invalid(
                "resource and health snapshots must use separate paths".to_owned(),
            ));
        }
        if let Some(updates) = &self.updates {
            if updates.max_artifact_bytes == 0 || updates.max_artifact_bytes > 17_179_869_184 {
                return Err(ConfigError::Invalid(
                    "updates.max_artifact_bytes must be between 1 and 17179869184".to_owned(),
                ));
            }
            let release_key = parse_update_key(
                "updates.release_public_key_hex",
                &updates.release_public_key_hex,
            )?;
            let owner_key = parse_update_key(
                "updates.owner_approval_public_key_hex",
                &updates.owner_approval_public_key_hex,
            )?;
            if release_key == owner_key {
                return Err(ConfigError::Invalid(
                    "update release and owner-approval keys must be role-separated".to_owned(),
                ));
            }
            if [
                agent_green_health_key.as_ref(),
                action_broker_health_key.as_ref(),
                resource_snapshot_key.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|snapshot_key| snapshot_key == &release_key || snapshot_key == &owner_key)
            {
                return Err(ConfigError::Invalid(
                    "snapshot and update authority keys must be role-separated".to_owned(),
                ));
            }
        }
        if policy.max_action_runtime_secs == 0 || policy.max_action_runtime_secs > 3600 {
            return Err(ConfigError::Invalid(
                "max_action_runtime_secs must be between 1 and 3600".to_owned(),
            ));
        }
        if policy.max_file_read_bytes == 0
            || policy.max_file_read_bytes > crate::protocol::MAX_FILE_READ_BYTES as usize
            || policy.max_file_read_bytes >= policy.max_frame_bytes
        {
            return Err(ConfigError::Invalid(
                "max_file_read_bytes must be non-zero and fit both protocol and frame limits"
                    .to_owned(),
            ));
        }
        if policy.max_file_write_bytes == 0
            || policy.max_file_write_bytes > crate::protocol::MAX_FILE_WRITE_BYTES
            || policy.max_file_write_bytes >= policy.max_frame_bytes
        {
            return Err(ConfigError::Invalid(
                "max_file_write_bytes must be non-zero and fit both protocol and frame limits"
                    .to_owned(),
            ));
        }
        if policy.max_action_output_bytes == 0
            || policy.max_action_output_bytes > crate::protocol::MAX_ACTION_OUTPUT_BYTES
            || policy.max_action_output_bytes >= policy.max_frame_bytes
        {
            return Err(ConfigError::Invalid(
                "max_action_output_bytes must be non-zero and fit both protocol and frame limits"
                    .to_owned(),
            ));
        }

        for (root_id, root) in &self.file_roots {
            validate_identifier("file root", root_id)?;
            require_absolute("file root", root)?;
            reject_symlink_path("file root", root)?;
            let canonical_root = root.canonicalize().map_err(|error| {
                ConfigError::Invalid(format!("file root {root_id} cannot be resolved: {error}"))
            })?;
            let canonical_data_dir = self.data_dir.canonicalize().map_err(|error| {
                ConfigError::Invalid(format!("data_dir cannot be resolved: {error}"))
            })?;
            if canonical_root.starts_with(&canonical_data_dir)
                || canonical_data_dir.starts_with(&canonical_root)
            {
                return Err(ConfigError::Invalid(format!(
                    "file root {root_id} must not contain or be contained by the node data directory"
                )));
            }
            if let Some(tls) = &self.tls
                && (path_contains_or_is_contained(root, &tls.private_key_pem)?
                    || path_contains_or_is_contained(root, &tls.certificate_pem)?)
            {
                return Err(ConfigError::Invalid(format!(
                    "file root {root_id} overlaps TLS credential material"
                )));
            }
            if let Some(agent_green) = &self.health.agent_green
                && agent_green.snapshot_path.exists()
                && path_contains_or_is_contained(root, &agent_green.snapshot_path)?
            {
                return Err(ConfigError::Invalid(format!(
                    "file root {root_id} overlaps Agent Green health material"
                )));
            }
            if let Some(action_broker) = &self.health.action_broker
                && action_broker.snapshot_path.exists()
                && path_contains_or_is_contained(root, &action_broker.snapshot_path)?
            {
                return Err(ConfigError::Invalid(format!(
                    "file root {root_id} overlaps Action Broker health material"
                )));
            }
            if let Some(resource) = &self.resource_reporting.snapshot
                && resource.snapshot_path.exists()
                && path_contains_or_is_contained(root, &resource.snapshot_path)?
            {
                return Err(ConfigError::Invalid(format!(
                    "file root {root_id} overlaps resource snapshot material"
                )));
            }
        }

        for (action_id, action) in &self.approved_actions {
            validate_identifier("approved action", action_id)?;
            require_absolute("approved action executable", &action.executable)?;
            require_absolute(
                "approved action working directory",
                &action.working_directory,
            )?;
            reject_symlink_path("approved action executable", &action.executable)?;
            reject_symlink_path(
                "approved action working directory",
                &action.working_directory,
            )?;
            if action.executable.starts_with(&self.data_dir)
                || action.working_directory.starts_with(&self.data_dir)
            {
                return Err(ConfigError::Invalid(format!(
                    "approved action {action_id} must not execute from the node data directory"
                )));
            }
            if action.executable_sha256.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "approved action {action_id} requires an executable SHA-256 digest"
                )));
            }
            for (root_id, root) in &self.file_roots {
                if path_contains_or_is_contained(root, &action.executable)? {
                    return Err(ConfigError::Invalid(format!(
                        "file root {root_id} overlaps approved action {action_id} executable"
                    )));
                }
            }
            if let Some(digest) = &action.executable_sha256
                && (digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(ConfigError::Invalid(format!(
                    "approved action {action_id} has an invalid SHA-256 digest"
                )));
            }
            if let Some(timeout) = action.timeout_secs
                && (timeout == 0 || timeout > policy.max_action_runtime_secs)
            {
                return Err(ConfigError::Invalid(format!(
                    "approved action {action_id} timeout exceeds the policy limit"
                )));
            }
        }

        Ok(())
    }
}

fn parse_update_key(name: &str, value: &str) -> Result<VerifyingKey, ConfigError> {
    parse_ed25519_key(name, value)
}

fn parse_ed25519_key(name: &str, value: &str) -> Result<VerifyingKey, ConfigError> {
    let bytes = hex::decode(value)
        .map_err(|_| ConfigError::Invalid(format!("{name} must be hexadecimal")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::Invalid(format!("{name} must contain exactly 32 bytes")))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ConfigError::Invalid(format!("{name} is not a valid Ed25519 key")))?;
    if key.is_weak() {
        return Err(ConfigError::Invalid(format!(
            "{name} is a weak Ed25519 key"
        )));
    }
    Ok(key)
}

fn validate_health_adapter(
    name: &str,
    adapter: &HealthSnapshotConfig,
) -> Result<VerifyingKey, ConfigError> {
    require_absolute(&format!("{name}.snapshot_path"), &adapter.snapshot_path)?;
    if adapter.max_age_secs == 0 || adapter.max_age_secs > 86_400 {
        return Err(ConfigError::Invalid(format!(
            "{name}.max_age_secs must be between 1 and 86400"
        )));
    }
    let key = parse_ed25519_key(&format!("{name}.public_key_hex"), &adapter.public_key_hex)?;
    Ok(key)
}

fn validate_resource_adapter(
    name: &str,
    adapter: &ResourceSnapshotConfig,
) -> Result<VerifyingKey, ConfigError> {
    require_absolute(&format!("{name}.snapshot_path"), &adapter.snapshot_path)?;
    if adapter.max_age_secs == 0 || adapter.max_age_secs > 86_400 {
        return Err(ConfigError::Invalid(format!(
            "{name}.max_age_secs must be between 1 and 86400"
        )));
    }
    parse_ed25519_key(&format!("{name}.public_key_hex"), &adapter.public_key_hex)
}

fn require_absolute(name: &str, value: &Path) -> Result<(), ConfigError> {
    if value.is_absolute() {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "{name} must be an absolute path"
        )))
    }
}

fn reject_symlink_path(name: &str, path: &Path) -> Result<(), ConfigError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            ConfigError::Invalid(format!(
                "{name} {} cannot be inspected: {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigError::Invalid(format!(
                "{name} {} contains a symbolic link",
                path.display()
            )));
        }
    }
    Ok(())
}

fn path_contains_or_is_contained(left: &Path, right: &Path) -> Result<bool, ConfigError> {
    let left = left.canonicalize().map_err(|error| {
        ConfigError::Invalid(format!(
            "path {} cannot be resolved: {error}",
            left.display()
        ))
    })?;
    let right = right.canonicalize().map_err(|error| {
        ConfigError::Invalid(format!(
            "path {} cannot be resolved: {error}",
            right.display()
        ))
    })?;
    Ok(left.starts_with(&right) || right.starts_with(&left))
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), ConfigError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "invalid {kind} identifier {value:?}"
        )))
    }
}

pub fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || is_ipv6_unique_local(ip)
        }
    }
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ed25519_dalek::SigningKey;

    use super::*;

    fn minimal_config() -> NodeConfig {
        NodeConfig {
            data_dir: PathBuf::from("/var/lib/sovereign-node"),
            policy_version: 1,
            listen: None,
            tls: None,
            policy: PolicyConfig::default(),
            file_roots: BTreeMap::new(),
            approved_actions: BTreeMap::new(),
            health: HealthConfig::default(),
            resource_reporting: ResourceReportingConfig::default(),
            updates: None,
        }
    }

    #[test]
    fn public_listener_is_rejected() {
        let mut config = minimal_config();
        config.listen = Some(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 7443));
        config.tls = Some(TlsConfig {
            certificate_pem: PathBuf::from("/tmp/cert.pem"),
            private_key_pem: PathBuf::from("/tmp/key.pem"),
        });
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn exact_private_listener_with_tls_is_allowed() {
        let mut config = minimal_config();
        config.listen = Some(SocketAddr::new(Ipv4Addr::new(192, 168, 1, 7).into(), 7443));
        config.tls = Some(TlsConfig {
            certificate_pem: PathBuf::from("/tmp/cert.pem"),
            private_key_pem: PathBuf::from("/tmp/key.pem"),
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn data_directory_cannot_be_exposed_as_a_file_root() {
        let mut config = minimal_config();
        config.file_roots.insert(
            "unsafe".to_owned(),
            PathBuf::from("/var/lib/sovereign-node/files"),
        );
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn peer_request_limit_must_be_bounded() {
        let mut config = minimal_config();
        config.policy.max_requests_per_peer_per_minute = 0;
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
        config.policy.max_requests_per_peer_per_minute = 60_001;
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn global_request_limit_must_cover_each_peer() {
        let mut config = minimal_config();
        config.policy.max_requests_global_per_minute =
            config.policy.max_requests_per_peer_per_minute - 1;
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
        config.policy.max_requests_global_per_minute = 1_000_001;
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn clock_rollback_tolerance_is_tightly_bounded() {
        let mut config = minimal_config();
        config.policy.max_clock_rollback_secs = 0;
        assert!(config.validate().is_ok());
        config.policy.max_clock_rollback_secs = 60;
        assert!(config.validate().is_ok());
        config.policy.max_clock_rollback_secs = 61;
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn update_keys_must_be_valid_role_separated_and_bounded() {
        let release = SigningKey::from_bytes(&[0x41; 32]);
        let owner = SigningKey::from_bytes(&[0x42; 32]);
        let mut config = minimal_config();
        config.updates = Some(UpdateConfig {
            release_public_key_hex: hex::encode(release.verifying_key().as_bytes()),
            owner_approval_public_key_hex: hex::encode(owner.verifying_key().as_bytes()),
            max_artifact_bytes: 1_048_576,
        });
        assert!(config.validate().is_ok());

        config.updates = Some(UpdateConfig {
            release_public_key_hex: hex::encode(release.verifying_key().as_bytes()),
            owner_approval_public_key_hex: hex::encode(release.verifying_key().as_bytes()),
            max_artifact_bytes: 1_048_576,
        });
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
        config.updates = Some(UpdateConfig {
            release_public_key_hex: hex::encode(release.verifying_key().as_bytes()),
            owner_approval_public_key_hex: "not-hex".to_owned(),
            max_artifact_bytes: 1_048_576,
        });
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
        config.updates = Some(UpdateConfig {
            release_public_key_hex: hex::encode(release.verifying_key().as_bytes()),
            owner_approval_public_key_hex: hex::encode(owner.verifying_key().as_bytes()),
            max_artifact_bytes: 0,
        });
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn health_snapshot_keys_are_bounded_and_role_separated() {
        let agent_green = SigningKey::from_bytes(&[0x61; 32]);
        let action_broker = SigningKey::from_bytes(&[0x62; 32]);
        let mut config = minimal_config();
        config.health = HealthConfig {
            agent_green: Some(HealthSnapshotConfig {
                snapshot_path: PathBuf::from("/run/agentgreen/health.json"),
                public_key_hex: hex::encode(agent_green.verifying_key().to_bytes()),
                max_age_secs: 60,
            }),
            action_broker: Some(HealthSnapshotConfig {
                snapshot_path: PathBuf::from("/run/sovereign-action-broker/health.json"),
                public_key_hex: hex::encode(action_broker.verifying_key().to_bytes()),
                max_age_secs: 30,
            }),
        };
        assert!(config.validate().is_ok());

        if let Some(adapter) = &mut config.health.action_broker {
            adapter.public_key_hex =
                hex::encode(agent_green.verifying_key().to_bytes()).to_uppercase();
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        if let Some(adapter) = &mut config.health.action_broker {
            adapter.public_key_hex = hex::encode(action_broker.verifying_key().to_bytes());
            adapter.snapshot_path = PathBuf::from("/run/agentgreen/health.json");
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        if let Some(adapter) = &mut config.health.action_broker {
            adapter.snapshot_path = PathBuf::from("/run/sovereign-action-broker/health.json");
            adapter.max_age_secs = 0;
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn resource_snapshot_is_role_separated_and_bounded() {
        let health_key = SigningKey::from_bytes(&[0x63; 32]);
        let resource_key = SigningKey::from_bytes(&[0x64; 32]);
        let mut config = minimal_config();
        config.health.agent_green = Some(HealthSnapshotConfig {
            snapshot_path: PathBuf::from("/run/agentgreen/health.json"),
            public_key_hex: hex::encode(health_key.verifying_key().to_bytes()),
            max_age_secs: 60,
        });
        config.resource_reporting.snapshot = Some(ResourceSnapshotConfig {
            snapshot_path: PathBuf::from("/run/sovereign-resources/snapshot.json"),
            public_key_hex: hex::encode(resource_key.verifying_key().to_bytes()),
            max_age_secs: 30,
        });
        assert!(config.validate().is_ok());

        if let Some(resource) = &mut config.resource_reporting.snapshot {
            resource.public_key_hex =
                hex::encode(health_key.verifying_key().to_bytes()).to_uppercase();
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        if let Some(resource) = &mut config.resource_reporting.snapshot {
            resource.public_key_hex = hex::encode(resource_key.verifying_key().to_bytes());
            resource.snapshot_path = PathBuf::from("/run/agentgreen/health.json");
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        if let Some(resource) = &mut config.resource_reporting.snapshot {
            resource.snapshot_path = PathBuf::from("/run/sovereign-resources/snapshot.json");
            resource.max_age_secs = 86_401;
        }
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        let update_owner = SigningKey::from_bytes(&[0x65; 32]);
        if let Some(resource) = &mut config.resource_reporting.snapshot {
            resource.max_age_secs = 30;
        }
        config.updates = Some(UpdateConfig {
            release_public_key_hex: hex::encode(resource_key.verifying_key().to_bytes()),
            owner_approval_public_key_hex: hex::encode(update_owner.verifying_key().to_bytes()),
            max_artifact_bytes: 1_024,
        });
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn dedicated_status_capabilities_require_their_exact_adapters() {
        let resource_key = SigningKey::from_bytes(&[0x66; 32]);
        let health_key = SigningKey::from_bytes(&[0x67; 32]);
        let mut config = minimal_config();
        config.policy.enabled_capabilities.extend([
            Capability::GpuStatus,
            Capability::EngineStatus,
            Capability::ModelStatus,
        ]);
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));

        config.resource_reporting.snapshot = Some(ResourceSnapshotConfig {
            snapshot_path: PathBuf::from("/run/sovereign-resources/snapshot.json"),
            public_key_hex: hex::encode(resource_key.verifying_key().to_bytes()),
            max_age_secs: 30,
        });
        assert!(config.validate().is_ok());

        config
            .policy
            .enabled_capabilities
            .push(Capability::AgentGreenHealth);
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
        config.health.agent_green = Some(HealthSnapshotConfig {
            snapshot_path: PathBuf::from("/run/agentgreen/health.json"),
            public_key_hex: hex::encode(health_key.verifying_key().to_bytes()),
            max_age_secs: 30,
        });
        assert!(config.validate().is_ok());

        config
            .policy
            .enabled_capabilities
            .push(Capability::ActionBrokerHealth);
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }
}
