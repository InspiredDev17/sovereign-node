use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use crate::config::{HealthConfig, HealthSnapshotConfig};
use crate::protocol::{
    Architecture, Availability, ComponentHealthV1, CpuResourceV1, DeviceIdentityV1, DiskResourceV1,
    HardwareSummaryV1, HealthState, InferenceEngineStatusV1, MAX_DISKS, MemoryResourceV1, NodeId,
    NodeResourceReportV1, NodeSystemInfoV1, OperatingSystemFamily, PROTOCOL_VERSION_V1,
    PlatformInfoV1, QueueStatusV1, SCHEMA_VERSION_V1, SoftwareVersionV1, ThermalState, TrustStatus,
    UnixMillis, UtilizationPermille,
};

const HEALTH_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/local-health-snapshot/v1\0";
const MAX_HEALTH_SNAPSHOT_BYTES: u64 = 8 * 1_024;
const MAX_HEALTH_DETAIL_CODE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HealthComponent {
    AgentGreen,
    ActionBroker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSnapshotV1 {
    pub schema_version: u16,
    pub component: HealthComponent,
    pub state: HealthState,
    pub observed_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub detail_code: Option<String>,
}

#[must_use]
pub fn health_snapshot_signing_bytes(payload_json: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEALTH_SNAPSHOT_SIGNATURE_DOMAIN.len() + payload_json.len());
    bytes.extend_from_slice(HEALTH_SNAPSHOT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(payload_json);
    bytes
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHealthSnapshotV1 {
    /// Exact UTF-8 JSON bytes of `HealthSnapshotV1`, encoded as hex.
    pub payload_hex: String,
    /// Ed25519 signature over `health_snapshot_signing_bytes(payload)`, encoded as hex.
    pub signature_hex: String,
}

#[derive(Debug)]
struct HealthAdapter {
    snapshot_path: PathBuf,
    public_key: VerifyingKey,
    maximum_age_millis: u64,
    component: HealthComponent,
}

#[derive(Debug)]
pub struct HealthReporter {
    agent_green: Option<HealthAdapter>,
    action_broker: Option<HealthAdapter>,
}

impl HealthReporter {
    #[must_use]
    pub fn new(config: &HealthConfig) -> Self {
        Self {
            agent_green: config.agent_green.as_ref().and_then(|adapter| {
                HealthAdapter::from_config(adapter, HealthComponent::AgentGreen)
            }),
            action_broker: config.action_broker.as_ref().and_then(|adapter| {
                HealthAdapter::from_config(adapter, HealthComponent::ActionBroker)
            }),
        }
    }

    #[must_use]
    pub fn agent_green(&self, now: UnixMillis) -> ComponentHealthV1 {
        self.agent_green.as_ref().map_or_else(
            || unknown_health(now, "Agent Green"),
            |adapter| adapter.read(now),
        )
    }

    #[must_use]
    pub fn action_broker(&self, now: UnixMillis) -> ComponentHealthV1 {
        self.action_broker.as_ref().map_or_else(
            || unknown_health(now, "Action Broker"),
            |adapter| adapter.read(now),
        )
    }
}

impl HealthAdapter {
    fn from_config(config: &HealthSnapshotConfig, component: HealthComponent) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(&config.public_key_hex).ok()?.try_into().ok()?;
        let public_key = VerifyingKey::from_bytes(&bytes).ok()?;
        if public_key.is_weak() {
            return None;
        }
        Some(Self {
            snapshot_path: config.snapshot_path.clone(),
            public_key,
            maximum_age_millis: config.max_age_secs.checked_mul(1_000)?,
            component,
        })
    }

    fn read(&self, now: UnixMillis) -> ComponentHealthV1 {
        self.read_verified(now)
            .unwrap_or_else(|| unverifiable_health(now, self.component))
    }

    fn read_verified(&self, now: UnixMillis) -> Option<ComponentHealthV1> {
        let raw = read_bounded_regular_nofollow(&self.snapshot_path).ok()?;
        let signed: SignedHealthSnapshotV1 = serde_json::from_slice(&raw).ok()?;
        let payload = hex::decode(&signed.payload_hex).ok()?;
        if payload.len() > MAX_HEALTH_SNAPSHOT_BYTES as usize / 2 {
            return None;
        }
        let signature_bytes: [u8; 64] = hex::decode(&signed.signature_hex).ok()?.try_into().ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.public_key
            .verify_strict(&health_snapshot_signing_bytes(&payload), &signature)
            .ok()?;
        let snapshot: HealthSnapshotV1 = serde_json::from_slice(&payload).ok()?;
        if snapshot.schema_version != 1
            || snapshot.component != self.component
            || snapshot.observed_at_unix_ms > now.0
            || snapshot.valid_until_unix_ms <= now.0
            || snapshot.valid_until_unix_ms < snapshot.observed_at_unix_ms
            || snapshot
                .valid_until_unix_ms
                .saturating_sub(snapshot.observed_at_unix_ms)
                > self.maximum_age_millis
            || now.0.saturating_sub(snapshot.observed_at_unix_ms) > self.maximum_age_millis
            || !valid_detail_code(snapshot.detail_code.as_deref())
        {
            return None;
        }
        Some(ComponentHealthV1 {
            state: snapshot.state,
            last_observed_at: UnixMillis(snapshot.observed_at_unix_ms),
            detail: snapshot
                .detail_code
                .as_ref()
                .map(|code| format!("authenticated-local-snapshot:{code}")),
        })
    }
}

fn valid_detail_code(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_HEALTH_DETAIL_CODE_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    })
}

fn read_bounded_regular_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "health snapshot is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_HEALTH_SNAPSHOT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_HEALTH_SNAPSHOT_BYTES {
        return Err(std::io::Error::other("health snapshot exceeds local limit"));
    }
    Ok(bytes)
}

fn unverifiable_health(now: UnixMillis, component: HealthComponent) -> ComponentHealthV1 {
    let label = match component {
        HealthComponent::AgentGreen => "Agent Green",
        HealthComponent::ActionBroker => "Action Broker",
    };
    ComponentHealthV1 {
        state: HealthState::Unknown,
        last_observed_at: now,
        detail: Some(format!("{label} snapshot is unavailable or unverifiable")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueSnapshot {
    pub queued: u32,
    pub running: u32,
    pub capacity: u32,
    pub accepting_remote_work: bool,
}

impl Default for QueueSnapshot {
    fn default() -> Self {
        Self {
            queued: 0,
            running: 0,
            capacity: 1,
            accepting_remote_work: false,
        }
    }
}

#[derive(Debug)]
pub struct ResourceReporter {
    node_id: NodeId,
    device: DeviceIdentityV1,
}

impl ResourceReporter {
    #[must_use]
    pub fn new(node_id: NodeId, device: DeviceIdentityV1) -> Self {
        Self { node_id, device }
    }

    #[must_use]
    pub fn system_info(&self, trust_status: TrustStatus) -> NodeSystemInfoV1 {
        let system = System::new_all();
        NodeSystemInfoV1 {
            node_id: self.node_id,
            device: self.device.clone(),
            platform: platform_info(),
            hardware: hardware_summary(&system),
            software: software_version(),
            trust_status,
        }
    }

    #[must_use]
    pub fn report(
        &self,
        now: UnixMillis,
        queue: QueueSnapshot,
        agent_green: ComponentHealthV1,
        action_broker: ComponentHealthV1,
    ) -> NodeResourceReportV1 {
        let system = System::new_all();
        let total_memory = system.total_memory();
        let available_memory = system.available_memory().min(total_memory);
        let cpu_permille = f32_to_permille(system.global_cpu_usage());
        let logical_count = u16::try_from(system.cpus().len()).unwrap_or(u16::MAX);

        let disks = Disks::new_with_refreshed_list()
            .list()
            .iter()
            .take(MAX_DISKS)
            .enumerate()
            .map(|(index, disk)| DiskResourceV1 {
                // Deliberately do not expose a mount point, volume name, serial, or device path.
                label: format!("disk-{index}"),
                total_bytes: disk.total_space(),
                available_bytes: disk.available_space().min(disk.total_space()),
            })
            .collect();

        NodeResourceReportV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: PROTOCOL_VERSION_V1,
            node_id: self.node_id,
            observed_at: now,
            cpu: CpuResourceV1 {
                logical_cpu_count: logical_count,
                utilization: UtilizationPermille(cpu_permille),
                load_one_minute_milli: None,
                temperature_millidegrees_celsius: None,
            },
            ram: MemoryResourceV1 {
                total_bytes: total_memory,
                available_bytes: available_memory,
                used_bytes: total_memory.saturating_sub(available_memory),
            },
            // A platform adapter must explicitly identify unified memory. RAM is not guessed as VRAM.
            unified_memory: None,
            disks,
            gpus: Vec::new(),
            thermal_state: ThermalState::Unsupported,
            inference_engines: vec![InferenceEngineStatusV1 {
                engine_id: "native-inference-engine".to_owned(),
                native: true,
                availability: Availability::Unknown,
                version: None,
            }],
            loaded_models: Vec::new(),
            queue: QueueStatusV1 {
                queued: queue.queued,
                running: queue.running,
                capacity: queue.capacity,
                accepting_local_work: true,
                accepting_remote_work: queue.accepting_remote_work,
            },
            agent_green,
            action_broker,
        }
    }
}

#[must_use]
pub fn unknown_health(now: UnixMillis, component: &str) -> ComponentHealthV1 {
    ComponentHealthV1 {
        state: HealthState::Unknown,
        last_observed_at: now,
        detail: Some(format!("{component} health adapter is not configured")),
    }
}

fn f32_to_permille(percent: f32) -> u16 {
    let bounded = if percent.is_finite() {
        percent.clamp(0.0, 100.0)
    } else {
        0.0
    };
    // sysinfo returns percent, while the wire type is 0..=1000 permille.
    (bounded * 10.0).round() as u16
}

fn platform_info() -> PlatformInfoV1 {
    PlatformInfoV1 {
        os: operating_system(),
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".to_owned()),
        architecture: architecture(),
    }
}

fn hardware_summary(system: &System) -> HardwareSummaryV1 {
    HardwareSummaryV1 {
        logical_cpu_count: u16::try_from(system.cpus().len()).unwrap_or(u16::MAX),
        physical_cpu_count: System::physical_core_count()
            .and_then(|count| u16::try_from(count).ok()),
        total_ram_bytes: system.total_memory(),
        total_unified_memory_bytes: None,
        gpus: Vec::new(),
    }
}

fn software_version() -> SoftwareVersionV1 {
    SoftwareVersionV1 {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        build_id: option_env!("SOVEREIGN_NODE_BUILD_ID")
            .unwrap_or("development")
            .to_owned(),
        protocol_version: PROTOCOL_VERSION_V1,
    }
}

const fn operating_system() -> OperatingSystemFamily {
    if cfg!(target_os = "linux") {
        OperatingSystemFamily::Linux
    } else if cfg!(target_os = "macos") {
        OperatingSystemFamily::MacOs
    } else if cfg!(target_os = "windows") {
        OperatingSystemFamily::Windows
    } else if cfg!(target_os = "freebsd") {
        OperatingSystemFamily::FreeBsd
    } else {
        OperatingSystemFamily::Other
    }
}

const fn architecture() -> Architecture {
    if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else if cfg!(target_arch = "riscv64") {
        Architecture::RiscV64
    } else {
        Architecture::Other
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn resource_report_omits_hardware_identifiers_and_exposes_unknown_adapters() {
        let reporter = ResourceReporter::new(
            NodeId(Uuid::nil()),
            DeviceIdentityV1 {
                display_name: "test-node".to_owned(),
                installation_id: Uuid::from_u128(1),
            },
        );
        let report = reporter.report(
            UnixMillis(10),
            QueueSnapshot::default(),
            unknown_health(UnixMillis(10), "Agent Green"),
            unknown_health(UnixMillis(10), "Action Broker"),
        );
        assert!(report.validate().is_ok());
        assert_eq!(report.agent_green.state, HealthState::Unknown);
        assert_eq!(report.action_broker.state, HealthState::Unknown);
        assert!(
            report
                .disks
                .iter()
                .all(|disk| disk.label.starts_with("disk-"))
        );
    }

    fn write_snapshot(
        directory: &TempDir,
        filename: &str,
        key: &SigningKey,
        snapshot: HealthSnapshotV1,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(&snapshot)?;
        let signature = key.sign(&health_snapshot_signing_bytes(&payload));
        let signed = SignedHealthSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let path = directory.path().join(filename);
        fs::write(&path, serde_json::to_vec(&signed)?)?;
        Ok(path)
    }

    fn adapter(path: PathBuf, key: &SigningKey) -> HealthSnapshotConfig {
        HealthSnapshotConfig {
            snapshot_path: path,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            max_age_secs: 60,
        }
    }

    fn snapshot(component: HealthComponent) -> HealthSnapshotV1 {
        HealthSnapshotV1 {
            schema_version: 1,
            component,
            state: HealthState::Healthy,
            observed_at_unix_ms: 10_000,
            valid_until_unix_ms: 20_000,
            detail_code: Some("contract-ok".to_owned()),
        }
    }

    #[test]
    fn fresh_component_bound_health_snapshot_is_reported() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let path = write_snapshot(
            &directory,
            "agent-green.json",
            &key,
            snapshot(HealthComponent::AgentGreen),
        )?;
        let reporter = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(path, &key)),
            action_broker: None,
        });

        let health = reporter.agent_green(UnixMillis(15_000));
        assert_eq!(health.state, HealthState::Healthy);
        assert_eq!(health.last_observed_at, UnixMillis(10_000));
        assert_eq!(
            health.detail.as_deref(),
            Some("authenticated-local-snapshot:contract-ok")
        );
        assert_eq!(
            reporter.action_broker(UnixMillis(15_000)).state,
            HealthState::Unknown
        );
        Ok(())
    }

    #[test]
    fn forged_stale_or_swapped_health_snapshot_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let trusted_key = SigningKey::from_bytes(&[0x52; 32]);
        let forged_key = SigningKey::from_bytes(&[0x53; 32]);
        let forged_path = write_snapshot(
            &directory,
            "forged.json",
            &forged_key,
            snapshot(HealthComponent::AgentGreen),
        )?;
        let forged = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(forged_path, &trusted_key)),
            action_broker: None,
        });
        assert_eq!(
            forged.agent_green(UnixMillis(15_000)).state,
            HealthState::Unknown
        );

        let stale_path = write_snapshot(
            &directory,
            "stale.json",
            &trusted_key,
            snapshot(HealthComponent::AgentGreen),
        )?;
        let stale = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(stale_path, &trusted_key)),
            action_broker: None,
        });
        assert_eq!(
            stale.agent_green(UnixMillis(20_000)).state,
            HealthState::Unknown
        );

        let swapped_path = write_snapshot(
            &directory,
            "swapped.json",
            &trusted_key,
            snapshot(HealthComponent::ActionBroker),
        )?;
        let swapped = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(swapped_path, &trusted_key)),
            action_broker: None,
        });
        assert_eq!(
            swapped.agent_green(UnixMillis(15_000)).state,
            HealthState::Unknown
        );
        Ok(())
    }

    #[test]
    fn oversized_health_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x54; 32]);
        let path = directory.path().join("oversized.json");
        fs::write(&path, vec![b'x'; MAX_HEALTH_SNAPSHOT_BYTES as usize + 1])?;
        let reporter = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(path, &key)),
            action_broker: None,
        });
        assert_eq!(
            reporter.agent_green(UnixMillis(15_000)).state,
            HealthState::Unknown
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_health_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let target = write_snapshot(
            &directory,
            "target.json",
            &key,
            snapshot(HealthComponent::AgentGreen),
        )?;
        let link = directory.path().join("link.json");
        symlink(target, &link)?;
        let reporter = HealthReporter::new(&HealthConfig {
            agent_green: Some(adapter(link, &key)),
            action_broker: None,
        });
        assert_eq!(
            reporter.agent_green(UnixMillis(15_000)).state,
            HealthState::Unknown
        );
        Ok(())
    }
}
