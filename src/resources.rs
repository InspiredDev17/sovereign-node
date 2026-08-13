use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use crate::config::{
    HealthConfig, HealthSnapshotConfig, ResourceReportingConfig, ResourceSnapshotConfig,
};
use crate::protocol::{
    Architecture, Availability, ComponentHealthV1, CpuResourceV1, DeviceIdentityV1, DiskResourceV1,
    GpuMemoryKind, GpuResourceV1, HardwareSummaryV1, HealthState, InferenceEngineStatusV1,
    LoadedModelV1, MAX_DISKS, MAX_ENGINE_STATUSES, MAX_GPUS, MAX_ID_BYTES, MAX_LOADED_MODELS,
    MAX_VERSION_BYTES, MemoryResourceV1, ModelLoadState, NodeId, NodeResourceReportV1,
    NodeSystemInfoV1, OperatingSystemFamily, PROTOCOL_VERSION_V1, PlatformInfoV1, QueueStatusV1,
    SCHEMA_VERSION_V1, SoftwareVersionV1, ThermalState, TrustStatus, UnixMillis,
    UtilizationPermille,
};

const HEALTH_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/local-health-snapshot/v1\0";
const MAX_HEALTH_SNAPSHOT_BYTES: u64 = 8 * 1_024;
const MAX_HEALTH_DETAIL_CODE_BYTES: usize = 64;
const RESOURCE_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/local-resource-snapshot/v1\0";
const MAX_RESOURCE_SNAPSHOT_BYTES: u64 = 256 * 1_024;

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
        let raw =
            read_bounded_regular_nofollow(&self.snapshot_path, MAX_HEALTH_SNAPSHOT_BYTES).ok()?;
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

pub(crate) fn read_bounded_regular_nofollow(
    path: &Path,
    maximum_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "local snapshot is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(std::io::Error::other(
            "local snapshot exceeds configured limit",
        ));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSnapshotV1 {
    pub schema_version: u16,
    pub observed_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub unified_memory: Option<MemoryResourceV1>,
    pub gpus: Vec<GpuResourceV1>,
    pub thermal_state: ThermalState,
    pub inference_engines: Vec<InferenceEngineStatusV1>,
    pub loaded_models: Vec<LoadedModelV1>,
}

#[must_use]
pub fn resource_snapshot_signing_bytes(payload_json: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(RESOURCE_SNAPSHOT_SIGNATURE_DOMAIN.len() + payload_json.len());
    bytes.extend_from_slice(RESOURCE_SNAPSHOT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(payload_json);
    bytes
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedResourceSnapshotV1 {
    /// Exact UTF-8 JSON bytes of `ResourceSnapshotV1`, encoded as hex.
    pub payload_hex: String,
    /// Ed25519 signature over `resource_snapshot_signing_bytes(payload)`, encoded as hex.
    pub signature_hex: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedResourceSnapshot {
    pub observed_at: Option<UnixMillis>,
    pub unified_memory: Option<MemoryResourceV1>,
    pub gpus: Vec<GpuResourceV1>,
    pub thermal_state: ThermalState,
    pub inference_engines: Vec<InferenceEngineStatusV1>,
    pub loaded_models: Vec<LoadedModelV1>,
}

impl Default for VerifiedResourceSnapshot {
    fn default() -> Self {
        Self {
            observed_at: None,
            unified_memory: None,
            gpus: Vec::new(),
            thermal_state: ThermalState::Unknown,
            inference_engines: vec![InferenceEngineStatusV1 {
                engine_id: "native-inference-engine".to_owned(),
                native: true,
                availability: Availability::Unknown,
                version: None,
            }],
            loaded_models: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ResourceSnapshotReporter {
    adapter: Option<ResourceSnapshotAdapter>,
}

#[derive(Debug)]
struct ResourceSnapshotAdapter {
    snapshot_path: PathBuf,
    public_key: VerifyingKey,
    maximum_age_millis: u64,
}

impl ResourceSnapshotReporter {
    #[must_use]
    pub fn new(config: &ResourceReportingConfig) -> Self {
        Self {
            adapter: config
                .snapshot
                .as_ref()
                .and_then(ResourceSnapshotAdapter::from_config),
        }
    }

    #[must_use]
    pub fn read(&self, now: UnixMillis, total_ram_bytes: u64) -> VerifiedResourceSnapshot {
        self.adapter
            .as_ref()
            .and_then(|adapter| adapter.read_verified(now, total_ram_bytes))
            .unwrap_or_default()
    }
}

impl ResourceSnapshotAdapter {
    fn from_config(config: &ResourceSnapshotConfig) -> Option<Self> {
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

    fn read_verified(
        &self,
        now: UnixMillis,
        total_ram_bytes: u64,
    ) -> Option<VerifiedResourceSnapshot> {
        let raw =
            read_bounded_regular_nofollow(&self.snapshot_path, MAX_RESOURCE_SNAPSHOT_BYTES).ok()?;
        let signed: SignedResourceSnapshotV1 = serde_json::from_slice(&raw).ok()?;
        let payload = hex::decode(&signed.payload_hex).ok()?;
        if payload.len() > MAX_RESOURCE_SNAPSHOT_BYTES as usize / 2 {
            return None;
        }
        let signature_bytes: [u8; 64] = hex::decode(&signed.signature_hex).ok()?.try_into().ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.public_key
            .verify_strict(&resource_snapshot_signing_bytes(&payload), &signature)
            .ok()?;
        let snapshot: ResourceSnapshotV1 = serde_json::from_slice(&payload).ok()?;
        if !snapshot_valid(&snapshot, now, self.maximum_age_millis, total_ram_bytes) {
            return None;
        }
        Some(VerifiedResourceSnapshot {
            observed_at: Some(UnixMillis(snapshot.observed_at_unix_ms)),
            unified_memory: snapshot.unified_memory,
            gpus: snapshot.gpus,
            thermal_state: snapshot.thermal_state,
            inference_engines: snapshot.inference_engines,
            loaded_models: snapshot.loaded_models,
        })
    }
}

fn snapshot_valid(
    snapshot: &ResourceSnapshotV1,
    now: UnixMillis,
    maximum_age_millis: u64,
    total_ram_bytes: u64,
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
        || snapshot.gpus.len() > MAX_GPUS
        || snapshot.inference_engines.is_empty()
        || snapshot.inference_engines.len() > MAX_ENGINE_STATUSES
        || snapshot.loaded_models.len() > MAX_LOADED_MODELS
        || snapshot
            .unified_memory
            .as_ref()
            .is_some_and(|memory| !memory_valid(memory) || memory.total_bytes > total_ram_bytes)
    {
        return false;
    }

    let mut gpu_indexes = BTreeSet::new();
    if snapshot.gpus.iter().any(|gpu| {
        !gpu_indexes.insert(gpu.index)
            || gpu.utilization.is_some_and(|value| value.0 > 1_000)
            || matches!(
                (gpu.total_memory_bytes, gpu.used_memory_bytes),
                (None, Some(_)) | (Some(_), None)
            )
            || matches!(
                (gpu.total_memory_bytes, gpu.used_memory_bytes),
                (Some(total), Some(used)) if used > total
            )
            || !temperature_valid(gpu.temperature_millidegrees_celsius)
    }) {
        return false;
    }

    let mut engine_states = BTreeMap::new();
    if snapshot.inference_engines.iter().any(|engine| {
        !local_identifier_valid(&engine.engine_id)
            || engine_states
                .insert(engine.engine_id.as_str(), engine.availability)
                .is_some()
            || engine
                .version
                .as_ref()
                .is_some_and(|version| !bounded_text_valid(version, MAX_VERSION_BYTES))
    }) || !snapshot
        .inference_engines
        .iter()
        .any(|engine| engine.native)
    {
        return false;
    }

    let mut model_ids = BTreeSet::new();
    let dedicated_vram = snapshot
        .gpus
        .iter()
        .filter(|gpu| gpu.memory_kind == GpuMemoryKind::DedicatedVram)
        .filter_map(|gpu| gpu.total_memory_bytes)
        .fold(0_u64, u64::saturating_add);
    let maximum_model_memory = total_ram_bytes.saturating_add(dedicated_vram);
    !snapshot.loaded_models.iter().any(|model| {
        !local_identifier_valid(&model.model_id)
            || !model_ids.insert(model.model_id.as_str())
            || !engine_states.contains_key(model.engine_id.as_str())
            || (model.state == ModelLoadState::Loaded
                && !matches!(
                    engine_states.get(model.engine_id.as_str()),
                    Some(Availability::Available | Availability::Degraded)
                ))
            || model
                .allocated_memory_bytes
                .is_some_and(|bytes| bytes > maximum_model_memory)
    })
}

fn memory_valid(memory: &MemoryResourceV1) -> bool {
    memory.available_bytes <= memory.total_bytes
        && memory.used_bytes <= memory.total_bytes
        && memory.used_bytes.saturating_add(memory.available_bytes) <= memory.total_bytes
}

fn temperature_valid(value: Option<i32>) -> bool {
    value.is_none_or(|value| (-100_000..=250_000).contains(&value))
}

fn local_identifier_valid(value: &str) -> bool {
    bounded_text_valid(value, MAX_ID_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn bounded_text_valid(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.contains('\0')
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
    pub fn signed_resource_snapshot(
        &self,
        now: UnixMillis,
        reporter: &ResourceSnapshotReporter,
    ) -> VerifiedResourceSnapshot {
        reporter.read(now, System::new_all().total_memory())
    }

    #[must_use]
    pub fn report(
        &self,
        now: UnixMillis,
        queue: QueueSnapshot,
        external_reporter: &ResourceSnapshotReporter,
        agent_green: ComponentHealthV1,
        action_broker: ComponentHealthV1,
    ) -> NodeResourceReportV1 {
        let system = System::new_all();
        let total_memory = system.total_memory();
        let available_memory = system.available_memory().min(total_memory);
        let external = external_reporter.read(now, total_memory);
        let observed_at = external.observed_at.unwrap_or(now);
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
            // Use the oldest optional adapter observation so the combined report never overstates
            // accelerator/model freshness. Host and queue measurements were sampled no earlier.
            observed_at,
            cpu: CpuResourceV1 {
                logical_cpu_count: logical_count,
                utilization: UtilizationPermille(cpu_permille),
                load_one_minute_milli: load_milli(System::load_average().one),
                temperature_millidegrees_celsius: None,
            },
            ram: MemoryResourceV1 {
                total_bytes: total_memory,
                available_bytes: available_memory,
                used_bytes: total_memory.saturating_sub(available_memory),
            },
            // RAM is never guessed as unified memory; only the signed local adapter may assert it.
            unified_memory: external.unified_memory,
            disks,
            gpus: external.gpus,
            thermal_state: external.thermal_state,
            inference_engines: external.inference_engines,
            loaded_models: external.loaded_models,
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

fn load_milli(load: f64) -> Option<u32> {
    if !load.is_finite() || load < 0.0 {
        return None;
    }
    Some((load * 1_000.0).round().clamp(0.0, f64::from(u32::MAX)) as u32)
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
            &ResourceSnapshotReporter::new(&ResourceReportingConfig::default()),
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
        let mut invalid = report;
        invalid.inference_engines[0].engine_id = "../engine".to_owned();
        assert!(invalid.validate().is_err());
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

    fn write_resource_snapshot(
        directory: &TempDir,
        filename: &str,
        key: &SigningKey,
        snapshot: ResourceSnapshotV1,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(&snapshot)?;
        let signature = key.sign(&resource_snapshot_signing_bytes(&payload));
        let signed = SignedResourceSnapshotV1 {
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let path = directory.path().join(filename);
        fs::write(&path, serde_json::to_vec(&signed)?)?;
        Ok(path)
    }

    fn resource_adapter(path: PathBuf, key: &SigningKey) -> ResourceReportingConfig {
        ResourceReportingConfig {
            snapshot: Some(ResourceSnapshotConfig {
                snapshot_path: path,
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                max_age_secs: 60,
            }),
        }
    }

    fn resource_snapshot() -> ResourceSnapshotV1 {
        ResourceSnapshotV1 {
            schema_version: 1,
            observed_at_unix_ms: 10_000,
            valid_until_unix_ms: 20_000,
            unified_memory: Some(MemoryResourceV1 {
                total_bytes: 16_000,
                available_bytes: 6_000,
                used_bytes: 10_000,
            }),
            gpus: vec![GpuResourceV1 {
                index: 0,
                utilization: Some(UtilizationPermille(500)),
                memory_kind: crate::protocol::GpuMemoryKind::Unified,
                total_memory_bytes: Some(16_000),
                used_memory_bytes: Some(4_000),
                temperature_millidegrees_celsius: Some(65_000),
            }],
            thermal_state: ThermalState::Nominal,
            inference_engines: vec![InferenceEngineStatusV1 {
                engine_id: "native-engine".to_owned(),
                native: true,
                availability: Availability::Available,
                version: Some("1.2.3".to_owned()),
            }],
            loaded_models: vec![LoadedModelV1 {
                model_id: "owner-model-1".to_owned(),
                engine_id: "native-engine".to_owned(),
                state: crate::protocol::ModelLoadState::Loaded,
                allocated_memory_bytes: Some(4_000),
            }],
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

    #[test]
    fn fresh_signed_resource_snapshot_reports_accelerators_and_models()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let path =
            write_resource_snapshot(&directory, "resources.json", &key, resource_snapshot())?;
        let reporter = ResourceSnapshotReporter::new(&resource_adapter(path, &key));

        let measured = reporter.read(UnixMillis(15_000), 32_000);
        assert_eq!(measured.thermal_state, ThermalState::Nominal);
        assert_eq!(measured.observed_at, Some(UnixMillis(10_000)));
        assert_eq!(measured.gpus.len(), 1);
        assert_eq!(measured.inference_engines.len(), 1);
        assert_eq!(measured.loaded_models.len(), 1);
        assert_eq!(
            measured
                .unified_memory
                .as_ref()
                .map(|memory| memory.total_bytes),
            Some(16_000)
        );

        let node_reporter = ResourceReporter::new(
            NodeId(Uuid::nil()),
            DeviceIdentityV1 {
                display_name: "test-node".to_owned(),
                installation_id: Uuid::from_u128(2),
            },
        );
        let report = node_reporter.report(
            UnixMillis(15_000),
            QueueSnapshot::default(),
            &reporter,
            unknown_health(UnixMillis(15_000), "Agent Green"),
            unknown_health(UnixMillis(15_000), "Action Broker"),
        );
        assert!(report.validate().is_ok());
        assert_eq!(report.observed_at, UnixMillis(10_000));
        assert_eq!(report.gpus.len(), 1);
        assert_eq!(report.loaded_models.len(), 1);
        Ok(())
    }

    #[test]
    fn forged_stale_or_invalid_resource_snapshot_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let trusted_key = SigningKey::from_bytes(&[0x72; 32]);
        let forged_key = SigningKey::from_bytes(&[0x73; 32]);
        let forged_path = write_resource_snapshot(
            &directory,
            "forged-resources.json",
            &forged_key,
            resource_snapshot(),
        )?;
        let forged = ResourceSnapshotReporter::new(&resource_adapter(forged_path, &trusted_key));
        assert_eq!(
            forged.read(UnixMillis(15_000), 32_000).thermal_state,
            ThermalState::Unknown
        );

        let stale_path = write_resource_snapshot(
            &directory,
            "stale-resources.json",
            &trusted_key,
            resource_snapshot(),
        )?;
        let stale = ResourceSnapshotReporter::new(&resource_adapter(stale_path, &trusted_key));
        assert_eq!(
            stale.read(UnixMillis(20_000), 32_000).thermal_state,
            ThermalState::Unknown
        );

        let mut invalid_snapshot = resource_snapshot();
        invalid_snapshot.loaded_models[0].model_id = "private/path/model".to_owned();
        let invalid_path = write_resource_snapshot(
            &directory,
            "invalid-resources.json",
            &trusted_key,
            invalid_snapshot,
        )?;
        let invalid = ResourceSnapshotReporter::new(&resource_adapter(invalid_path, &trusted_key));
        let measured = invalid.read(UnixMillis(15_000), 32_000);
        assert_eq!(measured.thermal_state, ThermalState::Unknown);
        assert!(measured.gpus.is_empty());
        assert!(measured.loaded_models.is_empty());
        assert_eq!(
            measured.inference_engines[0].availability,
            Availability::Unknown
        );
        Ok(())
    }

    #[test]
    fn duplicate_gpu_or_engine_ids_and_impossible_memory_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x74; 32]);

        let mut duplicate_gpu = resource_snapshot();
        duplicate_gpu.gpus.push(duplicate_gpu.gpus[0].clone());
        let path = write_resource_snapshot(&directory, "duplicate.json", &key, duplicate_gpu)?;
        assert_eq!(
            ResourceSnapshotReporter::new(&resource_adapter(path, &key))
                .read(UnixMillis(15_000), 32_000)
                .thermal_state,
            ThermalState::Unknown
        );

        let mut duplicate_engine = resource_snapshot();
        duplicate_engine
            .inference_engines
            .push(duplicate_engine.inference_engines[0].clone());
        let path =
            write_resource_snapshot(&directory, "duplicate-engine.json", &key, duplicate_engine)?;
        assert_eq!(
            ResourceSnapshotReporter::new(&resource_adapter(path, &key))
                .read(UnixMillis(15_000), 32_000)
                .thermal_state,
            ThermalState::Unknown
        );

        let mut excessive_unified_memory = resource_snapshot();
        if let Some(memory) = &mut excessive_unified_memory.unified_memory {
            memory.total_bytes = 64_000;
        }
        let path =
            write_resource_snapshot(&directory, "memory.json", &key, excessive_unified_memory)?;
        assert_eq!(
            ResourceSnapshotReporter::new(&resource_adapter(path, &key))
                .read(UnixMillis(15_000), 32_000)
                .thermal_state,
            ThermalState::Unknown
        );

        let mut unavailable_engine = resource_snapshot();
        unavailable_engine.inference_engines[0].availability = Availability::Unavailable;
        let path = write_resource_snapshot(
            &directory,
            "unavailable-engine.json",
            &key,
            unavailable_engine,
        )?;
        assert_eq!(
            ResourceSnapshotReporter::new(&resource_adapter(path, &key))
                .read(UnixMillis(15_000), 32_000)
                .thermal_state,
            ThermalState::Unknown
        );

        let mut excessive_model_memory = resource_snapshot();
        excessive_model_memory.loaded_models[0].allocated_memory_bytes = Some(40_000);
        let path = write_resource_snapshot(
            &directory,
            "model-memory.json",
            &key,
            excessive_model_memory,
        )?;
        assert_eq!(
            ResourceSnapshotReporter::new(&resource_adapter(path, &key))
                .read(UnixMillis(15_000), 32_000)
                .thermal_state,
            ThermalState::Unknown
        );
        Ok(())
    }

    #[test]
    fn oversized_resource_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x75; 32]);
        let path = directory.path().join("oversized-resources.json");
        fs::write(&path, vec![b'x'; MAX_RESOURCE_SNAPSHOT_BYTES as usize + 1])?;
        let measured = ResourceSnapshotReporter::new(&resource_adapter(path, &key))
            .read(UnixMillis(15_000), 32_000);
        assert_eq!(measured.thermal_state, ThermalState::Unknown);
        assert!(measured.gpus.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_resource_snapshot_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[0x76; 32]);
        let target = write_resource_snapshot(
            &directory,
            "resource-target.json",
            &key,
            resource_snapshot(),
        )?;
        let link = directory.path().join("resource-link.json");
        symlink(target, &link)?;
        let measured = ResourceSnapshotReporter::new(&resource_adapter(link, &key))
            .read(UnixMillis(15_000), 32_000);
        assert_eq!(measured.thermal_state, ThermalState::Unknown);
        assert!(measured.gpus.is_empty());
        Ok(())
    }
}
