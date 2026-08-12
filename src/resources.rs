use sysinfo::{Disks, System};

use crate::protocol::{
    Architecture, Availability, ComponentHealthV1, CpuResourceV1, DeviceIdentityV1, DiskResourceV1,
    HardwareSummaryV1, HealthState, InferenceEngineStatusV1, MAX_DISKS, MemoryResourceV1, NodeId,
    NodeResourceReportV1, NodeSystemInfoV1, OperatingSystemFamily, PROTOCOL_VERSION_V1,
    PlatformInfoV1, QueueStatusV1, SCHEMA_VERSION_V1, SoftwareVersionV1, ThermalState, TrustStatus,
    UnixMillis, UtilizationPermille,
};

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
}
