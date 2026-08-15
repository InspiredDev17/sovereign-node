use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::OwnedFd;

use crate::authz::VerifiedAction;
use crate::config::NodeConfig;
use crate::process_status::{ProcessStatusError, ProcessStatusReporter};
use crate::protocol::{
    ActionArguments, ActionErrorCode, ActionResultV1, ActionTarget, FileReadResultV1,
    GpuResourceV1, InferenceEngineStatusV1, LoadedModelV1, Sha256Digest, TrustStatus, UnixMillis,
};
use crate::repository_status::{RepositoryStatusError, RepositoryStatusReporter};
use crate::resources::{HealthReporter, QueueSnapshot, ResourceReporter, ResourceSnapshotReporter};
use crate::service_status::{ServiceStatusError, ServiceStatusReporter};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Eq, Error, PartialEq)]
pub enum CapabilityError {
    #[error("capability target is not locally allowlisted")]
    TargetNotAllowed,
    #[error("file access is outside the authorized root or violates file policy")]
    UnauthorizedFileAccess,
    #[error("capability arguments do not match the verified request")]
    ArgumentMismatch,
    #[error("capability is not implemented by a configured local adapter")]
    Unsupported,
    #[error("local execution failed")]
    Execution,
    #[error("capability result exceeded a local resource limit")]
    ResourceExhausted,
}

impl CapabilityError {
    #[must_use]
    pub const fn code(&self) -> ActionErrorCode {
        match self {
            Self::TargetNotAllowed => ActionErrorCode::TargetNotAllowed,
            Self::UnauthorizedFileAccess => ActionErrorCode::UnauthorizedFileAccess,
            Self::ArgumentMismatch => ActionErrorCode::CapabilityMismatch,
            Self::Unsupported => ActionErrorCode::CapabilityNotAdvertised,
            Self::Execution => ActionErrorCode::LocalExecutionFailed,
            Self::ResourceExhausted => ActionErrorCode::ResourceExhausted,
        }
    }
}

#[derive(Debug)]
pub struct CapabilityExecutor {
    config: Arc<NodeConfig>,
    resources: ResourceReporter,
    external_resources: ResourceSnapshotReporter,
    process_status: ProcessStatusReporter,
    service_status: ServiceStatusReporter,
    repository_status: RepositoryStatusReporter,
    read_roots: BTreeMap<String, ReadRootHandle>,
    health: HealthReporter,
}

#[cfg(unix)]
#[derive(Debug)]
struct ReadRootHandle {
    directory: OwnedFd,
    allowed_files: BTreeSet<String>,
}

#[cfg(not(unix))]
#[derive(Debug)]
struct ReadRootHandle;

impl CapabilityExecutor {
    #[must_use]
    pub fn new(config: Arc<NodeConfig>, resources: ResourceReporter) -> Self {
        let health = HealthReporter::new(&config.health);
        let external_resources = ResourceSnapshotReporter::new(&config.resource_reporting);
        let process_status = ProcessStatusReporter::new(config.process_reporting.snapshot.as_ref());
        let service_status = ServiceStatusReporter::new(config.service_reporting.snapshot.as_ref());
        let repository_status =
            RepositoryStatusReporter::new(config.repository_reporting.snapshot.as_ref());
        let read_roots = open_read_roots(&config);
        Self {
            config,
            resources,
            external_resources,
            process_status,
            service_status,
            repository_status,
            read_roots,
            health,
        }
    }

    pub async fn execute(
        &self,
        action: &VerifiedAction,
        now: UnixMillis,
        queue: QueueSnapshot,
        trust_status: TrustStatus,
    ) -> Result<ActionResultV1, CapabilityError> {
        let request = action.request();
        match (&request.target, &request.arguments) {
            (ActionTarget::Node, ActionArguments::SystemInfo) => Ok(ActionResultV1::SystemInfo(
                self.resources.system_info(trust_status),
            )),
            (ActionTarget::Node, ActionArguments::ResourceStatus) => {
                Ok(ActionResultV1::ResourceStatus(self.resources.report(
                    now,
                    queue,
                    &self.external_resources,
                    self.health.agent_green(now),
                    self.health.action_broker(now),
                )))
            }
            (
                ActionTarget::File {
                    root_id,
                    relative_path,
                },
                ActionArguments::FileRead { offset, max_bytes },
            ) => self
                .read_file(root_id, relative_path, *offset, *max_bytes)
                .map(ActionResultV1::FileRead),
            (ActionTarget::File { .. }, ActionArguments::FileWrite { .. }) => {
                Err(CapabilityError::Unsupported)
            }
            (target, ActionArguments::ProcessStatus { include_children }) => self
                .process_status
                .status(now, logical_process_target(target, *include_children)?)
                .map(ActionResultV1::ProcessStatus)
                .map_err(|error| match error {
                    ProcessStatusError::SnapshotUnavailable => CapabilityError::Execution,
                    ProcessStatusError::TargetNotFound => CapabilityError::TargetNotAllowed,
                }),
            (ActionTarget::Service { service_name }, ActionArguments::ServiceStatus) => self
                .service_status
                .status(now, service_name)
                .map(ActionResultV1::ServiceStatus)
                .map_err(|error| match error {
                    ServiceStatusError::SnapshotUnavailable => CapabilityError::Execution,
                    ServiceStatusError::TargetNotFound => CapabilityError::TargetNotAllowed,
                }),
            (
                ActionTarget::Repository { repository_id },
                ActionArguments::RepositoryStatus {
                    include_untracked_summary,
                },
            ) => self
                .repository_status
                .status(now, repository_id, *include_untracked_summary)
                .map(ActionResultV1::RepositoryStatus)
                .map_err(|error| match error {
                    RepositoryStatusError::SnapshotUnavailable => CapabilityError::Execution,
                    RepositoryStatusError::TargetNotFound => CapabilityError::TargetNotAllowed,
                }),
            (
                ActionTarget::ApprovedAction { .. },
                ActionArguments::ExecuteApprovedAction { .. },
            ) => Err(CapabilityError::Unsupported),
            (ActionTarget::Gpu { index }, ActionArguments::GpuStatus) => {
                let snapshot = self
                    .resources
                    .signed_resource_snapshot(now, &self.external_resources);
                filter_gpu_status(snapshot.gpus, *index).map(ActionResultV1::GpuStatus)
            }
            (ActionTarget::Engine { engine_id }, ActionArguments::EngineStatus) => {
                let snapshot = self
                    .resources
                    .signed_resource_snapshot(now, &self.external_resources);
                filter_engine_status(
                    snapshot.inference_engines,
                    engine_id.as_deref(),
                    snapshot.observed_at.is_some(),
                )
                .map(ActionResultV1::EngineStatus)
            }
            (ActionTarget::Model { model_id }, ActionArguments::ModelStatus) => {
                let snapshot = self
                    .resources
                    .signed_resource_snapshot(now, &self.external_resources);
                filter_model_status(snapshot.loaded_models, model_id.as_deref())
                    .map(ActionResultV1::ModelStatus)
            }
            (ActionTarget::AgentGreen, ActionArguments::AgentGreenHealth) => Ok(
                ActionResultV1::AgentGreenHealth(self.health.agent_green(now)),
            ),
            (ActionTarget::ActionBroker, ActionArguments::ActionBrokerHealth) => Ok(
                ActionResultV1::ActionBrokerHealth(self.health.action_broker(now)),
            ),
            _ => Err(CapabilityError::ArgumentMismatch),
        }
    }

    fn read_file(
        &self,
        root_id: &str,
        relative_path: &str,
        offset: u64,
        requested_max: u64,
    ) -> Result<FileReadResultV1, CapabilityError> {
        let policy_max = u64::try_from(self.config.policy.max_file_read_bytes)
            .map_err(|_| CapabilityError::ResourceExhausted)?;
        if requested_max == 0 || requested_max > policy_max {
            return Err(CapabilityError::ResourceExhausted);
        }
        let root = self
            .read_roots
            .get(root_id)
            .ok_or(CapabilityError::TargetNotAllowed)?;
        if !root_allows(root, relative_path) {
            return Err(CapabilityError::TargetNotAllowed);
        }
        let mut file = open_published_file(root, relative_path)?;
        let metadata = file
            .metadata()
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        if !metadata.is_file() {
            return Err(CapabilityError::UnauthorizedFileAccess);
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        let buffer_len =
            usize::try_from(requested_max).map_err(|_| CapabilityError::ResourceExhausted)?;
        let mut contents = vec![0_u8; buffer_len];
        let bytes_read = file
            .read(&mut contents)
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        contents.truncate(bytes_read);
        let bytes_read_u64 = u64::try_from(bytes_read).unwrap_or(u64::MAX);
        let end_of_file = offset.saturating_add(bytes_read_u64) >= metadata.len();
        Ok(FileReadResultV1 {
            offset,
            content_digest: Sha256Digest(Sha256::digest(&contents).into()),
            contents,
            end_of_file,
        })
    }
}

#[cfg(unix)]
fn open_read_roots(config: &NodeConfig) -> BTreeMap<String, ReadRootHandle> {
    config
        .read_roots
        .iter()
        .filter_map(|(root_id, root)| {
            let directory = open_absolute_directory_nofollow(&root.path).ok()?;
            directory_is_owner_controlled(&directory).then(|| {
                (
                    root_id.clone(),
                    ReadRootHandle {
                        directory,
                        allowed_files: root.allowed_files.iter().cloned().collect(),
                    },
                )
            })
        })
        .collect()
}

#[cfg(unix)]
fn open_absolute_directory_nofollow(path: &Path) -> Result<OwnedFd, CapabilityError> {
    use rustix::fs::{Mode, OFlags};

    if !path.is_absolute() {
        return Err(CapabilityError::TargetNotAllowed);
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CapabilityError::TargetNotAllowed)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(component) => {
                directory = rustix::fs::openat(
                    &directory,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CapabilityError::TargetNotAllowed)?;
            }
            _ => return Err(CapabilityError::TargetNotAllowed),
        }
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_read_roots(_config: &NodeConfig) -> BTreeMap<String, ReadRootHandle> {
    BTreeMap::new()
}

#[cfg(unix)]
fn root_allows(root: &ReadRootHandle, relative_path: &str) -> bool {
    root.allowed_files.contains(relative_path)
}

#[cfg(not(unix))]
fn root_allows(_root: &ReadRootHandle, _relative_path: &str) -> bool {
    false
}

#[cfg(unix)]
fn open_published_file(
    root: &ReadRootHandle,
    relative_path: &str,
) -> Result<std::fs::File, CapabilityError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(CapabilityError::UnauthorizedFileAccess);
    }
    let components: Vec<_> = path.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CapabilityError::UnauthorizedFileAccess);
    }
    let mut directory = rustix::fs::openat(
        &root.directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
    for component in &components[..components.len() - 1] {
        let std::path::Component::Normal(component) = component else {
            return Err(CapabilityError::UnauthorizedFileAccess);
        };
        directory = rustix::fs::openat(
            &directory,
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        if !directory_is_owner_controlled(&directory) {
            return Err(CapabilityError::UnauthorizedFileAccess);
        }
    }
    let std::path::Component::Normal(filename) = components[components.len() - 1] else {
        return Err(CapabilityError::UnauthorizedFileAccess);
    };
    let descriptor = rustix::fs::openat(
        &directory,
        filename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
    let status =
        rustix::fs::fstat(&descriptor).map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
    let mode = rustix::fs::Mode::from_raw_mode(status.st_mode);
    if FileType::from_raw_mode(status.st_mode) != FileType::RegularFile
        || status.st_nlink != 1
        || status.st_uid != rustix::process::geteuid().as_raw()
        || mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH | Mode::WGRP | Mode::WOTH)
    {
        return Err(CapabilityError::UnauthorizedFileAccess);
    }
    Ok(descriptor.into())
}

#[cfg(not(unix))]
fn open_published_file(
    _root: &ReadRootHandle,
    _relative_path: &str,
) -> Result<std::fs::File, CapabilityError> {
    Err(CapabilityError::Unsupported)
}

#[cfg(unix)]
fn directory_is_owner_controlled(directory: &OwnedFd) -> bool {
    use rustix::fs::{FileType, Mode};

    rustix::fs::fstat(directory).is_ok_and(|status| {
        FileType::from_raw_mode(status.st_mode) == FileType::Directory
            && status.st_uid == rustix::process::geteuid().as_raw()
            && !Mode::from_raw_mode(status.st_mode).intersects(Mode::WGRP | Mode::WOTH)
    })
}

fn filter_gpu_status(
    gpus: Vec<GpuResourceV1>,
    requested_index: Option<u16>,
) -> Result<Vec<GpuResourceV1>, CapabilityError> {
    match requested_index {
        None => Ok(gpus),
        Some(index) => gpus
            .into_iter()
            .find(|gpu| gpu.index == index)
            .map(|gpu| vec![gpu])
            .ok_or(CapabilityError::TargetNotAllowed),
    }
}

fn logical_process_target(
    target: &ActionTarget,
    include_children: bool,
) -> Result<&str, CapabilityError> {
    if include_children {
        return Err(CapabilityError::ArgumentMismatch);
    }
    match target {
        ActionTarget::ManagedProcess { process_id } => Ok(process_id),
        ActionTarget::Process { .. } => Err(CapabilityError::TargetNotAllowed),
        _ => Err(CapabilityError::ArgumentMismatch),
    }
}

fn filter_engine_status(
    engines: Vec<InferenceEngineStatusV1>,
    requested_id: Option<&str>,
    verified_snapshot: bool,
) -> Result<Vec<InferenceEngineStatusV1>, CapabilityError> {
    match requested_id {
        None => Ok(engines),
        Some(_) if !verified_snapshot => Err(CapabilityError::TargetNotAllowed),
        Some(engine_id) => engines
            .into_iter()
            .find(|engine| engine.engine_id == engine_id)
            .map(|engine| vec![engine])
            .ok_or(CapabilityError::TargetNotAllowed),
    }
}

fn filter_model_status(
    models: Vec<LoadedModelV1>,
    requested_id: Option<&str>,
) -> Result<Vec<LoadedModelV1>, CapabilityError> {
    match requested_id {
        None => Ok(models),
        Some(model_id) => models
            .into_iter()
            .find(|model| model.model_id == model_id)
            .map(|model| vec![model])
            .ok_or(CapabilityError::TargetNotAllowed),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Read;

    use crate::protocol::{Availability, GpuMemoryKind, ModelLoadState, UtilizationPermille};

    use super::*;

    #[test]
    fn shipping_executor_contains_no_process_spawn_api() {
        let source = include_str!("capabilities.rs");
        for needle in [
            ["process::", "Command"].concat(),
            ["Command", "::new"].concat(),
            [".spa", "wn()"].concat(),
        ] {
            assert!(!source.contains(&needle));
        }
    }

    #[test]
    fn dedicated_status_filters_deny_unknown_specific_targets() {
        let gpus = vec![GpuResourceV1 {
            index: 2,
            utilization: Some(UtilizationPermille(500)),
            memory_kind: GpuMemoryKind::DedicatedVram,
            total_memory_bytes: Some(8_000),
            used_memory_bytes: Some(4_000),
            temperature_millidegrees_celsius: None,
        }];
        assert_eq!(filter_gpu_status(gpus.clone(), None), Ok(gpus.clone()));
        assert_eq!(filter_gpu_status(gpus.clone(), Some(2)), Ok(gpus));
        assert!(matches!(
            filter_gpu_status(Vec::new(), Some(2)),
            Err(CapabilityError::TargetNotAllowed)
        ));

        let engines = vec![InferenceEngineStatusV1 {
            engine_id: "native-engine".to_owned(),
            native: true,
            availability: Availability::Available,
            version: None,
        }];
        assert_eq!(
            filter_engine_status(engines.clone(), Some("native-engine"), true),
            Ok(engines)
        );
        assert!(matches!(
            filter_engine_status(
                vec![InferenceEngineStatusV1 {
                    engine_id: "native-inference-engine".to_owned(),
                    native: true,
                    availability: Availability::Unknown,
                    version: None,
                }],
                Some("native-inference-engine"),
                false,
            ),
            Err(CapabilityError::TargetNotAllowed)
        ));

        let models = vec![LoadedModelV1 {
            model_id: "owner-model".to_owned(),
            engine_id: "native-engine".to_owned(),
            state: ModelLoadState::Loaded,
            allocated_memory_bytes: None,
        }];
        assert_eq!(
            filter_model_status(models.clone(), Some("owner-model")),
            Ok(models)
        );
        assert!(matches!(
            filter_model_status(Vec::new(), Some("owner-model")),
            Err(CapabilityError::TargetNotAllowed)
        ));
    }

    #[test]
    fn process_status_accepts_only_logical_targets_and_never_raw_pids() {
        let logical = ActionTarget::ManagedProcess {
            process_id: "model-engine".to_owned(),
        };
        assert_eq!(logical_process_target(&logical, false), Ok("model-engine"));
        assert_eq!(
            logical_process_target(&logical, true),
            Err(CapabilityError::ArgumentMismatch)
        );
        assert_eq!(
            logical_process_target(&ActionTarget::Process { process_id: 42 }, false),
            Err(CapabilityError::TargetNotAllowed)
        );
    }

    #[cfg(unix)]
    fn read_root_handle(
        path: &Path,
        allowed_files: &[&str],
    ) -> Result<ReadRootHandle, CapabilityError> {
        Ok(ReadRootHandle {
            directory: open_absolute_directory_nofollow(path)?,
            allowed_files: allowed_files
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        })
    }

    #[cfg(unix)]
    #[test]
    fn published_file_read_is_exact_bounded_and_pins_the_root_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let root_path = directory.path().join("published");
        fs::create_dir_all(root_path.join("daily"))?;
        let root_path = root_path.canonicalize()?;
        fs::write(root_path.join("daily/status.txt"), b"trusted-report")?;
        fs::write(root_path.join("daily/private.txt"), b"private")?;
        let root = read_root_handle(&root_path, &["daily/status.txt"])?;
        assert!(root_allows(&root, "daily/status.txt"));
        assert!(!root_allows(&root, "daily/private.txt"));

        let moved = directory.path().join("published-original");
        fs::rename(&root_path, &moved)?;
        fs::create_dir_all(root_path.join("daily"))?;
        fs::write(root_path.join("daily/status.txt"), b"replacement")?;

        let mut opened = open_published_file(&root, "daily/status.txt")?;
        let mut contents = Vec::new();
        opened.read_to_end(&mut contents)?;
        assert_eq!(contents, b"trusted-report");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn published_file_read_rejects_symlinks_hardlinks_executables_and_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::TempDir::new()?;
        let root_path = directory.path().join("published");
        fs::create_dir_all(root_path.join("nested"))?;
        let root_path = root_path.canonicalize()?;
        fs::write(root_path.join("safe.txt"), b"safe")?;
        fs::write(root_path.join("outside.txt"), b"outside")?;
        fs::write(root_path.join("executable.txt"), b"program")?;
        fs::set_permissions(
            root_path.join("executable.txt"),
            fs::Permissions::from_mode(0o700),
        )?;
        fs::hard_link(root_path.join("safe.txt"), root_path.join("hard.txt"))?;
        symlink(root_path.join("outside.txt"), root_path.join("link.txt"))?;
        symlink(root_path.join("nested"), root_path.join("linked-directory"))?;
        let root = read_root_handle(
            &root_path,
            &[
                "safe.txt",
                "hard.txt",
                "link.txt",
                "executable.txt",
                "nested",
                "linked-directory/file.txt",
            ],
        )?;

        for denied in [
            "safe.txt",
            "hard.txt",
            "link.txt",
            "executable.txt",
            "nested",
            "linked-directory/file.txt",
        ] {
            assert_eq!(
                open_published_file(&root, denied).map(|_| ()),
                Err(CapabilityError::UnauthorizedFileAccess),
                "{denied} should be denied"
            );
        }
        Ok(())
    }
}
