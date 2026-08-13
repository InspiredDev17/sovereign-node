use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::authz::VerifiedAction;
use crate::config::{ApprovedActionConfig, NodeConfig};
use crate::process_status::{ProcessStatusError, ProcessStatusReporter};
use crate::protocol::{
    ActionArguments, ActionErrorCode, ActionResultV1, ActionTarget, ApprovedActionOutcome,
    ApprovedActionResultV1, FileReadResultV1, FileWriteMode, FileWriteResultV1, GpuResourceV1,
    InferenceEngineStatusV1, LoadedModelV1, Sha256Digest, TrustStatus, UnixMillis,
};
use crate::resources::{HealthReporter, QueueSnapshot, ResourceReporter, ResourceSnapshotReporter};
use crate::service_status::{ServiceStatusError, ServiceStatusReporter};

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
    #[error("approved action executable does not match local policy")]
    ExecutablePolicy,
    #[error("local execution failed")]
    Execution,
    #[error("capability result exceeded a local resource limit")]
    ResourceExhausted,
}

impl CapabilityError {
    #[must_use]
    pub const fn code(&self) -> ActionErrorCode {
        match self {
            Self::TargetNotAllowed | Self::ExecutablePolicy => ActionErrorCode::TargetNotAllowed,
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
    health: HealthReporter,
}

impl CapabilityExecutor {
    #[must_use]
    pub fn new(config: Arc<NodeConfig>, resources: ResourceReporter) -> Self {
        let health = HealthReporter::new(&config.health);
        let external_resources = ResourceSnapshotReporter::new(&config.resource_reporting);
        let process_status = ProcessStatusReporter::new(config.process_reporting.snapshot.as_ref());
        let service_status = ServiceStatusReporter::new(config.service_reporting.snapshot.as_ref());
        Self {
            config,
            resources,
            external_resources,
            process_status,
            service_status,
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
            (
                ActionTarget::File {
                    root_id,
                    relative_path,
                },
                ActionArguments::FileWrite {
                    contents,
                    mode,
                    expected_current_digest,
                },
            ) => self
                .write_file(
                    root_id,
                    relative_path,
                    contents,
                    *mode,
                    *expected_current_digest,
                )
                .map(ActionResultV1::FileWrite),
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
                ActionTarget::ApprovedAction { action_id },
                ActionArguments::ExecuteApprovedAction { parameters },
            ) => self
                .execute_approved_action(action_id, parameters)
                .await
                .map(ActionResultV1::ExecuteApprovedAction),
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
            (ActionTarget::Repository { .. }, ActionArguments::RepositoryStatus { .. }) => {
                Err(CapabilityError::Unsupported)
            }
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
        let root = self.open_file_root(root_id)?;
        let policy_max = u64::try_from(self.config.policy.max_file_read_bytes)
            .map_err(|_| CapabilityError::ResourceExhausted)?;
        if requested_max == 0 || requested_max > policy_max {
            return Err(CapabilityError::ResourceExhausted);
        }
        let mut file = root
            .open(relative_path)
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
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

    fn write_file(
        &self,
        root_id: &str,
        relative_path: &str,
        contents: &[u8],
        mode: FileWriteMode,
        expected_current_digest: Option<Sha256Digest>,
    ) -> Result<FileWriteResultV1, CapabilityError> {
        if contents.len() > self.config.policy.max_file_write_bytes {
            return Err(CapabilityError::ResourceExhausted);
        }
        let root = self.open_file_root(root_id)?;
        let mut options = OpenOptions::new();
        options.write(true);
        let mut file = match mode {
            FileWriteMode::CreateNew => {
                if expected_current_digest.is_some() {
                    return Err(CapabilityError::ArgumentMismatch);
                }
                options.create_new(true);
                root.open_with(relative_path, &options)
            }
            FileWriteMode::ReplaceExisting => {
                let expected =
                    expected_current_digest.ok_or(CapabilityError::UnauthorizedFileAccess)?;
                options.read(true);
                let mut file = root
                    .open_with(relative_path, &options)
                    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
                let metadata = file
                    .metadata()
                    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
                if !metadata.is_file()
                    || metadata.len()
                        > u64::try_from(self.config.policy.max_file_write_bytes).unwrap_or(u64::MAX)
                {
                    return Err(CapabilityError::UnauthorizedFileAccess);
                }
                let mut current = Vec::with_capacity(
                    usize::try_from(metadata.len())
                        .map_err(|_| CapabilityError::ResourceExhausted)?,
                );
                file.read_to_end(&mut current)
                    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
                if Sha256Digest(Sha256::digest(&current).into()) != expected {
                    return Err(CapabilityError::UnauthorizedFileAccess);
                }
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
                file.set_len(0)
                    .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
                Ok(file)
            }
        }
        .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;

        file.write_all(contents)
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        file.sync_all()
            .map_err(|_| CapabilityError::UnauthorizedFileAccess)?;
        Ok(FileWriteResultV1 {
            bytes_written: u64::try_from(contents.len()).unwrap_or(u64::MAX),
            content_digest: Sha256Digest(Sha256::digest(contents).into()),
        })
    }

    fn open_file_root(&self, root_id: &str) -> Result<Dir, CapabilityError> {
        let path = self
            .config
            .file_roots
            .get(root_id)
            .ok_or(CapabilityError::TargetNotAllowed)?;
        Dir::open_ambient_dir(path, ambient_authority())
            .map_err(|_| CapabilityError::TargetNotAllowed)
    }

    async fn execute_approved_action(
        &self,
        action_id: &str,
        parameters: &BTreeMap<String, String>,
    ) -> Result<ApprovedActionResultV1, CapabilityError> {
        // v1 intentionally defines no caller-controlled parameter schema. A future schema may map
        // typed values to a local adapter, but values must never become argv or environment input.
        if !parameters.is_empty() {
            return Err(CapabilityError::ArgumentMismatch);
        }
        let action = self
            .config
            .approved_actions
            .get(action_id)
            .ok_or(CapabilityError::TargetNotAllowed)?;
        validate_executable(action)?;
        let timeout_seconds = action
            .timeout_secs
            .unwrap_or(self.config.policy.max_action_runtime_secs);
        let mut command = tokio::process::Command::new(&action.executable);
        command
            .args(&action.fixed_arguments)
            .current_dir(&action.working_directory)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| CapabilityError::Execution)?;
        let stdout = child.stdout.take().ok_or(CapabilityError::Execution)?;
        let stderr = child.stderr.take().ok_or(CapabilityError::Execution)?;
        let output_limit = self.config.policy.max_action_output_bytes;
        let stdout_task = tokio::spawn(read_bounded_and_drain(stdout, output_limit));
        let stderr_task = tokio::spawn(read_bounded_and_drain(stderr, 0));

        let outcome =
            match tokio::time::timeout(Duration::from_secs(timeout_seconds), child.wait()).await {
                Ok(Ok(status)) if status.success() => ApprovedActionOutcome::Completed,
                Ok(Ok(_)) | Ok(Err(_)) => ApprovedActionOutcome::Failed,
                Err(_) => {
                    child.kill().await.map_err(|_| CapabilityError::Execution)?;
                    let _ = child.wait().await;
                    ApprovedActionOutcome::TimedOut
                }
            };
        let drain_deadline = Duration::from_secs(2);
        let (output, output_truncated) = tokio::time::timeout(drain_deadline, stdout_task)
            .await
            .map_err(|_| CapabilityError::Execution)?
            .map_err(|_| CapabilityError::Execution)?
            .map_err(|_| CapabilityError::Execution)?;
        tokio::time::timeout(drain_deadline, stderr_task)
            .await
            .map_err(|_| CapabilityError::Execution)?
            .map_err(|_| CapabilityError::Execution)?
            .map_err(|_| CapabilityError::Execution)?;
        Ok(ApprovedActionResultV1 {
            outcome,
            output,
            output_truncated,
        })
    }
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

async fn read_bounded_and_drain<R>(
    mut reader: R,
    retain_limit: usize,
) -> Result<(Vec<u8>, bool), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut retained = Vec::with_capacity(retain_limit.min(65_536));
    let mut truncated = false;
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = retain_limit.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < count;
    }
    Ok((retained, truncated))
}

fn validate_executable(action: &ApprovedActionConfig) -> Result<(), CapabilityError> {
    if is_shell_or_interpreter(&action.executable) {
        return Err(CapabilityError::ExecutablePolicy);
    }
    let metadata = std::fs::symlink_metadata(&action.executable)
        .map_err(|_| CapabilityError::ExecutablePolicy)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CapabilityError::ExecutablePolicy);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
            return Err(CapabilityError::ExecutablePolicy);
        }
    }
    if let Some(expected_hex) = &action.executable_sha256 {
        let contents =
            std::fs::read(&action.executable).map_err(|_| CapabilityError::ExecutablePolicy)?;
        if contents.len() > 512 * 1_048_576 {
            return Err(CapabilityError::ExecutablePolicy);
        }
        let actual = hex::encode(Sha256::digest(contents));
        if !actual.eq_ignore_ascii_case(expected_hex) {
            return Err(CapabilityError::ExecutablePolicy);
        }
    }
    Ok(())
}

fn is_shell_or_interpreter(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return true;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "ksh"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "python"
            | "python3"
            | "node"
            | "deno"
            | "bun"
    )
}

#[cfg(test)]
mod tests {
    use crate::protocol::{Availability, GpuMemoryKind, ModelLoadState, UtilizationPermille};

    use super::*;

    #[test]
    fn shell_and_script_interpreters_are_never_catalog_executables() {
        for path in ["/bin/sh", "/bin/bash", "/usr/bin/python3", "/usr/bin/node"] {
            assert!(is_shell_or_interpreter(Path::new(path)));
        }
        assert!(!is_shell_or_interpreter(Path::new(
            "/usr/local/libexec/fixed-action"
        )));
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
}
