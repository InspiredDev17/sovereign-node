//! Versioned wire types shared by the node, Action Broker, and owner clients.
//!
//! The protocol deliberately contains data and canonicalization only. Policy,
//! replay persistence, key lookup, and Ed25519 verification belong to the local
//! authorization layer. Enum variant order and field order are wire format: add
//! new protocol versions rather than reordering existing variants or fields.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Component,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const PROTOCOL_VERSION_V1: u16 = 1;

pub const NONCE_LENGTH: usize = 32;
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

pub const MAX_DISPLAY_NAME_BYTES: usize = 128;
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_DETAIL_BYTES: usize = 1_024;
pub const MAX_VERSION_BYTES: usize = 128;
pub const MAX_CAPABILITIES: usize = 64;
pub const MAX_PARAMETERS: usize = 64;
pub const MAX_PARAMETER_KEY_BYTES: usize = 128;
pub const MAX_PARAMETER_VALUE_BYTES: usize = 4_096;
pub const MAX_FILE_READ_BYTES: u64 = 4 * 1_024 * 1_024;
pub const MAX_FILE_WRITE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_ACTION_OUTPUT_BYTES: usize = 1_024 * 1_024;
pub const MAX_DISKS: usize = 128;
pub const MAX_GPUS: usize = 32;
pub const MAX_LOADED_MODELS: usize = 128;
pub const MAX_ENGINE_STATUSES: usize = 64;
pub const MAX_RESPONSE_MESSAGE_BYTES: usize = 1_024;
/// Transport implementations must reject a frame larger than this before
/// asking postcard to allocate and decode its contents.
pub const MAX_WIRE_MESSAGE_BYTES: usize = 8 * 1_024 * 1_024;

const ACTION_ARGUMENTS_DIGEST_DOMAIN: &[u8] = b"sovereign-node/action-arguments/v1\0";
const ACTION_TARGET_DIGEST_DOMAIN: &[u8] = b"sovereign-node/action-target/v1\0";
const ACTION_REQUEST_DIGEST_DOMAIN: &[u8] = b"sovereign-node/action-request-digest/v1\0";
const OWNER_ACTION_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/owner-action-signature/v1\0";
const BROKER_ACTION_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/broker-action-signature/v1\0";
const NODE_REGISTRATION_SIGNATURE_DOMAIN: &[u8] =
    b"sovereign-node/node-registration-signature/v1\0";
const CAPABILITY_MANIFEST_DIGEST_DOMAIN: &[u8] = b"sovereign-node/capability-manifest-digest/v1\0";
const NODE_IDENTITY_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"sovereign-node/node-identity-proof-signature/v2\0";
const ACTION_RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"sovereign-node/action-response-signature/v1\0";

pub const MAX_IDENTITY_PROOF_TTL_MILLIS: u64 = 5 * 60 * 1_000;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(NodeId);
uuid_id!(RequestId);
uuid_id!(TaskId);
uuid_id!(AgentId);
uuid_id!(PairingId);
uuid_id!(AuthorizationId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UnixMillis(pub u64);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Nonce(pub [u8; NONCE_LENGTH]);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PublicKeyBytes(pub [u8; ED25519_PUBLIC_KEY_LENGTH]);

/// A wire-safe Ed25519 signature whose exact length is checked while decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(ValidationError::InvalidSignatureLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_array(&self) -> Result<[u8; ED25519_SIGNATURE_LENGTH], ValidationError> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| ValidationError::InvalidSignatureLength(self.0.len()))
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != ED25519_SIGNATURE_LENGTH {
            return Err(D::Error::custom("Ed25519 signature must contain 64 bytes"));
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Capability {
    SystemInfo,
    ResourceStatus,
    FileRead,
    FileWrite,
    ProcessStatus,
    ServiceStatus,
    ExecuteApprovedAction,
    GpuStatus,
    EngineStatus,
    ModelStatus,
    RepositoryStatus,
    AgentGreenHealth,
    ActionBrokerHealth,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionTarget {
    Node,
    File {
        root_id: String,
        relative_path: String,
    },
    Process {
        process_id: u32,
    },
    Service {
        service_name: String,
    },
    ApprovedAction {
        action_id: String,
    },
    Gpu {
        index: Option<u16>,
    },
    Engine {
        engine_id: Option<String>,
    },
    Model {
        model_id: Option<String>,
    },
    Repository {
        repository_id: String,
    },
    AgentGreen,
    ActionBroker,
    /// Owner-defined logical process identity. Unlike `Process`, this never exposes or accepts a
    /// host PID, which may be reused and is not a stable authorization target.
    ManagedProcess {
        process_id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FileWriteMode {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionArguments {
    SystemInfo,
    ResourceStatus,
    FileRead {
        offset: u64,
        max_bytes: u64,
    },
    FileWrite {
        contents: Vec<u8>,
        mode: FileWriteMode,
        expected_current_digest: Option<Sha256Digest>,
    },
    ProcessStatus {
        include_children: bool,
    },
    ServiceStatus,
    ExecuteApprovedAction {
        /// Data parameters for a locally installed, allowlisted action. These
        /// values are not command-line or shell source.
        parameters: BTreeMap<String, String>,
    },
    GpuStatus,
    EngineStatus,
    ModelStatus,
    RepositoryStatus {
        include_untracked_summary: bool,
    },
    AgentGreenHealth,
    ActionBrokerHealth,
}

impl ActionArguments {
    #[must_use]
    pub const fn capability(&self) -> Capability {
        match self {
            Self::SystemInfo => Capability::SystemInfo,
            Self::ResourceStatus => Capability::ResourceStatus,
            Self::FileRead { .. } => Capability::FileRead,
            Self::FileWrite { .. } => Capability::FileWrite,
            Self::ProcessStatus { .. } => Capability::ProcessStatus,
            Self::ServiceStatus => Capability::ServiceStatus,
            Self::ExecuteApprovedAction { .. } => Capability::ExecuteApprovedAction,
            Self::GpuStatus => Capability::GpuStatus,
            Self::EngineStatus => Capability::EngineStatus,
            Self::ModelStatus => Capability::ModelStatus,
            Self::RepositoryStatus { .. } => Capability::RepositoryStatus,
            Self::AgentGreenHealth => Capability::AgentGreenHealth,
            Self::ActionBrokerHealth => Capability::ActionBrokerHealth,
        }
    }

    pub fn digest(&self) -> Result<Sha256Digest, postcard::Error> {
        digest_postcard(ACTION_ARGUMENTS_DIGEST_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::FileRead { max_bytes, .. } if *max_bytes == 0 => {
                Err(ValidationError::InvalidValue("file read max_bytes"))
            }
            Self::FileRead { max_bytes, .. } if *max_bytes > MAX_FILE_READ_BYTES => {
                Err(ValidationError::LimitExceeded("file read bytes"))
            }
            Self::FileWrite { contents, .. } if contents.len() > MAX_FILE_WRITE_BYTES => {
                Err(ValidationError::LimitExceeded("file write bytes"))
            }
            Self::ExecuteApprovedAction { parameters } => validate_parameters(parameters),
            _ => Ok(()),
        }
    }
}

impl Capability {
    #[must_use]
    pub fn matches_arguments(self, arguments: &ActionArguments) -> bool {
        self == arguments.capability()
    }

    #[must_use]
    pub const fn matches_target(self, target: &ActionTarget) -> bool {
        matches!(
            (self, target),
            (Self::SystemInfo | Self::ResourceStatus, ActionTarget::Node)
                | (Self::FileRead | Self::FileWrite, ActionTarget::File { .. })
                | (Self::ProcessStatus, ActionTarget::ManagedProcess { .. })
                | (Self::ServiceStatus, ActionTarget::Service { .. })
                | (
                    Self::ExecuteApprovedAction,
                    ActionTarget::ApprovedAction { .. }
                )
                | (Self::GpuStatus, ActionTarget::Gpu { .. })
                | (Self::EngineStatus, ActionTarget::Engine { .. })
                | (Self::ModelStatus, ActionTarget::Model { .. })
                | (Self::RepositoryStatus, ActionTarget::Repository { .. })
                | (Self::AgentGreenHealth, ActionTarget::AgentGreen)
                | (Self::ActionBrokerHealth, ActionTarget::ActionBroker)
        )
    }
}

impl ActionTarget {
    pub fn digest(&self) -> Result<Sha256Digest, postcard::Error> {
        digest_postcard(ACTION_TARGET_DIGEST_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Node | Self::Gpu { index: None } | Self::AgentGreen | Self::ActionBroker => {
                Ok(())
            }
            Self::File {
                root_id,
                relative_path,
            } => {
                validate_local_identifier(root_id, "file root id")?;
                validate_relative_path(relative_path)
            }
            Self::Repository { repository_id } => {
                validate_local_identifier(repository_id, "repository id")
            }
            Self::Process { process_id } if *process_id == 0 => {
                Err(ValidationError::InvalidValue("process id"))
            }
            Self::Process { .. } | Self::Gpu { index: Some(_) } => Ok(()),
            Self::ManagedProcess { process_id } => {
                validate_local_identifier(process_id, "logical process id")
            }
            Self::Service { service_name } => {
                validate_local_identifier(service_name, "logical service id")
            }
            Self::ApprovedAction { action_id } => {
                validate_required_string(action_id, MAX_ID_BYTES, "approved action id")
            }
            Self::Engine { engine_id } => {
                validate_optional_string(engine_id, MAX_ID_BYTES, "engine id")
            }
            Self::Model { model_id } => {
                validate_optional_string(model_id, MAX_ID_BYTES, "model id")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorityKind {
    OwnerInteractive,
    OwnerPolicyGrant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserAuthorityV1 {
    pub authority_id: AuthorizationId,
    pub owner_id: String,
    pub kind: AuthorityKind,
    pub approval_reason: Option<String>,
}

impl UserAuthorityV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_required_string(&self.owner_id, MAX_ID_BYTES, "owner id")?;
        validate_optional_string(&self.approval_reason, MAX_DETAIL_BYTES, "approval reason")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayProtectionV1 {
    pub nonce: Nonce,
    /// Monotonic within a pairing trust epoch. The local replay store must
    /// atomically reject an already consumed `(pairing_id, sequence, nonce)`.
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizationClaimsV1 {
    pub authorization_id: AuthorizationId,
    pub pairing_id: PairingId,
    pub trust_epoch: u64,
    pub policy_version: u64,
    pub permitted_capability: Capability,
    pub permitted_target_digest: Sha256Digest,
    pub owner_key_id: Sha256Digest,
    pub broker_key_id: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionRequestV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub user_authority: UserAuthorityV1,
    pub node_id: NodeId,
    pub capability: Capability,
    pub target: ActionTarget,
    pub arguments: ActionArguments,
    pub arguments_digest: Sha256Digest,
    pub issued_at: UnixMillis,
    pub not_before: UnixMillis,
    pub expires_at: UnixMillis,
    pub replay_protection: ReplayProtectionV1,
    pub authorization: AuthorizationClaimsV1,
}

impl ActionRequestV1 {
    // Explicit protocol fields are preferable here to an opaque builder whose
    // defaults could silently weaken an authorization envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: RequestId,
        task_id: TaskId,
        agent_id: AgentId,
        user_authority: UserAuthorityV1,
        node_id: NodeId,
        target: ActionTarget,
        arguments: ActionArguments,
        issued_at: UnixMillis,
        not_before: UnixMillis,
        expires_at: UnixMillis,
        replay_protection: ReplayProtectionV1,
        mut authorization: AuthorizationClaimsV1,
    ) -> Result<Self, postcard::Error> {
        let capability = arguments.capability();
        let arguments_digest = arguments.digest()?;
        authorization.permitted_capability = capability;
        authorization.permitted_target_digest = target.digest()?;
        Ok(Self {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: PROTOCOL_VERSION_V1,
            request_id,
            task_id,
            agent_id,
            user_authority,
            node_id,
            capability,
            target,
            arguments,
            arguments_digest,
            issued_at,
            not_before,
            expires_at,
            replay_protection,
            authorization,
        })
    }

    pub fn owner_signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        domain_separated_postcard(OWNER_ACTION_SIGNATURE_DOMAIN, self)
    }

    pub fn request_digest(&self) -> Result<Sha256Digest, postcard::Error> {
        digest_postcard(ACTION_REQUEST_DIGEST_DOMAIN, self)
    }

    pub fn validate_for_node(
        &self,
        expected_node: NodeId,
        now: UnixMillis,
        expected_trust_epoch: u64,
    ) -> Result<(), ValidationError> {
        self.validate_structure()?;
        if self.node_id != expected_node {
            return Err(ValidationError::WrongNode {
                expected: expected_node,
                actual: self.node_id,
            });
        }
        if now.0 < self.not_before.0 {
            return Err(ValidationError::NotYetValid);
        }
        if now.0 >= self.expires_at.0 {
            return Err(ValidationError::Expired);
        }
        if self.authorization.trust_epoch != expected_trust_epoch {
            return Err(ValidationError::TrustEpochMismatch);
        }
        Ok(())
    }

    pub fn validate_structure(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ValidationError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self.issued_at.0 > self.not_before.0 || self.not_before.0 >= self.expires_at.0 {
            return Err(ValidationError::InvalidTimeWindow);
        }
        if self.replay_protection.nonce.0 == [0; NONCE_LENGTH] {
            return Err(ValidationError::InvalidValue("replay nonce"));
        }
        validate_uuid(self.request_id.as_uuid(), "request id")?;
        validate_uuid(self.task_id.as_uuid(), "task id")?;
        validate_uuid(self.agent_id.as_uuid(), "agent id")?;
        validate_uuid(self.node_id.as_uuid(), "node id")?;
        validate_uuid(
            self.user_authority.authority_id.as_uuid(),
            "user authority id",
        )?;
        validate_uuid(
            self.authorization.authorization_id.as_uuid(),
            "authorization id",
        )?;
        validate_uuid(self.authorization.pairing_id.as_uuid(), "pairing id")?;
        if !self.capability.matches_arguments(&self.arguments) {
            return Err(ValidationError::CapabilityMismatch);
        }
        if !self.capability.matches_target(&self.target) {
            return Err(ValidationError::TargetMismatch);
        }
        self.target.validate()?;
        self.arguments.validate()?;
        self.user_authority.validate()?;

        let actual_arguments_digest = self
            .arguments
            .digest()
            .map_err(|_| ValidationError::CanonicalEncoding)?;
        if actual_arguments_digest != self.arguments_digest {
            return Err(ValidationError::ArgumentsDigestMismatch);
        }
        if self.authorization.permitted_capability != self.capability {
            return Err(ValidationError::AuthorizationCapabilityMismatch);
        }
        let target_digest = self
            .target
            .digest()
            .map_err(|_| ValidationError::CanonicalEncoding)?;
        if self.authorization.permitted_target_digest != target_digest {
            return Err(ValidationError::AuthorizationTargetMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedActionV1 {
    pub request: ActionRequestV1,
    pub owner_signature: SignatureBytes,
    pub broker_signature: SignatureBytes,
}

impl SignedActionV1 {
    pub fn broker_signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        #[derive(Serialize)]
        struct BrokerSignedPayload<'a> {
            request: &'a ActionRequestV1,
            owner_signature: &'a SignatureBytes,
        }

        domain_separated_postcard(
            BROKER_ACTION_SIGNATURE_DOMAIN,
            &BrokerSignedPayload {
                request: &self.request,
                owner_signature: &self.owner_signature,
            },
        )
    }

    pub fn payload_digest(&self) -> Result<Sha256Digest, postcard::Error> {
        self.request.request_digest()
    }

    pub fn validate_for_node(
        &self,
        expected_node: NodeId,
        now: UnixMillis,
        expected_trust_epoch: u64,
    ) -> Result<(), ValidationError> {
        self.request
            .validate_for_node(expected_node, now, expected_trust_epoch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    UnsupportedSchemaVersion(u16),
    UnsupportedProtocolVersion(u16),
    WrongNode { expected: NodeId, actual: NodeId },
    InvalidTimeWindow,
    NotYetValid,
    Expired,
    TrustEpochMismatch,
    CapabilityMismatch,
    TargetMismatch,
    ArgumentsDigestMismatch,
    AuthorizationCapabilityMismatch,
    AuthorizationTargetMismatch,
    InvalidSignatureLength(usize),
    EmptyValue(&'static str),
    InvalidValue(&'static str),
    LimitExceeded(&'static str),
    CanonicalEncoding,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported schema version {version}")
            }
            Self::UnsupportedProtocolVersion(version) => {
                write!(formatter, "unsupported protocol version {version}")
            }
            Self::WrongNode { expected, actual } => {
                write!(formatter, "wrong node: expected {expected}, got {actual}")
            }
            Self::InvalidTimeWindow => formatter.write_str("invalid authorization time window"),
            Self::NotYetValid => formatter.write_str("authorization is not yet valid"),
            Self::Expired => formatter.write_str("authorization has expired"),
            Self::TrustEpochMismatch => formatter.write_str("pairing trust epoch mismatch"),
            Self::CapabilityMismatch => formatter.write_str("capability and arguments mismatch"),
            Self::TargetMismatch => formatter.write_str("capability and target mismatch"),
            Self::ArgumentsDigestMismatch => formatter.write_str("arguments digest mismatch"),
            Self::AuthorizationCapabilityMismatch => {
                formatter.write_str("authorization capability mismatch")
            }
            Self::AuthorizationTargetMismatch => {
                formatter.write_str("authorization target mismatch")
            }
            Self::InvalidSignatureLength(length) => {
                write!(formatter, "invalid Ed25519 signature length {length}")
            }
            Self::EmptyValue(field) => write!(formatter, "{field} must not be empty"),
            Self::InvalidValue(field) => write!(formatter, "{field} is invalid"),
            Self::LimitExceeded(field) => write!(formatter, "{field} exceeds protocol limit"),
            Self::CanonicalEncoding => formatter.write_str("canonical encoding failed"),
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionStatus {
    Accepted,
    Running,
    Succeeded,
    Rejected,
    Failed,
    Expired,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionErrorCode {
    Unauthorized,
    ForgedAuthorization,
    RevokedPairing,
    ReplayDetected,
    DuplicateRequest,
    ExpiredAuthorization,
    NotYetValid,
    WrongNode,
    CapabilityNotAdvertised,
    CapabilityMismatch,
    TargetNotAllowed,
    UnauthorizedFileAccess,
    VersionMismatch,
    ResourceExhausted,
    DisconnectedTrustAuthority,
    InvalidRequest,
    LocalExecutionFailed,
    Internal,
    ClockRollback,
    StoragePressure,
}

impl ActionRequestV1 {
    pub fn validate_execution_time(&self, now: UnixMillis) -> Result<(), ValidationError> {
        if now.0 < self.not_before.0 {
            return Err(ValidationError::NotYetValid);
        }
        if now.0 >= self.expires_at.0 {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionErrorV1 {
    pub code: ActionErrorCode,
    /// Safe for the remote caller. Local logs may contain a separately redacted
    /// diagnostic, but raw paths, credentials, and command material do not.
    pub message: String,
    pub retryable: bool,
}

impl ActionErrorV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_required_string(
            &self.message,
            MAX_RESPONSE_MESSAGE_BYTES,
            "response message",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionResultV1 {
    SystemInfo(NodeSystemInfoV1),
    ResourceStatus(NodeResourceReportV1),
    FileRead(FileReadResultV1),
    FileWrite(FileWriteResultV1),
    ProcessStatus(EntityStatusV1),
    ServiceStatus(EntityStatusV1),
    ExecuteApprovedAction(ApprovedActionResultV1),
    GpuStatus(Vec<GpuResourceV1>),
    EngineStatus(Vec<InferenceEngineStatusV1>),
    ModelStatus(Vec<LoadedModelV1>),
    RepositoryStatus(RepositoryStatusV1),
    AgentGreenHealth(ComponentHealthV1),
    ActionBrokerHealth(ComponentHealthV1),
}

impl ActionResultV1 {
    #[must_use]
    pub const fn capability(&self) -> Capability {
        match self {
            Self::SystemInfo(_) => Capability::SystemInfo,
            Self::ResourceStatus(_) => Capability::ResourceStatus,
            Self::FileRead(_) => Capability::FileRead,
            Self::FileWrite(_) => Capability::FileWrite,
            Self::ProcessStatus(_) => Capability::ProcessStatus,
            Self::ServiceStatus(_) => Capability::ServiceStatus,
            Self::ExecuteApprovedAction(_) => Capability::ExecuteApprovedAction,
            Self::GpuStatus(_) => Capability::GpuStatus,
            Self::EngineStatus(_) => Capability::EngineStatus,
            Self::ModelStatus(_) => Capability::ModelStatus,
            Self::RepositoryStatus(_) => Capability::RepositoryStatus,
            Self::AgentGreenHealth(_) => Capability::AgentGreenHealth,
            Self::ActionBrokerHealth(_) => Capability::ActionBrokerHealth,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::ResourceStatus(report) => report.validate(),
            Self::FileRead(result) if result.contents.len() > MAX_FILE_READ_BYTES as usize => {
                Err(ValidationError::LimitExceeded("file read result"))
            }
            Self::ExecuteApprovedAction(result)
                if result.output.len() > MAX_ACTION_OUTPUT_BYTES =>
            {
                Err(ValidationError::LimitExceeded("approved action output"))
            }
            Self::GpuStatus(gpus) => validate_gpu_results(gpus),
            Self::EngineStatus(engines) => validate_engine_results(engines),
            Self::ModelStatus(models) => validate_model_results(models),
            Self::ProcessStatus(status) | Self::ServiceStatus(status) => status.validate(),
            Self::RepositoryStatus(status) => status.validate(),
            Self::AgentGreenHealth(health) | Self::ActionBrokerHealth(health) => {
                validate_optional_string(&health.detail, MAX_DETAIL_BYTES, "health detail")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionResponseV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub node_id: NodeId,
    pub status: ActionStatus,
    pub result: Option<ActionResultV1>,
    pub error: Option<ActionErrorV1>,
    pub started_at: Option<UnixMillis>,
    pub finished_at: UnixMillis,
}

impl ActionResponseV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        domain_separated_postcard(ACTION_RESPONSE_SIGNATURE_DOMAIN, self)
    }

    pub fn digest(&self) -> Result<Sha256Digest, postcard::Error> {
        digest_postcard(ACTION_RESPONSE_SIGNATURE_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ValidationError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self
            .started_at
            .is_some_and(|started_at| started_at.0 > self.finished_at.0)
        {
            return Err(ValidationError::InvalidTimeWindow);
        }
        match self.status {
            ActionStatus::Succeeded if self.result.is_some() && self.error.is_none() => {}
            ActionStatus::Rejected
            | ActionStatus::Failed
            | ActionStatus::Expired
            | ActionStatus::Duplicate
                if self.result.is_none() && self.error.is_some() => {}
            ActionStatus::Accepted | ActionStatus::Running
                if self.result.is_none() && self.error.is_none() => {}
            _ => return Err(ValidationError::InvalidValue("action response outcome")),
        }
        if let Some(error) = &self.error {
            error.validate()?;
        }
        if let Some(result) = &self.result {
            result.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedActionResponseV1 {
    pub response: ActionResponseV1,
    pub response_digest: Sha256Digest,
    pub node_signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustStatus {
    Unpaired,
    PairingPending,
    Trusted,
    Suspended,
    Degraded,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CryptographicIdentityV1 {
    pub algorithm: KeyAlgorithm,
    pub key_id: Sha256Digest,
    pub public_key: PublicKeyBytes,
    pub created_at: UnixMillis,
    pub rotation_counter: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentityV1 {
    /// Owner-selected name; it is not a hardware serial number.
    pub display_name: String,
    /// Randomly generated once at installation, not derived from hardware.
    pub installation_id: Uuid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperatingSystemFamily {
    Linux,
    MacOs,
    Windows,
    FreeBsd,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Architecture {
    X86_64,
    Aarch64,
    RiscV64,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformInfoV1 {
    pub os: OperatingSystemFamily,
    pub os_version: String,
    pub architecture: Architecture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSummaryV1 {
    pub logical_cpu_count: u16,
    pub physical_cpu_count: Option<u16>,
    pub total_ram_bytes: u64,
    pub total_unified_memory_bytes: Option<u64>,
    /// Deliberately excludes serial numbers, MAC addresses, and firmware IDs.
    pub gpus: Vec<GpuDescriptionV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDescriptionV1 {
    pub index: u16,
    pub vendor: String,
    pub model: String,
    pub memory_kind: GpuMemoryKind,
    pub total_memory_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GpuMemoryKind {
    DedicatedVram,
    Unified,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareVersionV1 {
    pub version: String,
    pub build_id: String,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifestV1 {
    pub manifest_version: u64,
    /// An explicit set. Empty means the node accepts no remote actions.
    pub capabilities: Vec<Capability>,
    pub generated_at: UnixMillis,
}

impl CapabilityManifestV1 {
    pub fn digest(&self) -> Result<Sha256Digest, postcard::Error> {
        digest_postcard(CAPABILITY_MANIFEST_DIGEST_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ValidationError::LimitExceeded("capability manifest"));
        }
        let mut sorted = self.capabilities.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.capabilities.len() {
            return Err(ValidationError::InvalidValue("duplicate capability"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRegistrationV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub node_id: NodeId,
    pub device: DeviceIdentityV1,
    pub cryptographic_identity: CryptographicIdentityV1,
    pub capability_manifest: CapabilityManifestV1,
    pub platform: PlatformInfoV1,
    pub hardware: HardwareSummaryV1,
    pub trust_status: TrustStatus,
    pub software: SoftwareVersionV1,
    pub generated_at: UnixMillis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeRegistrationV1 {
    pub registration: NodeRegistrationV1,
    /// Proof of possession for `registration.cryptographic_identity.public_key`.
    pub node_signature: SignatureBytes,
}

/// Privacy-preserving summary of the currently active peer trust set. The
/// digest binds exact active records without publishing peer identifiers or keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveTrustSummaryV1 {
    pub active_peer_count: u32,
    pub maximum_peer_trust_epoch: u64,
    pub active_trust_set_digest: Sha256Digest,
}

/// Fresh, requester-bound proof of the node's public identity snapshot. This
/// authenticates one statement; it grants no action authority and is not host attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentityProofV2 {
    pub schema_version: u16,
    pub registration: NodeRegistrationV1,
    pub capability_manifest_digest: Sha256Digest,
    pub local_policy_digest: Sha256Digest,
    pub active_trust: ActiveTrustSummaryV1,
    pub requester_challenge: Nonce,
    pub issued_at: UnixMillis,
    pub expires_at: UnixMillis,
}

impl NodeIdentityProofV2 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        domain_separated_postcard(NODE_IDENTITY_PROOF_SIGNATURE_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != 2 {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        self.registration.validate()?;
        if self.registration.generated_at != self.issued_at {
            return Err(ValidationError::InvalidValue(
                "identity proof generation time",
            ));
        }
        let expected_key_id = Sha256Digest(
            Sha256::digest(self.registration.cryptographic_identity.public_key.0).into(),
        );
        if expected_key_id != self.registration.cryptographic_identity.key_id {
            return Err(ValidationError::InvalidValue("node key ID"));
        }
        if self
            .registration
            .capability_manifest
            .digest()
            .map_err(|_| ValidationError::InvalidValue("capability manifest canonical encoding"))?
            != self.capability_manifest_digest
        {
            return Err(ValidationError::InvalidValue("capability manifest digest"));
        }
        if self.local_policy_digest.0 == [0_u8; 32]
            || self.registration.capability_manifest.manifest_version == 0
        {
            return Err(ValidationError::InvalidValue("local policy binding"));
        }
        if self.requester_challenge.0 == [0_u8; NONCE_LENGTH]
            || self.issued_at.0 >= self.expires_at.0
            || self.expires_at.0.saturating_sub(self.issued_at.0) > MAX_IDENTITY_PROOF_TTL_MILLIS
        {
            return Err(ValidationError::InvalidValue(
                "identity proof freshness bounds",
            ));
        }
        match self.active_trust.active_peer_count {
            0 if self.registration.trust_status == TrustStatus::Unpaired
                && self.active_trust.maximum_peer_trust_epoch == 0 => {}
            count
                if count > 0
                    && self.registration.trust_status == TrustStatus::Trusted
                    && self.active_trust.maximum_peer_trust_epoch > 0 => {}
            _ => {
                return Err(ValidationError::InvalidValue("active trust summary"));
            }
        }
        if self.active_trust.active_trust_set_digest.0 == [0_u8; 32] {
            return Err(ValidationError::InvalidValue("active trust set digest"));
        }
        Ok(())
    }

    pub fn validate_freshness(
        &self,
        now: UnixMillis,
        expected_challenge: Nonce,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        if self.requester_challenge != expected_challenge {
            return Err(ValidationError::InvalidValue("requester challenge"));
        }
        if now.0 < self.issued_at.0 {
            return Err(ValidationError::NotYetValid);
        }
        if now.0 >= self.expires_at.0 {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeIdentityProofV2 {
    pub proof: NodeIdentityProofV2,
    pub node_signature: SignatureBytes,
}

impl SignedNodeRegistrationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        self.registration.signing_bytes()
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.registration.validate()
    }
}

impl NodeRegistrationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        domain_separated_postcard(NODE_REGISTRATION_SIGNATURE_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ValidationError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        validate_uuid(self.node_id.as_uuid(), "node id")?;
        validate_uuid(&self.device.installation_id, "installation id")?;
        if self.cryptographic_identity.public_key.0 == [0; ED25519_PUBLIC_KEY_LENGTH] {
            return Err(ValidationError::InvalidValue("node public key"));
        }
        if self.cryptographic_identity.key_id.0 == [0; 32] {
            return Err(ValidationError::InvalidValue("node key id"));
        }
        validate_required_string(
            &self.device.display_name,
            MAX_DISPLAY_NAME_BYTES,
            "device display name",
        )?;
        validate_required_string(&self.platform.os_version, MAX_VERSION_BYTES, "OS version")?;
        validate_required_string(
            &self.software.version,
            MAX_VERSION_BYTES,
            "software version",
        )?;
        validate_required_string(&self.software.build_id, MAX_ID_BYTES, "build id")?;
        if self.software.protocol_version != self.protocol_version {
            return Err(ValidationError::UnsupportedProtocolVersion(
                self.software.protocol_version,
            ));
        }
        if self.hardware.gpus.len() > MAX_GPUS {
            return Err(ValidationError::LimitExceeded("GPU descriptions"));
        }
        self.capability_manifest.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UtilizationPermille(pub u16);

impl UtilizationPermille {
    pub fn new(value: u16) -> Result<Self, ValidationError> {
        if value > 1_000 {
            return Err(ValidationError::InvalidValue("utilization permille"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ThermalState {
    Nominal,
    Fair,
    Serious,
    Critical,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CpuResourceV1 {
    pub logical_cpu_count: u16,
    pub utilization: UtilizationPermille,
    pub load_one_minute_milli: Option<u32>,
    pub temperature_millidegrees_celsius: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryResourceV1 {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiskResourceV1 {
    /// A mount label or policy-safe path, never a volume serial number.
    pub label: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GpuResourceV1 {
    pub index: u16,
    pub utilization: Option<UtilizationPermille>,
    pub memory_kind: GpuMemoryKind,
    pub total_memory_bytes: Option<u64>,
    pub used_memory_bytes: Option<u64>,
    pub temperature_millidegrees_celsius: Option<i32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Availability {
    Available,
    Unavailable,
    Degraded,
    Unsupported,
    PermissionDenied,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InferenceEngineStatusV1 {
    pub engine_id: String,
    pub native: bool,
    pub availability: Availability,
    pub version: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ModelLoadState {
    Loading,
    Loaded,
    Unloading,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoadedModelV1 {
    pub model_id: String,
    pub engine_id: String,
    pub state: ModelLoadState,
    pub allocated_memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueStatusV1 {
    pub queued: u32,
    pub running: u32,
    pub capacity: u32,
    pub accepting_local_work: bool,
    pub accepting_remote_work: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentHealthV1 {
    pub state: HealthState,
    pub last_observed_at: UnixMillis,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeResourceReportV1 {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub node_id: NodeId,
    pub observed_at: UnixMillis,
    pub cpu: CpuResourceV1,
    pub ram: MemoryResourceV1,
    pub unified_memory: Option<MemoryResourceV1>,
    pub disks: Vec<DiskResourceV1>,
    pub gpus: Vec<GpuResourceV1>,
    pub thermal_state: ThermalState,
    pub inference_engines: Vec<InferenceEngineStatusV1>,
    pub loaded_models: Vec<LoadedModelV1>,
    pub queue: QueueStatusV1,
    pub agent_green: ComponentHealthV1,
    pub action_broker: ComponentHealthV1,
}

impl NodeResourceReportV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ValidationError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }
        if self.cpu.utilization.0 > 1_000 {
            return Err(ValidationError::InvalidValue("CPU utilization"));
        }
        validate_temperature(self.cpu.temperature_millidegrees_celsius, "CPU temperature")?;
        validate_memory(&self.ram, "RAM")?;
        if let Some(memory) = &self.unified_memory {
            validate_memory(memory, "unified memory")?;
        }
        if self.disks.len() > MAX_DISKS {
            return Err(ValidationError::LimitExceeded("disk reports"));
        }
        if self.gpus.len() > MAX_GPUS {
            return Err(ValidationError::LimitExceeded("GPU reports"));
        }
        if self.inference_engines.len() > MAX_ENGINE_STATUSES {
            return Err(ValidationError::LimitExceeded("inference engines"));
        }
        if self.loaded_models.len() > MAX_LOADED_MODELS {
            return Err(ValidationError::LimitExceeded("loaded models"));
        }
        if self.queue.running > self.queue.capacity
            || self.queue.queued.saturating_add(self.queue.running) > self.queue.capacity
        {
            return Err(ValidationError::InvalidValue("queue capacity"));
        }
        for disk in &self.disks {
            validate_local_identifier(&disk.label, "disk label")?;
            if disk.available_bytes > disk.total_bytes {
                return Err(ValidationError::InvalidValue("disk capacity"));
            }
        }
        validate_gpu_results(&self.gpus)?;
        validate_engine_results(&self.inference_engines)?;
        validate_model_results(&self.loaded_models)?;
        let engine_ids: BTreeSet<_> = self
            .inference_engines
            .iter()
            .map(|engine| engine.engine_id.as_str())
            .collect();
        if self
            .loaded_models
            .iter()
            .any(|model| !engine_ids.contains(model.engine_id.as_str()))
        {
            return Err(ValidationError::InvalidValue("model engine id"));
        }
        let engine_states: BTreeMap<_, _> = self
            .inference_engines
            .iter()
            .map(|engine| (engine.engine_id.as_str(), engine.availability))
            .collect();
        if self.loaded_models.iter().any(|model| {
            model.state == ModelLoadState::Loaded
                && !matches!(
                    engine_states.get(model.engine_id.as_str()),
                    Some(Availability::Available | Availability::Degraded)
                )
        }) {
            return Err(ValidationError::InvalidValue("loaded model engine state"));
        }
        let dedicated_vram = self
            .gpus
            .iter()
            .filter(|gpu| gpu.memory_kind == GpuMemoryKind::DedicatedVram)
            .filter_map(|gpu| gpu.total_memory_bytes)
            .fold(0_u64, u64::saturating_add);
        let maximum_model_memory = self.ram.total_bytes.saturating_add(dedicated_vram);
        if self.loaded_models.iter().any(|model| {
            model
                .allocated_memory_bytes
                .is_some_and(|bytes| bytes > maximum_model_memory)
        }) {
            return Err(ValidationError::InvalidValue("model allocated memory"));
        }
        validate_optional_string(
            &self.agent_green.detail,
            MAX_DETAIL_BYTES,
            "Agent Green health detail",
        )?;
        validate_optional_string(
            &self.action_broker.detail,
            MAX_DETAIL_BYTES,
            "Action Broker health detail",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeSystemInfoV1 {
    pub node_id: NodeId,
    pub device: DeviceIdentityV1,
    pub platform: PlatformInfoV1,
    pub hardware: HardwareSummaryV1,
    pub software: SoftwareVersionV1,
    pub trust_status: TrustStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileReadResultV1 {
    pub offset: u64,
    pub contents: Vec<u8>,
    pub end_of_file: bool,
    pub content_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileWriteResultV1 {
    pub bytes_written: u64,
    pub content_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntityStatusV1 {
    pub state: String,
    pub detail: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl EntityStatusV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_required_string(&self.state, MAX_ID_BYTES, "entity state")?;
        validate_optional_string(&self.detail, MAX_DETAIL_BYTES, "entity detail")?;
        validate_parameters(&self.attributes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovedActionResultV1 {
    pub outcome: ApprovedActionOutcome,
    pub output: Vec<u8>,
    pub output_truncated: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovedActionOutcome {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryStatusV1 {
    pub head: Option<String>,
    pub branch: Option<String>,
    pub clean: bool,
    pub ahead: u32,
    pub behind: u32,
    pub untracked_count: Option<u32>,
}

impl RepositoryStatusV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(head) = &self.head
            && !((head.len() == 40 || head.len() == 64)
                && head.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(ValidationError::InvalidValue("repository revision"));
        }
        if let Some(branch) = &self.branch {
            validate_local_identifier(branch, "repository branch alias")?;
        }
        if self.ahead > 1_000_000 || self.behind > 1_000_000 {
            return Err(ValidationError::LimitExceeded("repository divergence"));
        }
        if self.untracked_count.is_some_and(|count| count > 1_000_000) {
            return Err(ValidationError::LimitExceeded("repository untracked count"));
        }
        if self.clean && self.untracked_count.is_some_and(|count| count > 0) {
            return Err(ValidationError::InvalidValue("repository clean state"));
        }
        Ok(())
    }
}

fn domain_separated_postcard<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<Vec<u8>, postcard::Error> {
    let encoded = postcard::to_allocvec(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn digest_postcard<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, postcard::Error> {
    let bytes = domain_separated_postcard(domain, value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(Sha256Digest(hasher.finalize().into()))
}

fn validate_required_string(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyValue(field));
    }
    if value.len() > max_bytes {
        return Err(ValidationError::LimitExceeded(field));
    }
    if value.contains('\0') {
        return Err(ValidationError::InvalidValue(field));
    }
    Ok(())
}

fn validate_optional_string(
    value: &Option<String>,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_required_string(value, max_bytes, field)?;
    }
    Ok(())
}

fn validate_uuid(value: &Uuid, field: &'static str) -> Result<(), ValidationError> {
    if value.is_nil() {
        return Err(ValidationError::InvalidValue(field));
    }
    Ok(())
}

fn validate_parameters(parameters: &BTreeMap<String, String>) -> Result<(), ValidationError> {
    if parameters.len() > MAX_PARAMETERS {
        return Err(ValidationError::LimitExceeded("approved action parameters"));
    }
    for (key, value) in parameters {
        validate_required_string(key, MAX_PARAMETER_KEY_BYTES, "parameter key")?;
        if value.len() > MAX_PARAMETER_VALUE_BYTES {
            return Err(ValidationError::LimitExceeded("parameter value"));
        }
        if value.contains('\0') {
            return Err(ValidationError::InvalidValue("parameter value"));
        }
    }
    Ok(())
}

fn validate_local_identifier(value: &str, field: &'static str) -> Result<(), ValidationError> {
    validate_required_string(value, MAX_ID_BYTES, field)?;
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::InvalidValue(field));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ValidationError> {
    validate_required_string(value, MAX_PATH_BYTES, "relative path")?;
    if value.contains('\\') {
        return Err(ValidationError::InvalidValue("relative path"));
    }
    let path = std::path::Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ValidationError::InvalidValue("relative path"));
    }
    Ok(())
}

fn validate_memory(memory: &MemoryResourceV1, field: &'static str) -> Result<(), ValidationError> {
    if memory.available_bytes > memory.total_bytes
        || memory.used_bytes > memory.total_bytes
        || memory.used_bytes.saturating_add(memory.available_bytes) > memory.total_bytes
    {
        return Err(ValidationError::InvalidValue(field));
    }
    Ok(())
}

fn validate_temperature(value: Option<i32>, field: &'static str) -> Result<(), ValidationError> {
    if value.is_some_and(|value| !(-100_000..=250_000).contains(&value)) {
        return Err(ValidationError::InvalidValue(field));
    }
    Ok(())
}

fn validate_gpu_results(gpus: &[GpuResourceV1]) -> Result<(), ValidationError> {
    if gpus.len() > MAX_GPUS {
        return Err(ValidationError::LimitExceeded("GPU results"));
    }
    let mut indexes = BTreeSet::new();
    for gpu in gpus {
        if !indexes.insert(gpu.index) {
            return Err(ValidationError::InvalidValue("GPU index"));
        }
        if gpu.utilization.is_some_and(|value| value.0 > 1_000) {
            return Err(ValidationError::InvalidValue("GPU utilization"));
        }
        validate_temperature(gpu.temperature_millidegrees_celsius, "GPU temperature")?;
        if matches!(
            (gpu.total_memory_bytes, gpu.used_memory_bytes),
            (None, Some(_)) | (Some(_), None)
        ) || matches!(
            (gpu.total_memory_bytes, gpu.used_memory_bytes),
            (Some(total), Some(used)) if used > total
        ) {
            return Err(ValidationError::InvalidValue("GPU memory"));
        }
    }
    Ok(())
}

fn validate_engine_results(engines: &[InferenceEngineStatusV1]) -> Result<(), ValidationError> {
    if engines.len() > MAX_ENGINE_STATUSES {
        return Err(ValidationError::LimitExceeded("engine results"));
    }
    let mut ids = BTreeSet::new();
    for engine in engines {
        validate_local_identifier(&engine.engine_id, "inference engine id")?;
        if !ids.insert(engine.engine_id.as_str()) {
            return Err(ValidationError::InvalidValue("inference engine id"));
        }
        validate_optional_string(
            &engine.version,
            MAX_VERSION_BYTES,
            "inference engine version",
        )?;
    }
    Ok(())
}

fn validate_model_results(models: &[LoadedModelV1]) -> Result<(), ValidationError> {
    if models.len() > MAX_LOADED_MODELS {
        return Err(ValidationError::LimitExceeded("model results"));
    }
    let mut ids = BTreeSet::new();
    for model in models {
        validate_local_identifier(&model.model_id, "model id")?;
        validate_local_identifier(&model.engine_id, "model engine id")?;
        if !ids.insert(model.model_id.as_str()) {
            return Err(ValidationError::InvalidValue("model id"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn sample_request(arguments: ActionArguments) -> Result<ActionRequestV1, postcard::Error> {
        let target = match arguments.capability() {
            Capability::FileRead | Capability::FileWrite => ActionTarget::File {
                root_id: "reports".to_owned(),
                relative_path: "daily/report.txt".to_owned(),
            },
            Capability::ProcessStatus => ActionTarget::ManagedProcess {
                process_id: "model-engine".to_owned(),
            },
            Capability::ServiceStatus => ActionTarget::Service {
                service_name: "example.service".to_owned(),
            },
            Capability::ExecuteApprovedAction => ActionTarget::ApprovedAction {
                action_id: "restart-example-service".to_owned(),
            },
            Capability::GpuStatus => ActionTarget::Gpu { index: None },
            Capability::EngineStatus => ActionTarget::Engine { engine_id: None },
            Capability::ModelStatus => ActionTarget::Model { model_id: None },
            Capability::RepositoryStatus => ActionTarget::Repository {
                repository_id: "primary".to_owned(),
            },
            Capability::AgentGreenHealth => ActionTarget::AgentGreen,
            Capability::ActionBrokerHealth => ActionTarget::ActionBroker,
            Capability::SystemInfo | Capability::ResourceStatus => ActionTarget::Node,
        };
        ActionRequestV1::new(
            RequestId(id(1)),
            TaskId(id(2)),
            AgentId(id(3)),
            UserAuthorityV1 {
                authority_id: AuthorizationId(id(4)),
                owner_id: "owner-1".to_owned(),
                kind: AuthorityKind::OwnerInteractive,
                approval_reason: Some("requested by owner".to_owned()),
            },
            NodeId(id(5)),
            target,
            arguments,
            UnixMillis(1_000),
            UnixMillis(1_000),
            UnixMillis(2_000),
            ReplayProtectionV1 {
                nonce: Nonce([7; NONCE_LENGTH]),
                sequence: 9,
            },
            AuthorizationClaimsV1 {
                authorization_id: AuthorizationId(id(6)),
                pairing_id: PairingId(id(7)),
                trust_epoch: 3,
                policy_version: 12,
                permitted_capability: Capability::SystemInfo,
                permitted_target_digest: Sha256Digest([0; 32]),
                owner_key_id: Sha256Digest([8; 32]),
                broker_key_id: Sha256Digest([9; 32]),
            },
        )
    }

    #[test]
    fn canonical_bytes_and_digests_are_deterministic_and_domain_separated()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = sample_request(ActionArguments::ExecuteApprovedAction {
            parameters: BTreeMap::from([
                ("mode".to_owned(), "graceful".to_owned()),
                ("timeout_ms".to_owned(), "5000".to_owned()),
            ]),
        })?;

        let first = request.owner_signing_bytes()?;
        let second = request.owner_signing_bytes()?;
        assert_eq!(first, second);
        assert_eq!(request.request_digest()?, request.request_digest()?);

        let signed = SignedActionV1 {
            request,
            owner_signature: SignatureBytes::from_slice(&[11; 64])?,
            broker_signature: SignatureBytes::from_slice(&[12; 64])?,
        };
        assert_ne!(
            signed.request.owner_signing_bytes()?,
            signed.broker_signing_bytes()?
        );
        Ok(())
    }

    #[test]
    fn arguments_digest_changes_with_argument_content() -> Result<(), postcard::Error> {
        let first = ActionArguments::FileRead {
            offset: 0,
            max_bytes: 1_024,
        };
        let second = ActionArguments::FileRead {
            offset: 1,
            max_bytes: 1_024,
        };
        assert_ne!(first.digest()?, second.digest()?);
        Ok(())
    }

    #[test]
    fn every_argument_variant_maps_to_exactly_one_capability() {
        let arguments = vec![
            ActionArguments::SystemInfo,
            ActionArguments::ResourceStatus,
            ActionArguments::FileRead {
                offset: 0,
                max_bytes: 1,
            },
            ActionArguments::FileWrite {
                contents: Vec::new(),
                mode: FileWriteMode::CreateNew,
                expected_current_digest: None,
            },
            ActionArguments::ProcessStatus {
                include_children: false,
            },
            ActionArguments::ServiceStatus,
            ActionArguments::ExecuteApprovedAction {
                parameters: BTreeMap::new(),
            },
            ActionArguments::GpuStatus,
            ActionArguments::EngineStatus,
            ActionArguments::ModelStatus,
            ActionArguments::RepositoryStatus {
                include_untracked_summary: false,
            },
            ActionArguments::AgentGreenHealth,
            ActionArguments::ActionBrokerHealth,
        ];

        for argument in arguments {
            let expected = argument.capability();
            assert!(expected.matches_arguments(&argument));
            assert!(
                Capability::SystemInfo == expected
                    || !Capability::SystemInfo.matches_arguments(&argument)
            );
        }
    }

    #[test]
    fn logical_process_target_is_strict_and_appended_without_repurposing_pid_target() {
        let logical = ActionTarget::ManagedProcess {
            process_id: "model-engine".to_owned(),
        };
        assert!(logical.validate().is_ok());
        assert!(Capability::ProcessStatus.matches_target(&logical));
        assert!(
            ActionTarget::ManagedProcess {
                process_id: "private/path".to_owned(),
            }
            .validate()
            .is_err()
        );
        // The legacy target remains decodable for deterministic denial by the executor; it was
        // not silently reinterpreted as a logical identifier.
        let legacy = ActionTarget::Process { process_id: 42 };
        assert!(legacy.validate().is_ok());
        assert!(!Capability::ProcessStatus.matches_target(&legacy));
    }

    #[test]
    fn logical_service_target_rejects_paths_and_free_form_names() {
        let logical = ActionTarget::Service {
            service_name: "model-engine.service".to_owned(),
        };
        assert!(logical.validate().is_ok());
        assert!(Capability::ServiceStatus.matches_target(&logical));
        for invalid in ["private/path", "model engine", "../service", ""] {
            assert!(
                ActionTarget::Service {
                    service_name: invalid.to_owned(),
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn capability_must_match_arguments_and_target() -> Result<(), postcard::Error> {
        let mut request = sample_request(ActionArguments::FileRead {
            offset: 0,
            max_bytes: 1_024,
        })?;
        assert!(
            request
                .validate_for_node(NodeId(id(5)), UnixMillis(1_500), 3)
                .is_ok()
        );

        request.capability = Capability::FileWrite;
        assert_eq!(
            request.validate_structure(),
            Err(ValidationError::CapabilityMismatch)
        );
        Ok(())
    }

    #[test]
    fn modified_arguments_fail_digest_validation() -> Result<(), postcard::Error> {
        let mut request = sample_request(ActionArguments::FileRead {
            offset: 0,
            max_bytes: 1_024,
        })?;
        request.arguments = ActionArguments::FileRead {
            offset: 100,
            max_bytes: 1_024,
        };
        assert_eq!(
            request.validate_structure(),
            Err(ValidationError::ArgumentsDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn signature_decoder_rejects_non_ed25519_length() -> Result<(), postcard::Error> {
        let encoded = postcard::to_allocvec(&vec![1_u8; 63])?;
        assert!(postcard::from_bytes::<SignatureBytes>(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn dedicated_status_results_reject_malformed_or_duplicate_entries() {
        let gpu = GpuResourceV1 {
            index: 1,
            utilization: Some(UtilizationPermille(500)),
            memory_kind: GpuMemoryKind::DedicatedVram,
            total_memory_bytes: Some(8_000),
            used_memory_bytes: Some(4_000),
            temperature_millidegrees_celsius: Some(60_000),
        };
        assert!(
            ActionResultV1::GpuStatus(vec![gpu.clone()])
                .validate()
                .is_ok()
        );
        assert!(
            ActionResultV1::GpuStatus(vec![gpu.clone(), gpu])
                .validate()
                .is_err()
        );

        let engine = InferenceEngineStatusV1 {
            engine_id: "native-engine".to_owned(),
            native: true,
            availability: Availability::Available,
            version: Some("1.0".to_owned()),
        };
        assert!(
            ActionResultV1::EngineStatus(vec![engine.clone()])
                .validate()
                .is_ok()
        );
        assert!(
            ActionResultV1::EngineStatus(vec![engine.clone(), engine])
                .validate()
                .is_err()
        );

        let model = LoadedModelV1 {
            model_id: "owner-model".to_owned(),
            engine_id: "native-engine".to_owned(),
            state: ModelLoadState::Loaded,
            allocated_memory_bytes: None,
        };
        assert!(
            ActionResultV1::ModelStatus(vec![model.clone()])
                .validate()
                .is_ok()
        );
        let mut invalid = model;
        invalid.model_id = "private/path".to_owned();
        assert!(
            ActionResultV1::ModelStatus(vec![invalid])
                .validate()
                .is_err()
        );

        let repository = RepositoryStatusV1 {
            head: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            branch: Some("main".to_owned()),
            clean: true,
            ahead: 0,
            behind: 0,
            untracked_count: Some(0),
        };
        assert!(
            ActionResultV1::RepositoryStatus(repository.clone())
                .validate()
                .is_ok()
        );
        let mut invalid = repository.clone();
        invalid.branch = Some("private/path".to_owned());
        assert!(
            ActionResultV1::RepositoryStatus(invalid)
                .validate()
                .is_err()
        );
        let mut invalid = repository;
        invalid.untracked_count = Some(1);
        assert!(
            ActionResultV1::RepositoryStatus(invalid)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn resource_report_rejects_queue_and_loaded_model_inconsistency() {
        let mut report = NodeResourceReportV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: PROTOCOL_VERSION_V1,
            node_id: NodeId(id(900)),
            observed_at: UnixMillis(1),
            cpu: CpuResourceV1 {
                logical_cpu_count: 1,
                utilization: UtilizationPermille(0),
                load_one_minute_milli: None,
                temperature_millidegrees_celsius: None,
            },
            ram: MemoryResourceV1 {
                total_bytes: 1_000,
                available_bytes: 500,
                used_bytes: 500,
            },
            unified_memory: None,
            disks: Vec::new(),
            gpus: Vec::new(),
            thermal_state: ThermalState::Unknown,
            inference_engines: vec![InferenceEngineStatusV1 {
                engine_id: "native-engine".to_owned(),
                native: true,
                availability: Availability::Unavailable,
                version: None,
            }],
            loaded_models: vec![LoadedModelV1 {
                model_id: "owner-model".to_owned(),
                engine_id: "native-engine".to_owned(),
                state: ModelLoadState::Loaded,
                allocated_memory_bytes: Some(500),
            }],
            queue: QueueStatusV1 {
                queued: 1,
                running: 1,
                capacity: 1,
                accepting_local_work: true,
                accepting_remote_work: true,
            },
            agent_green: ComponentHealthV1 {
                state: HealthState::Unknown,
                last_observed_at: UnixMillis(1),
                detail: None,
            },
            action_broker: ComponentHealthV1 {
                state: HealthState::Unknown,
                last_observed_at: UnixMillis(1),
                detail: None,
            },
        };
        assert!(report.validate().is_err());

        report.queue.queued = 0;
        assert!(report.validate().is_err());

        report.inference_engines[0].availability = Availability::Available;
        assert!(report.validate().is_ok());

        report.loaded_models[0].allocated_memory_bytes = Some(1_001);
        assert!(report.validate().is_err());
    }
}
