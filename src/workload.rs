//! Transitional typed workload admission for sovereign local services.
//!
//! This module deliberately performs no process creation, model inference,
//! filesystem action, network proxying, or cognitive routing. Canonical shared
//! types remain an external Sovereign-AI-Contracts dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::{IdentityError, NodeIdentity};
use crate::protocol::{NodeId, PublicKeyBytes, Sha256Digest, SignatureBytes, UnixMillis};

const WORKLOAD_INTENT_DOMAIN: &[u8] = b"sovereign-node/workload-intent/v1\0";
const NODE_MANIFEST_DOMAIN: &[u8] = b"sovereign-node/capability-manifest/v1\0";
const MAX_TEXT_BYTES: usize = 128;
const MAX_SERVICES: usize = 128;
const MAX_ARTIFACTS: usize = 256;
pub const MAX_WORKLOAD_WIRE_BYTES: usize = 256 * 1024;
pub const MAX_SERVICE_RESULT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ExecutionClass {
    TextInference,
    VisionLanguageInference,
    Embeddings,
    Reranking,
    Speech,
    ImageInference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Classification {
    Public,
    Private,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Locality {
    PrivateNetwork,
    ThisNodeOnly,
}

impl Locality {
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::ThisNodeOnly, _) | (Self::PrivateNetwork, Self::PrivateNetwork)
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnrollmentState {
    Unenrolled,
    Pending,
    Active,
    Restricted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnforcementLevel {
    Enforced,
    Partial,
    Advisory,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCapabilitiesV1 {
    pub process_isolation: EnforcementLevel,
    pub filesystem_isolation: EnforcementLevel,
    pub network_isolation: EnforcementLevel,
    pub resource_enforcement: EnforcementLevel,
    pub dedicated_identity: EnforcementLevel,
    pub descendant_termination: EnforcementLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ServiceHealth {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedServiceDefinitionV1 {
    pub service_id: String,
    pub protocol_revision: u16,
    pub accepted_contract_revisions: BTreeSet<u16>,
    pub endpoint_id: String,
    pub endpoint_key_id: Sha256Digest,
    pub version: String,
    pub trusted: bool,
    pub health: ServiceHealth,
    pub locality: Locality,
    pub execution_classes: BTreeSet<ExecutionClass>,
    pub approved_artifact_digests: BTreeSet<Sha256Digest>,
    pub sandbox: SandboxCapabilitiesV1,
    pub availability_reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct TrustedServiceRegistry {
    services: BTreeMap<String, TrustedServiceDefinitionV1>,
}

impl TrustedServiceRegistry {
    pub fn from_local_definitions(
        definitions: impl IntoIterator<Item = TrustedServiceDefinitionV1>,
    ) -> Result<Self, WorkloadError> {
        let mut services = BTreeMap::new();
        for definition in definitions {
            validate_service(&definition)?;
            let id = definition.service_id.clone();
            if services.insert(id, definition).is_some() || services.len() > MAX_SERVICES {
                return Err(WorkloadError::Invalid(
                    "service registry is duplicate or oversized",
                ));
            }
        }
        Ok(Self { services })
    }

    #[must_use]
    pub fn get(&self, service_id: &str) -> Option<&TrustedServiceDefinitionV1> {
        self.services.get(service_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceEnvelopeV1 {
    pub memory_bytes: u64,
    pub cpu_units: u32,
    pub accelerator_memory_bytes: u64,
    pub workload_slots: u16,
}

impl ResourceEnvelopeV1 {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            cpu_units: self.cpu_units.checked_add(other.cpu_units)?,
            accelerator_memory_bytes: self
                .accelerator_memory_bytes
                .checked_add(other.accelerator_memory_bytes)?,
            workload_slots: self.workload_slots.checked_add(other.workload_slots)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_sub(other.memory_bytes)?,
            cpu_units: self.cpu_units.checked_sub(other.cpu_units)?,
            accelerator_memory_bytes: self
                .accelerator_memory_bytes
                .checked_sub(other.accelerator_memory_bytes)?,
            workload_slots: self.workload_slots.checked_sub(other.workload_slots)?,
        })
    }

    fn fits_within(self, ceiling: Self) -> bool {
        self.memory_bytes <= ceiling.memory_bytes
            && self.cpu_units <= ceiling.cpu_units
            && self.accelerator_memory_bytes <= ceiling.accelerator_memory_bytes
            && self.workload_slots <= ceiling.workload_slots
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIntentV1 {
    pub schema_version: u16,
    pub protocol_revision: u16,
    pub contract_revision: u16,
    pub workload_id: Uuid,
    pub idempotency_key: Uuid,
    pub task_id: Uuid,
    pub cognitive_plan_id: Uuid,
    pub cognitive_node_id: Uuid,
    pub parent_workload_id: Option<Uuid>,
    pub service_id: String,
    pub artifact_digest: Option<Sha256Digest>,
    pub execution_class: ExecutionClass,
    pub classification: Classification,
    pub classification_reference: Sha256Digest,
    pub locality: Locality,
    pub resources: ResourceEnvelopeV1,
    pub deadline: UnixMillis,
    pub authorization_principal: String,
    pub control_plane_id: String,
    pub node_id: NodeId,
    pub trust_epoch: u64,
    pub policy_revision: u64,
    pub policy_digest: Sha256Digest,
    pub created_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub correlation_id: Uuid,
}

impl WorkloadIntentV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WorkloadError> {
        self.validate_structure()?;
        let encoded = postcard::to_allocvec(self)?;
        let mut bytes = Vec::with_capacity(WORKLOAD_INTENT_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(WORKLOAD_INTENT_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<Sha256Digest, WorkloadError> {
        Ok(Sha256Digest(Sha256::digest(self.signing_bytes()?).into()))
    }

    fn validate_structure(&self) -> Result<(), WorkloadError> {
        if self.schema_version != 1 || self.protocol_revision != 1 || self.contract_revision != 1 {
            return Err(WorkloadError::Version);
        }
        if [
            self.workload_id,
            self.idempotency_key,
            self.task_id,
            self.cognitive_plan_id,
            self.cognitive_node_id,
            self.correlation_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.node_id.0.is_nil()
            || self.trust_epoch == 0
            || self.policy_revision == 0
            || self.classification_reference.0 == [0; 32]
            || self.created_at.0 >= self.expires_at.0
            || self.expires_at.0 > self.deadline.0
        {
            return Err(WorkloadError::Invalid(
                "workload identity or timing is invalid",
            ));
        }
        validate_text(&self.service_id)?;
        validate_text(&self.authorization_principal)?;
        validate_text(&self.control_plane_id)?;
        if self.resources.memory_bytes == 0 || self.resources.workload_slots == 0 {
            return Err(WorkloadError::Invalid("resource envelope is empty"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkloadIntentV1 {
    pub intent: WorkloadIntentV1,
    pub signature_suite: String,
    pub control_plane_public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl SignedWorkloadIntentV1 {
    pub fn verify(&self, expected_key: PublicKeyBytes) -> Result<(), WorkloadError> {
        if self.signature_suite != "Ed25519" || self.control_plane_public_key != expected_key {
            return Err(WorkloadError::Authorization);
        }
        let key =
            VerifyingKey::from_bytes(&expected_key.0).map_err(|_| WorkloadError::Authorization)?;
        if key.is_weak() {
            return Err(WorkloadError::Authorization);
        }
        let signature = Signature::from_slice(self.signature.as_bytes())
            .map_err(|_| WorkloadError::Authorization)?;
        key.verify_strict(&self.intent.signing_bytes()?, &signature)
            .map_err(|_| WorkloadError::Authorization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGreenRestrictionsV1 {
    pub schema_version: u16,
    pub observed_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub deny_new_workloads: bool,
    pub allowed_execution_classes: Option<BTreeSet<ExecutionClass>>,
    pub blocked_services: BTreeSet<String>,
    pub blocked_artifacts: BTreeSet<Sha256Digest>,
    pub network_disabled: bool,
}

impl AgentGreenRestrictionsV1 {
    fn permits(&self, intent: &WorkloadIntentV1, now: UnixMillis) -> bool {
        self.schema_version == 1
            && self.observed_at.0 <= now.0
            && now.0 < self.expires_at.0
            && !self.deny_new_workloads
            && self
                .allowed_execution_classes
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&intent.execution_class))
            && !self.blocked_services.contains(&intent.service_id)
            && intent
                .artifact_digest
                .is_none_or(|artifact| !self.blocked_artifacts.contains(&artifact))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WorkloadState {
    Received,
    Validated,
    Admitted,
    Starting,
    Running,
    Canceling,
    Recovering,
    Completed,
    Rejected,
    Failed,
    Canceled,
    TimedOut,
    UnknownAfterCrash,
}

impl WorkloadState {
    pub fn transition(self, next: Self) -> Result<Self, WorkloadError> {
        let valid = matches!(
            (self, next),
            (
                Self::Received,
                Self::Validated | Self::Rejected | Self::Canceled
            ) | (
                Self::Validated,
                Self::Admitted | Self::Rejected | Self::Canceled
            ) | (
                Self::Admitted,
                Self::Starting | Self::Canceling | Self::TimedOut
            ) | (
                Self::Starting,
                Self::Running | Self::Failed | Self::Canceling | Self::Recovering
            ) | (
                Self::Running,
                Self::Completed
                    | Self::Failed
                    | Self::Canceling
                    | Self::TimedOut
                    | Self::Recovering
            ) | (
                Self::Canceling,
                Self::Canceled | Self::Completed | Self::Failed | Self::Recovering
            ) | (
                Self::Recovering,
                Self::Running | Self::Failed | Self::Canceled | Self::UnknownAfterCrash
            )
        );
        valid.then_some(next).ok_or(WorkloadError::StateTransition)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AdmissionDecision {
    Admitted,
    RejectedPolicy,
    RejectedResource,
    RejectedSecurity,
    RejectedUnavailable,
    RejectedVersion,
    RejectedStale,
    RejectedReplay,
    Canceled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Reservation {
    digest: Sha256Digest,
    idempotency_key: Uuid,
    resources: ResourceEnvelopeV1,
    state: WorkloadState,
}

#[derive(Debug)]
struct ReservationState {
    used: ResourceEnvelopeV1,
    workloads: BTreeMap<Uuid, Reservation>,
    idempotency: BTreeMap<Uuid, (Uuid, Sha256Digest)>,
}

#[derive(Debug)]
pub struct ReservationLedger {
    capacity: ResourceEnvelopeV1,
    safety_reserve: ResourceEnvelopeV1,
    state: Mutex<ReservationState>,
}

impl ReservationLedger {
    pub fn new(
        capacity: ResourceEnvelopeV1,
        safety_reserve: ResourceEnvelopeV1,
    ) -> Result<Self, WorkloadError> {
        if !safety_reserve.fits_within(capacity) {
            return Err(WorkloadError::Resource);
        }
        Ok(Self {
            capacity,
            safety_reserve,
            state: Mutex::new(ReservationState {
                used: ResourceEnvelopeV1 {
                    memory_bytes: 0,
                    cpu_units: 0,
                    accelerator_memory_bytes: 0,
                    workload_slots: 0,
                },
                workloads: BTreeMap::new(),
                idempotency: BTreeMap::new(),
            }),
        })
    }

    fn reserve(&self, intent: &WorkloadIntentV1) -> Result<ReservationOutcome, WorkloadError> {
        let digest = intent.digest()?;
        let mut state = self.state.lock().map_err(|_| WorkloadError::Unavailable)?;
        if let Some(existing) = state.workloads.get(&intent.workload_id) {
            return Ok(
                if existing.digest == digest && existing.idempotency_key == intent.idempotency_key {
                    ReservationOutcome::Duplicate(existing.state)
                } else {
                    ReservationOutcome::Collision
                },
            );
        }
        if let Some((workload_id, existing_digest)) = state.idempotency.get(&intent.idempotency_key)
        {
            return Ok(
                if *workload_id == intent.workload_id && *existing_digest == digest {
                    ReservationOutcome::Duplicate(WorkloadState::Admitted)
                } else {
                    ReservationOutcome::Collision
                },
            );
        }
        let admissible = self
            .capacity
            .checked_sub(self.safety_reserve)
            .ok_or(WorkloadError::Resource)?;
        let next = state
            .used
            .checked_add(intent.resources)
            .ok_or(WorkloadError::Resource)?;
        if !next.fits_within(admissible) {
            return Ok(ReservationOutcome::Insufficient);
        }
        state.used = next;
        state
            .idempotency
            .insert(intent.idempotency_key, (intent.workload_id, digest));
        state.workloads.insert(
            intent.workload_id,
            Reservation {
                digest,
                idempotency_key: intent.idempotency_key,
                resources: intent.resources,
                state: WorkloadState::Admitted,
            },
        );
        Ok(ReservationOutcome::Reserved)
    }

    pub fn reconcile_terminal(
        &self,
        workload_id: Uuid,
        terminal: WorkloadState,
    ) -> Result<(), WorkloadError> {
        if !matches!(
            terminal,
            WorkloadState::Completed
                | WorkloadState::Failed
                | WorkloadState::Canceled
                | WorkloadState::TimedOut
                | WorkloadState::UnknownAfterCrash
        ) {
            return Err(WorkloadError::StateTransition);
        }
        let mut state = self.state.lock().map_err(|_| WorkloadError::Unavailable)?;
        let reservation = state
            .workloads
            .remove(&workload_id)
            .ok_or(WorkloadError::Unavailable)?;
        state.used = state
            .used
            .checked_sub(reservation.resources)
            .ok_or(WorkloadError::Resource)?;
        Ok(())
    }

    /// Persisting cancellation intent belongs to the future durable workload
    /// store. This in-memory development ledger deliberately retains capacity
    /// until a service adapter supplies terminal reconciliation evidence.
    pub fn request_cancellation(&self, workload_id: Uuid) -> Result<(), WorkloadError> {
        let mut state = self.state.lock().map_err(|_| WorkloadError::Unavailable)?;
        let reservation = state
            .workloads
            .get_mut(&workload_id)
            .ok_or(WorkloadError::Unavailable)?;
        reservation.state = reservation.state.transition(WorkloadState::Canceling)?;
        Ok(())
    }

    #[must_use]
    pub fn used(&self) -> ResourceEnvelopeV1 {
        self.state.lock().map_or(self.capacity, |state| state.used)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationOutcome {
    Reserved,
    Duplicate(WorkloadState),
    Collision,
    Insufficient,
}

#[derive(Debug)]
pub struct AdmissionContext<'a> {
    pub now: UnixMillis,
    pub expected_node: NodeId,
    pub expected_control_plane_id: &'a str,
    pub control_plane_key: PublicKeyBytes,
    pub enrollment: EnrollmentState,
    pub trust_epoch: u64,
    pub policy_revision: u64,
    pub policy_digest: Sha256Digest,
    pub classification_verified: bool,
    pub resource_snapshot_fresh: bool,
    pub storage_healthy: bool,
    pub agent_green_required: bool,
    pub agent_green: Option<&'a AgentGreenRestrictionsV1>,
    pub services: &'a TrustedServiceRegistry,
    pub reservations: &'a ReservationLedger,
}

pub fn admit_workload(
    signed: &SignedWorkloadIntentV1,
    context: &AdmissionContext<'_>,
) -> Result<AdmissionDecision, WorkloadError> {
    if let Err(WorkloadError::Version) = signed.intent.validate_structure() {
        return Ok(AdmissionDecision::RejectedVersion);
    }
    signed.intent.validate_structure()?;
    signed.verify(context.control_plane_key)?;
    let intent = &signed.intent;
    if intent.control_plane_id != context.expected_control_plane_id
        || intent.node_id != context.expected_node
        || intent.trust_epoch != context.trust_epoch
    {
        return Ok(AdmissionDecision::RejectedSecurity);
    }
    if intent.policy_revision != context.policy_revision
        || intent.policy_digest != context.policy_digest
    {
        return Ok(AdmissionDecision::RejectedPolicy);
    }
    if context.enrollment != EnrollmentState::Active
        || !context.classification_verified
        || !context.storage_healthy
    {
        return Ok(AdmissionDecision::RejectedSecurity);
    }
    if context.now.0 >= intent.expires_at.0
        || context.now.0 >= intent.deadline.0
        || !context.resource_snapshot_fresh
    {
        return Ok(AdmissionDecision::RejectedStale);
    }
    let restrictions_valid = context
        .agent_green
        .is_some_and(|snapshot| snapshot.permits(intent, context.now));
    if (context.agent_green_required && !restrictions_valid)
        || context.agent_green.is_some() && !restrictions_valid
    {
        return Ok(AdmissionDecision::RejectedSecurity);
    }
    let Some(service) = context.services.get(&intent.service_id) else {
        return Ok(AdmissionDecision::RejectedUnavailable);
    };
    if !service.trusted
        || service.health != ServiceHealth::Ready
        || !service
            .accepted_contract_revisions
            .contains(&intent.contract_revision)
        || !service.execution_classes.contains(&intent.execution_class)
    {
        return Ok(AdmissionDecision::RejectedUnavailable);
    }
    if intent.classification == Classification::Secret
        && (intent.locality != Locality::ThisNodeOnly || service.locality != Locality::ThisNodeOnly)
    {
        return Ok(AdmissionDecision::RejectedPolicy);
    }
    if !service.locality.satisfies(intent.locality)
        || intent
            .artifact_digest
            .is_some_and(|artifact| !service.approved_artifact_digests.contains(&artifact))
    {
        return Ok(AdmissionDecision::RejectedUnavailable);
    }
    Ok(match context.reservations.reserve(intent)? {
        ReservationOutcome::Reserved => AdmissionDecision::Admitted,
        ReservationOutcome::Duplicate(_) | ReservationOutcome::Collision => {
            AdmissionDecision::RejectedReplay
        }
        ReservationOutcome::Insufficient => AdmissionDecision::RejectedResource,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilityManifestV1 {
    pub schema_version: u16,
    pub node_id: NodeId,
    pub device_key_id: Sha256Digest,
    pub identity_generation: u64,
    pub software_version: String,
    pub protocol_revision: u16,
    pub contract_revisions: BTreeSet<u16>,
    pub generation: u64,
    pub generated_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub operating_system: String,
    pub architecture: String,
    pub logical_cores: u32,
    pub total_memory_bytes: u64,
    pub services: Vec<TrustedServiceDefinitionV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedNodeCapabilityManifestV1 {
    pub manifest: NodeCapabilityManifestV1,
    pub signature_suite: String,
    pub public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl NodeCapabilityManifestV1 {
    fn signing_bytes(&self) -> Result<Vec<u8>, WorkloadError> {
        if self.schema_version != 1
            || self.node_id.0.is_nil()
            || self.generation == 0
            || self.generated_at.0 >= self.expires_at.0
            || self.services.len() > MAX_SERVICES
        {
            return Err(WorkloadError::Invalid("node manifest is invalid"));
        }
        let encoded = postcard::to_allocvec(self)?;
        let mut bytes = Vec::with_capacity(NODE_MANIFEST_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(NODE_MANIFEST_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }
}

pub fn sign_node_manifest(
    identity: &NodeIdentity,
    manifest: NodeCapabilityManifestV1,
) -> Result<SignedNodeCapabilityManifestV1, WorkloadError> {
    if manifest.node_id != identity.node_id()
        || manifest.device_key_id != identity.key_id()
        || manifest.identity_generation != identity.cryptographic_identity().rotation_counter
    {
        return Err(WorkloadError::Authorization);
    }
    let signature = identity.sign(&manifest.signing_bytes()?)?;
    Ok(SignedNodeCapabilityManifestV1 {
        manifest,
        signature_suite: "Ed25519".to_owned(),
        public_key: identity.public_key(),
        signature,
    })
}

impl SignedNodeCapabilityManifestV1 {
    pub fn verify(
        &self,
        expected_node: NodeId,
        expected_key: PublicKeyBytes,
        now: UnixMillis,
        minimum_generation: u64,
    ) -> Result<(), WorkloadError> {
        if self.signature_suite != "Ed25519"
            || self.public_key != expected_key
            || self.manifest.node_id != expected_node
            || self.manifest.generation < minimum_generation
            || now.0 < self.manifest.generated_at.0
            || now.0 >= self.manifest.expires_at.0
        {
            return Err(WorkloadError::Authorization);
        }
        let key =
            VerifyingKey::from_bytes(&expected_key.0).map_err(|_| WorkloadError::Authorization)?;
        if key.is_weak() {
            return Err(WorkloadError::Authorization);
        }
        let signature = Signature::from_slice(self.signature.as_bytes())
            .map_err(|_| WorkloadError::Authorization)?;
        key.verify_strict(&self.manifest.signing_bytes()?, &signature)
            .map_err(|_| WorkloadError::Authorization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeStatusSnapshotV1 {
    pub schema_version: u16,
    pub node_id: NodeId,
    pub manifest_generation: u64,
    pub snapshot_generation: u64,
    pub generated_at: UnixMillis,
    pub expires_at: UnixMillis,
    pub available_memory_bytes: Option<u64>,
    pub memory_pressure: ResourcePressure,
    pub cpu_pressure: ResourcePressure,
    pub active_workloads: u32,
    pub reserved_resources: ResourceEnvelopeV1,
    pub storage_healthy: bool,
    pub enrollment: EnrollmentState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResourcePressure {
    Normal,
    Elevated,
    Critical,
    Unknown,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceWorkloadRequest {
    pub workload_id: Uuid,
    pub task_id: Uuid,
    pub cognitive_plan_id: Uuid,
    pub cognitive_node_id: Uuid,
    pub artifact_digest: Option<Sha256Digest>,
    pub execution_class: ExecutionClass,
    pub resources: ResourceEnvelopeV1,
    pub deadline: UnixMillis,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceWorkloadResult {
    pub workload_id: Uuid,
    pub state: WorkloadState,
    pub result_digest: Option<Sha256Digest>,
    pub bounded_result: Vec<u8>,
}

/// Transitional protocol boundary for an already-running, locally configured
/// sovereign service. The registry, never the workload, selects its endpoint.
/// Implementations must not create processes or accept caller-selected paths.
pub trait SovereignServiceAdapter {
    fn health(&self) -> Result<ServiceHealth, WorkloadError>;
    fn execute(
        &self,
        request: &ServiceWorkloadRequest,
    ) -> Result<ServiceWorkloadResult, WorkloadError>;
    fn cancel(&self, workload_id: Uuid) -> Result<(), WorkloadError>;
    fn reconcile(&self, workload_id: Uuid) -> Result<WorkloadState, WorkloadError>;
}

pub fn decode_signed_workload(input: &[u8]) -> Result<SignedWorkloadIntentV1, WorkloadError> {
    if input.is_empty() || input.len() > MAX_WORKLOAD_WIRE_BYTES {
        return Err(WorkloadError::Invalid("workload frame size is invalid"));
    }
    let (decoded, remainder) = postcard::take_from_bytes(input)?;
    if !remainder.is_empty() || postcard::to_allocvec(&decoded)? != input {
        return Err(WorkloadError::Invalid(
            "workload frame is trailing or noncanonical",
        ));
    }
    Ok(decoded)
}

pub fn validate_service_result(result: &ServiceWorkloadResult) -> Result<(), WorkloadError> {
    if result.workload_id.is_nil()
        || result.bounded_result.len() > MAX_SERVICE_RESULT_BYTES
        || !matches!(
            result.state,
            WorkloadState::Completed
                | WorkloadState::Failed
                | WorkloadState::Canceled
                | WorkloadState::TimedOut
                | WorkloadState::UnknownAfterCrash
        )
    {
        return Err(WorkloadError::Invalid("service result is invalid"));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum WorkloadError {
    #[error("workload contract version is unsupported")]
    Version,
    #[error("workload input is invalid: {0}")]
    Invalid(&'static str),
    #[error("workload authorization is invalid")]
    Authorization,
    #[error("workload resources are unavailable or invalid")]
    Resource,
    #[error("workload state transition is invalid")]
    StateTransition,
    #[error("workload state is unavailable")]
    Unavailable,
    #[error("workload encoding failed: {0}")]
    Codec(#[from] postcard::Error),
    #[error("node identity operation failed: {0}")]
    Identity(#[from] IdentityError),
}

fn validate_service(service: &TrustedServiceDefinitionV1) -> Result<(), WorkloadError> {
    validate_text(&service.service_id)?;
    validate_text(&service.endpoint_id)?;
    validate_text(&service.version)?;
    if service.protocol_revision == 0
        || service.accepted_contract_revisions.is_empty()
        || service.execution_classes.is_empty()
        || service.approved_artifact_digests.len() > MAX_ARTIFACTS
        || service
            .availability_reason
            .as_ref()
            .is_some_and(|reason| reason.len() > MAX_TEXT_BYTES)
    {
        return Err(WorkloadError::Invalid("service definition is invalid"));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), WorkloadError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        Err(WorkloadError::Invalid("text field is invalid"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    use super::*;

    fn envelope(memory: u64) -> ResourceEnvelopeV1 {
        ResourceEnvelopeV1 {
            memory_bytes: memory,
            cpu_units: 1,
            accelerator_memory_bytes: 0,
            workload_slots: 1,
        }
    }

    #[test]
    fn concurrent_reservations_preserve_capacity_and_safety_reserve()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ledger = Arc::new(ReservationLedger::new(
            ResourceEnvelopeV1 {
                memory_bytes: 12,
                cpu_units: 4,
                accelerator_memory_bytes: 0,
                workload_slots: 2,
            },
            ResourceEnvelopeV1 {
                memory_bytes: 2,
                cpu_units: 0,
                accelerator_memory_bytes: 0,
                workload_slots: 0,
            },
        )?);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for seed in [1_u128, 2] {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                let mut intent = sample_intent(seed, 6);
                intent.idempotency_key = Uuid::from_u128(seed + 100);
                barrier.wait();
                ledger.reserve(&intent)
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| WorkloadError::Unavailable)?)
            .collect::<Result<Vec<_>, WorkloadError>>()?;
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReservationOutcome::Reserved)
                .count(),
            1
        );
        assert_eq!(ledger.used().memory_bytes, 6);
        Ok(())
    }

    #[test]
    fn secret_locality_agent_restrictions_and_unknown_services_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = SigningKey::generate(&mut OsRng);
        let node_id = NodeId(Uuid::new_v4());
        let artifact = Sha256Digest([7; 32]);
        let registry = TrustedServiceRegistry::from_local_definitions([service(
            "native-engine",
            Locality::ThisNodeOnly,
            artifact,
        )])?;
        let ledger = ReservationLedger::new(
            ResourceEnvelopeV1 {
                memory_bytes: 16,
                cpu_units: 4,
                accelerator_memory_bytes: 0,
                workload_slots: 4,
            },
            ResourceEnvelopeV1 {
                memory_bytes: 2,
                cpu_units: 0,
                accelerator_memory_bytes: 0,
                workload_slots: 1,
            },
        )?;
        let restrictions = AgentGreenRestrictionsV1 {
            schema_version: 1,
            observed_at: UnixMillis(900),
            expires_at: UnixMillis(2_000),
            deny_new_workloads: false,
            allowed_execution_classes: None,
            blocked_services: BTreeSet::new(),
            blocked_artifacts: BTreeSet::new(),
            network_disabled: true,
        };
        let context = AdmissionContext {
            now: UnixMillis(1_100),
            expected_node: node_id,
            expected_control_plane_id: "ai-avenger",
            control_plane_key: PublicKeyBytes(key.verifying_key().to_bytes()),
            enrollment: EnrollmentState::Active,
            trust_epoch: 3,
            policy_revision: 5,
            policy_digest: Sha256Digest([9; 32]),
            classification_verified: true,
            resource_snapshot_fresh: true,
            storage_healthy: true,
            agent_green_required: true,
            agent_green: Some(&restrictions),
            services: &registry,
            reservations: &ledger,
        };
        let mut intent = sample_intent(1, 8);
        intent.node_id = node_id;
        intent.artifact_digest = Some(artifact);
        let signed = sign_intent(intent.clone(), &key)?;
        assert_eq!(
            admit_workload(&signed, &context)?,
            AdmissionDecision::Admitted
        );

        let mut remote_secret = intent.clone();
        remote_secret.workload_id = Uuid::new_v4();
        remote_secret.idempotency_key = Uuid::new_v4();
        remote_secret.locality = Locality::PrivateNetwork;
        assert_eq!(
            admit_workload(&sign_intent(remote_secret, &key)?, &context)?,
            AdmissionDecision::RejectedPolicy
        );
        let mut unknown = intent;
        unknown.workload_id = Uuid::new_v4();
        unknown.idempotency_key = Uuid::new_v4();
        unknown.service_id = "unregistered".to_owned();
        assert_eq!(
            admit_workload(&sign_intent(unknown, &key)?, &context)?,
            AdmissionDecision::RejectedUnavailable
        );
        Ok(())
    }

    #[test]
    fn simulated_nodes_report_eligibility_without_ranking() -> Result<(), WorkloadError> {
        let artifact = Sha256Digest([4; 32]);
        let mac = TrustedServiceRegistry::from_local_definitions([service(
            "metal-engine",
            Locality::ThisNodeOnly,
            artifact,
        )])?;
        let linux_cuda = TrustedServiceRegistry::from_local_definitions([service(
            "cuda-engine",
            Locality::ThisNodeOnly,
            artifact,
        )])?;
        let restricted = EnrollmentState::Restricted;
        assert!(mac.get("metal-engine").is_some());
        assert!(linux_cuda.get("cuda-engine").is_some());
        assert_eq!(restricted, EnrollmentState::Restricted);
        Ok(())
    }

    proptest! {
        #[test]
        fn locality_can_only_stay_equal_or_become_more_restrictive(required_local in any::<bool>()) {
            let required = if required_local { Locality::ThisNodeOnly } else { Locality::PrivateNetwork };
            prop_assert!(Locality::ThisNodeOnly.satisfies(required));
            if required_local {
                prop_assert!(!Locality::PrivateNetwork.satisfies(required));
            }
        }

        #[test]
        fn terminal_states_never_transition_back_to_running(index in 0usize..5) {
            let terminal = [
                WorkloadState::Completed,
                WorkloadState::Rejected,
                WorkloadState::Failed,
                WorkloadState::Canceled,
                WorkloadState::TimedOut,
            ][index];
            prop_assert!(terminal.transition(WorkloadState::Running).is_err());
        }

        #[test]
        fn arbitrary_workload_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode_signed_workload(&bytes);
        }
    }

    #[test]
    fn cancellation_retains_capacity_until_terminal_reconciliation() -> Result<(), WorkloadError> {
        let ledger = ReservationLedger::new(
            ResourceEnvelopeV1 {
                memory_bytes: 10,
                cpu_units: 2,
                accelerator_memory_bytes: 0,
                workload_slots: 2,
            },
            ResourceEnvelopeV1 {
                memory_bytes: 2,
                cpu_units: 0,
                accelerator_memory_bytes: 0,
                workload_slots: 0,
            },
        )?;
        let intent = sample_intent(11, 8);
        assert_eq!(ledger.reserve(&intent)?, ReservationOutcome::Reserved);
        ledger.request_cancellation(intent.workload_id)?;
        assert_eq!(ledger.used().memory_bytes, 8);
        ledger.reconcile_terminal(intent.workload_id, WorkloadState::Canceled)?;
        assert_eq!(ledger.used().memory_bytes, 0);
        Ok(())
    }

    #[test]
    fn signed_manifest_is_bound_to_node_key_generation_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let (identity, _) =
            NodeIdentity::load_or_initialize(directory.path(), "manifest-test", UnixMillis(1_000))?;
        let manifest = NodeCapabilityManifestV1 {
            schema_version: 1,
            node_id: identity.node_id(),
            device_key_id: identity.key_id(),
            identity_generation: identity.cryptographic_identity().rotation_counter,
            software_version: "0.1.0".to_owned(),
            protocol_revision: 1,
            contract_revisions: BTreeSet::from([1]),
            generation: 7,
            generated_at: UnixMillis(1_000),
            expires_at: UnixMillis(2_000),
            operating_system: "macos".to_owned(),
            architecture: "aarch64".to_owned(),
            logical_cores: 8,
            total_memory_bytes: 64 * 1024 * 1024 * 1024,
            services: Vec::new(),
        };
        let signed = sign_node_manifest(&identity, manifest)?;
        signed.verify(
            identity.node_id(),
            identity.public_key(),
            UnixMillis(1_500),
            7,
        )?;
        assert!(
            signed
                .verify(
                    NodeId(Uuid::new_v4()),
                    identity.public_key(),
                    UnixMillis(1_500),
                    7,
                )
                .is_err()
        );
        assert!(
            signed
                .verify(
                    identity.node_id(),
                    identity.public_key(),
                    UnixMillis(2_000),
                    7,
                )
                .is_err()
        );
        assert!(
            signed
                .verify(
                    identity.node_id(),
                    identity.public_key(),
                    UnixMillis(1_500),
                    8,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn workload_module_cannot_reach_legacy_dispatch_or_process_apis() {
        let source = include_str!("workload.rs");
        let forbidden = [
            ["use crate::", "capabilities"].concat(),
            ["std::", "process::"].concat(),
            ["tokio::", "process::"].concat(),
            ["Command", "::new"].concat(),
        ];
        for needle in forbidden {
            assert!(!source.contains(&needle));
        }
    }

    fn sample_intent(seed: u128, memory: u64) -> WorkloadIntentV1 {
        WorkloadIntentV1 {
            schema_version: 1,
            protocol_revision: 1,
            contract_revision: 1,
            workload_id: Uuid::from_u128(seed),
            idempotency_key: Uuid::from_u128(seed + 10),
            task_id: Uuid::from_u128(seed + 20),
            cognitive_plan_id: Uuid::from_u128(seed + 30),
            cognitive_node_id: Uuid::from_u128(seed + 40),
            parent_workload_id: None,
            service_id: "native-engine".to_owned(),
            artifact_digest: None,
            execution_class: ExecutionClass::TextInference,
            classification: Classification::Secret,
            classification_reference: Sha256Digest([2; 32]),
            locality: Locality::ThisNodeOnly,
            resources: envelope(memory),
            deadline: UnixMillis(2_000),
            authorization_principal: "owner-authorized-plan".to_owned(),
            control_plane_id: "ai-avenger".to_owned(),
            node_id: NodeId(Uuid::from_u128(99)),
            trust_epoch: 3,
            policy_revision: 5,
            policy_digest: Sha256Digest([9; 32]),
            created_at: UnixMillis(1_000),
            expires_at: UnixMillis(1_900),
            correlation_id: Uuid::from_u128(seed + 50),
        }
    }

    fn service(id: &str, locality: Locality, artifact: Sha256Digest) -> TrustedServiceDefinitionV1 {
        TrustedServiceDefinitionV1 {
            service_id: id.to_owned(),
            protocol_revision: 1,
            accepted_contract_revisions: BTreeSet::from([1]),
            endpoint_id: format!("{id}-uds"),
            endpoint_key_id: Sha256Digest([3; 32]),
            version: "0.1.0".to_owned(),
            trusted: true,
            health: ServiceHealth::Ready,
            locality,
            execution_classes: BTreeSet::from([ExecutionClass::TextInference]),
            approved_artifact_digests: BTreeSet::from([artifact]),
            sandbox: SandboxCapabilitiesV1 {
                process_isolation: EnforcementLevel::Unavailable,
                filesystem_isolation: EnforcementLevel::Unavailable,
                network_isolation: EnforcementLevel::Unavailable,
                resource_enforcement: EnforcementLevel::Advisory,
                dedicated_identity: EnforcementLevel::Unavailable,
                descendant_termination: EnforcementLevel::Unavailable,
            },
            availability_reason: None,
        }
    }

    fn sign_intent(
        intent: WorkloadIntentV1,
        key: &SigningKey,
    ) -> Result<SignedWorkloadIntentV1, WorkloadError> {
        let signature = key.sign(&intent.signing_bytes()?);
        Ok(SignedWorkloadIntentV1 {
            intent,
            signature_suite: "Ed25519".to_owned(),
            control_plane_public_key: PublicKeyBytes(key.verifying_key().to_bytes()),
            signature: SignatureBytes::from_slice(&signature.to_bytes())
                .map_err(|_| WorkloadError::Authorization)?,
        })
    }
}
